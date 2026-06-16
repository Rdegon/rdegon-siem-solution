from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import secrets
import shlex
import ssl
import sys
import textwrap
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from deploy.proxmox_fleet_wave_deploy import (
    PROXMOX_HOST,
    _connect,
    _env,
    _extract_json_payload,
    _guest_exec,
    _guest_write_text,
    _repo_text,
    _required_env,
    _require_success,
    _run,
    _run_sudo,
)


VM4_HOST = "192.168.1.39"
REMOTE_ROOT = "/opt/siem/siem-solution"
VM4_WEB_PYTHON = "/opt/siem/venv-web/bin/python"
PILOT_GITEA_VMID = 123
NAVIDROME_VMID = 121
KEYCLOAK_HOST = "192.168.1.39"
KEYCLOAK_ISSUER = f"https://{KEYCLOAK_HOST}/realms/siem"
KEYCLOAK_DISCOVERY = f"{KEYCLOAK_ISSUER}/.well-known/openid-configuration"
GITEA_HOST = "pilot-web-01.lab.home.arpa"
GITEA_URL = f"http://{GITEA_HOST}:3000"
NAVIDROME_URL = "http://navidrome-01.lab.home.arpa"
GITEA_AUTH_NAME = "Keycloak SSO"
SEEDED_SSO_USER = "pilot.operator"
GITEA_BREAKGLASS_USER = "gitea-breakglass"
NAVIDROME_BREAKGLASS_USER = "navidrome-breakglass"
OAUTH2_PROXY_VERSION = "7.13.0"
OAUTH2_PROXY_URL = f"https://github.com/oauth2-proxy/oauth2-proxy/releases/download/v{OAUTH2_PROXY_VERSION}/oauth2-proxy-v{OAUTH2_PROXY_VERSION}.linux-amd64.tar.gz"
NAVIDROME_DEFAULT_ENCRYPTION_KEY = "just for obfuscation"


def _stdout_setup() -> None:
    for stream_name in ("stdout", "stderr"):
        stream = getattr(sys, stream_name, None)
        if stream is not None and hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass


def _strong_secret(prefix: str) -> str:
    token = secrets.token_urlsafe(18).replace("-", "A").replace("_", "B")
    return f"{prefix}{token}"


def _cookie_secret() -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii")


def _navidrome_encrypt_password(password: str, *, encryption_key: str = NAVIDROME_DEFAULT_ENCRYPTION_KEY) -> str:
    key = hashlib.sha256(encryption_key.encode("utf-8")).digest()
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, password.encode("utf-8"), None)
    return base64.b64encode(nonce + ciphertext).decode("ascii")


def _fetch_server_certificate(host: str, port: int = 443) -> str:
    return ssl.get_server_certificate((host, port))


def _vm4_python(client, code: str, *, sudo_password: str) -> str:
    payload = base64.b64encode(code.encode("utf-8")).decode("ascii")
    command = (
        "bash -lc "
        + shlex.quote(
            "cd /opt/siem/siem-solution && "
            f"PYTHONPATH=/opt/siem/siem-solution {VM4_WEB_PYTHON} - <<'PY'\n"
            "import base64\n"
            "import os\n"
            "from pathlib import Path\n"
            "for raw in Path('/etc/siem/web.env').read_text(encoding='utf-8').splitlines():\n"
            "    line = raw.strip()\n"
            "    if not line or line.startswith('#') or '=' not in line:\n"
            "        continue\n"
            "    key, value = line.split('=', 1)\n"
            "    os.environ.setdefault(key.strip(), value.strip())\n"
            f"exec(compile(base64.b64decode('{payload}').decode('utf-8'), '<pilot_sso_correlation_wave>', 'exec'), {{}})\n"
            "PY"
        )
    )
    code_rc, out, err = _run_sudo(client, command, sudo_password=sudo_password)
    return _require_success(code_rc, out, err, "VM4 Python command failed")


def _ensure_vm4_sso_state(
    vm4,
    *,
    seeded_password: str,
    sudo_password: str,
) -> dict[str, Any]:
    code = textwrap.dedent(
        f"""
        import json

        import control_plane_access_ops as access_ops
        import keycloak_admin_runtime as kc

        actor = "pilot-sso-correlation-wave"
        username = {SEEDED_SSO_USER!r}
        password = {seeded_password!r}

        def find_exact_user(name: str):
            items = kc.list_users(search=name, limit=50)
            return next((item for item in items if str(item.get("username") or "").strip().lower() == name.lower()), None)

        user = find_exact_user(username)
        payload = {{
            "username": username,
            "email": f"{{username}}@lab.internal",
            "first_name": "Pilot",
            "last_name": "Operator",
            "enabled": True,
            "email_verified": True,
        }}
        if user:
            user_detail = kc.update_user(str(user.get("id") or ""), payload, actor=actor)
            kc.set_user_password(str(user_detail.get("id") or ""), {{"password": password, "temporary": False}}, actor=actor)
        else:
            user_detail = kc.create_user({{**payload, "password": password}}, actor=actor)

        gitea_client = kc.save_client(
            {{
                "client_id": "pilot-gitea",
                "name": "Pilot Gitea",
                "description": "Internal Gitea SSO client",
                "enabled": True,
                "public_client": False,
                "service_accounts_enabled": False,
                "standard_flow_enabled": True,
                "direct_access_grants_enabled": False,
                "frontchannel_logout": False,
                "redirect_uris": [{f"{GITEA_URL}/*"!r}],
                "web_origins": [{GITEA_URL!r}],
                "root_url": {GITEA_URL!r},
                "base_url": {GITEA_URL!r},
            }},
            actor=actor,
            client_id="pilot-gitea",
        )
        gitea_secret = kc.rotate_client_secret("pilot-gitea", actor=actor)["secret"]
        kc.ensure_group_membership_mapper("pilot-gitea", actor=actor, claim_name="groups", mapper_name="groups")

        nav_client = kc.save_client(
            {{
                "client_id": "navidrome-proxy",
                "name": "Navidrome Proxy",
                "description": "Reverse-proxy browser SSO for Navidrome",
                "enabled": True,
                "public_client": False,
                "service_accounts_enabled": False,
                "standard_flow_enabled": True,
                "direct_access_grants_enabled": False,
                "frontchannel_logout": False,
                "redirect_uris": [{f"{NAVIDROME_URL}/oauth2/callback"!r}],
                "web_origins": [{NAVIDROME_URL!r}],
                "root_url": {NAVIDROME_URL!r},
                "base_url": {NAVIDROME_URL!r},
            }},
            actor=actor,
            client_id="navidrome-proxy",
        )
        nav_secret = kc.rotate_client_secret("navidrome-proxy", actor=actor)["secret"]
        kc.ensure_group_membership_mapper("navidrome-proxy", actor=actor, claim_name="groups", mapper_name="groups")
        kc.ensure_audience_mapper("navidrome-proxy", actor=actor, audience="navidrome-proxy", mapper_name="audience")

        gitea_grant = access_ops.save_access_grant(
            {{
                "principal_kind": "keycloak_user",
                "principal_id": username,
                "system_id": "gitea",
                "role": "admin",
                "sections": ["repos", "issues", "wiki", "packages", "admin"],
                "enabled": True,
            }},
            actor=actor,
        )
        navidrome_grant = access_ops.save_access_grant(
            {{
                "principal_kind": "keycloak_user",
                "principal_id": username,
                "system_id": "navidrome",
                "role": "admin",
                "sections": ["library", "playlists", "sharing", "admin"],
                "enabled": True,
            }},
            actor=actor,
        )

        summary = {{
            "seeded_user": {{
                "username": username,
                "id": user_detail.get("id"),
                "email": user_detail.get("email"),
            }},
            "gitea_client": {{
                "client_id": gitea_client.get("client_id"),
                "secret": gitea_secret,
            }},
            "navidrome_client": {{
                "client_id": nav_client.get("client_id"),
                "secret": nav_secret,
            }},
            "grants": [gitea_grant, navidrome_grant],
        }}
        print(json.dumps(summary, ensure_ascii=False))
        """
    ).strip()
    raw = _vm4_python(vm4, code, sudo_password=sudo_password)
    return json.loads(_extract_json_payload(raw))


def _configure_gitea(
    proxmox,
    *,
    certificate_pem: str,
    client_secret: str,
    breakglass_password: str,
) -> dict[str, Any]:
    gitea_env = "USER_UID=1000\nUSER_GID=1000\nSSL_CERT_FILE=/data/ca/siem-keycloak.crt\n"
    gitea_app_ini = textwrap.dedent(
        f"""
        APP_NAME = Gitea
        RUN_MODE = prod

        [server]
        APP_DATA_PATH = /data/gitea
        DOMAIN = {GITEA_HOST}
        SSH_DOMAIN = {GITEA_HOST}
        HTTP_PORT = 3000
        ROOT_URL = {GITEA_URL}/
        DISABLE_SSH = false
        SSH_PORT = 2222
        SSH_LISTEN_PORT = 22

        [database]
        DB_TYPE = sqlite3
        PATH = /data/gitea/gitea.db

        [repository]
        ROOT = /data/git/repositories

        [repository.local]
        LOCAL_COPY_PATH = /data/gitea/tmp/local-repo

        [repository.upload]
        TEMP_PATH = /data/gitea/uploads

        [indexer]
        ISSUE_INDEXER_PATH = /data/gitea/indexers/issues.bleve

        [session]
        PROVIDER_CONFIG = /data/gitea/sessions

        [picture]
        AVATAR_UPLOAD_PATH = /data/gitea/avatars
        REPOSITORY_AVATAR_UPLOAD_PATH = /data/gitea/repo-avatars

        [attachment]
        PATH = /data/gitea/attachments

        [log]
        MODE = console
        LEVEL = info
        ROOT_PATH = /data/gitea/log

        [security]
        INSTALL_LOCK = true
        SECRET_KEY = {_strong_secret("gk-")}
        INTERNAL_TOKEN = {_strong_secret("it-")}
        PASSWORD_HASH_ALGO = pbkdf2
        REVERSE_PROXY_LIMIT = 1
        REVERSE_PROXY_TRUSTED_PROXIES = *

        [service]
        DISABLE_REGISTRATION = false
        REQUIRE_SIGNIN_VIEW = true
        REGISTER_EMAIL_CONFIRM = false
        ENABLE_NOTIFY_MAIL = false
        ALLOW_ONLY_EXTERNAL_REGISTRATION = true
        SHOW_REGISTRATION_BUTTON = false

        [oauth2]
        JWT_SECRET = {_strong_secret("jwt-")}

        [oauth2_client]
        ENABLE_AUTO_REGISTRATION = true
        ACCOUNT_LINKING = auto

        [openid]
        ENABLE_OPENID_SIGNIN = true
        ENABLE_OPENID_SIGNUP = false

        [lfs]
        PATH = /data/git/lfs
        """
    ).strip() + "\n"
    _guest_write_text(proxmox, type("Guest", (), {"vmid": PILOT_GITEA_VMID, "guest_type": "qemu", "name": "pilot-web-01"})(), "/etc/default/pilot-gitea", gitea_env, mode="0600")
    _guest_write_text(proxmox, type("Guest", (), {"vmid": PILOT_GITEA_VMID, "guest_type": "qemu", "name": "pilot-web-01"})(), "/opt/pilot/gitea/ca/siem-keycloak.crt", certificate_pem, mode="0644")
    _guest_write_text(proxmox, type("Guest", (), {"vmid": PILOT_GITEA_VMID, "guest_type": "qemu", "name": "pilot-web-01"})(), "/opt/pilot/gitea/gitea/conf/app.ini", gitea_app_ini, mode="0640")
    _guest_write_text(proxmox, type("Guest", (), {"vmid": PILOT_GITEA_VMID, "guest_type": "qemu", "name": "pilot-web-01"})(), "/etc/systemd/system/pilot-gitea.service", _repo_text("deploy/common/pilot-gitea.service"), mode="0644")
    _guest_exec(
        proxmox,
        type("Guest", (), {"vmid": PILOT_GITEA_VMID, "guest_type": "qemu", "name": "pilot-web-01"})(),
        "install -d -m 0755 /opt/pilot/gitea /opt/pilot/gitea/gitea /opt/pilot/gitea/gitea/conf /opt/pilot/gitea/ca && "
        "chown -R 1000:1000 /opt/pilot/gitea",
        timeout=120,
    )
    _guest_exec(
        proxmox,
        type("Guest", (), {"vmid": PILOT_GITEA_VMID, "guest_type": "qemu", "name": "pilot-web-01"})(),
        "systemctl daemon-reload && systemctl enable pilot-gitea --now && systemctl restart pilot-gitea && systemctl is-active pilot-gitea",
        timeout=900,
    )
    _guest_exec(
        proxmox,
        type("Guest", (), {"vmid": PILOT_GITEA_VMID, "guest_type": "qemu", "name": "pilot-web-01"})(),
        "for attempt in $(seq 1 40); do curl -fsS http://127.0.0.1:3000/ >/dev/null && exit 0; sleep 3; done; exit 1",
        timeout=240,
    )
    _guest_exec(
        proxmox,
        type("Guest", (), {"vmid": PILOT_GITEA_VMID, "guest_type": "qemu", "name": "pilot-web-01"})(),
        "docker exec --user git pilot-gitea gitea migrate --config /data/gitea/conf/app.ini",
        timeout=240,
    )
    auth_list = _guest_exec(
        proxmox,
        type("Guest", (), {"vmid": PILOT_GITEA_VMID, "guest_type": "qemu", "name": "pilot-web-01"})(),
        "docker exec --user git pilot-gitea gitea admin auth list --config /data/gitea/conf/app.ini || true",
        timeout=120,
    )
    auth_id = ""
    for raw_line in auth_list.splitlines():
        line = raw_line.strip()
        if GITEA_AUTH_NAME.lower() in line.lower():
            parts = [part for part in line.replace("|", " ").split() if part]
            auth_id = parts[0] if parts and parts[0].isdigit() else ""
            break
    auth_common = (
        "docker exec --user git pilot-gitea gitea admin auth "
        + ("update-oauth" if auth_id else "add-oauth")
        + " --config /data/gitea/conf/app.ini "
        + (f"--id {auth_id} " if auth_id else "")
        + f"--name {shlex.quote(GITEA_AUTH_NAME)} "
        + "--provider openidConnect "
        + "--key pilot-gitea "
        + f"--secret {shlex.quote(client_secret)} "
        + f"--auto-discover-url {shlex.quote(KEYCLOAK_DISCOVERY)} "
        + "--scopes \"profile email\" "
        + "--group-claim-name groups "
        + "--required-claim-name groups "
        + "--required-claim-value gitea-users "
        + "--admin-group gitea-admins"
    )
    _guest_exec(
        proxmox,
        type("Guest", (), {"vmid": PILOT_GITEA_VMID, "guest_type": "qemu", "name": "pilot-web-01"})(),
        auth_common,
        timeout=240,
    )
    _guest_exec(
        proxmox,
        type("Guest", (), {"vmid": PILOT_GITEA_VMID, "guest_type": "qemu", "name": "pilot-web-01"})(),
        textwrap.dedent(
            f"""
            python3 - <<'PY'
            import json
            import sqlite3

            conn = sqlite3.connect('/opt/pilot/gitea/gitea/gitea.db')
            cur = conn.cursor()
            row = cur.execute(
                "select id, cfg from login_source where lower(name)=lower(?)",
                ({GITEA_AUTH_NAME!r},),
            ).fetchone()
            if not row:
                raise SystemExit('Gitea Keycloak auth source not found')
            auth_id, cfg_raw = row
            cfg = json.loads(cfg_raw or '{{}}')
            cfg['Scopes'] = ['profile', 'email']
            cur.execute(
                "update login_source set cfg=? where id=?",
                (json.dumps(cfg, ensure_ascii=False, separators=(',', ':')), auth_id),
            )
            conn.commit()
            conn.close()
            PY
            """
        ).strip(),
        timeout=240,
    )
    _guest_exec(
        proxmox,
        type("Guest", (), {"vmid": PILOT_GITEA_VMID, "guest_type": "qemu", "name": "pilot-web-01"})(),
        "systemctl restart pilot-gitea && systemctl is-active pilot-gitea",
        timeout=240,
    )
    create_or_rotate = textwrap.dedent(
        f"""
        set -e
        if docker exec --user git pilot-gitea gitea admin user list --config /data/gitea/conf/app.ini | grep -qi {shlex.quote(GITEA_BREAKGLASS_USER)}; then
          docker exec --user git pilot-gitea gitea admin user change-password --config /data/gitea/conf/app.ini --username {shlex.quote(GITEA_BREAKGLASS_USER)} --password {shlex.quote(breakglass_password)}
        else
          docker exec --user git pilot-gitea gitea admin user create --config /data/gitea/conf/app.ini --admin --username {shlex.quote(GITEA_BREAKGLASS_USER)} --password {shlex.quote(breakglass_password)} --email gitea-breakglass@lab.internal --must-change-password=false
        fi
        docker exec --user git pilot-gitea gitea admin auth list --config /data/gitea/conf/app.ini
        """
    ).strip()
    auth_sources = _guest_exec(
        proxmox,
        type("Guest", (), {"vmid": PILOT_GITEA_VMID, "guest_type": "qemu", "name": "pilot-web-01"})(),
        create_or_rotate,
        timeout=240,
    )
    return {
        "url": GITEA_URL,
        "auth_sources": auth_sources,
        "breakglass_user": GITEA_BREAKGLASS_USER,
    }


def _configure_navidrome(
    proxmox,
    *,
    certificate_pem: str,
    client_secret: str,
    cookie_secret: str,
    breakglass_password: str,
) -> dict[str, Any]:
    guest = type("Guest", (), {"vmid": NAVIDROME_VMID, "guest_type": "lxc", "name": "navidrome-01"})()
    navidrome_toml = textwrap.dedent(
        """
        Address = '127.0.0.1'
        Port = 4533
        MusicFolder = '/var/lib/navidrome/music'
        DataFolder = '/var/lib/navidrome/data'
        LogLevel = 'info'
        EnableSharing = true
        EnableUserEditing = false

        [ExtAuth]
        TrustedSources = '127.0.0.1/32'
        UserHeader = 'Remote-User'
        """
    ).strip() + "\n"
    oauth2_proxy_toml = textwrap.dedent(
        f"""
        provider = "oidc"
        oidc_issuer_url = "{KEYCLOAK_ISSUER}"
        provider_ca_files = ["/etc/ssl/certs/siem-keycloak.crt"]
        use_system_trust_store = true
        client_id = "navidrome-proxy"
        client_secret = "{client_secret}"
        cookie_secret = "{cookie_secret}"
        http_address = "127.0.0.1:4180"
        redirect_url = "{NAVIDROME_URL}/oauth2/callback"
        upstreams = ["http://127.0.0.1:4533/"]
        email_domains = ["*"]
        scope = "openid profile email"
        set_xauthrequest = true
        reverse_proxy = true
        pass_access_token = false
        pass_authorization_header = false
        skip_provider_button = true
        cookie_secure = false
        """
    ).strip() + "\n"
    _guest_exec(
        proxmox,
        guest,
        "export DEBIAN_FRONTEND=noninteractive && apt-get update && apt-get install -y nginx ca-certificates curl",
        timeout=1200,
    )
    _guest_exec(
        proxmox,
        guest,
        textwrap.dedent(
            f"""
            if ! command -v oauth2-proxy >/dev/null 2>&1 && [ ! -x /usr/local/bin/oauth2-proxy ]; then
              tmpdir=$(mktemp -d)
              cd "$tmpdir"
              curl -fsSL {shlex.quote(OAUTH2_PROXY_URL)} -o oauth2-proxy.tar.gz
              tar -xzf oauth2-proxy.tar.gz
              install -m 0755 oauth2-proxy-*/oauth2-proxy /usr/local/bin/oauth2-proxy
              rm -rf "$tmpdir"
            fi
            """
        ).strip(),
        timeout=1200,
    )
    _guest_exec(
        proxmox,
        guest,
        "install -d -m 0755 /etc/navidrome /usr/local/share/ca-certificates /etc/nginx/sites-available /etc/nginx/sites-enabled "
        "/var/lib/navidrome /var/lib/navidrome/data /var/lib/navidrome/music && "
        "id -u navidrome >/dev/null 2>&1 && chown -R navidrome:navidrome /var/lib/navidrome || true",
        timeout=120,
    )
    _guest_write_text(proxmox, guest, "/etc/navidrome/navidrome.toml", navidrome_toml, mode="0644")
    _guest_write_text(proxmox, guest, "/etc/navidrome/oauth2-proxy.toml", oauth2_proxy_toml, mode="0640")
    _guest_write_text(proxmox, guest, "/etc/ssl/certs/siem-keycloak.crt", certificate_pem, mode="0644")
    _guest_write_text(proxmox, guest, "/etc/systemd/system/navidrome.service", _repo_text("deploy/common/navidrome.service"), mode="0644")
    _guest_write_text(proxmox, guest, "/etc/systemd/system/navidrome-oauth2-proxy.service", _repo_text("deploy/common/navidrome-oauth2-proxy.service"), mode="0644")
    _guest_write_text(proxmox, guest, "/etc/nginx/sites-available/navidrome.conf", _repo_text("deploy/common/navidrome-nginx.conf"), mode="0644")
    _guest_exec(
        proxmox,
        guest,
        "chmod 0755 /etc/navidrome && "
        "chown navidrome:navidrome /etc/navidrome/navidrome.toml && "
        "chmod 0644 /etc/navidrome/navidrome.toml && "
        "chown www-data:www-data /etc/navidrome/oauth2-proxy.toml && "
        "chmod 0640 /etc/navidrome/oauth2-proxy.toml && "
        "rm -f /etc/nginx/sites-enabled/default && ln -sf /etc/nginx/sites-available/navidrome.conf /etc/nginx/sites-enabled/navidrome.conf && "
        "nginx -t && "
        "update-ca-certificates >/dev/null 2>&1 || true && "
        "systemctl daemon-reload && systemctl enable navidrome --now && systemctl restart navidrome && "
        "systemctl enable navidrome-oauth2-proxy --now && systemctl restart navidrome-oauth2-proxy && "
        "systemctl enable nginx --now && systemctl restart nginx",
        timeout=600,
    )
    _guest_exec(
        proxmox,
        guest,
        "for attempt in $(seq 1 30); do curl -fsS -H 'Remote-User: pilot.operator' http://127.0.0.1:4533/app/ >/dev/null && exit 0; sleep 2; done; exit 1",
        timeout=180,
    )
    _guest_exec(
        proxmox,
        guest,
        textwrap.dedent(
            f"""
            set -e
            python3 - <<'PY'
            import sqlite3
            import uuid

            username = {NAVIDROME_BREAKGLASS_USER!r}
            display_name = 'Navidrome Breakglass'
            email = 'navidrome-breakglass@lab.internal'
            encrypted_password = {_navidrome_encrypt_password(breakglass_password)!r}

            conn = sqlite3.connect('/var/lib/navidrome/data/navidrome.db')
            cur = conn.cursor()
            row = cur.execute("select id from user where lower(user_name)=lower(?)", (username,)).fetchone()
            if row:
                cur.execute(
                    "update user set name=?, email=?, password=?, is_admin=1, updated_at=datetime('now') where lower(user_name)=lower(?)",
                    (display_name, email, encrypted_password, username),
                )
            else:
                cur.execute(
                    "insert into user (id, user_name, name, email, password, is_admin, created_at, updated_at) values (?, ?, ?, ?, ?, 1, datetime('now'), datetime('now'))",
                    (uuid.uuid4().hex, username, display_name, email, encrypted_password),
                )
            conn.commit()
            for item in cur.execute("select user_name, is_admin from user order by user_name"):
                print("|".join(str(part) for part in item))
            conn.close()
            PY
            """
        ).strip(),
        timeout=240,
    )
    return {
        "url": NAVIDROME_URL,
        "breakglass_user": NAVIDROME_BREAKGLASS_USER,
    }


def main() -> int:
    _stdout_setup()
    parser = argparse.ArgumentParser(description="Deploy pilot Gitea/Navidrome SSO wave and correlation authoring runtime.")
    parser.add_argument("--skip-vm4", action="store_true")
    args = parser.parse_args()

    proxmox_password = _required_env("SIEM_PROXMOX_PASSWORD")
    vm4_password = _required_env("SIEM_VM4_PASSWORD")
    certificate_pem = _fetch_server_certificate(KEYCLOAK_HOST)
    seeded_password = _strong_secret("PilotSso!")
    gitea_breakglass_password = _strong_secret("GiteaBG!")
    navidrome_breakglass_password = _strong_secret("NavidromeBG!")
    cookie_secret = _cookie_secret()

    summary: dict[str, Any] = {
        "seeded_sso_user": {
            "username": SEEDED_SSO_USER,
            "password": seeded_password,
        },
        "gitea": {
            "breakglass_user": GITEA_BREAKGLASS_USER,
            "breakglass_password": gitea_breakglass_password,
        },
        "navidrome": {
            "breakglass_user": NAVIDROME_BREAKGLASS_USER,
            "breakglass_password": navidrome_breakglass_password,
        },
    }

    if not args.skip_vm4:
        vm4 = _connect(VM4_HOST, "rdegon", vm4_password)
        try:
            summary["keycloak"] = _ensure_vm4_sso_state(vm4, seeded_password=seeded_password, sudo_password=vm4_password)
        finally:
            vm4.close()

    proxmox = _connect(_env("SIEM_PROXMOX_HOST", PROXMOX_HOST), _env("SIEM_PROXMOX_USER", "root"), proxmox_password)
    try:
        summary["gitea"].update(
            _configure_gitea(
                proxmox,
                certificate_pem=certificate_pem,
                client_secret=str(((summary.get("keycloak") or {}).get("gitea_client") or {}).get("secret") or ""),
                breakglass_password=gitea_breakglass_password,
            )
        )
        summary["navidrome"].update(
            _configure_navidrome(
                proxmox,
                certificate_pem=certificate_pem,
                client_secret=str(((summary.get("keycloak") or {}).get("navidrome_client") or {}).get("secret") or ""),
                cookie_secret=cookie_secret,
                breakglass_password=navidrome_breakglass_password,
            )
        )
    finally:
        proxmox.close()

    print(json.dumps(summary, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
