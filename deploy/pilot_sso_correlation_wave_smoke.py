from __future__ import annotations

import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from deploy.pilot_sso_correlation_wave_deploy import (
    GITEA_AUTH_NAME,
    GITEA_URL,
    KEYCLOAK_DISCOVERY,
    NAVIDROME_URL,
    SEEDED_SSO_USER,
    VM4_HOST,
    _connect,
    _extract_json_payload,
    _guest_exec,
    _require_success,
    _run_sudo,
)


PROXMOX_HOST = "192.168.1.101"


def _required_env(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value:
        raise RuntimeError(f"{name} is required")
    return value


def _stdout_setup() -> None:
    for stream_name in ("stdout", "stderr"):
        stream = getattr(sys, stream_name, None)
        if stream is not None and hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass


def _vm4_python(client, code: str, *, sudo_password: str) -> str:
    import base64
    import shlex

    payload = base64.b64encode(code.encode("utf-8")).decode("ascii")
    command = (
        "bash -lc "
        + shlex.quote(
            "cd /opt/siem/siem-solution && "
            "PYTHONPATH=/opt/siem/siem-solution /opt/siem/venv-web/bin/python - <<'PY'\n"
            "import base64\n"
            "import os\n"
            "from pathlib import Path\n"
            "for raw in Path('/etc/siem/web.env').read_text(encoding='utf-8').splitlines():\n"
            "    line = raw.strip()\n"
            "    if not line or line.startswith('#') or '=' not in line:\n"
            "        continue\n"
            "    key, value = line.split('=', 1)\n"
            "    os.environ.setdefault(key.strip(), value.strip())\n"
            f"exec(compile(base64.b64decode('{payload}').decode('utf-8'), '<pilot_sso_correlation_smoke>', 'exec'), {{}})\n"
            "PY"
        )
    )
    code_rc, out, err = _run_sudo(client, command, sudo_password=sudo_password)
    return _require_success(code_rc, out, err, "VM4 smoke Python failed")


def main() -> int:
    _stdout_setup()
    proxmox = _connect(
        os.getenv("SIEM_PROXMOX_HOST", PROXMOX_HOST),
        os.getenv("SIEM_PROXMOX_USER", "root"),
        _required_env("SIEM_PROXMOX_PASSWORD"),
    )
    vm4 = _connect(
        os.getenv("SIEM_VM4_HOST", VM4_HOST),
        os.getenv("SIEM_VM4_USER", "rdegon"),
        _required_env("SIEM_VM4_PASSWORD"),
    )
    vm4_sudo_password = _required_env("SIEM_VM4_SUDO_PASSWORD")
    try:
        gitea_state_raw = _guest_exec(
            proxmox,
            type("Guest", (), {"vmid": 123, "guest_type": "qemu", "name": "pilot-web-01"})(),
            """
python3 - <<'PY'
import json
import sqlite3
from pathlib import Path

app_ini = Path('/opt/pilot/gitea/gitea/conf/app.ini').read_text(encoding='utf-8')
conn = sqlite3.connect('/opt/pilot/gitea/gitea/gitea.db')
cur = conn.cursor()
row = cur.execute(
    "select id, cfg from login_source where lower(name)=lower(?)",
    ('Keycloak SSO',),
).fetchone()
if not row:
    raise SystemExit('missing Gitea Keycloak auth source')
auth_id, cfg_raw = row
cfg = json.loads(cfg_raw or '{}')
print(json.dumps({
    'auth_id': auth_id,
    'app_ini': {
        'disable_registration': 'DISABLE_REGISTRATION = false' in app_ini,
        'allow_only_external_registration': 'ALLOW_ONLY_EXTERNAL_REGISTRATION = true' in app_ini,
        'show_registration_button': 'SHOW_REGISTRATION_BUTTON = false' in app_ini,
        'enable_auto_registration': 'ENABLE_AUTO_REGISTRATION = true' in app_ini,
        'account_linking_auto': 'ACCOUNT_LINKING = auto' in app_ini,
    },
    'cfg': cfg,
}, ensure_ascii=False))
conn.close()
PY
            """.strip(),
            timeout=180,
        )
        navidrome_state_raw = _guest_exec(
            proxmox,
            type("Guest", (), {"vmid": 121, "guest_type": "lxc", "name": "navidrome-01"})(),
            """
python3 - <<'PY'
import json
import subprocess
from pathlib import Path

services = {}
for service in ('navidrome', 'navidrome-oauth2-proxy', 'nginx'):
    result = subprocess.run(['systemctl', 'is-active', service], capture_output=True, text=True, check=False)
    services[service] = result.stdout.strip()

proxy_cfg = Path('/etc/navidrome/oauth2-proxy.toml').read_text(encoding='utf-8')
nginx_cfg = Path('/etc/nginx/sites-available/navidrome.conf').read_text(encoding='utf-8')
seed_check = subprocess.run(
    ['/opt/navidrome/navidrome', 'user', 'list', '-c', '/etc/navidrome/navidrome.toml'],
    capture_output=True,
    text=True,
    check=False,
)
print(json.dumps({
    'services': services,
    'scope_profile_email_only': 'scope = \"openid profile email\"' in proxy_cfg,
    'nginx_proxy_buffers': 'proxy_buffer_size 32k;' in nginx_cfg and 'proxy_buffers 8 32k;' in nginx_cfg,
    'nginx_manifest_bypass': 'location = /app/manifest.webmanifest' in nginx_cfg and 'location = /favicon.ico' in nginx_cfg,
    'seeded_user_present': 'pilot.operator' in seed_check.stdout,
}, ensure_ascii=False))
PY
            """.strip(),
            timeout=180,
        )
        gitea_state = json.loads(gitea_state_raw)
        navidrome_state = json.loads(navidrome_state_raw)
        keycloak_state_raw = _vm4_python(
            vm4,
            """
import json
import control_plane_access_ops as access_ops
import keycloak_admin_runtime as kc

print(json.dumps({
    "clients": [item for item in kc.list_clients() if item.get("client_id") in {"pilot-gitea", "navidrome-proxy"}],
    "seeded_user": [item for item in kc.list_users(search="pilot.operator", limit=20)],
    "gitea_client": kc.get_client("pilot-gitea"),
    "navidrome_client": kc.get_client("navidrome-proxy"),
    "grantable_systems": access_ops.list_access_systems(grantable_only=True),
}, ensure_ascii=False))
            """.strip(),
            sudo_password=vm4_sudo_password,
        )
        keycloak_state = json.loads(_extract_json_payload(keycloak_state_raw))
    finally:
        proxmox.close()
        vm4.close()

    summary = {
        "gitea_url": GITEA_URL,
        "navidrome_url": NAVIDROME_URL,
        "keycloak_discovery": KEYCLOAK_DISCOVERY,
        "gitea_auth_contains_keycloak": bool(gitea_state.get("auth_id")),
        "gitea_cfg_scopes": ((gitea_state.get("cfg") or {}).get("Scopes") or []),
        "gitea_auto_registration_ready": all((gitea_state.get("app_ini") or {}).values()),
        "navidrome_seeded_user": bool(navidrome_state.get("seeded_user_present")),
        "navidrome_scope_profile_email_only": bool(navidrome_state.get("scope_profile_email_only")),
        "navidrome_nginx_buffers": bool(navidrome_state.get("nginx_proxy_buffers")),
        "navidrome_manifest_bypass": bool(navidrome_state.get("nginx_manifest_bypass")),
        "keycloak_clients": [item.get("client_id") for item in keycloak_state.get("clients", [])],
        "gitea_redirect_uris": ((keycloak_state.get("gitea_client") or {}).get("redirect_uris") or []),
        "grantable_systems": [item.get("id") for item in keycloak_state.get("grantable_systems", [])],
        "smoke": "success",
    }
    if not summary["gitea_auth_contains_keycloak"]:
        raise SystemExit(f"Gitea auth source missing: {gitea_state}")
    if summary["gitea_cfg_scopes"] != ["profile", "email"]:
        raise SystemExit(f"Gitea scopes drifted: {summary['gitea_cfg_scopes']}")
    if not summary["gitea_auto_registration_ready"]:
        raise SystemExit(f"Gitea auto-registration flags missing: {gitea_state.get('app_ini')}")
    if f"{GITEA_URL}/*" not in summary["gitea_redirect_uris"]:
        raise SystemExit(f"Gitea redirect URI missing: {summary['gitea_redirect_uris']}")
    if not summary["navidrome_scope_profile_email_only"]:
        raise SystemExit(f"Navidrome oauth2-proxy scope drifted: {navidrome_state}")
    if not summary["navidrome_nginx_buffers"] or not summary["navidrome_manifest_bypass"]:
        raise SystemExit(f"Navidrome nginx config drifted: {navidrome_state}")
    if "gitea" not in summary["grantable_systems"] or "navidrome" not in summary["grantable_systems"]:
        raise SystemExit(f"Grantable systems missing: {summary['grantable_systems']}")
    if "pilot-gitea" not in summary["keycloak_clients"] or "navidrome-proxy" not in summary["keycloak_clients"]:
        raise SystemExit(f"Keycloak clients missing: {summary['keycloak_clients']}")
    print(json.dumps(summary, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
