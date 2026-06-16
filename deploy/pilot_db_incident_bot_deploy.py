from __future__ import annotations

import argparse
import base64
import json
import os
import shlex
import ssl
import sys
import textwrap
from http.cookiejar import CookieJar
from pathlib import Path
from urllib.parse import urlencode
from urllib.request import HTTPCookieProcessor, HTTPSHandler, Request, build_opener

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from deploy.proxmox_fleet_wave_deploy import PROXMOX_HOST, GuestSpec, _connect, _env, _guest_exec, _guest_write_text

PILOT_DB = GuestSpec(124, "qemu", "pilot-db-01", "pilot-db", ("postgresql@14-main", "ssh", "rsyslog", "incident-telegram-bot"))
OPENCLAW = GuestSpec(126, "qemu", "openclaw-gateway", "openclaw-gateway", ("openclaw-vless", "ssh"))
BOT_ROOT = "/opt/siem/incident-telegram-bot"
SERVICE_ACCOUNT_ID = "incident-telegram-bot"
VM4_HOST = "192.168.1.39"
OPENCLAW_PROXY_IP = "10.20.30.126"
OPENCLAW_PROXY_HOST = "openclaw-gateway.lab.home.arpa"
OPENCLAW_PROXY_PORT = 10809


def _stdout_setup() -> None:
    for stream_name in ("stdout", "stderr"):
        stream = getattr(sys, stream_name, None)
        if stream is not None and hasattr(stream, "reconfigure"):
            try:
                stream.reconfigure(encoding="utf-8", errors="replace")
            except Exception:
                pass


def _required_env(name: str) -> str:
    value = _env(name)
    if value:
        return value
    raise SystemExit(f"Missing required environment variable: {name}")


def _repo_text(rel_path: str) -> str:
    return (ROOT / rel_path).read_text(encoding="utf-8")


def _strong_secret(prefix: str) -> str:
    token = base64.urlsafe_b64encode(os.urandom(18)).decode("ascii").rstrip("=")
    return f"{prefix}{token}"


def _existing_env(proxmox) -> dict[str, str]:
    try:
        content = _guest_exec(
            proxmox,
            PILOT_DB,
            "python3 - <<'PY'\nfrom pathlib import Path\npath = Path('/etc/siem/incident-telegram-bot.env')\nprint(path.read_text(encoding='utf-8') if path.exists() else '')\nPY",
            timeout=60,
        )
    except Exception:
        return {}
    values: dict[str, str] = {}
    for raw_line in str(content or "").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in raw_line:
            continue
        key, value = raw_line.split("=", 1)
        values[key.strip()] = value.strip()
    return values


class Client:
    def __init__(self, base_url: str) -> None:
        self.base_url = base_url.rstrip("/")
        self.jar = CookieJar()
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        self.opener = build_opener(HTTPSHandler(context=context), HTTPCookieProcessor(self.jar))

    def csrf_token(self) -> str:
        for cookie in self.jar:
            if cookie.name == "csrf_token":
                return cookie.value
        return ""

    def request(self, path: str, *, method: str = "GET", headers: dict[str, str] | None = None, data: bytes | None = None) -> tuple[int, str]:
        prepared_headers = dict(headers or {})
        if method.upper() not in {"GET", "HEAD", "OPTIONS"} and "X-CSRF-Token" not in prepared_headers:
            csrf = self.csrf_token()
            if csrf:
                prepared_headers["X-CSRF-Token"] = csrf
        request = Request(f"{self.base_url}{path}", headers=prepared_headers, data=data, method=method)
        with self.opener.open(request, timeout=25) as response:
            return response.status, response.read().decode("utf-8", errors="replace")


def _login(client: Client, username: str, password: str) -> None:
    code, _ = client.request("/auth/login")
    if code != 200:
        raise RuntimeError(f"Unable to load login page: {code}")
    payload = urlencode(
        {
            "username": username,
            "password": password,
            "auth_flow": "break_glass",
            "break_glass_reason": "pilot db incident bot deploy",
            "break_glass_minutes": "30",
        }
    ).encode("utf-8")
    code, body = client.request(
        "/auth/login",
        method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        data=payload,
    )
    if code != 200 or 'id="root"' not in body:
        raise RuntimeError("Unable to authenticate to SIEM for incident bot deploy")


def _request_json(client: Client, path: str, *, method: str = "GET", payload: dict[str, object] | None = None) -> dict[str, object]:
    data = None
    headers = {"Accept": "application/json"}
    if payload is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(payload).encode("utf-8")
    code, body = client.request(path, method=method, headers=headers, data=data)
    if code != 200:
        raise RuntimeError(f"Unexpected status for {path}: {code}")
    parsed = json.loads(body)
    if isinstance(parsed, dict) and parsed.get("error"):
        raise RuntimeError(f"{path} failed: {parsed['error']}")
    return parsed


def _ensure_service_account_token(client: Client) -> tuple[str, str]:
    desired_permissions = ["alerts:view", "alerts:history:view", "cases:view", "health:view", "incidents:update", "response:view", "response:run"]
    payload = {
        "id": SERVICE_ACCOUNT_ID,
        "name": SERVICE_ACCOUNT_ID,
        "description": "Telegram incident notification bot",
        "enabled": True,
        "permissions": desired_permissions,
        "permission_bundles": [],
        "tags": ["incident-bot", "telegram"],
    }
    _request_json(client, "/api/auth/service-accounts", method="POST", payload=payload)
    token_result = _request_json(
        client,
        f"/api/auth/service-accounts/{SERVICE_ACCOUNT_ID}/tokens",
        method="POST",
        payload={"title": "pilot-db deploy token", "expires_days": 365},
    )
    token = str(((token_result.get("token") or {}) if isinstance(token_result, dict) else {}).get("token") or "").strip()
    if not token:
        raise RuntimeError("Incident bot service-account token was not returned")
    return SERVICE_ACCOUNT_ID, token


def _configure_postgres(proxmox, *, db_password: str) -> None:
    sql = textwrap.dedent(
        f"""
        DO $$
        BEGIN
          IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'siem_incident_bot') THEN
            CREATE ROLE siem_incident_bot LOGIN PASSWORD '{db_password}';
          ELSE
            ALTER ROLE siem_incident_bot WITH LOGIN PASSWORD '{db_password}';
          END IF;
        END $$;
        SELECT 'created';
        """
    ).strip()
    _guest_exec(
        proxmox,
        PILOT_DB,
        "sudo -u postgres psql -v ON_ERROR_STOP=1 -d postgres <<'SQL'\n"
        + sql
        + "\nSQL\n"
        + "sudo -u postgres psql -tAc \"SELECT 1 FROM pg_database WHERE datname='siem_incident_bot'\" | grep -q 1 || "
        + "sudo -u postgres createdb -O siem_incident_bot siem_incident_bot",
        timeout=240,
    )


def _ensure_host_runtime_service(proxmox) -> None:
    script = textwrap.dedent(
        """
        python3 - <<'PY'
        from pathlib import Path

        env_path = Path("/etc/siem/host-runtime.env")
        lines = env_path.read_text(encoding="utf-8").splitlines()
        output = []
        updated = False
        for raw in lines:
            if raw.startswith("SIEM_HOST_RUNTIME_SERVICES="):
                _, value = raw.split("=", 1)
                services = [item.strip() for item in value.split(",") if item.strip()]
                if "incident-telegram-bot" not in services:
                    services.append("incident-telegram-bot")
                raw = "SIEM_HOST_RUNTIME_SERVICES=" + ",".join(services)
                updated = True
            output.append(raw)
        if not updated:
            output.append("SIEM_HOST_RUNTIME_SERVICES=postgresql@14-main,ssh,rsyslog,incident-telegram-bot")
        env_path.write_text("\\n".join(output) + "\\n", encoding="utf-8")
        PY
        """
    ).strip()
    _guest_exec(proxmox, PILOT_DB, script, timeout=120)


def _ensure_openclaw_proxy(proxmox, *, allow_from: str, proxy_ip: str) -> None:
    script = textwrap.dedent(
        f"""
        python3 - <<'PY'
        import json
        from pathlib import Path

        path = Path("/home/openclaw/.config/xray/openclaw-vless-client.json")
        data = json.loads(path.read_text(encoding="utf-8"))
        changed = False
        for inbound in data.get("inbounds", []):
            if inbound.get("tag") == "http-in" and inbound.get("listen") != "{proxy_ip}":
                inbound["listen"] = "{proxy_ip}"
                changed = True
        if changed:
            path.write_text(json.dumps(data, indent=2) + "\\n", encoding="utf-8")
        PY
        systemctl restart openclaw-vless.service
        if command -v ufw >/dev/null 2>&1; then
          ufw allow from {allow_from} to any port {OPENCLAW_PROXY_PORT} proto tcp >/dev/null 2>&1 || true
        fi
        systemctl is-active openclaw-vless.service
        """
    ).strip()
    _guest_exec(proxmox, OPENCLAW, script, timeout=240)


def _deploy_files(
    proxmox,
    *,
    service_token: str,
    db_password: str,
    telegram_bot_token: str,
    telegram_chat_id: str,
    telegram_proxy_url: str,
) -> None:
    env_text = textwrap.dedent(
        f"""
        SIEM_BOT_BASE_URL=https://{VM4_HOST}
        SIEM_BOT_OPEN_BASE_URL=https://{VM4_HOST}
        SIEM_BOT_API_TOKEN={service_token}
        SIEM_BOT_INCIDENT_VIEW=agg
        SIEM_BOT_INCIDENT_WINDOW=24h
        SIEM_BOT_INCIDENT_LIMIT=30
        SIEM_BOT_POLL_SECONDS=45
        SIEM_BOT_VERIFY_TLS=false
        SIEM_BOT_ENABLE_CALLBACKS=true
        SIEM_BOT_DEFAULT_TIMEZONE=Europe/Moscow
        SIEM_TELEGRAM_BOT_TOKEN={telegram_bot_token}
        SIEM_TELEGRAM_CHAT_ID={telegram_chat_id}
        SIEM_TELEGRAM_PROXY_URL={telegram_proxy_url}
        SIEM_BOT_POSTGRES_DSN=postgresql://siem_incident_bot:{db_password}@127.0.0.1:5432/siem_incident_bot
        """
    ).strip() + "\n"
    _guest_write_text(proxmox, PILOT_DB, f"{BOT_ROOT}/incident_telegram_bot.py", _repo_text("services/incident_telegram_bot.py"), mode="0755")
    _guest_write_text(proxmox, PILOT_DB, "/etc/systemd/system/incident-telegram-bot.service", _repo_text("deploy/common/incident-telegram-bot.service"), mode="0644")
    _guest_write_text(proxmox, PILOT_DB, "/etc/siem/incident-telegram-bot.env", env_text, mode="0600")


def _install_bot_runtime(proxmox) -> None:
    _guest_exec(
        proxmox,
        PILOT_DB,
        textwrap.dedent(
            f"""
            export DEBIAN_FRONTEND=noninteractive
            apt-get update
            apt-get install -y python3-venv python3-pip ca-certificates
            install -d -m 0755 {BOT_ROOT}
            python3 -m venv {BOT_ROOT}/.venv
            {BOT_ROOT}/.venv/bin/pip install --upgrade pip setuptools wheel
            {BOT_ROOT}/.venv/bin/pip install psycopg[binary] requests
            systemctl daemon-reload
            systemctl enable incident-telegram-bot.service
            systemctl restart incident-telegram-bot.service
            """
        ).strip(),
        timeout=1800,
    )


def _smoke(proxmox) -> dict[str, object]:
    service_active = _guest_exec(proxmox, PILOT_DB, "systemctl is-active incident-telegram-bot.service", timeout=60).strip()
    schema = _guest_exec(
        proxmox,
        PILOT_DB,
        "sudo -u postgres psql -d siem_incident_bot -tAc \"select count(*) from information_schema.tables where table_name in ('incident_delivery_state','telegram_bot_state')\"",
        timeout=60,
    ).strip()
    env_state = _guest_exec(
        proxmox,
        PILOT_DB,
        "python3 - <<'PY'\nfrom pathlib import Path\ntext = Path('/etc/siem/incident-telegram-bot.env').read_text(encoding='utf-8')\nprint('bot_token=' + ('set' if 'SIEM_TELEGRAM_BOT_TOKEN=' in text and text.split('SIEM_TELEGRAM_BOT_TOKEN=',1)[1].splitlines()[0].strip() else 'missing'))\nprint('chat_id=' + ('set' if 'SIEM_TELEGRAM_CHAT_ID=' in text and text.split('SIEM_TELEGRAM_CHAT_ID=',1)[1].splitlines()[0].strip() else 'missing'))\nprint('proxy_url=' + ('set' if 'SIEM_TELEGRAM_PROXY_URL=' in text and text.split('SIEM_TELEGRAM_PROXY_URL=',1)[1].splitlines()[0].strip() else 'missing'))\nPY",
        timeout=60,
    )
    delivery_state = _guest_exec(
        proxmox,
        PILOT_DB,
        "sudo -u postgres psql -d siem_incident_bot -tAc \"select count(*), coalesce((select payload->'telegram'->>'status' from incident_delivery_state order by updated_at desc nulls last limit 1),'') from incident_delivery_state\"",
        timeout=60,
    ).strip()
    return {
        "service_active": service_active,
        "schema_tables": schema,
        "env_state": env_state.strip().splitlines(),
        "delivery_state": delivery_state,
    }


def main() -> int:
    _stdout_setup()
    parser = argparse.ArgumentParser(description="Deploy incident Telegram bot to pilot-db-01")
    parser.add_argument("--skip-service-account", action="store_true")
    args = parser.parse_args()

    proxmox_user = _env("SIEM_PROXMOX_USER", "root")
    proxmox_password = _required_env("SIEM_PROXMOX_PASSWORD")
    admin_user = _required_env("SIEM_WEB_ADMIN_USER")
    admin_password = _required_env("SIEM_WEB_ADMIN_PASSWORD")
    base_url = _env("SIEM_WEB_BASE_URL", f"https://{VM4_HOST}")
    telegram_proxy_url = _env("SIEM_TELEGRAM_PROXY_URL", f"http://{OPENCLAW_PROXY_HOST}:{OPENCLAW_PROXY_PORT}")
    postgres_password = _env("SIEM_BOT_DB_PASSWORD", _strong_secret("pgbot-"))

    client = Client(base_url)
    _login(client, admin_user, admin_password)
    _, service_token = (SERVICE_ACCOUNT_ID, _env("SIEM_BOT_API_TOKEN")) if args.skip_service_account else _ensure_service_account_token(client)
    if not service_token:
        raise RuntimeError("Incident bot service token is empty")

    proxmox = _connect(PROXMOX_HOST, proxmox_user, proxmox_password)
    try:
        existing_env = _existing_env(proxmox)
        telegram_bot_token = _env("SIEM_TELEGRAM_BOT_TOKEN", existing_env.get("SIEM_TELEGRAM_BOT_TOKEN", ""))
        telegram_chat_id = _env("SIEM_TELEGRAM_CHAT_ID", existing_env.get("SIEM_TELEGRAM_CHAT_ID", ""))
        if not telegram_bot_token:
            raise RuntimeError("Telegram bot token is empty and no existing token was found on pilot-db-01")
        if not telegram_chat_id:
            raise RuntimeError("Telegram chat id is empty and no existing chat id was found on pilot-db-01")
        _ensure_openclaw_proxy(proxmox, allow_from="10.20.30.124", proxy_ip=OPENCLAW_PROXY_IP)
        _configure_postgres(proxmox, db_password=postgres_password)
        _ensure_host_runtime_service(proxmox)
        _deploy_files(
            proxmox,
            service_token=service_token,
            db_password=postgres_password,
            telegram_bot_token=telegram_bot_token,
            telegram_chat_id=telegram_chat_id,
            telegram_proxy_url=telegram_proxy_url,
        )
        _install_bot_runtime(proxmox)
        summary = _smoke(proxmox)
    finally:
        proxmox.close()

    print(json.dumps({"service_account_id": SERVICE_ACCOUNT_ID, "telegram_enabled": bool(telegram_bot_token and telegram_chat_id), "summary": summary}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
