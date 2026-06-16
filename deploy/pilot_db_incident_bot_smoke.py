from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from deploy.pilot_db_incident_bot_deploy import PILOT_DB, PROXMOX_HOST, _connect, _env, _required_env, _smoke, _stdout_setup


def main() -> int:
    _stdout_setup()
    proxmox_user = _env("SIEM_PROXMOX_USER", "root")
    proxmox_password = _required_env("SIEM_PROXMOX_PASSWORD")
    proxmox = _connect(PROXMOX_HOST, proxmox_user, proxmox_password)
    try:
        summary = _smoke(proxmox)
    finally:
        proxmox.close()
    healthy = summary.get("service_active") == "active" and str(summary.get("schema_tables") or "").strip() == "2"
    print(json.dumps({"healthy": healthy, "summary": summary}, ensure_ascii=False))
    return 0 if healthy else 1


if __name__ == "__main__":
    raise SystemExit(main())
