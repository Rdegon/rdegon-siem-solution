from __future__ import annotations

import base64
import json
import shlex
import sys
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from deploy.soc_foundation_provision import Proxmox


VMID = 124
SOURCE = ROOT / "services" / "incident_telegram_bot.py"
DESTINATION = "/opt/siem/incident-telegram-bot/incident_telegram_bot.py"
PYTHON = "/opt/siem/incident-telegram-bot/.venv/bin/python"


def _push(pve: Proxmox, backup_path: str) -> None:
    encoded = base64.b64encode(SOURCE.read_bytes()).decode("ascii")
    temporary = "/tmp/incident-telegram-bot.py.b64"
    pve.guest_exec(
        VMID,
        f"install -d -m 0750 {shlex.quote(str(PurePosixPath(backup_path).parent))}; "
        f"cp -a {shlex.quote(DESTINATION)} {shlex.quote(backup_path)}; "
        f": > {shlex.quote(temporary)}",
    )
    for offset in range(0, len(encoded), 32_000):
        pve.guest_exec(
            VMID,
            f"printf %s {shlex.quote(encoded[offset:offset + 32_000])} "
            f">> {shlex.quote(temporary)}",
        )
    pve.guest_exec(
        VMID,
        f"base64 -d {shlex.quote(temporary)} > {shlex.quote(DESTINATION)}; "
        f"rm -f {shlex.quote(temporary)}; "
        f"chmod 0755 {shlex.quote(DESTINATION)}",
    )


def main() -> int:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup = f"/var/backups/siem/incident-bot-{stamp}.py"
    with Proxmox() as pve:
        _push(pve, backup)
        output = pve.guest_exec(
            VMID,
            "set -euo pipefail; "
            f"{shlex.quote(PYTHON)} -m py_compile {shlex.quote(DESTINATION)}; "
            "systemctl restart incident-telegram-bot.service; "
            "for attempt in $(seq 1 20); do "
            "systemctl is-active --quiet incident-telegram-bot.service && break; "
            "sleep 1; done; "
            "systemctl is-active incident-telegram-bot.service; "
            "for attempt in $(seq 1 30); do "
            "columns=$(sudo -u postgres psql -d siem_incident_bot -Atc "
            "\"select count(*) from information_schema.columns "
            "where table_name='incident_delivery_state' "
            "and column_name in ("
            "'telegram_message_id','telegram_chat_id','delivery_count','last_seen_at',"
            "'current_incident_key','aggregation_fingerprint','operation_key','operation_kind',"
            "'operation_state','operation_fingerprint','retry_count','last_error')\"); "
            "[ \"$columns\" = 12 ] && break; "
            "sleep 1; "
            "done; "
            "printf '%s\\n' \"$columns\"",
            timeout=180,
        )
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    if lines[-2:] != ["active", "12"]:
        raise RuntimeError(f"Incident bot release smoke failed: {lines}")
    print(
        json.dumps(
            {
                "vmid": VMID,
                "backup": backup,
                "service": lines[-2],
                "migration_columns": int(lines[-1]),
            },
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
