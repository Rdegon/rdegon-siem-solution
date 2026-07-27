from __future__ import annotations

import argparse
import json
import shlex

try:
    from deploy.soc_foundation_provision import Proxmox
except ModuleNotFoundError:
    from soc_foundation_provision import Proxmox


VMID = 106
DATA_PATH = "/var/lib/clickhouse"
STAGING_PATH = "/mnt/clickhouse-nvme"
# ext4 labels are limited to 16 bytes; mkfs truncates the descriptive name.
TARGET_LABEL = "siem-clickhouse-"
MAINTENANCE_MARKER = "/run/siem-maintenance"
CLICKHOUSE_SERVICES = (
    "clickhouse-server.service",
    "siem-writer.service",
    "siem-writer@2.service",
    "siem-stream-corr.service",
    "siem-batch-corr.service",
    "siem-alert-agg.service",
)
MOUNT_DROP_IN = """[Unit]
RequiresMountsFor=/var/lib/clickhouse
After=var-lib-clickhouse.mount
"""


def _service_names() -> str:
    return " ".join(shlex.quote(service) for service in CLICKHOUSE_SERVICES)


def enter_maintenance(pve: Proxmox) -> dict[str, object]:
    script = f"""set -euo pipefail
touch {shlex.quote(MAINTENANCE_MARKER)}
systemctl stop {_service_names()}
printf 'maintenance_marker=present\n'
printf 'services='
{{ systemctl is-active {_service_names()} || true; }} | paste -sd, -
"""
    output = pve.guest_exec(VMID, script, timeout=300)
    return {
        "vmid": VMID,
        "status": [
            line.strip() for line in output.splitlines() if line.strip()
        ],
    }


def validate(pve: Proxmox) -> dict[str, object]:
    script = f"""set -euo pipefail
target=$(blkid -L {shlex.quote(TARGET_LABEL)})
test -n "$target"
printf 'target_device=%s\n' "$target"
printf 'target_uuid=%s\n' "$(blkid -s UUID -o value "$target")"
printf 'data_mount=%s\n' "$(findmnt -n -o SOURCE {shlex.quote(DATA_PATH)} || true)"
printf 'staging_mount=%s\n' "$(findmnt -n -o SOURCE {shlex.quote(STAGING_PATH)} || true)"
printf 'fstab_entry='
findmnt --fstab -n -o SOURCE,TARGET,OPTIONS {shlex.quote(DATA_PATH)} || true
printf 'drop_in='
test -f /etc/systemd/system/clickhouse-server.service.d/20-hot-storage.conf \
  && echo present || echo missing
printf 'maintenance_marker='
test -e {shlex.quote(MAINTENANCE_MARKER)} && echo present || echo absent
printf 'services='
{{ systemctl is-active {_service_names()} || true; }} | paste -sd, -
"""
    output = pve.guest_exec(VMID, script, timeout=120)
    return {
        "vmid": VMID,
        "status": [
            line.strip() for line in output.splitlines() if line.strip()
        ],
    }


def finalize(pve: Proxmox) -> dict[str, object]:
    script = f"""set -euo pipefail
target=$(blkid -L {shlex.quote(TARGET_LABEL)})
test -n "$target"
test "$(findmnt -n -o TARGET "$target")" = {shlex.quote(STAGING_PATH)}
test -n "$(findmnt -n -o SOURCE {shlex.quote(DATA_PATH)})"
for service in {_service_names()}; do
  test "$(systemctl is-active "$service" || true)" != active
done
changes=$(rsync -aHAXn --numeric-ids --delete --itemize-changes \
  {shlex.quote(DATA_PATH)}/ {shlex.quote(STAGING_PATH)}/ | wc -l)
test "$changes" -eq 0
uuid=$(blkid -s UUID -o value "$target")
test -n "$uuid"
cp -a /etc/fstab /etc/fstab.siem-before-clickhouse-hot
python3 - "$uuid" <<'PY'
from pathlib import Path
import sys

path = Path("/etc/fstab")
uuid = sys.argv[1]
replacement = (
    f"UUID={{uuid}} /var/lib/clickhouse ext4 "
    "defaults,noatime,x-systemd.device-timeout=90s 0 2"
)
lines = []
replaced = False
for line in path.read_text(encoding="utf-8").splitlines():
    fields = line.split()
    if len(fields) >= 2 and fields[1] == "/var/lib/clickhouse":
        if not replaced:
            lines.append(replacement)
            replaced = True
        continue
    lines.append(line)
if not replaced:
    lines.append(replacement)
path.write_text("\\n".join(lines).rstrip() + "\\n", encoding="utf-8")
PY
install -d -m 0755 /etc/systemd/system/clickhouse-server.service.d
cat >/etc/systemd/system/clickhouse-server.service.d/20-hot-storage.conf <<'EOF'
{MOUNT_DROP_IN.rstrip()}
EOF
systemctl daemon-reload
umount {shlex.quote(DATA_PATH)}
umount {shlex.quote(STAGING_PATH)}
mount {shlex.quote(DATA_PATH)}
test "$(findmnt -n -o UUID {shlex.quote(DATA_PATH)})" = "$uuid"
chown clickhouse:clickhouse {shlex.quote(DATA_PATH)}
systemctl unmask --runtime {_service_names()} >/dev/null
systemctl start clickhouse-server.service
for attempt in $(seq 1 90); do
  clickhouse-client --query 'SELECT 1' >/dev/null 2>&1 && break
  sleep 2
done
clickhouse-client --query 'SELECT 1' >/dev/null
systemctl start siem-writer.service siem-writer@2.service \
  siem-stream-corr.service siem-batch-corr.service siem-alert-agg.service
rm -f {shlex.quote(MAINTENANCE_MARKER)}
systemctl start siem-host-runtime-agent.timer 2>/dev/null || true
printf 'target_device=%s\n' "$target"
printf 'target_uuid=%s\n' "$uuid"
printf 'dry_run_changes=%s\n' "$changes"
printf 'mounted_source=%s\n' "$(findmnt -n -o SOURCE {shlex.quote(DATA_PATH)})"
printf 'services='
systemctl is-active {_service_names()} | paste -sd, -
"""
    output = pve.guest_exec(VMID, script, timeout=600)
    return {
        "vmid": VMID,
        "status": [
            line.strip() for line in output.splitlines() if line.strip()
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Validate or atomically finalize VM106 ClickHouse data placement "
            "on the dedicated NVMe-backed disk"
        )
    )
    parser.add_argument(
        "--finalize",
        action="store_true",
        help="switch the already verified rsync copy into production",
    )
    parser.add_argument(
        "--enter-maintenance",
        action="store_true",
        help="set the watchdog maintenance marker and stop the storage pipeline",
    )
    args = parser.parse_args()
    if args.finalize and args.enter_maintenance:
        parser.error("--finalize and --enter-maintenance are mutually exclusive")
    with Proxmox() as pve:
        if args.enter_maintenance:
            result = enter_maintenance(pve)
        elif args.finalize:
            result = finalize(pve)
        else:
            result = validate(pve)
    print(json.dumps(result, indent=2, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
