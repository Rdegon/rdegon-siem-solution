from __future__ import annotations

import os
from pathlib import Path
import shlex
import sys


ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from deploy.soc_foundation_provision import Proxmox


STANDBY_VMID = int(os.getenv("SIEM_POSTGRES_STANDBY_VMID", "104") or "104")
EXPECTED_PRIMARY = os.getenv("SIEM_POSTGRES_PRIMARY_HOST", "10.20.10.107").strip()
DATA_DIRECTORY = "/var/lib/postgresql/14/main"


def _repair_script() -> str:
    expected_primary = shlex.quote(EXPECTED_PRIMARY)
    return f"""set -euo pipefail
data={shlex.quote(DATA_DIRECTORY)}
expected_primary={expected_primary}
resolved_data=$(readlink -m "$data")
[ "$resolved_data" = {shlex.quote(DATA_DIRECTORY)} ]
[ -f "$data/postgresql.auto.conf" ]

conninfo=$(sed -n "s/^primary_conninfo = '\\(.*\\)'/\\1/p" "$data/postgresql.auto.conf" | tail -n 1)
[ -n "$conninfo" ]
case "$conninfo" in
  *"host=$expected_primary"*) ;;
  *) echo "primary_conninfo does not target the expected internal primary" >&2; exit 1 ;;
esac

stamp=$(date -u +%Y%m%dT%H%M%SZ)
backup_root=/var/backups/postgresql
backup="$backup_root/14-main-stale-$stamp"
install -d -m 0700 -o postgres -g postgres "$backup_root"

systemctl stop postgresql@14-main
mv "$data" "$backup"
install -d -m 0700 -o postgres -g postgres "$data"

rollback() {{
  status=$?
  if [ "$status" -ne 0 ]; then
    systemctl stop postgresql@14-main >/dev/null 2>&1 || true
    [ "$(readlink -m "$data")" = {shlex.quote(DATA_DIRECTORY)} ]
    rm -rf -- "$data"
    mv "$backup" "$data"
    systemctl start postgresql@14-main >/dev/null 2>&1 || true
  fi
  exit "$status"
}}
trap rollback EXIT

runuser -u postgres -- pg_basebackup \
  --dbname="$conninfo" \
  --pgdata="$data" \
  --write-recovery-conf \
  --wal-method=stream \
  --checkpoint=fast

systemctl start postgresql@14-main
for attempt in $(seq 1 30); do
  systemctl is-active --quiet postgresql@14-main && break
  sleep 1
done
sleep 5

streaming=$(runuser -u postgres -- psql -Atqc \
  "SELECT count(*) FROM pg_stat_wal_receiver WHERE status = 'streaming'")
[ "$streaming" = "1" ]
recovery=$(runuser -u postgres -- psql -Atqc "SELECT pg_is_in_recovery()")
[ "$recovery" = "t" ]

trap - EXIT
printf 'service=active\\n'
printf 'recovery=true\\n'
printf 'walreceiver=streaming\\n'
printf 'stale_backup=%s\\n' "$backup"
"""


def main() -> int:
    if not EXPECTED_PRIMARY:
        raise RuntimeError("SIEM_POSTGRES_PRIMARY_HOST must not be empty")
    with Proxmox() as pve:
        print(pve.guest_exec(STANDBY_VMID, _repair_script(), timeout=900))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
