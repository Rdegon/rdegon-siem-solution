from __future__ import annotations

import json

try:
    from deploy.soc_foundation_provision import Proxmox
except ModuleNotFoundError:
    from soc_foundation_provision import Proxmox


def main() -> int:
    with Proxmox() as pve:
        output = pve.guest_exec(
            106,
            r"""
set -euo pipefail
set -a
. /etc/siem/storage.env
set +a
query() {
  clickhouse-client \
    --host "${SIEM_CH_HOST:-127.0.0.1}" \
    --port "${SIEM_CH_PORT:-9000}" \
    --user "${SIEM_CH_USER:-default}" \
    --password "${SIEM_CH_PASSWORD:-}" \
    --query "$1"
}
before="$(query "
  SELECT count()
  FROM siem.events
  WHERE device_product = 'step-ca'
    AND ts >= now() - INTERVAL 2 DAY
")"
query "
  ALTER TABLE siem.events
  DELETE WHERE device_product = 'step-ca'
    AND ts >= now() - INTERVAL 2 DAY
  SETTINGS mutations_sync = 2
"
after="$(query "
  SELECT count()
  FROM siem.events
  WHERE device_product = 'step-ca'
    AND ts >= now() - INTERVAL 2 DAY
")"
printf '{"removed":%s,"remaining":%s}\n' "$before" "$after"
""",
            timeout=600,
        )
    result = json.loads(output)
    if int(result["remaining"]) != 0:
        raise RuntimeError("Legacy unsanitized step-ca events remain in ClickHouse")
    print(json.dumps(result, indent=2, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
