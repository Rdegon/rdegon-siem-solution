from __future__ import annotations

import argparse
import json
import time

try:
    from deploy.soc_foundation_provision import Proxmox
except ModuleNotFoundError:
    from soc_foundation_provision import Proxmox


def _storage_query(pve: Proxmox, query: str, timeout: int = 600) -> str:
    escaped = query.replace("\\", "\\\\").replace('"', '\\"')
    return pve.guest_exec(
        106,
        f"""
set -euo pipefail
set -a
. /etc/siem/storage.env
set +a
clickhouse-client \
  --host "${{SIEM_CH_HOST:-127.0.0.1}}" \
  --port "${{SIEM_CH_PORT:-9000}}" \
  --user "${{SIEM_CH_USER:-default}}" \
  --password "${{SIEM_CH_PASSWORD:-}}" \
  --query "{escaped}"
""",
        timeout=timeout,
    ).strip()


def main() -> int:
    parser = argparse.ArgumentParser(description="Replay MISP inventory into active SIEM enrichment.")
    parser.add_argument(
        "--resume",
        action="store_true",
        help="Wait for an already exported JSONL file instead of resetting the pipeline.",
    )
    args = parser.parse_args()
    with Proxmox() as pve:
        if args.resume:
            expected = int(
                pve.guest_exec(
                    131,
                    "wc -l </var/log/siem/misp-events.jsonl",
                    timeout=120,
                ).strip()
                or 0
            )
        else:
            pve.guest_exec(
                131,
                """
set -euo pipefail
systemctl stop siem-misp-exporter.timer
systemctl stop siem-misp-exporter.service
systemctl stop siem-security-sensor-forwarder@misp.service
: >/var/log/siem/misp-events.jsonl
rm -f \
  /var/lib/siem-misp-exporter/state.json \
  /var/lib/siem-security-forwarder/misp.state.json \
  /var/lib/siem-security-forwarder/misp.spool.jsonl
systemctl start siem-security-sensor-forwarder@misp.service
""",
                timeout=180,
            )
            _storage_query(
                pve,
                """
ALTER TABLE siem.events
DELETE WHERE device_product = 'misp'
SETTINGS mutations_sync = 2
""",
            )
            _storage_query(
                pve,
                """
ALTER TABLE siem.threat_intel_iocs
DELETE WHERE provider = 'MISP'
SETTINGS mutations_sync = 2
""",
            )
            export_result = json.loads(
                pve.guest_exec(
                    131,
                    """
python3 /opt/siem/deploy/misp_event_exporter.py \
  --lookback-seconds 2592000 \
  --page-size 250 \
  --max-pages 100
""",
                    timeout=1800,
                )
            )
            expected = int(export_result.get("attributes_exported") or 0)
        if expected <= 0:
            raise RuntimeError("MISP bootstrap returned no published attributes")
        pve.guest_exec(131, "systemctl start siem-misp-exporter.timer")
        delivered = 0
        for _ in range(240):
            time.sleep(5)
            delivered = int(
                _storage_query(
                    pve,
                    "SELECT count() FROM siem.events WHERE device_product = 'misp'",
                    timeout=120,
                )
                or 0
            )
            if delivered >= expected:
                break
        if delivered < expected:
            raise RuntimeError(
                f"MISP replay is incomplete: delivered={delivered}, expected={expected}"
            )
        sync_output = pve.guest_exec(
            106,
            "systemctl start siem-misp-ioc-sync.service; "
            "journalctl -u siem-misp-ioc-sync.service -n 1 --no-pager -o cat",
            timeout=900,
        ).strip()
        active = int(
            _storage_query(
                pve,
                """
SELECT uniqExact(indicator)
FROM siem.threat_intel_iocs
WHERE provider = 'MISP' AND enabled = 1
""",
            )
            or 0
        )
    if active <= 0:
        raise RuntimeError("MISP replay completed but no active IOC entered enrichment")
    print(
        json.dumps(
            {
                "exported": expected,
                "delivered": delivered,
                "active_iocs": active,
                "sync": sync_output,
            },
            indent=2,
            ensure_ascii=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
