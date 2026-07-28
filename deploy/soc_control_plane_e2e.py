from __future__ import annotations

import json
import time

try:
    from deploy.soc_foundation_provision import Proxmox
except ModuleNotFoundError:
    from soc_foundation_provision import Proxmox


def _exercise_step_ca(pve: Proxmox) -> dict[str, object]:
    output = pve.ct(
        132,
        r"""
set -euo pipefail
name="siem-pki-e2e-$(date +%s)"
token="$(HOME=/etc/step-ca step ca token "$name" \
  --san "$name.lab.home.arpa" \
  --ca-url https://10.20.10.132:9000 \
  --root /etc/step-ca/certs/root_ca.crt \
  --password-file /etc/step-ca/secrets/provisioner_password)"
step ca certificate "$name" \
  /tmp/siem-pki-e2e.crt /tmp/siem-pki-e2e.key \
  --token "$token" \
  --ca-url https://10.20.10.132:9000 \
  --root /etc/step-ca/certs/root_ca.crt >/dev/null
step ca revoke \
  --cert /tmp/siem-pki-e2e.crt \
  --key /tmp/siem-pki-e2e.key \
  --ca-url https://10.20.10.132:9000 \
  --root /etc/step-ca/certs/root_ca.crt >/dev/null
rm -f /tmp/siem-pki-e2e.crt /tmp/siem-pki-e2e.key
systemctl start siem-journal-event-exporter@step-ca.service
python3 - <<'PY'
import json
from pathlib import Path
print(json.dumps({
    "issue_revoke": "ok",
    "audit_lines": len(Path("/var/log/siem/step-ca-audit.jsonl").read_text().splitlines()),
}))
PY
""",
        timeout=300,
    )
    return json.loads(output)


def _exercise_minio(pve: Proxmox) -> dict[str, object]:
    output = pve.ct(
        133,
        r"""
set -euo pipefail
. /etc/siem/evidence.env
bucket="siem-e2e-$(date +%s)"
printf 'SOC evidence pipeline canary\n' >/tmp/siem-evidence-e2e.txt
/usr/local/bin/mc alias set e2e https://10.20.10.133:9000 \
  "$MINIO_ROOT_USER" "$MINIO_ROOT_PASSWORD" >/dev/null
/usr/local/bin/mc mb "e2e/$bucket" >/dev/null
/usr/local/bin/mc cp /tmp/siem-evidence-e2e.txt "e2e/$bucket/evidence.txt" >/dev/null
/usr/local/bin/mc stat "e2e/$bucket/evidence.txt" >/dev/null
/usr/local/bin/mc cat "e2e/$bucket/evidence.txt" >/dev/null
/usr/local/bin/mc rm "e2e/$bucket/evidence.txt" >/dev/null
/usr/local/bin/mc rb "e2e/$bucket" >/dev/null
rm -f /tmp/siem-evidence-e2e.txt
sleep 3
python3 - <<'PY'
import json
from pathlib import Path
print(json.dumps({
    "put_get_delete": "ok",
    "audit_lines": len(Path("/var/log/siem/minio-audit.jsonl").read_text().splitlines()),
}))
PY
""",
        timeout=300,
    )
    return json.loads(output)


def _query_siem(
    pve: Proxmox,
    *,
    storage_vmids: tuple[int, ...] = (106, 108),
) -> tuple[int, list[dict[str, object]]]:
    query_script = r"""
set -euo pipefail
set -a
if [ -f /etc/siem/storage.env ]; then
  env_file=/etc/siem/storage.env
else
  env_file=/etc/siem/storage-standby.env
fi
. <(grep -E '^[A-Za-z_][A-Za-z0-9_]*=' "$env_file")
set +a
clickhouse-client \
  --host "${SIEM_CH_HOST:-127.0.0.1}" \
  --port "${SIEM_CH_PORT:-9000}" \
  --user "${SIEM_CH_USER:-default}" \
  --password "${SIEM_CH_PASSWORD:-}" \
  --query "
    SELECT
      device_product,
      category,
      subcategory,
      event_action,
      event_outcome,
      count() AS events,
      max(ts) AS latest
    FROM siem.events
    WHERE ts >= now() - INTERVAL 20 MINUTE
      AND device_product IN ('step-ca', 'minio', 'arkime')
    GROUP BY
      device_product,
      category,
      subcategory,
      event_action,
      event_outcome
    ORDER BY device_product, event_action
    FORMAT JSONEachRow"
"""
    failures: list[str] = []
    for vmid in storage_vmids:
        try:
            output = pve.guest_exec(vmid, query_script, timeout=180)
        except RuntimeError as exc:
            failures.append(f"VM{vmid}: {exc}")
            continue
        return vmid, [
            json.loads(line) for line in output.splitlines() if line.strip()
        ]
    raise RuntimeError(
        "no ClickHouse storage node was available: " + "; ".join(failures)
    )


def main() -> int:
    with Proxmox() as pve:
        result = {
            "step_ca": _exercise_step_ca(pve),
            "minio": _exercise_minio(pve),
        }
        pve.guest_exec(127, "systemctl start siem-arkime-metrics-exporter.service")
        time.sleep(30)
        query_vmid, events = _query_siem(pve)
        result["query_vmid"] = query_vmid
        result["siem_events"] = events
    products = {str(item["device_product"]) for item in result["siem_events"]}
    missing = {"step-ca", "minio", "arkime"} - products
    if missing:
        raise RuntimeError(f"SIEM did not receive control-plane products: {sorted(missing)}")
    print(json.dumps(result, indent=2, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
