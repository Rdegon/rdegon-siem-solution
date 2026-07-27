from __future__ import annotations

import base64
import json
import os
import shlex

try:
    from deploy.proxmox_resource_rightsize import CLICKHOUSE_JSON_PROFILE
    from deploy.soc_foundation_provision import Proxmox
except ModuleNotFoundError:
    from proxmox_resource_rightsize import CLICKHOUSE_JSON_PROFILE
    from soc_foundation_provision import Proxmox


TARGETS = (106, 108)


def _write_profile(pve: Proxmox, vmid: int) -> None:
    encoded = base64.b64encode(CLICKHOUSE_JSON_PROFILE.encode("ascii")).decode("ascii")
    temporary = f"/tmp/siem-json-parser-{os.getpid()}.b64"
    destination = "/etc/clickhouse-server/users.d/siem-json-parser.xml"
    pve.guest_exec(
        vmid,
        f"install -d -m 0755 /etc/clickhouse-server/users.d; "
        f"printf %s {shlex.quote(encoded)} > {shlex.quote(temporary)}; "
        f"base64 -d {shlex.quote(temporary)} > {shlex.quote(destination)}; "
        f"chmod 0644 {shlex.quote(destination)}; "
        f"rm -f {shlex.quote(temporary)}",
        timeout=120,
    )


def _restart_and_verify(pve: Proxmox, vmid: int) -> dict[str, object]:
    output = pve.guest_exec(
        vmid,
        """
set -euo pipefail
systemctl restart clickhouse-server
for attempt in $(seq 1 60); do
  clickhouse-client --query 'SELECT 1' >/dev/null 2>&1 && break
  sleep 2
done
test "$(clickhouse-client --query \"SELECT value FROM system.settings WHERE name='allow_simdjson'\")" = "0"
test "$(clickhouse-client --query \"SELECT JSONExtractString('{\\\"a\\\":\\\"b\\\"}', 'a')\")" = "b"
printf 'service='
systemctl is-active clickhouse-server
printf 'allow_simdjson='
clickhouse-client --query "SELECT value FROM system.settings WHERE name='allow_simdjson'"
""",
        timeout=300,
    )
    return {"vmid": vmid, "status": output.strip().splitlines()}


def main() -> int:
    with Proxmox() as pve:
        for vmid in TARGETS:
            _write_profile(pve, vmid)
        result = [_restart_and_verify(pve, vmid) for vmid in TARGETS]
        print(json.dumps(result, indent=2, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
