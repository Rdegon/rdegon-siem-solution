from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

try:
    from deploy.soc_foundation_provision import Proxmox
except ModuleNotFoundError:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from soc_foundation_provision import Proxmox


@dataclass(frozen=True)
class Guest:
    vmid: int
    segment: str
    kind: str

    @property
    def old_gateway(self) -> str:
        return f"{self.segment}.1"

    @property
    def new_gateway(self) -> str:
        return f"{self.segment}.254"


GUESTS = (
    Guest(104, "10.20.10", "vm"),
    Guest(105, "10.20.10", "vm"),
    Guest(106, "10.20.10", "vm"),
    Guest(107, "10.20.10", "vm"),
    Guest(108, "10.20.10", "vm"),
    Guest(122, "10.20.30", "vm"),
    Guest(123, "10.20.30", "vm"),
    Guest(124, "10.20.30", "vm"),
    Guest(125, "10.20.30", "vm"),
    Guest(127, "10.20.10", "vm"),
    Guest(130, "10.20.20", "vm"),
    Guest(131, "10.20.10", "vm"),
    Guest(100, "10.20.20", "ct"),
    Guest(120, "10.20.20", "ct"),
    Guest(121, "10.20.20", "ct"),
    Guest(128, "10.20.10", "ct"),
    Guest(129, "10.20.30", "ct"),
    Guest(132, "10.20.10", "ct"),
    Guest(133, "10.20.10", "ct"),
)


def _lab_edge_unbound_script(*, rollback: bool) -> str:
    mode = "rollback" if rollback else "apply"
    return r"""
set -euo pipefail
conf=/etc/unbound/unbound.conf.d/lab-home-arpa.conf
test -f "$conf"
cp -an "$conf" "$conf.pre-opnsense"
python3 - "$conf" __MODE__ <<'PY'
from __future__ import annotations

import re
import sys
from pathlib import Path

path = Path(sys.argv[1])
mode = sys.argv[2]
text = path.read_text(encoding="utf-8")
legacy_interfaces = (
    "10.20.10.1",
    "10.20.20.1",
    "10.20.30.1",
    "10.20.40.1",
)
lines = [
    line
    for line in text.splitlines()
    if not (
        mode == "apply"
        and line.strip().startswith("interface:")
        and line.strip().split(":", 1)[1].strip() in legacy_interfaces
    )
]
if mode == "rollback":
    existing = {line.strip() for line in lines}
    insert_at = next(
        (
            index + 1
            for index, line in enumerate(lines)
            if line.strip() == "interface: 192.168.3.102"
        ),
        1,
    )
    additions = [
        f"  interface: {address}"
        for address in legacy_interfaces
        if f"interface: {address}" not in existing
    ]
    lines[insert_at:insert_at] = additions
target = "10.20.10.1" if mode == "rollback" else "192.168.3.102"
text = "\n".join(lines) + "\n"
text = re.sub(
    r'(local-data:\s*"lab-edge-01\.lab\.home\.arpa\.\s+IN\s+A\s+)[0-9.]+(")',
    rf"\g<1>{target}\g<2>",
    text,
)
path.write_text(text, encoding="utf-8")
PY
unbound-checkconf
systemctl reset-failed unbound.service
systemctl restart unbound.service
systemctl is-active --quiet unbound.service
ss -lunt | grep -q '192.168.3.102:53'
""".replace("__MODE__", mode)


def _vm_script(source: str, target: str, stamp: str) -> str:
    escaped_source = source.replace(".", r"\.")
    return f"""
set -euo pipefail
backup=/var/backups/siem-network/{stamp}
install -d -m 0700 "$backup"
for file in /etc/netplan/*.yaml; do
  [ -f "$file" ] || continue
  cp -an "$file" "$backup/$(basename "$file")"
  sed -E -i 's#{escaped_source}([^0-9]|$)#{target}\\1#g' "$file"
  if [ "$(basename "$file")" != "01-siem-segmented.yaml" ] \
     && grep -Eq '192\\.168\\.1\\.[0-9]+/24|via:[[:space:]]*192\\.168\\.1\\.1' "$file"; then
    mv "$file" "$file.legacy-disabled"
  fi
done
install -d -m 0755 /etc/systemd/resolved.conf.d
cat >/etc/systemd/resolved.conf.d/siem-dns.conf <<'EOF'
[Resolve]
DNS=
DNS={target}
FallbackDNS=
Domains=lab.home.arpa
EOF
netplan generate
netplan apply || true
systemctl restart systemd-resolved
for attempt in $(seq 1 30); do
  ip route show default | grep -q 'via {target}' && break
  sleep 1
done
ip route show default | grep 'via {target}'
if resolvectl dns | grep -Eq '(^|[[:space:]])(192\\.168\\.1\\.1|1\\.1\\.1\\.1|8\\.8\\.8\\.8)([[:space:]]|$)'; then
  resolvectl status --no-pager
  exit 1
fi
getent ahostsv4 github.com >/dev/null
curl -kfsS --connect-timeout 5 --max-time 15 https://10.20.10.104/health >/dev/null
"""


def _ct_live_script(target: str) -> str:
    return f"""
set -euo pipefail
ip route replace default via {target} dev eth0
printf 'nameserver {target}\\n' >/etc/resolv.conf
ip route show default | grep 'via {target}'
getent ahostsv4 github.com >/dev/null
curl -kfsS --connect-timeout 5 --max-time 15 https://10.20.10.104/health >/dev/null
"""


def _set_ct_config(
    pve: Proxmox,
    guest: Guest,
    source: str,
    target: str,
) -> None:
    command = f"""
set -euo pipefail
cfg=$(pct config {guest.vmid} | sed -n 's/^net0: //p')
test -n "$cfg"
new=$(printf '%s' "$cfg" | sed 's/gw={source}/gw={target}/g')
pct set {guest.vmid} -net0 "$new"
pct set {guest.vmid} -nameserver {target}
"""
    pve.run(command)


def _set_proxmox_routes(pve: Proxmox, source: str, target: str) -> str:
    command = f"""
set -euo pipefail
unit=/etc/systemd/system/siem-segment-routes.service
test -f "$unit"
cp -an "$unit" "$unit.pre-opnsense"
sed -i 's/via {source}/via {target}/g' "$unit"
systemctl daemon-reload
systemctl restart siem-segment-routes.service
for net in 10.20.10.0/24 10.20.20.0/24 10.20.30.0/24 10.20.40.0/24; do
  ip route show "$net" | grep 'via {target}'
done
ping -c1 -W2 10.20.10.104 >/dev/null
curl -kfsS --connect-timeout 5 --max-time 15 https://10.20.10.107/ >/dev/null
"""
    return pve.run(command)


def apply_cutover(pve: Proxmox, *, rollback: bool) -> dict[str, object]:
    stamp = "opnsense-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    results: list[dict[str, object]] = []
    for guest in GUESTS:
        source = guest.new_gateway if rollback else guest.old_gateway
        target = guest.old_gateway if rollback else guest.new_gateway
        if guest.kind == "vm":
            output = pve.guest_exec(
                guest.vmid,
                _vm_script(source, target, stamp),
                timeout=180,
            )
        else:
            _set_ct_config(pve, guest, source, target)
            output = pve.ct(
                guest.vmid,
                _ct_live_script(target),
                timeout=120,
            )
        results.append(
            {
                "vmid": guest.vmid,
                "kind": guest.kind,
                "gateway": target,
                "status": "ok",
                "route": next(
                    (
                        line.strip()
                        for line in output.splitlines()
                        if line.startswith("default via ")
                    ),
                    "",
                ),
            }
        )

    pve.guest_exec(
        102,
        _lab_edge_unbound_script(rollback=rollback),
        timeout=120,
    )
    pve_source = "192.168.3.103" if rollback else "192.168.3.102"
    pve_target = "192.168.3.102" if rollback else "192.168.3.103"
    _set_proxmox_routes(pve, pve_source, pve_target)
    return {
        "mode": "rollback" if rollback else "apply",
        "guests": results,
        "proxmox_segment_next_hop": pve_target,
    }


def inspect(pve: Proxmox) -> dict[str, object]:
    guests: list[dict[str, object]] = []
    for guest in GUESTS:
        command = "ip route show default | head -1"
        if guest.kind == "vm":
            output = pve.guest_exec(guest.vmid, command, timeout=30)
        else:
            output = pve.ct(guest.vmid, command, timeout=30)
        guests.append(
            {
                "vmid": guest.vmid,
                "kind": guest.kind,
                "route": output.strip(),
            }
        )
    return {
        "mode": "inspect",
        "guests": guests,
        "proxmox_routes": pve.run(
            "ip route show | grep -E '^10\\.20\\.(10|20|30|40)\\.0/24 '"
        ).splitlines(),
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Move persistent SOC guest gateways between VM102 and OPNsense."
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--apply", action="store_true")
    mode.add_argument("--rollback", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    with Proxmox() as pve:
        result = (
            apply_cutover(pve, rollback=args.rollback)
            if args.apply or args.rollback
            else inspect(pve)
        )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
