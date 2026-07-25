#!/usr/bin/env python3
"""Stage a full segmented-network cutover plan on the Proxmox host.

This script intentionally generates reviewable cutover artifacts instead of
changing live networking. Run it on the Proxmox host with:

    python3 stage_full_segmentation.py --output-dir /root/siem-full-segmentation

Then review the generated files from local console before executing any cutover.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parent
DEFAULT_MANIFEST = ROOT / "full_segmentation_manifest.json"


def _shell_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def _write(path: Path, content: str, executable: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8", newline="\n")
    if executable:
        path.chmod(0o755)


def _legacy_routes(manifest: dict) -> list[tuple[str, str]]:
    segments = manifest["segments"]
    host_to_segment_ip: dict[str, str] = {}
    for segment in ("sec", "servers_games", "lab", "users", "mgmt"):
        host_to_segment_ip.update(segments[segment].get("hosts", {}))
    routes: list[tuple[str, str]] = []
    for host, legacy_ips in manifest["legacy_service_ips"].items():
        if host == "lab-edge-01":
            continue
        target = host_to_segment_ip.get(host)
        if not target:
            continue
        for legacy_ip in legacy_ips:
            routes.append((f"{legacy_ip}/32", target))
    return routes


def _legacy_routes_by_segment(manifest: dict, segment_name: str) -> list[tuple[str, str]]:
    segment_hosts = set(manifest["segments"][segment_name].get("hosts", {}))
    routes: list[tuple[str, str]] = []
    for host, legacy_ips in manifest["legacy_service_ips"].items():
        if host == "lab-edge-01" or host not in segment_hosts:
            continue
        target = manifest["segments"][segment_name]["hosts"].get(host)
        if not target:
            continue
        for legacy_ip in legacy_ips:
            routes.append((f"{legacy_ip}/32", target))
    return routes


def _netplan_routes(routes: list[tuple[str, str]], indent: int = 6) -> str:
    if not routes:
        return ""
    pad = " " * indent
    item_pad = " " * (indent + 2)
    lines = [f"{pad}routes:"]
    for cidr, via in routes:
        lines.append(f"{item_pad}- to: {cidr}")
        lines.append(f"{item_pad}  via: {via}")
    return "\n" + "\n".join(lines)


def _address_list(primary: str, aliases: list[str] | None = None) -> str:
    addresses = [f"{primary}/24"]
    addresses.extend(f"{alias}/32" for alias in aliases or [])
    return "[" + ", ".join(addresses) + "]"


def render_lab_edge_script(manifest: dict) -> str:
    mgmt = manifest["segments"]["mgmt"]
    sec = manifest["segments"]["sec"]
    servers = manifest["segments"]["servers_games"]
    lab = manifest["segments"]["lab"]
    users = manifest["segments"]["users"]
    legacy_routes = _legacy_routes(manifest)
    sec_legacy_routes = _legacy_routes_by_segment(manifest, "sec")
    servers_legacy_routes = _legacy_routes_by_segment(manifest, "servers_games")
    lab_legacy_routes = _legacy_routes_by_segment(manifest, "lab")
    users_legacy_routes = _legacy_routes_by_segment(manifest, "users")
    legacy_route_lines = "\n".join(
        f"ip route replace {cidr} via {via}" for cidr, via in legacy_routes
    )
    legacy_alias_lines = "\n".join(
        f"ip address replace {ip}/32 dev eth2 label eth2:legacy{idx}"
        for idx, ip in enumerate(manifest["legacy_service_ips"].get("lab-edge-01", []), start=1)
    )
    return f"""#!/usr/bin/env bash
set -euo pipefail

backup_dir="/root/siem-full-segmentation/backups/lab-edge-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "${{backup_dir}}"
cp -a /etc/netplan "${{backup_dir}}/" 2>/dev/null || true
cp -a /etc/nftables.conf "${{backup_dir}}/" 2>/dev/null || true
cp -a /etc/unbound/unbound.conf.d/lab-home-arpa.conf "${{backup_dir}}/" 2>/dev/null || true

cat >/etc/netplan/50-siem-segmented.yaml <<'YAML'
network:
  version: 2
  renderer: networkd
  ethernets:
    eth0:
      addresses: [{mgmt["hosts"]["lab-edge-01"]}/24]
      routes:
        - to: default
          via: {mgmt["gateway"]}
      nameservers:
        addresses: [{mgmt["gateway"]}]
        search: [lab.home.arpa]
    eth1:
      addresses: {_address_list(lab["hosts"]["lab-edge-01"])}
{_netplan_routes(lab_legacy_routes)}
      nameservers:
        addresses: [{lab["gateway"]}]
        search: [lab.home.arpa]
    eth2:
      addresses: {_address_list(sec["hosts"]["lab-edge-01"], manifest["legacy_service_ips"].get("lab-edge-01", []))}
{_netplan_routes(sec_legacy_routes)}
      nameservers:
        addresses: [{sec["gateway"]}]
        search: [lab.home.arpa]
    eth3:
      addresses: {_address_list(servers["hosts"]["lab-edge-01"])}
{_netplan_routes(servers_legacy_routes)}
      nameservers:
        addresses: [{servers["gateway"]}]
        search: [lab.home.arpa]
    eth4:
      addresses: {_address_list(users["hosts"]["lab-edge-01"])}
{_netplan_routes(users_legacy_routes)}
      nameservers:
        addresses: [{users["gateway"]}]
        search: [lab.home.arpa]
YAML

netplan generate
netplan apply
sysctl -w net.ipv4.ip_forward=1 >/dev/null

{legacy_alias_lines}
{legacy_route_lines}

cat >/etc/nftables.conf <<'NFT'
flush ruleset
table inet filter {{
  chain input {{
    type filter hook input priority 0; policy drop;
    iifname "lo" accept
    ct state established,related accept
    ip protocol icmp accept
    iifname "eth0" ip saddr {{ {mgmt["cidr"]}, 10.10.10.0/24, 10.66.66.0/24 }} tcp dport {{ 22, 53 }} accept
    iifname "eth0" ip saddr {{ {mgmt["cidr"]}, 10.10.10.0/24, 10.66.66.0/24 }} udp dport 53 accept
    iifname {{ "eth1", "eth2", "eth3", "eth4" }} tcp dport {{ 22, 53 }} accept
    iifname {{ "eth1", "eth2", "eth3", "eth4" }} udp dport 53 accept
    log prefix "nft-input-drop " level notice
    drop
  }}
  chain forward {{
    type filter hook forward priority 0; policy drop;
    ct state established,related accept
    iifname "eth1" oifname "eth1" accept
    iifname "eth2" oifname "eth2" accept
    iifname "eth3" oifname "eth3" accept
    iifname "eth4" oifname "eth4" accept
    iifname "eth2" oifname {{ "eth1", "eth3", "eth4", "eth0" }} accept
    iifname "eth3" oifname {{ "eth2", "eth0" }} accept
    iifname "eth1" oifname {{ "eth2", "eth3", "eth0" }} accept
    iifname "eth4" oifname {{ "eth2", "eth3", "eth0" }} accept
    iifname "eth0" ip saddr {{ {mgmt["cidr"]}, 10.10.10.0/24, 10.66.66.0/24 }} oifname {{ "eth1", "eth2", "eth3", "eth4" }} accept
    log prefix "nft-forward-drop " level notice
    drop
  }}
  chain output {{
    type filter hook output priority 0; policy accept;
  }}
}}
table ip nat {{
  chain prerouting {{
    type nat hook prerouting priority dstnat; policy accept;
    iifname "eth0" ip daddr {mgmt["hosts"]["lab-edge-01"]} tcp dport 80 dnat to {sec["hosts"]["siem-web"]}:80
    iifname "eth0" ip daddr {mgmt["hosts"]["lab-edge-01"]} tcp dport 443 dnat to {sec["hosts"]["siem-web"]}:443
    iifname "eth0" ip daddr {mgmt["hosts"]["lab-edge-01"]} tcp dport 8443 dnat to {sec["hosts"]["siem-ingest"]}:443
    iifname "eth0" ip daddr {mgmt["hosts"]["lab-edge-01"]} tcp dport 1514-1518 dnat to {sec["hosts"]["siem-ingest"]}
    iifname "eth0" ip daddr {mgmt["hosts"]["lab-edge-01"]} udp dport 1514-1518 dnat to {sec["hosts"]["siem-ingest"]}
    iifname "eth0" ip daddr {mgmt["hosts"]["lab-edge-01"]} tcp dport 9443 dnat to {servers["hosts"]["nextcloud-siem"]}:443
    iifname "eth0" ip daddr {mgmt["hosts"]["lab-edge-01"]} tcp dport 9444 dnat to {servers["hosts"]["navidrome-01"]}:80
    iifname "eth0" ip daddr {mgmt["hosts"]["lab-edge-01"]} tcp dport 9445 dnat to {servers["hosts"]["gamepanel-01"]}:80
    iifname "eth0" ip daddr {mgmt["hosts"]["lab-edge-01"]} tcp dport 2022 dnat to {servers["hosts"]["gamepanel-01"]}:2022
    iifname "eth0" ip daddr {mgmt["hosts"]["lab-edge-01"]} tcp dport 8080 dnat to {servers["hosts"]["gamepanel-01"]}:8080
    iifname "eth0" ip daddr {mgmt["hosts"]["lab-edge-01"]} tcp dport 25565 dnat to {servers["hosts"]["minecraft-01"]}:25565
    iifname "eth0" ip daddr {mgmt["hosts"]["lab-edge-01"]} udp dport 25565 dnat to {servers["hosts"]["minecraft-01"]}:25565
    iifname "eth0" ip daddr {mgmt["hosts"]["lab-edge-01"]} tcp dport 8100 dnat to {servers["hosts"]["minecraft-01"]}:8100
    iifname "eth0" ip daddr {mgmt["hosts"]["lab-edge-01"]} tcp dport 8111 dnat to {servers["hosts"]["minecraft-01"]}:8111
  }}
  chain postrouting {{
    type nat hook postrouting priority srcnat; policy accept;
    ip saddr {{ {sec["cidr"]}, {servers["cidr"]}, {lab["cidr"]}, {users["cidr"]} }} oifname "eth0" masquerade
    ip saddr {{ 10.10.10.0/24, 10.66.66.0/24 }} oifname {{ "eth1", "eth2", "eth3", "eth4" }} masquerade
  }}
}}
NFT
nft -c -f /etc/nftables.conf
systemctl enable --now nftables
systemctl restart nftables

python3 - <<'PY'
from pathlib import Path
conf = Path('/etc/unbound/unbound.conf.d/lab-home-arpa.conf')
text = conf.read_text(encoding='utf-8') if conf.exists() else 'server:\\n'
access = [
  '  access-control: 127.0.0.0/8 allow',
  '  access-control: {mgmt["cidr"]} allow',
  '  access-control: {sec["cidr"]} allow',
  '  access-control: {servers["cidr"]} allow',
  '  access-control: {lab["cidr"]} allow',
  '  access-control: {users["cidr"]} allow',
  '  access-control: 10.10.10.0/24 allow',
  '  access-control: 10.66.66.0/24 allow',
]
lines = [line for line in text.splitlines() if not line.strip().startswith('access-control:')]
try:
    idx = lines.index('server:')
except ValueError:
    lines.insert(0, 'server:')
    idx = 0
lines[idx + 1:idx + 1] = access
conf.write_text('\\n'.join(lines) + '\\n', encoding='utf-8')
PY
unbound-checkconf
systemctl restart unbound
"""


def render_proxmox_cutover(manifest: dict) -> str:
    mgmt = manifest["segments"]["mgmt"]
    users = manifest["segments"]["users"]
    lab_edge_mgmt = mgmt["hosts"]["lab-edge-01"]
    route_targets = [
        manifest["segments"]["sec"]["cidr"],
        manifest["segments"]["servers_games"]["cidr"],
        manifest["segments"]["lab"]["cidr"],
        manifest["segments"]["users"]["cidr"],
    ]
    for legacy_ips in manifest["legacy_service_ips"].values():
        route_targets.extend(f"{legacy_ip}/32" for legacy_ip in legacy_ips)
    route_targets = sorted(set(route_targets))
    route_lines = "\n".join(
        f"ip route replace {cidr} via {lab_edge_mgmt}" for cidr in route_targets
    )
    return f"""#!/usr/bin/env bash
set -euo pipefail

backup_dir="/root/siem-full-segmentation/backups/pve-$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "${{backup_dir}}"
cp -a /etc/network/interfaces "${{backup_dir}}/interfaces"
cp -a /etc/pve/qemu-server "${{backup_dir}}/" 2>/dev/null || true
cp -a /etc/pve/lxc "${{backup_dir}}/" 2>/dev/null || true

replace_csv_fields() {{
  python3 - "$@" <<'PY'
import sys

value = sys.argv[1]
updates = dict(arg.split("=", 1) for arg in sys.argv[2:])
parts = value.split(",")
seen = set()
out = []
for part in parts:
    if "=" in part:
        key, _old = part.split("=", 1)
        if key in updates:
            out.append(f"{{key}}={{updates[key]}}")
            seen.add(key)
        else:
            out.append(part)
    else:
        out.append(part)
for key, new_value in updates.items():
    if key not in seen:
        out.append(f"{{key}}={{new_value}}")
print(",".join(out))
PY
}}

qm_net_value() {{
  qm config "$1" | sed -n "s/^$2: //p" | head -n1
}}

pct_net_value() {{
  pct config "$1" | sed -n "s/^$2: //p" | head -n1
}}

set_qm_bridge_preserve() {{
  local vmid="$1" net="$2" bridge="$3" current updated
  current="$(qm_net_value "$vmid" "$net")"
  if [ -z "$current" ]; then
    echo "missing VM $vmid $net; skipping bridge update" >&2
    return 0
  fi
  updated="$(replace_csv_fields "$current" "bridge=$bridge")"
  qm set "$vmid" "--$net" "$updated"
}}

set_pct_net_preserve() {{
  local ctid="$1" net="$2" bridge="$3" ip="$4" gw="$5" current updated
  current="$(pct_net_value "$ctid" "$net")"
  if [ -z "$current" ]; then
    echo "missing CT $ctid $net; skipping network update" >&2
    return 0
  fi
  updated="$(replace_csv_fields "$current" "bridge=$bridge" "ip=$ip" "gw=$gw")"
  pct set "$ctid" "--$net" "$updated"
}}

python3 - <<'PY'
from pathlib import Path
path = Path('/etc/network/interfaces')
text = path.read_text(encoding='utf-8')
route_targets = {route_targets!r}
route_next_hop = '{lab_edge_mgmt}'
if 'auto vmbr4' not in text:
    text += '''

auto vmbr4
iface vmbr4 inet manual
        bridge-ports none
        bridge-stp off
        bridge-fd 0
        bridge-vlan-aware no
'''
lines = text.splitlines()
out = []
i = 0
while i < len(lines):
    line = lines[i]
    if line.strip() == 'iface vmbr0 inet static':
        out.append(line)
        i += 1
        while i < len(lines) and (lines[i].startswith('\\t') or lines[i].startswith(' ') or lines[i].strip() == ''):
            stripped = lines[i].strip()
            if stripped.startswith('address '):
                out.append('\\taddress {mgmt["hosts"]["pve"]}/24')
            elif stripped.startswith('gateway '):
                out.append('\\tgateway {mgmt["gateway"]}')
                for cidr in route_targets:
                    out.append(f'\\tpost-up ip route replace {{cidr}} via {{route_next_hop}} || true')
            elif stripped.startswith('post-up ip route replace ') or stripped.startswith('post-down ip route del '):
                pass
            else:
                out.append(lines[i])
            i += 1
        continue
    out.append(line)
    i += 1
path.write_text('\\n'.join(out) + '\\n', encoding='utf-8')
PY

# Add lab-edge users NIC if missing.
qm config 102 | grep -q '^net4:' || qm set 102 --net4 virtio,bridge={users["bridge"]}

# Move services off the physical management bridge while preserving existing
# NIC models, MAC addresses, firewall flags and other Proxmox net options.
set_qm_bridge_preserve 130 net0 {manifest["segments"]["servers_games"]["bridge"]}
set_pct_net_preserve 100 net0 {manifest["segments"]["servers_games"]["bridge"]} {manifest["segments"]["servers_games"]["hosts"]["minecraft-01"]}/24 {manifest["segments"]["servers_games"]["gateway"]}

# Keep the SIEM internal NICs on the sec bridge. Do not disable old external
# NICs here; do that only after each guest has moved its default route and
# legacy /32 alias to the internal NIC.
set_qm_bridge_preserve 104 net2 {manifest["segments"]["sec"]["bridge"]}
set_qm_bridge_preserve 105 net2 {manifest["segments"]["sec"]["bridge"]}
set_qm_bridge_preserve 106 net2 {manifest["segments"]["sec"]["bridge"]}
set_qm_bridge_preserve 107 net2 {manifest["segments"]["sec"]["bridge"]}
set_qm_bridge_preserve 108 net2 {manifest["segments"]["sec"]["bridge"]}

ifreload -a

{route_lines}

echo "Proxmox segmentation cutover commands executed. Reboot affected guests or apply guest scripts next."
"""


def render_disable_legacy_nics(manifest: dict) -> str:
    return f"""#!/usr/bin/env bash
set -euo pipefail

echo "This disables old SIEM vmbr0 NICs after guest configs have been moved to 10.20.10.x + /32 aliases."
echo "Run only after validating SSH, SIEM services, ingest, Kafka, ClickHouse and Web through the sec segment."

replace_csv_fields() {{
  python3 - "$@" <<'PY'
import sys

value = sys.argv[1]
updates = dict(arg.split("=", 1) for arg in sys.argv[2:])
parts = value.split(",")
seen = set()
out = []
for part in parts:
    if "=" in part:
        key, _old = part.split("=", 1)
        if key in updates:
            out.append(f"{{key}}={{updates[key]}}")
            seen.add(key)
        else:
            out.append(part)
    else:
        out.append(part)
for key, new_value in updates.items():
    if key not in seen:
        out.append(f"{{key}}={{new_value}}")
print(",".join(out))
PY
}}

qm_net_value() {{
  qm config "$1" | sed -n "s/^$2: //p" | head -n1
}}

set_qm_link_down_preserve() {{
  local vmid="$1" net="$2" current updated
  current="$(qm_net_value "$vmid" "$net")"
  if [ -z "$current" ]; then
    echo "missing VM $vmid $net; skipping link_down update" >&2
    return 0
  fi
  updated="$(replace_csv_fields "$current" "link_down=1")"
  qm set "$vmid" "--$net" "$updated"
}}

set_qm_link_down_preserve 104 net1
set_qm_link_down_preserve 105 net1
set_qm_link_down_preserve 106 net1
set_qm_link_down_preserve 107 net1
set_qm_link_down_preserve 108 net1
"""


def render_guest_readme(manifest: dict) -> str:
    return f"""# Generated guest cutover notes

Apply guest network changes from local console or Proxmox guest agent, one host at a time.

Target addresses:

- siem-ingest: 10.20.10.104/24 + legacy 192.168.1.35/32
- siem-processing: 10.20.10.105/24 + legacy 192.168.1.37/32
- siem-storage: 10.20.10.106/24 + legacy 192.168.1.38/32
- siem-web: 10.20.10.107/24 + legacy 192.168.1.39/32
- siem-transport: 10.20.10.108/24 + legacy 192.168.1.40/32
- gamepanel-01: 10.20.20.130/24 + legacy 192.168.1.30/32, .43/32, .44/32, .45/32
- minecraft-01: 10.20.20.100/24 + legacy 192.168.1.32/32

Suggested guest model:

- SIEM VMs: put the `10.20.10.x/24` primary address, default route `10.20.10.1`, DNS `10.20.10.1`, and the old `192.168.1.x/32` alias on the internal `vmbr2` NIC. Current inventory used `ens20` for that NIC.
- gamepanel-01: put `10.20.20.130/24`, default route `10.20.20.1`, DNS `10.20.20.1`, and the old `192.168.1.30/32`, `.43/32`, `.44/32`, `.45/32` aliases on the `vmbr3` NIC.
- minecraft-01: Proxmox LXC config is moved to `10.20.20.100/24`, gateway `10.20.20.1`; keep `192.168.1.32/32` inside the container if an old endpoint must stay reachable.
- nextcloud-siem and navidrome-01 are already in `10.20.20.0/24`; no IP change is required.

Example netplan shape for one SIEM VM:

```yaml
network:
  version: 2
  renderer: networkd
  ethernets:
    ens20:
      addresses: [10.20.10.104/24, 192.168.1.35/32]
      routes:
        - to: default
          via: 10.20.10.1
      nameservers:
        addresses: [10.20.10.1]
        search: [lab.home.arpa]
```

Do not remove legacy `192.168.1.x` aliases until all SIEM env files and external references have been moved to DNS names or `10.20.x` addresses.
After every SIEM guest is validated on `10.20.10.x`, run `04_disable_legacy_siem_vmbr0_nics.sh` from the Proxmox console to disconnect the old vmbr0 NICs.
"""


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", default=str(DEFAULT_MANIFEST))
    parser.add_argument("--output-dir", default="/root/siem-full-segmentation")
    args = parser.parse_args()

    manifest = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
    out = Path(args.output_dir)
    _write(out / "manifest.json", json.dumps(manifest, ensure_ascii=False, indent=2) + "\n")
    _write(out / "01_pve_cutover.sh", render_proxmox_cutover(manifest), executable=True)
    _write(out / "02_lab_edge_cutover.sh", render_lab_edge_script(manifest), executable=True)
    _write(out / "03_guest_cutover_notes.md", render_guest_readme(manifest))
    _write(out / "04_disable_legacy_siem_vmbr0_nics.sh", render_disable_legacy_nics(manifest), executable=True)
    _write(
        out / "README.md",
        "Generated full segmentation cutover artifacts. Review every file before execution. Do not run over SSH.\n",
    )
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
