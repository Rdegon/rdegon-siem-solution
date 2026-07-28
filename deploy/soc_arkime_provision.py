from __future__ import annotations

import base64
import json
import os
import shlex
from pathlib import Path

try:
    from deploy.soc_foundation_provision import Proxmox
except ModuleNotFoundError:
    from soc_foundation_provision import Proxmox


ROOT = Path(__file__).resolve().parents[1]
VMID = 127
OPENSEARCH_VERSION = "2.18.0"
ARKIME_VERSION = "6.3.1"
MONITOR_INTERFACES = (
    "enp6s19",
    "enp6s20",
    "enp6s21",
    "enp6s22",
    "enp6s23",
)


def opensearch_overrides() -> str:
    return """cluster.name: rdegon-arkime
node.name: soc-ndr-01
path.data: /srv/arkime-opensearch
path.logs: /var/log/opensearch
network.host: 127.0.0.1
http.port: 9200
discovery.type: single-node
bootstrap.memory_lock: false
"""


def arkime_config() -> str:
    interfaces = ";".join(MONITOR_INTERFACES)
    return f"""[default]
interface={interfaces}
pcapDir=/srv/arkime-pcap
snapLen=65535
maxFileSizeG=2
maxFileTimeM=1
freeSpaceG=30
rotateIndex=daily
elasticsearch=https://127.0.0.1:9200
elasticsearchBasicAuth=admin:$ARKIME_OPENSEARCH_PASSWORD
caTrustFile=/etc/opensearch/root-ca.pem
viewHost=0.0.0.0
viewPort=8005
passwordSecret=$ARKIME_PASSWORD_SECRET
authMode=digest
parseSMTP=true
parseSMB=true
parseQSValue=true
supportSha256=true
packetThreads=3
maxPacketsInQueue=500000
dbBulkSize=500000
compressES=true
"""


def _guest_write(
    pve: Proxmox,
    destination: str,
    content: bytes,
    mode: int = 0o644,
) -> None:
    encoded = base64.b64encode(content).decode("ascii")
    parent = str(Path(destination).parent).replace("\\", "/")
    remote = f"/tmp/soc-arkime-{os.getpid()}-{Path(destination).name}.b64"
    pve.guest_exec(
        VMID,
        f"install -d -m 0755 {shlex.quote(parent)}; : > {shlex.quote(remote)}",
    )
    try:
        for offset in range(0, len(encoded), 24_000):
            pve.guest_exec(
                VMID,
                f"printf %s {shlex.quote(encoded[offset:offset + 24_000])} "
                f">> {shlex.quote(remote)}",
            )
        pve.guest_exec(
            VMID,
            f"base64 -d {shlex.quote(remote)} > {shlex.quote(destination)} && "
            f"chmod {mode:o} {shlex.quote(destination)}",
        )
    finally:
        pve.guest_exec(VMID, f"rm -f {shlex.quote(remote)}")


def _prepare_storage(pve: Proxmox) -> None:
    pve.guest_exec(
        VMID,
        """
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq xfsprogs curl ca-certificates jq libcap2-bin

test "$(lsblk -ndo SERIAL /dev/sdb | xargs)" = ARKIMEMETA
test "$(lsblk -ndo SERIAL /dev/sdc | xargs)" = ARKIMEPCAP

if [ -z "$(lsblk -ndo FSTYPE /dev/sdb | xargs)" ]; then
  mkfs.xfs -f -L arkime-meta /dev/sdb
fi
if [ -z "$(lsblk -ndo FSTYPE /dev/sdc | xargs)" ]; then
  mkfs.xfs -f -L arkime-pcap /dev/sdc
fi

test "$(blkid -s LABEL -o value /dev/sdb)" = arkime-meta
test "$(blkid -s LABEL -o value /dev/sdc)" = arkime-pcap
install -d -m 0750 /srv/arkime-opensearch /srv/arkime-pcap
grep -q '^LABEL=arkime-meta ' /etc/fstab \
  || printf 'LABEL=arkime-meta /srv/arkime-opensearch xfs defaults,noatime,nofail 0 2\\n' >>/etc/fstab
grep -q '^LABEL=arkime-pcap ' /etc/fstab \
  || printf 'LABEL=arkime-pcap /srv/arkime-pcap xfs defaults,noatime,nofail 0 2\\n' >>/etc/fstab
mountpoint -q /srv/arkime-opensearch || mount /srv/arkime-opensearch
mountpoint -q /srv/arkime-pcap || mount /srv/arkime-pcap
findmnt -n -o SOURCE,FSTYPE /srv/arkime-opensearch
findmnt -n -o SOURCE,FSTYPE /srv/arkime-pcap

cat >/etc/sysctl.d/91-arkime-opensearch.conf <<'EOF'
vm.max_map_count=262144
net.core.netdev_max_backlog=250000
net.core.rmem_max=33554432
net.core.rmem_default=33554432
EOF
sysctl --system >/dev/null
""",
        timeout=900,
    )


def _install_opensearch(pve: Proxmox) -> None:
    _guest_write(
        pve,
        "/tmp/opensearch-overrides.yml",
        opensearch_overrides().encode("ascii"),
        0o600,
    )
    pve.guest_exec(
        VMID,
        f"""
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
install -d -m 0700 /etc/opensearch
if [ ! -s /etc/opensearch/admin-password ]; then
  umask 077
  printf 'Aa9-%s\\n' "$(openssl rand -hex 24)" >/etc/opensearch/admin-password
fi
if ! dpkg-query -W -f='${{Version}}' opensearch 2>/dev/null | grep -q '^{OPENSEARCH_VERSION}'; then
  curl --fail --location --retry 5 --retry-delay 5 \
    -o /tmp/opensearch.deb \
    https://artifacts.opensearch.org/releases/bundle/opensearch/{OPENSEARCH_VERSION}/opensearch-{OPENSEARCH_VERSION}-linux-x64.deb
  OPENSEARCH_INITIAL_ADMIN_PASSWORD="$(cat /etc/opensearch/admin-password)" \
    apt-get install -y -qq /tmp/opensearch.deb
  rm -f /tmp/opensearch.deb
fi

install -d -o opensearch -g opensearch -m 0750 \
  /srv/arkime-opensearch /var/log/opensearch /etc/opensearch/jvm.options.d
sed -i -E \
  '/^(cluster\\.name|node\\.name|path\\.data|path\\.logs|network\\.host|http\\.port|discovery\\.type|bootstrap\\.memory_lock):/d' \
  /etc/opensearch/opensearch.yml
cat /tmp/opensearch-overrides.yml >>/etc/opensearch/opensearch.yml
cat >/etc/opensearch/jvm.options.d/arkime.options <<'EOF'
-Xms4g
-Xmx4g
EOF
chown root:opensearch /etc/opensearch/admin-password /etc/opensearch/jvm.options.d/arkime.options
chmod 0640 /etc/opensearch/admin-password /etc/opensearch/jvm.options.d/arkime.options
systemctl daemon-reload
systemctl enable --now opensearch
for attempt in $(seq 1 120); do
  if curl -kfsS --connect-timeout 3 \
    -u "admin:$(cat /etc/opensearch/admin-password)" \
    https://127.0.0.1:9200/_cluster/health >/dev/null; then
    exit 0
  fi
  sleep 3
done
journalctl -u opensearch -n 120 --no-pager
exit 1
""",
        timeout=1800,
    )


def _install_arkime(pve: Proxmox) -> None:
    _guest_write(
        pve,
        "/tmp/arkime-config.template",
        arkime_config().encode("ascii"),
        0o600,
    )
    pve.guest_exec(
        VMID,
        f"""
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
if ! dpkg-query -W -f='${{Version}}' arkime 2>/dev/null | grep -q '^{ARKIME_VERSION}'; then
  curl --fail --location --retry 5 --retry-delay 5 \
    -o /tmp/arkime.deb \
    https://github.com/arkime/arkime/releases/download/v{ARKIME_VERSION}/arkime_{ARKIME_VERSION}-1.ubuntu2404_amd64.deb
  apt-get install -y -qq /tmp/arkime.deb
  rm -f /tmp/arkime.deb
fi

id arkime >/dev/null 2>&1 || useradd --system --home /opt/arkime --shell /usr/sbin/nologin arkime
install -d -o arkime -g arkime -m 0750 \
  /srv/arkime-pcap /var/log/arkime /opt/arkime/logs /etc/arkime/secrets
if [ ! -s /etc/arkime/secrets/admin-password ]; then
  umask 077
  printf 'Aa9-%s\\n' "$(openssl rand -hex 24)" >/etc/arkime/secrets/admin-password
fi
if [ ! -s /etc/arkime/secrets/session-secret ]; then
  umask 077
  openssl rand -hex 48 >/etc/arkime/secrets/session-secret
fi
OPENSEARCH_PASSWORD="$(cat /etc/opensearch/admin-password)"
PASSWORD_SECRET="$(cat /etc/arkime/secrets/session-secret)"
sed \
  -e "s|\\$ARKIME_OPENSEARCH_PASSWORD|${{OPENSEARCH_PASSWORD}}|g" \
  -e "s|\\$ARKIME_PASSWORD_SECRET|${{PASSWORD_SECRET}}|g" \
  /tmp/arkime-config.template >/opt/arkime/etc/config.ini
chown root:arkime \
  /opt/arkime/etc/config.ini \
  /etc/arkime/secrets/admin-password \
  /etc/arkime/secrets/session-secret
chmod 0640 \
  /opt/arkime/etc/config.ini \
  /etc/arkime/secrets/admin-password \
  /etc/arkime/secrets/session-secret

setcap 'cap_net_raw,cap_net_admin=eip' /opt/arkime/bin/capture
if ! curl -kfsS -u "admin:${{OPENSEARCH_PASSWORD}}" \
  https://127.0.0.1:9200/arkime_dstats/_count >/dev/null 2>&1; then
  /opt/arkime/db/db.pl --insecure --esuser "admin:${{OPENSEARCH_PASSWORD}}" \
    https://127.0.0.1:9200 init --ism
fi
/opt/arkime/db/db.pl --insecure --esuser "admin:${{OPENSEARCH_PASSWORD}}" \
  https://127.0.0.1:9200 ism 1d 14d --history 2
/opt/arkime/bin/arkime_add_user.sh --insecure \
  admin "SOC Administrator" "$(cat /etc/arkime/secrets/admin-password)" \
  --admin --remove >/dev/null

: >/opt/arkime/logs/capture.log
: >/opt/arkime/logs/viewer.log
systemctl daemon-reload
systemctl reset-failed arkimecapture.service arkimeviewer.service || true
systemctl enable --now arkimecapture.service arkimeviewer.service
for attempt in $(seq 1 90); do
  if systemctl is-active --quiet arkimecapture.service \
    && curl -fsS --digest \
    -u "admin:$(cat /etc/arkime/secrets/admin-password)" \
    http://127.0.0.1:8005/eshealth.json >/dev/null; then
    exit 0
  fi
  sleep 2
done
systemctl --no-pager --full status arkimecapture.service arkimeviewer.service || true
journalctl -u arkimecapture.service -u arkimeviewer.service -n 160 --no-pager
exit 1
""",
        timeout=1800,
    )


def _verify(pve: Proxmox) -> dict[str, object]:
    result = json.loads(
        pve.guest_exec(
            VMID,
            """
set -euo pipefail
test "$(findmnt -n -o FSTYPE /srv/arkime-opensearch)" = xfs
test "$(findmnt -n -o FSTYPE /srv/arkime-pcap)" = xfs
systemctl is-active --quiet opensearch arkimecapture.service arkimeviewer.service
health="$(curl -fsS --digest \
  -u "admin:$(cat /etc/arkime/secrets/admin-password)" \
  http://127.0.0.1:8005/eshealth.json)"
for attempt in $(seq 1 60); do
  pcap="$(find /srv/arkime-pcap -type f -name '*.pcap*' -print -quit)"
  sessions="$(curl -kfsS \
    -u "admin:$(cat /etc/opensearch/admin-password)" \
    'https://127.0.0.1:9200/arkime_sessions3-*/_count' \
    | jq -r '.count // 0')"
  test -n "$pcap" && test "$sessions" -gt 0 && break
  sleep 2
done
python3 - <<'PY'
import json
import os
import subprocess

pcap_files = subprocess.check_output(
    ["find", "/srv/arkime-pcap", "-type", "f", "-name", "*.pcap*"],
    text=True,
).splitlines()
if not pcap_files:
    raise SystemExit("Arkime capture is active but no PCAP was written")
with open("/etc/opensearch/admin-password", encoding="utf-8") as password_file:
    opensearch_password = password_file.read().strip()
sessions = json.loads(subprocess.check_output(
    [
        "curl",
        "-kfsS",
        "-u",
        f"admin:{opensearch_password}",
        "https://127.0.0.1:9200/arkime_sessions3-*/_count",
    ],
    text=True,
)).get("count", 0)
if not sessions:
    raise SystemExit("Arkime did not index any captured sessions")
print(json.dumps({
    "opensearch": "active",
    "capture": "active",
    "viewer": "active",
    "pcap_files": len(pcap_files),
    "pcap_bytes": sum(os.path.getsize(path) for path in pcap_files),
    "sessions": sessions,
}))
PY
""",
            timeout=180,
        )
    )
    return result


def _generate_capture_canary(pve: Proxmox) -> None:
    for source_vmid, destination in (
        (104, "https://10.20.10.107/"),
        (123, "https://10.20.10.104/health"),
        (130, "https://10.20.10.104/health"),
    ):
        pve.guest_exec(
            source_vmid,
            f"for attempt in $(seq 1 10); do "
            f"curl -kfsS --connect-timeout 3 --max-time 15 "
            f"{shlex.quote(destination)} >/dev/null; done",
            timeout=180,
        )


def main() -> int:
    with Proxmox() as pve:
        _prepare_storage(pve)
        _install_opensearch(pve)
        _install_arkime(pve)
        _generate_capture_canary(pve)
        result = _verify(pve)
    print(json.dumps(result, indent=2, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
