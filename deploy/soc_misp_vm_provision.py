from __future__ import annotations

import base64
import json
import shlex
import time

try:
    from deploy.soc_foundation_provision import Proxmox
except ModuleNotFoundError:
    from soc_foundation_provision import Proxmox


VMID = 131
HOSTNAME = "soc-ti-01"
ADDRESS = "10.20.10.131"
MEMORY_MB = 8192
BALLOON_MB = 8192
MISP_DOCKER_COMMIT = "223b675c4480730832f928e113b6f2e5260b450d"


CLOUD_CONFIG = """#cloud-config
hostname: soc-ti-01
fqdn: soc-ti-01.lab.home.arpa
manage_etc_hosts: true
timezone: Europe/Moscow
package_update: true
package_upgrade: false
packages:
  - qemu-guest-agent
  - ca-certificates
  - curl
  - git
  - jq
  - openssl
  - chrony
  - docker.io
  - docker-compose-v2
  - uuid-runtime
users:
  - default
  - name: socadmin
    groups: [adm, sudo, docker]
    shell: /bin/bash
    lock_passwd: true
    sudo: ALL=(ALL) NOPASSWD:ALL
runcmd:
  - [systemctl, enable, --now, qemu-guest-agent]
  - [systemctl, enable, --now, chrony]
  - [systemctl, enable, --now, docker]
  - [install, -d, -m, "0750", /etc/siem, /var/log/siem]
final_message: "soc-ti-01 cloud-init complete"
"""


def _write_host_file(pve: Proxmox, path: str, content: bytes, mode: int = 0o600) -> None:
    encoded = base64.b64encode(content).decode("ascii")
    temp = f"{path}.b64"
    pve.run(f"install -d -m 0755 {shlex.quote(path.rsplit('/', 1)[0])}; : > {shlex.quote(temp)}")
    try:
        for offset in range(0, len(encoded), 32_000):
            pve.run(
                f"printf %s {shlex.quote(encoded[offset:offset + 32_000])} "
                f">> {shlex.quote(temp)}"
            )
        pve.run(
            f"base64 -d {shlex.quote(temp)} > {shlex.quote(path)} && "
            f"chmod {mode:o} {shlex.quote(path)}"
        )
    finally:
        pve.run(f"rm -f {shlex.quote(temp)}")


def _remove_failed_lxc(pve: Proxmox) -> None:
    exists = pve.run(f"test -f /etc/pve/lxc/{VMID}.conf && echo yes || echo no").strip()
    if exists != "yes":
        return
    config = pve.run(f"pct config {VMID}")
    if f"hostname: {HOSTNAME}" not in config:
        raise RuntimeError(f"VMID {VMID} is an unrelated LXC and will not be removed")
    status = pve.run(f"pct status {VMID}").strip()
    if status.endswith("running"):
        pve.run(f"pct stop {VMID}", timeout=300)
    pve.run(f"pct destroy {VMID} --purge", timeout=1200)


def _ensure_vm(pve: Proxmox) -> None:
    exists = pve.run(
        f"test -f /etc/pve/qemu-server/{VMID}.conf && echo yes || echo no"
    ).strip()
    if exists == "yes":
        config = pve.run(f"qm config {VMID}")
        if f"name: {HOSTNAME}" not in config:
            raise RuntimeError(f"VMID {VMID} is an unrelated VM")
        pve.run(
            f"qm set {VMID} --memory {MEMORY_MB} --balloon {BALLOON_MB}"
        )
        return

    _remove_failed_lxc(pve)
    storage = json.loads(pve.run("pvesh get /storage/local --output-format json"))
    content = {item.strip() for item in str(storage.get("content") or "").split(",")}
    if "snippets" not in content:
        content.add("snippets")
        pve.run(f"pvesm set local --content {','.join(sorted(content))}")
    _write_host_file(
        pve,
        f"/var/lib/vz/snippets/{HOSTNAME}-user.yaml",
        CLOUD_CONFIG.encode("utf-8"),
    )

    pve.run(
        " ".join(
            (
                "qm create",
                str(VMID),
                f"--name {HOSTNAME}",
                "--ostype l26",
                "--machine q35",
                "--cpu host",
                "--cores 4",
                f"--memory {MEMORY_MB}",
                f"--balloon {BALLOON_MB}",
                "--scsihw virtio-scsi-single",
                "--net0 virtio,bridge=vmbr2,firewall=1",
                "--agent enabled=1,freeze-fs-on-backup=1",
                "--onboot 1",
                "--startup order=52,up=60,down=60",
                "--serial0 socket",
                "--vga serial0",
            )
        )
    )
    image = pve.run("pvesm path local:iso/noble-server-cloudimg-amd64.img").strip()
    pve.run(
        f"qm disk import {VMID} {shlex.quote(image)} kingston256gig "
        "--format qcow2 --target-disk scsi0",
        timeout=1200,
    )
    config = pve.run(f"qm config {VMID}")
    if "scsi0:" not in config:
        unused = next(
            (
                line.split(":", 1)[1].strip()
                for line in config.splitlines()
                if line.startswith("unused0:")
            ),
            "",
        )
        if not unused:
            raise RuntimeError("Imported MISP system disk was not attached")
        pve.run(f"qm set {VMID} --scsi0 {shlex.quote(unused)},discard=on,ssd=1")
    pve.run(f"qm disk resize {VMID} scsi0 80G")
    pve.run(f"qm set {VMID} --ide2 kingston256gig:cloudinit")
    pve.run(
        f"qm set {VMID} "
        f"--ipconfig0 ip={ADDRESS}/24,gw=10.20.10.1 "
        "--nameserver 10.20.10.1 "
        "--searchdomain lab.home.arpa "
        f"--cicustom user=local:snippets/{HOSTNAME}-user.yaml "
        "--boot order=scsi0"
    )


def _wait_for_guest(pve: Proxmox) -> None:
    status = pve.run(f"qm status {VMID}").strip()
    if not status.endswith("running"):
        pve.run(f"qm start {VMID}", timeout=300)
    for _ in range(180):
        try:
            if pve.guest_exec(VMID, "true", timeout=15) == "":
                break
        except (RuntimeError, ValueError, json.JSONDecodeError):
            time.sleep(5)
    else:
        raise RuntimeError("MISP VM did not expose QEMU guest agent")
    pve.guest_exec(VMID, "cloud-init status --wait", timeout=1800)


def _install_misp(pve: Proxmox) -> None:
    script = f"""
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
install -d -m 0750 /etc/siem /var/log/siem
systemctl enable --now docker qemu-guest-agent chrony
if [ ! -d /opt/misp-docker/.git ]; then
  git clone https://github.com/MISP/misp-docker.git /opt/misp-docker
fi
cd /opt/misp-docker
git fetch --depth 1 origin {MISP_DOCKER_COMMIT}
git checkout --detach {MISP_DOCKER_COMMIT}
if [ ! -s .env ]; then
  cp template.env .env
  umask 077
  admin_password="$(openssl rand -base64 36 | tr -d '\\n')"
  admin_key="$(openssl rand -hex 20)"
  mysql_password="$(openssl rand -base64 36 | tr -d '\\n')"
  mysql_root_password="$(openssl rand -base64 36 | tr -d '\\n')"
  # Redis password is embedded into a PHP session URI, so keep it URL-safe.
  redis_password="$(openssl rand -hex 32)"
  gpg_password="$(openssl rand -base64 36 | tr -d '\\n')"
  encryption_key="$(openssl rand -hex 32)"
  salt="$(openssl rand -hex 32)"
  instance_uuid="$(uuidgen)"
  set_env() {{
    key="$1"
    value="$2"
    if grep -q "^${{key}}=" .env; then
      sed -i "s|^${{key}}=.*|${{key}}=${{value}}|" .env
    elif grep -q "^# ${{key}}=" .env; then
      sed -i "s|^# ${{key}}=.*|${{key}}=${{value}}|" .env
    else
      printf '%s=%s\\n' "$key" "$value" >>.env
    fi
  }}
  set_env CORE_TAG v2.5.44
  set_env MODULES_TAG v3.0.9
  set_env GUARD_TAG v1.2
  set_env CORE_RUNNING_TAG v2.5.44
  set_env MODULES_RUNNING_TAG v3.0.9
  set_env ADMIN_EMAIL socadmin@lab.home.arpa
  set_env ADMIN_ORG Rdegon-SOC
  set_env ADMIN_PASSWORD "$admin_password"
  set_env ADMIN_KEY "$admin_key"
  set_env DISABLE_PRINTING_PLAINTEXT_CREDENTIALS true
  set_env GPG_PASSPHRASE "$gpg_password"
  set_env BASE_URL https://{ADDRESS}
  set_env ENABLE_DB_SETTINGS true
  set_env ENCRYPTION_KEY "$encryption_key"
  set_env SALT "$salt"
  set_env UUID "$instance_uuid"
  set_env AUTOGEN_ADMIN_KEY false
  set_env DISABLE_IPV6 true
  set_env TZ Europe/Moscow
  set_env MYSQL_PASSWORD "$mysql_password"
  set_env MYSQL_ROOT_PASSWORD "$mysql_root_password"
  set_env REDIS_PASSWORD "$redis_password"
  set_env ENABLE_REDIS_EMPTY_PASSWORD false
  set_env INNODB_BUFFER_POOL_SIZE 1024M
  set_env PHP_MEMORY_LIMIT 1024M
  set_env PHP_FCGI_CHILDREN 4
  set_env PHP_FCGI_START_SERVERS 2
  set_env PHP_FCGI_SPARE_SERVERS 1
  chmod 0600 .env
fi
: >/var/log/siem/misp-deploy.log
docker compose pull >>/var/log/siem/misp-deploy.log 2>&1
docker compose up -d >>/var/log/siem/misp-deploy.log 2>&1
for attempt in $(seq 1 180); do
  if curl -kfsS https://127.0.0.1/users/login >/dev/null; then
    break
  fi
  sleep 5
done
if ! curl -kfsS https://127.0.0.1/users/login >/dev/null; then
  docker ps -a --format 'table {{{{.Names}}}}\\t{{{{.Status}}}}'
  tail -n 100 /var/log/siem/misp-deploy.log
  exit 1
fi
docker compose ps --format json
"""
    pve.guest_exec(VMID, script, timeout=3600)


def main() -> int:
    with Proxmox() as pve:
        _ensure_vm(pve)
        _wait_for_guest(pve)
        _install_misp(pve)
        print(
            pve.guest_exec(
                VMID,
                "hostname; hostname -I; "
                "cd /opt/misp-docker && docker compose ps --status running "
                "--format '{{.Service}}:{{.Status}}' | sort; "
                "curl -kfsS -o /dev/null -w 'https_status=%{http_code}\\n' "
                "https://127.0.0.1/users/login",
            )
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
