from __future__ import annotations

import argparse
import base64
import ctypes
import hashlib
import json
import os
import shlex
import shutil
import subprocess
import tempfile
import time
import urllib.request
from pathlib import Path, PurePosixPath

try:
    from deploy.soc_foundation_provision import Proxmox
    from deploy.soc_security_integrations_deploy import _write_ct, _write_vm
except ModuleNotFoundError:
    from soc_foundation_provision import Proxmox
    from soc_security_integrations_deploy import _write_ct, _write_vm


ROOT = Path(__file__).resolve().parents[1]
VERSION = "0.77.1"
LINUX_URL = (
    "https://github.com/Velocidex/velociraptor/releases/download/"
    f"v{VERSION}/velociraptor-v{VERSION}-linux-amd64"
)
LINUX_SHA256 = "6636020f3ce03ea4eff5d5b96d635c400e51d2636c823a8f0bd458ddc7c4d28a"
WINDOWS_URL = (
    "https://github.com/Velocidex/velociraptor/releases/download/"
    f"v{VERSION}/velociraptor-v{VERSION}-windows-amd64.exe"
)
WINDOWS_SHA256 = "c91cf8a32731c4c45c148393bc7d2af688c392194a9fffc4535e8b583260d55e"
WINDOWS_SERVER_URL = b"https://192.168.3.102:8000/"
LINUX_CANARY_VMID = 130
LINUX_VMIDS = (102, 104, 105, 106, 107, 108, 122, 123, 124, 125, 127, 130, 131)
LINUX_CTIDS = (100, 120, 121, 129, 132, 133)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _client_config(pve: Proxmox) -> bytes:
    encoded = pve.ct(
        128,
        "base64 -w0 /etc/velociraptor/client.config.yaml",
    ).strip()
    config = base64.b64decode(encoded, validate=True)
    if b"https://10.20.10.128:8000/" not in config:
        raise RuntimeError("Velociraptor client config does not target the DFIR server")
    return config


def _linux_install_script() -> str:
    return f"""
set -euo pipefail
if [ ! -x /usr/local/bin/velociraptor ] || \
   [ "$(/usr/local/bin/velociraptor version 2>/dev/null | sed -n 's/.*version: //p' | head -1)" != "{VERSION}" ]; then
  curl -fsSLo /tmp/velociraptor {LINUX_URL}
  echo '{LINUX_SHA256}  /tmp/velociraptor' | sha256sum -c -
  install -m 0755 /tmp/velociraptor /usr/local/bin/velociraptor
  rm -f /tmp/velociraptor
fi
install -d -m 0700 /var/lib/velociraptor
systemctl daemon-reload
systemctl enable --now velociraptor-client.service
systemctl restart velociraptor-client.service
for attempt in $(seq 1 30); do
  systemctl is-active --quiet velociraptor-client.service && break
  sleep 2
done
systemctl is-active --quiet velociraptor-client.service
/usr/local/bin/velociraptor version | head -1
"""


def _install_linux_vm(
    pve: Proxmox,
    vmid: int,
    client_config: bytes,
) -> dict[str, str | int]:
    _write_vm(
        pve,
        vmid,
        "/etc/velociraptor/client.config.yaml",
        client_config,
        0o600,
    )
    _write_vm(
        pve,
        vmid,
        "/etc/systemd/system/velociraptor-client.service",
        (ROOT / "deploy/systemd/velociraptor-client.service").read_bytes(),
        0o644,
    )
    output = pve.guest_exec(
        vmid,
        _linux_install_script(),
        timeout=600,
    )
    return {
        "vmid": vmid,
        "kind": "vm",
        "status": output.strip().replace("\n", " | "),
    }


def _install_linux_ct(
    pve: Proxmox,
    vmid: int,
    client_config: bytes,
) -> dict[str, str | int]:
    _write_ct(
        pve,
        vmid,
        "/etc/velociraptor/client.config.yaml",
        client_config,
        0o600,
    )
    _write_ct(
        pve,
        vmid,
        "/etc/systemd/system/velociraptor-client.service",
        (ROOT / "deploy/systemd/velociraptor-client.service").read_bytes(),
        0o644,
    )
    output = pve.ct(vmid, _linux_install_script(), timeout=600)
    return {
        "vmid": vmid,
        "kind": "ct",
        "status": output.strip().replace("\n", " | "),
    }


def _write_proxmox_file(
    pve: Proxmox,
    path: str,
    content: bytes,
    mode: int,
) -> None:
    encoded = base64.b64encode(content).decode("ascii")
    temp = f"/tmp/velociraptor-proxmox-{os.getpid()}.b64"
    parent = str(PurePosixPath(path).parent)
    pve.run(f"install -d -m 0755 {shlex.quote(parent)}; : > {temp}")
    try:
        for offset in range(0, len(encoded), 24_000):
            pve.run(
                f"printf %s {shlex.quote(encoded[offset:offset + 24_000])} >> {temp}"
            )
        pve.run(
            f"base64 -d {temp} > {shlex.quote(path)} && "
            f"chmod {mode:o} {shlex.quote(path)}"
        )
    finally:
        pve.run(f"rm -f {temp}")


def _install_proxmox(
    pve: Proxmox,
    client_config: bytes,
) -> dict[str, str]:
    _write_proxmox_file(
        pve,
        "/etc/velociraptor/client.config.yaml",
        client_config,
        0o600,
    )
    _write_proxmox_file(
        pve,
        "/etc/systemd/system/velociraptor-client.service",
        (ROOT / "deploy/systemd/velociraptor-client.service").read_bytes(),
        0o644,
    )
    output = pve.run(_linux_install_script(), timeout=600)
    return {"host": "pve", "kind": "proxmox", "status": output.strip()}


def _run_checked(command: list[str], timeout: int = 120) -> str:
    completed = subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    output = "\n".join(
        part.strip()
        for part in (completed.stdout, completed.stderr)
        if part and part.strip()
    )
    if completed.returncode:
        raise RuntimeError(f"{command[0]} failed with exit code {completed.returncode}: {output}")
    return output


def _windows_service_state() -> str:
    completed = subprocess.run(
        ["sc.exe", "query", "Velociraptor"],
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode:
        return "missing"
    return "running" if "RUNNING" in completed.stdout else "stopped"


def _replace_windows_binary(source: Path, destination: Path) -> None:
    last_error: PermissionError | None = None
    for _ in range(30):
        try:
            shutil.copy2(source, destination)
            return
        except PermissionError as exc:
            last_error = exc
            time.sleep(1)
    raise RuntimeError(f"Velociraptor service did not release {destination}") from last_error


def _install_windows_client(client_config: bytes) -> dict[str, str]:
    if os.name != "nt":
        raise RuntimeError("Windows client deployment must run on WIN-RTX-test")
    if not ctypes.windll.shell32.IsUserAnAdmin():
        raise RuntimeError("Windows client deployment requires an elevated Codex process")

    install_dir = Path(os.environ["ProgramFiles"]) / "Velociraptor"
    installed_binary = install_dir / "Velociraptor.exe"
    installed_config = install_dir / "Velociraptor.config.yaml"
    prior_state = _windows_service_state()
    windows_config = client_config.replace(
        b"https://10.20.10.128:8000/",
        WINDOWS_SERVER_URL,
    )
    if WINDOWS_SERVER_URL not in windows_config:
        raise RuntimeError("Unable to set the Windows Velociraptor gateway URL")

    with tempfile.TemporaryDirectory(prefix="velociraptor-deploy-") as directory:
        downloaded = Path(directory) / "velociraptor.exe"
        temporary_config = Path(directory) / "client.config.yaml"
        urllib.request.urlretrieve(WINDOWS_URL, downloaded)
        if _sha256(downloaded) != WINDOWS_SHA256:
            raise RuntimeError("Velociraptor Windows binary checksum mismatch")
        temporary_config.write_bytes(windows_config)

        if prior_state == "missing":
            _run_checked(
                [
                    str(downloaded),
                    "service",
                    "install",
                    "--config",
                    str(temporary_config),
                ],
                timeout=300,
            )
        else:
            _run_checked(
                [
                    "powershell.exe",
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    "Stop-Service -Name Velociraptor -Force -ErrorAction Stop",
                ]
            )
            try:
                install_dir.mkdir(parents=True, exist_ok=True)
                if not installed_binary.exists() or _sha256(installed_binary) != WINDOWS_SHA256:
                    _replace_windows_binary(downloaded, installed_binary)
                installed_config.write_bytes(windows_config)
            finally:
                _run_checked(
                    [
                        "powershell.exe",
                        "-NoProfile",
                        "-NonInteractive",
                        "-Command",
                        "Start-Service -Name Velociraptor -ErrorAction Stop",
                    ]
                )

    if _sha256(installed_binary) != WINDOWS_SHA256:
        raise RuntimeError("Installed Velociraptor Windows binary checksum mismatch")
    _run_checked(
        [
            "icacls.exe",
            str(installed_config),
            "/inheritance:r",
            "/grant:r",
            "*S-1-5-18:(F)",
            "*S-1-5-32-544:(F)",
        ]
    )
    for _ in range(30):
        if _windows_service_state() == "running":
            break
        time.sleep(2)
    if _windows_service_state() != "running":
        raise RuntimeError("Velociraptor Windows service did not enter RUNNING state")
    version = _run_checked([str(installed_binary), "version"]).splitlines()[0]
    return {"host": os.environ.get("COMPUTERNAME", "WIN-RTX-test"), "status": version}


def _enrolled_clients(
    pve: Proxmox,
    expected: int = 2,
) -> list[dict[str, object]]:
    query = (
        "SELECT client_id, os_info.hostname AS hostname, "
        "os_info.system AS system, last_seen_at FROM clients()"
    )
    for _ in range(30):
        output = pve.ct(
            128,
            "runuser -u velociraptor -- /usr/local/bin/velociraptor "
            "--api_config /etc/velociraptor/api-soc-deploy.yaml "
            f"query --format jsonl {json.dumps(query)}",
        )
        clients = [
            json.loads(line)
            for line in output.splitlines()
            if line.strip().startswith("{")
        ]
        if len(clients) >= expected:
            return clients
        time.sleep(2)
    return clients


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Deploy the initial Velociraptor endpoint canaries")
    parser.add_argument("--skip-windows", action="store_true")
    parser.add_argument("--skip-linux", action="store_true")
    parser.add_argument("--all-linux", action="store_true")
    parser.add_argument("--include-proxmox", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    with Proxmox() as pve:
        config = _client_config(pve)
        result: dict[str, object] = {}
        if not args.skip_linux:
            if args.all_linux:
                linux: list[dict[str, str | int]] = []
                for vmid in LINUX_VMIDS:
                    linux.append(_install_linux_vm(pve, vmid, config))
                for vmid in LINUX_CTIDS:
                    linux.append(_install_linux_ct(pve, vmid, config))
                result["linux"] = linux
            else:
                result["linux"] = _install_linux_vm(pve, LINUX_CANARY_VMID, config)
            if args.include_proxmox:
                result["proxmox"] = _install_proxmox(pve, config)
        if not args.skip_windows:
            result["windows"] = _install_windows_client(config)
        expected = 2
        if args.all_linux:
            expected = len(LINUX_VMIDS) + len(LINUX_CTIDS) + 1
        if args.include_proxmox:
            expected += 1
        result["enrolled_clients"] = _enrolled_clients(pve, expected=expected)
        print(json.dumps(result, indent=2, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
