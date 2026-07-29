from __future__ import annotations

import base64
from pathlib import Path
import shlex
import sys


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from deploy.soc_foundation_provision import Proxmox


CORE_STARTUP = {
    102: "order=10,up=30,down=120",
    103: "order=20,up=30,down=120",
    106: "order=30,up=90,down=180",
    108: "order=35,up=60,down=120",
    105: "order=40,up=90,down=120",
    104: "order=45,up=60,down=90",
    107: "order=50,up=90,down=120",
}

SYSTEM_ASSETS = (
    (
        ROOT / "deploy" / "proxmox_cold_start_reconcile.sh",
        "/usr/local/sbin/siem-cold-start-reconcile",
        "0755",
    ),
    (
        ROOT / "deploy" / "systemd" / "siem-cold-start-reconcile.service",
        "/etc/systemd/system/siem-cold-start-reconcile.service",
        "0644",
    ),
    (
        ROOT / "deploy" / "systemd" / "siem-cold-start-reconcile.timer",
        "/etc/systemd/system/siem-cold-start-reconcile.timer",
        "0644",
    ),
)


def _install_asset(pve: Proxmox, source: Path, destination: str, mode: str) -> None:
    encoded = base64.b64encode(source.read_bytes()).decode("ascii")
    command = (
        f"printf %s {shlex.quote(encoded)} | base64 -d | "
        f"install -m {shlex.quote(mode)} /dev/stdin {shlex.quote(destination)}"
    )
    pve.run(command, timeout=60)


def main() -> int:
    with Proxmox() as pve:
        for source, destination, mode in SYSTEM_ASSETS:
            _install_asset(pve, source, destination, mode)
        for vmid, startup in CORE_STARTUP.items():
            pve.run(f"qm set {vmid} --onboot 1 --startup {startup}", timeout=60)
        pve.run(
            "systemctl daemon-reload && "
            "systemctl enable --now siem-cold-start-reconcile.timer",
            timeout=60,
        )
        for vmid, expected in CORE_STARTUP.items():
            config = pve.run(f"qm config {vmid}", timeout=60)
            actual = next(
                (line.split(":", 1)[1].strip() for line in config.splitlines() if line.startswith("startup:")),
                "",
            )
            if actual != expected:
                raise RuntimeError(f"VM{vmid} startup order mismatch: {actual!r}")
            print(f"VM{vmid}={actual}")
        timer_state = pve.run(
            "systemctl is-enabled siem-cold-start-reconcile.timer && "
            "systemctl is-active siem-cold-start-reconcile.timer",
            timeout=60,
        )
        print(f"cold_start_timer={','.join(timer_state.split())}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
