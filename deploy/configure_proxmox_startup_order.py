from __future__ import annotations

from pathlib import Path
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


def main() -> int:
    with Proxmox() as pve:
        for vmid, startup in CORE_STARTUP.items():
            pve.run(f"qm set {vmid} --onboot 1 --startup {startup}", timeout=60)
        for vmid, expected in CORE_STARTUP.items():
            config = pve.run(f"qm config {vmid}", timeout=60)
            actual = next(
                (line.split(":", 1)[1].strip() for line in config.splitlines() if line.startswith("startup:")),
                "",
            )
            if actual != expected:
                raise RuntimeError(f"VM{vmid} startup order mismatch: {actual!r}")
            print(f"VM{vmid}={actual}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
