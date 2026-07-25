#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path


DEFAULT_CONFIG = Path("/etc/suricata/suricata.yaml")
DEFAULT_THRESHOLD_CONFIG = Path("/etc/suricata/threshold.config")
DEFAULT_INTERFACES = ("eth0", "eth1", "eth2", "eth3", "eth4")
HOME_NETWORKS = (
    "192.168.3.0/24",
    "192.168.1.0/24",
    "10.20.10.0/24",
    "10.20.20.0/24",
    "10.20.30.0/24",
    "10.20.40.0/24",
    "10.66.66.0/24",
    "10.10.10.0/24",
    "10.8.0.0/24",
)
INFRASTRUCTURE_NOISE_SIDS = (
    2013504,
    2200074,
    2200075,
    2210045,
    2210046,
    2260003,
)
EXPECTED_SERVICE_SUPPRESSIONS = (
    (2033966, "10.20.30.126"),
    (2033966, "192.168.3.102"),
)
THRESHOLD_BLOCK_START = "# BEGIN RDEGON SEGMENTED IDS"
THRESHOLD_BLOCK_END = "# END RDEGON SEGMENTED IDS"


def _run(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=False, capture_output=True, text=True)


def render_af_packet(interfaces: tuple[str, ...]) -> str:
    lines = ["af-packet:"]
    for index, interface in enumerate(interfaces):
        lines.extend(
            (
                f"  - interface: {interface}",
                "    threads: 1",
                f"    cluster-id: {90 + index}",
                "    cluster-type: cluster_flow",
                "    defrag: yes",
                "    use-mmap: yes",
                "    tpacket-v3: yes",
                "    ring-size: 4096",
                "    block-size: 131072",
                "    block-timeout: 10",
                "    use-emergency-flush: yes",
                "    buffer-size: 1048576",
                "    checksum-checks: no",
                "    disable-promisc: no",
            )
        )
    return "\n".join(lines) + "\n\n"


def rewrite_threshold_config(text: str) -> str:
    managed_block = "\n".join(
        (
            THRESHOLD_BLOCK_START,
            "# Routine package management plus virtual-NIC and multi-interface artifacts.",
            *(f"suppress gen_id 1, sig_id {sid}" for sid in INFRASTRUCTURE_NOISE_SIDS),
            "# Expected Telegram integration and its Unbound-forwarded duplicate.",
            *(
                f"suppress gen_id 1, sig_id {sid}, track by_src, ip {source_ip}"
                for sid, source_ip in EXPECTED_SERVICE_SUPPRESSIONS
            ),
            THRESHOLD_BLOCK_END,
        )
    )
    without_block = re.sub(
        rf"(?ms)^\s*{re.escape(THRESHOLD_BLOCK_START)}.*?{re.escape(THRESHOLD_BLOCK_END)}\s*$",
        "",
        text,
    ).rstrip()
    return f"{without_block}\n\n{managed_block}\n"


def rewrite_config(text: str, interfaces: tuple[str, ...] = DEFAULT_INTERFACES) -> str:
    home_net = f'    HOME_NET: "[{",".join(HOME_NETWORKS)}]"'
    rewritten, count = re.subn(
        r'(?m)^[ \t]+HOME_NET:[^\r\n]*$',
        home_net,
        text,
        count=1,
    )
    if count != 1:
        raise ValueError("Unable to locate a unique HOME_NET setting")

    start_match = re.search(r"(?m)^af-packet:[ \t]*\r?$", rewritten)
    end_match = re.search(r"(?m)^af-xdp:[ \t]*\r?$", rewritten)
    if not start_match or not end_match or end_match.start() <= start_match.start():
        raise ValueError("Unable to locate the af-packet configuration block")

    rewritten = (
        rewritten[: start_match.start()]
        + render_af_packet(interfaces)
        + rewritten[end_match.start() :]
    )
    rewritten, threshold_count = re.subn(
        r"(?m)^#?[ \t]*threshold-file:[^\r\n]*$",
        "threshold-file: /etc/suricata/threshold.config",
        rewritten,
        count=1,
    )
    if threshold_count != 1:
        raise ValueError("Unable to locate a unique threshold-file setting")
    rewritten = re.sub(
        r"(?m)^([ \t]*)- flow[ \t]*$",
        r"\1# - flow  # Disabled: retain packet inspection without bulk correlation input.",
        rewritten,
        count=1,
    )
    return rewritten


def _validate_interfaces(interfaces: tuple[str, ...]) -> None:
    missing = [interface for interface in interfaces if not Path("/sys/class/net", interface).exists()]
    if missing:
        raise RuntimeError(f"Missing network interfaces: {', '.join(missing)}")


def _validate_config(config_path: Path) -> None:
    result = _run(["suricata", "-T", "-c", str(config_path)])
    if result.returncode != 0:
        message = (result.stderr or result.stdout).strip()
        raise RuntimeError(f"Suricata configuration validation failed: {message[-2000:]}")


def apply_config(
    config_path: Path,
    interfaces: tuple[str, ...],
    threshold_path: Path = DEFAULT_THRESHOLD_CONFIG,
) -> Path:
    if os.geteuid() != 0:
        raise PermissionError("Run as root")
    _validate_interfaces(interfaces)

    original = config_path.read_text(encoding="utf-8")
    rewritten = rewrite_config(original, interfaces)
    original_threshold = threshold_path.read_text(encoding="utf-8") if threshold_path.exists() else ""
    rewritten_threshold = rewrite_threshold_config(original_threshold)
    if rewritten == original and rewritten_threshold == original_threshold:
        _validate_config(config_path)
        return config_path

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup_path = config_path.with_name(f"{config_path.name}.bak-{timestamp}")
    threshold_backup_path = threshold_path.with_name(f"{threshold_path.name}.bak-{timestamp}")
    shutil.copy2(config_path, backup_path)
    if threshold_path.exists():
        shutil.copy2(threshold_path, threshold_backup_path)
    stat = config_path.stat()

    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=config_path.parent,
        prefix=f".{config_path.name}.",
        delete=False,
    ) as handle:
        handle.write(rewritten)
        candidate_path = Path(handle.name)
    os.chmod(candidate_path, stat.st_mode)
    os.chown(candidate_path, stat.st_uid, stat.st_gid)

    threshold_path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=threshold_path.parent,
        prefix=f".{threshold_path.name}.",
        delete=False,
    ) as handle:
        handle.write(rewritten_threshold)
        candidate_threshold_path = Path(handle.name)
    if threshold_path.exists():
        threshold_stat = threshold_path.stat()
        os.chmod(candidate_threshold_path, threshold_stat.st_mode)
        os.chown(candidate_threshold_path, threshold_stat.st_uid, threshold_stat.st_gid)
    else:
        os.chmod(candidate_threshold_path, 0o644)

    try:
        os.replace(candidate_threshold_path, threshold_path)
        _validate_config(candidate_path)
        os.replace(candidate_path, config_path)
        restart = _run(["systemctl", "restart", "suricata.service"])
        active = _run(["systemctl", "is-active", "suricata.service"])
        if restart.returncode != 0 or active.stdout.strip() != "active":
            raise RuntimeError(
                "Suricata failed to restart: "
                + (restart.stderr or restart.stdout or active.stdout).strip()
            )
    except Exception:
        candidate_path.unlink(missing_ok=True)
        candidate_threshold_path.unlink(missing_ok=True)
        shutil.copy2(backup_path, config_path)
        if threshold_backup_path.exists():
            shutil.copy2(threshold_backup_path, threshold_path)
        elif threshold_path.exists():
            threshold_path.unlink()
        _run(["systemctl", "restart", "suricata.service"])
        raise

    return backup_path


def main() -> int:
    parser = argparse.ArgumentParser(description="Configure lab-edge Suricata IDS capture")
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--interfaces", nargs="+", default=list(DEFAULT_INTERFACES))
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    interfaces = tuple(dict.fromkeys(str(item).strip() for item in args.interfaces if str(item).strip()))
    if not interfaces:
        parser.error("At least one interface is required")

    if not args.apply:
        rendered = rewrite_config(args.config.read_text(encoding="utf-8"), interfaces)
        sys.stdout.write(rendered)
        return 0

    backup = apply_config(args.config, interfaces)
    print(f"Suricata IDS capture configured; backup: {backup}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
