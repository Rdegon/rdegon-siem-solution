from __future__ import annotations

import argparse
import json
import shlex
import time
from dataclasses import dataclass
from datetime import datetime, timezone

try:
    from deploy.soc_falco_vm_deploy import _guest_write
    from deploy.soc_foundation_provision import Proxmox
except ModuleNotFoundError:
    from soc_falco_vm_deploy import _guest_write
    from soc_foundation_provision import Proxmox


GIB = 1024**3
OPENCLAW_VMID = 126
GAMEPANEL_VMID = 130
GAMEPANEL_SERVER_UUID = "289d4e9c-cc45-4aca-a67a-e309a5df1564"
OPENCLAW_RULE_IDS = (2301, 2303, 2304, 2305, 8303, 8345, 8354, 8470)
STORAGE_SYSTEM_DISK = "toshiba1ter:106/vm-106-disk-1.qcow2"


@dataclass(frozen=True)
class VmProfile:
    vmid: int
    name: str
    memory_mb: int
    balloon_mb: int
    services: tuple[str, ...]


SIEM_PROFILES = (
    VmProfile(
        104,
        "SIEM-Ingest",
        10_240,
        8_192,
        ("siem-ingest", "siem-kafka", "nginx"),
    ),
    VmProfile(
        105,
        "SIEM-Processing",
        12_288,
        10_240,
        ("siem-kafka", "siem-normalizer", "siem-filter"),
    ),
    VmProfile(
        106,
        "SIEM-Storage",
        20_480,
        18_432,
        (
            "clickhouse-server",
            "siem-writer",
            "siem-writer@2",
            "siem-stream-corr",
            "siem-batch-corr",
            "siem-alert-agg",
        ),
    ),
    VmProfile(
        107,
        "SIEM-WEB",
        10_240,
        8_192,
        ("siem-web", "siem-keycloak", "siem-vault", "nginx"),
    ),
    VmProfile(
        108,
        "SIEM-Transport",
        10_240,
        8_192,
        ("siem-kafka", "clickhouse-server", "siem-normalizer@1", "siem-filter@1"),
    ),
)

RESTART_ORDER = (107, 105, 108, 106, 104)
LXC_LIMITS_MB = {
    100: 8_192,
    120: 4_096,
    121: 2_048,
}

PRIMARY_CLICKHOUSE_CONFIG = """<clickhouse>
  <max_server_memory_usage>12884901888</max_server_memory_usage>
  <max_server_memory_usage_to_ram_ratio>0.65</max_server_memory_usage_to_ram_ratio>
</clickhouse>
"""

STANDBY_CLICKHOUSE_CONFIG = """<clickhouse>
  <max_server_memory_usage>6442450944</max_server_memory_usage>
  <max_server_memory_usage_to_ram_ratio>0.65</max_server_memory_usage_to_ram_ratio>
</clickhouse>
"""


def _wait_vm_state(pve: Proxmox, vmid: int, expected: str, timeout: int = 300) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        state = pve.run(f"qm status {vmid}").strip().rsplit(" ", 1)[-1]
        if state == expected:
            return
        time.sleep(3)
    raise RuntimeError(f"VM{vmid} did not reach state {expected!r}")


def _wait_guest(pve: Proxmox, vmid: int, timeout: int = 300) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            pve.guest_exec(vmid, "true", timeout=15)
            return
        except (RuntimeError, ValueError, json.JSONDecodeError):
            time.sleep(5)
    raise RuntimeError(f"VM{vmid} QEMU guest agent did not become ready")


def _active_services(pve: Proxmox, profile: VmProfile) -> None:
    quoted = " ".join(shlex.quote(unit) for unit in profile.services)
    pve.guest_exec(
        profile.vmid,
        f"systemctl is-active --quiet {quoted}",
        timeout=120,
    )


def _restart_vm(pve: Proxmox, profile: VmProfile) -> None:
    pve.run(f"qm shutdown {profile.vmid} --timeout 180", timeout=210)
    _wait_vm_state(pve, profile.vmid, "stopped", timeout=210)
    pve.run(f"qm start {profile.vmid}", timeout=300)
    _wait_vm_state(pve, profile.vmid, "running", timeout=120)
    _wait_guest(pve, profile.vmid, timeout=360)
    _active_services(pve, profile)


def _replace_env_values(content: str, replacements: dict[str, str]) -> str:
    pending = dict(replacements)
    rendered: list[str] = []
    for line in content.splitlines():
        key = line.split("=", 1)[0].strip() if "=" in line else ""
        if key in pending:
            rendered.append(f"{key}={pending.pop(key)}")
        else:
            rendered.append(line)
    rendered.extend(f"{key}={value}" for key, value in pending.items())
    return "\n".join(rendered).rstrip() + "\n"


def _decommission_openclaw(pve: Proxmox) -> None:
    current_env = pve.guest_exec(107, "cat /etc/siem/web.env", timeout=60)
    updated_env = _replace_env_values(
        current_env,
        {
            "SIEM_OPENCLAW_PROXY_URL": "",
            "SIEM_TELEGRAM_PROXY_URL": "",
        },
    )
    if updated_env != current_env:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        pve.guest_exec(
            107,
            f"cp -a /etc/siem/web.env /etc/siem/web.env.pre-openclaw-retirement-{timestamp}",
            timeout=60,
        )
        _guest_write(pve, 107, "/etc/siem/web.env", updated_env.encode("utf-8"), 0o600)
        pve.guest_exec(
            107,
            "systemctl restart siem-web && systemctl is-active --quiet siem-web",
            timeout=180,
        )

    ids = ",".join(str(rule_id) for rule_id in OPENCLAW_RULE_IDS)
    statements = (
        "ALTER TABLE siem.cmdb_assets "
        "UPDATE enabled=0, vuln_enabled=0, "
        "notes='Retired 2026-07-26: no active OpenClaw/Telegram dependency', "
        "updated_ts=now() "
        "WHERE asset_id='asset-openclaw-gateway' SETTINGS mutations_sync=2",
        "ALTER TABLE siem.correlation_rules_stream "
        f"UPDATE enabled=0, updated_ts=now() WHERE id IN ({ids}) SETTINGS mutations_sync=2",
        "ALTER TABLE siem.correlation_rules_batch "
        f"UPDATE enabled=0, updated_ts=now() WHERE id IN ({ids}) SETTINGS mutations_sync=2",
        "ALTER TABLE siem.detection_rule_catalog "
        f"UPDATE enabled=0, updated_ts=now() WHERE id IN ({ids}) SETTINGS mutations_sync=2",
        "ALTER TABLE siem.alerts_raw "
        "UPDATE status='suppressed', assignee='asset-retirement', updated_ts=now() "
        f"WHERE rule_id IN ({ids}) "
        "AND lower(status) NOT IN ('closed','resolved','false_positive','suppressed') "
        "SETTINGS mutations_sync=2",
    )
    for statement in statements:
        command = f"clickhouse-client --query {shlex.quote(statement)}"
        pve.guest_exec(106, command, timeout=180)

    pve.run(f"qm set {OPENCLAW_VMID} --onboot 0")
    if pve.run(f"qm status {OPENCLAW_VMID}").strip().endswith("running"):
        pve.run(f"qm shutdown {OPENCLAW_VMID} --timeout 180", timeout=210)
        _wait_vm_state(pve, OPENCLAW_VMID, "stopped", timeout=210)


def _rightsize_gamepanel(pve: Proxmox) -> None:
    update = (
        "DB::table('servers')->where('uuid',"
        f"'{GAMEPANEL_SERVER_UUID}')"
        "->update(['memory'=>10240,'swap'=>2048]);"
    )
    pve.guest_exec(
        GAMEPANEL_VMID,
        "cd /var/www/pterodactyl && "
        f"php artisan tinker --execute={shlex.quote(update)} >/dev/null && "
        f"docker update --memory 10g --memory-swap 12g {GAMEPANEL_SERVER_UUID} >/dev/null",
        timeout=180,
    )
    pve.run(f"qm shutdown {GAMEPANEL_VMID} --timeout 180", timeout=210)
    _wait_vm_state(pve, GAMEPANEL_VMID, "stopped", timeout=210)
    pve.run(f"qm set {GAMEPANEL_VMID} --memory 12288 --balloon 0")
    pve.run(f"qm start {GAMEPANEL_VMID}", timeout=300)
    _wait_vm_state(pve, GAMEPANEL_VMID, "running", timeout=120)
    _wait_guest(pve, GAMEPANEL_VMID, timeout=360)
    pve.guest_exec(
        GAMEPANEL_VMID,
        "systemctl is-active --quiet docker wings nginx && "
        f"if [ \"$(docker inspect -f '{{{{.State.Running}}}}' {GAMEPANEL_SERVER_UUID})\" != true ]; "
        f"then docker start {GAMEPANEL_SERVER_UUID} >/dev/null; fi && "
        "for attempt in $(seq 1 90); do "
        f"[ \"$(docker inspect -f '{{{{.State.Running}}}}' {GAMEPANEL_SERVER_UUID})\" = true ] "
        "&& exit 0; sleep 2; done; exit 1",
        timeout=240,
    )


def _apply_siem_profile(
    pve: Proxmox, restart_order: tuple[int, ...] = RESTART_ORDER
) -> None:
    _guest_write(
        pve,
        106,
        "/etc/clickhouse-server/config.d/siem-memory-tuning.xml",
        PRIMARY_CLICKHOUSE_CONFIG.encode("ascii"),
        0o644,
    )
    _guest_write(
        pve,
        108,
        "/etc/clickhouse-server/config.d/siem-memory-tuning.xml",
        STANDBY_CLICKHOUSE_CONFIG.encode("ascii"),
        0o644,
    )
    pve.run(
        "qm set 106 "
        f"--sata1 {STORAGE_SYSTEM_DISK},discard=on,aio=threads,cache=none"
    )
    profiles = {profile.vmid: profile for profile in SIEM_PROFILES}
    for profile in SIEM_PROFILES:
        pve.run(
            f"qm set {profile.vmid} --memory {profile.memory_mb} "
            f"--balloon {profile.balloon_mb}"
        )
    for vmid in restart_order:
        _restart_vm(pve, profiles[vmid])


def _apply_lxc_limits(pve: Proxmox) -> None:
    for vmid, memory_mb in LXC_LIMITS_MB.items():
        pve.run(f"pct set {vmid} --memory {memory_mb}")


def _summary(pve: Proxmox) -> dict[str, object]:
    resources = json.loads(
        pve.run("pvesh get /cluster/resources --type vm --output-format json")
    )
    selected = {
        profile.vmid for profile in SIEM_PROFILES
    } | {OPENCLAW_VMID, GAMEPANEL_VMID, *LXC_LIMITS_MB}
    rows = [
        {
            "vmid": int(item.get("vmid") or 0),
            "name": str(item.get("name") or ""),
            "status": str(item.get("status") or ""),
            "memory_gib": round(float(item.get("mem") or 0) / GIB, 2),
            "max_memory_gib": round(float(item.get("maxmem") or 0) / GIB, 2),
        }
        for item in resources
        if int(item.get("vmid") or 0) in selected
    ]
    rows.sort(key=lambda item: int(item["vmid"]))
    host_memory = pve.run(
        "free -b | awk '/^Mem:/{printf "
        "\"{\\\"total\\\":%s,\\\"used\\\":%s,\\\"available\\\":%s}\", $2,$3,$7}'"
    )
    return {"host_memory": json.loads(host_memory), "guests": rows}


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Apply the audited Proxmox memory right-sizing profile."
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Apply changes. Without this flag, print the intended profile only.",
    )
    parser.add_argument(
        "--skip-openclaw",
        action="store_true",
        help="Skip OpenClaw retirement when resuming a partially completed run.",
    )
    parser.add_argument(
        "--skip-gamepanel",
        action="store_true",
        help="Skip Gamepanel right-sizing when resuming a partially completed run.",
    )
    parser.add_argument(
        "--skip-lxc",
        action="store_true",
        help="Skip LXC memory limit changes.",
    )
    parser.add_argument(
        "--skip-siem",
        action="store_true",
        help="Skip the rolling SIEM memory profile.",
    )
    parser.add_argument(
        "--siem-restart-vmids",
        help=(
            "Comma-separated SIEM VM IDs to restart in the supplied order. "
            "The profile is still written to every SIEM VM."
        ),
    )
    args = parser.parse_args()
    restart_order = RESTART_ORDER
    if args.siem_restart_vmids:
        restart_order = tuple(
            int(value.strip())
            for value in args.siem_restart_vmids.split(",")
            if value.strip()
        )
        known_vmids = {profile.vmid for profile in SIEM_PROFILES}
        unknown_vmids = set(restart_order) - known_vmids
        if unknown_vmids:
            parser.error(
                "Unknown SIEM VM IDs: "
                + ", ".join(str(vmid) for vmid in sorted(unknown_vmids))
            )

    intended = {
        "siem": [
            {
                "vmid": profile.vmid,
                "memory_mb": profile.memory_mb,
                "balloon_mb": profile.balloon_mb,
            }
            for profile in SIEM_PROFILES
        ],
        "gamepanel": {"vmid": GAMEPANEL_VMID, "memory_mb": 12_288},
        "openclaw": {"vmid": OPENCLAW_VMID, "state": "retired"},
        "lxc_limits_mb": LXC_LIMITS_MB,
    }
    if not args.apply:
        print(json.dumps(intended, indent=2, ensure_ascii=True))
        return 0

    with Proxmox() as pve:
        if not args.skip_openclaw:
            _decommission_openclaw(pve)
        if not args.skip_gamepanel:
            _rightsize_gamepanel(pve)
        if not args.skip_lxc:
            _apply_lxc_limits(pve)
        if not args.skip_siem:
            _apply_siem_profile(pve, restart_order=restart_order)
        print(json.dumps(_summary(pve), indent=2, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
