from __future__ import annotations

import argparse
import base64
import json
import shlex
import sys
from datetime import datetime, time, timedelta, timezone
from pathlib import Path, PurePosixPath
from typing import Any

try:
    from deploy.soc_foundation_provision import Proxmox
except ModuleNotFoundError:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from soc_foundation_provision import Proxmox


ROOT = Path(__file__).resolve().parents[1]
REMOTE_ROOT = "/opt/siem/siem-solution"
RELEASE_FILES = (
    "services/writer/worker.py",
    "sql/19_event_insert_deduplication.sql",
)
TARGETS = (
    {
        "vmid": 108,
        "env": "/etc/siem/storage-standby.env",
        "service": "siem-writer-standby",
        "python": "/opt/siem/venv-storage/bin/python",
    },
    {
        "vmid": 106,
        "env": "/etc/siem/storage.env",
        "service": "siem-writer",
        "python": "/opt/siem/venv-storage/bin/python",
    },
)
TARGET_IPS = {
    106: "10.20.10.106",
    108: "10.20.10.108",
}


def _push_file(
    pve: Proxmox,
    vmid: int,
    relative: str,
    *,
    backup_root: str,
) -> None:
    source = ROOT / relative
    destination = str(PurePosixPath(REMOTE_ROOT) / relative)
    backup = str(
        PurePosixPath(backup_root)
        / destination.removeprefix("/").replace("/", "__")
    )
    temp = f"/tmp/siem-event-dedupe-{source.name}.b64"
    encoded = base64.b64encode(source.read_bytes()).decode("ascii")
    pve.guest_exec(
        vmid,
        f"install -d -m 0750 {shlex.quote(backup_root)} "
        f"{shlex.quote(str(PurePosixPath(destination).parent))}; "
        f"if [ -f {shlex.quote(destination)} ]; then "
        f"cp -a {shlex.quote(destination)} {shlex.quote(backup)}; fi; "
        f": > {shlex.quote(temp)}",
    )
    for offset in range(0, len(encoded), 32_000):
        pve.guest_exec(
            vmid,
            f"printf %s {shlex.quote(encoded[offset:offset + 32_000])} "
            f">> {shlex.quote(temp)}",
        )
    pve.guest_exec(
        vmid,
        f"base64 -d {shlex.quote(temp)} > {shlex.quote(destination)}; "
        f"rm -f {shlex.quote(temp)}; chmod 0644 {shlex.quote(destination)}",
    )


def _clickhouse_command(env_path: str, query: str, *, multiquery: bool = False) -> str:
    multi = "--multiquery " if multiquery else ""
    return (
        f"set -a; . {shlex.quote(env_path)}; set +a; "
        "clickhouse-client "
        '--host "$SIEM_CH_HOST" --port "$SIEM_CH_PORT" '
        '--user "$SIEM_CH_USER" --password "$SIEM_CH_PASSWORD" '
        f"{multi}--query {shlex.quote(query)}"
    )


def _remote_clickhouse_command(env_path: str, query: str) -> str:
    return (
        f"set -a; . {shlex.quote(env_path)}; set +a; "
        "clickhouse-client "
        '--param_remote_user "$SIEM_CH_USER" '
        '--param_remote_password "$SIEM_CH_PASSWORD" '
        f"--query {shlex.quote(query)}"
    )


def _remote_events(peer_ip: str) -> str:
    return (
        f"remote('{peer_ip}:9000','siem','events',"
        "{remote_user:String},{remote_password:String})"
    )


def _event_key_select(source: str, predicate: str, *, all_columns: bool = False) -> str:
    columns = (
        "*"
        if all_columns
        else "event_id, device_product, log_source, host_name"
    )
    return f"SELECT {columns} FROM {source} WHERE {predicate}"


def _reconcile_events(
    pve: Proxmox,
    *,
    days: int,
    cutoff_minutes: int,
) -> dict[str, Any]:
    cutoff = (
        datetime.now(timezone.utc) - timedelta(minutes=cutoff_minutes)
    ).replace(second=0, microsecond=0)
    source_start = datetime.combine(
        cutoff.date() - timedelta(days=days - 1),
        time.min,
        tzinfo=timezone.utc,
    )
    lookup_start = source_start - timedelta(days=1)
    lookup_end = cutoff + timedelta(days=1)

    def literal(value: datetime) -> str:
        return value.strftime("%Y-%m-%d %H:%M:%S")

    source_predicate = (
        f"ts >= toDateTime('{literal(source_start)}') "
        f"AND ts < toDateTime('{literal(cutoff)}')"
    )
    lookup_predicate = (
        f"ts >= toDateTime('{literal(lookup_start)}') "
        f"AND ts < toDateTime('{literal(lookup_end)}')"
    )
    result: dict[str, Any] = {
        "source_start_utc": source_start.isoformat(),
        "cutoff_utc": cutoff.isoformat(),
        "targets": {},
    }
    target_by_vmid = {int(target["vmid"]): target for target in TARGETS}
    for vmid, peer_vmid in ((106, 108), (108, 106)):
        target = target_by_vmid[vmid]
        remote_source = _remote_events(TARGET_IPS[peer_vmid])
        peer_keys = _event_key_select(remote_source, source_predicate)
        local_keys = _event_key_select("siem.events", lookup_predicate)
        anti_join = (
            f"({peer_keys}) AS peer LEFT ANTI JOIN ({local_keys}) AS local "
            "USING(event_id, device_product, log_source, host_name)"
        )
        count_query = f"SELECT count() FROM {anti_join}"
        command = _remote_clickhouse_command(str(target["env"]), count_query)
        before = int(pve.guest_exec(vmid, command, timeout=900).strip() or "0")
        if before:
            peer_rows = _event_key_select(
                remote_source,
                source_predicate,
                all_columns=True,
            )
            insert_query = (
                "INSERT INTO siem.events SELECT peer.* FROM "
                f"({peer_rows}) AS peer "
                f"LEFT ANTI JOIN ({local_keys}) AS local "
                "USING(event_id, device_product, log_source, host_name)"
            )
            pve.guest_exec(
                vmid,
                _remote_clickhouse_command(str(target["env"]), insert_query),
                timeout=1_800,
            )
        after = int(pve.guest_exec(vmid, command, timeout=900).strip() or "0")
        if after:
            raise RuntimeError(
                f"ClickHouse event reconciliation incomplete on VM{vmid}: "
                f"{after} peer rows are still missing"
            )
        result["targets"][str(vmid)] = {
            "peer_vmid": peer_vmid,
            "missing_before": before,
            "missing_after": after,
        }
    return result


def _partition_counts(
    pve: Proxmox,
    target: dict[str, Any],
    partitions: list[str],
) -> list[dict[str, int | str]]:
    values = ",".join(f"toDate('{value}')" for value in partitions)
    query = (
        "SELECT toString(toDate(ts)) AS partition, count() AS rows, "
        "uniqExact(tuple(event_id, device_product, log_source, host_name)) "
        "AS unique_events "
        "FROM siem.events "
        f"WHERE toDate(ts) IN ({values}) "
        "GROUP BY toDate(ts) ORDER BY toDate(ts) FORMAT JSONEachRow"
    )
    output = pve.guest_exec(
        int(target["vmid"]),
        _clickhouse_command(str(target["env"]), query),
        timeout=300,
    )
    rows: list[dict[str, int | str]] = []
    for line in output.splitlines():
        if not line.strip():
            continue
        raw = json.loads(line)
        count = int(raw["rows"])
        unique = int(raw["unique_events"])
        rows.append(
            {
                "partition": str(raw["partition"]),
                "rows": count,
                "unique_events": unique,
                "duplicate_events": max(0, count - unique),
            }
        )
    return rows


def _deduplicate_partitions(
    pve: Proxmox,
    target: dict[str, Any],
    partitions: list[str],
) -> dict[str, Any]:
    vmid = int(target["vmid"])
    service = str(target["service"])
    stage_table = f"siem.events_dedup_stage_{vmid}"
    pve.guest_exec(vmid, f"systemctl stop {shlex.quote(service)}", timeout=90)
    try:
        before = _partition_counts(pve, target, partitions)
        partition_values = ",".join(
            f"toDate('{partition}')" for partition in partitions
        )
        pve.guest_exec(
            vmid,
            _clickhouse_command(
                str(target["env"]),
                f"DROP TABLE IF EXISTS {stage_table}; "
                f"CREATE TABLE {stage_table} AS siem.events; "
                f"INSERT INTO {stage_table} "
                "SELECT * FROM siem.events "
                f"WHERE toDate(ts) IN ({partition_values}) "
                "ORDER BY ts ASC "
                "LIMIT 1 BY event_id, device_product, log_source, host_name",
                multiquery=True,
            ),
            timeout=1_800,
        )
        stage_counts = []
        stage_query = (
            "SELECT toString(toDate(ts)) AS partition, count() AS rows, "
            "uniqExact(tuple(event_id, device_product, log_source, host_name)) "
            f"AS unique_events FROM {stage_table} "
            "GROUP BY toDate(ts) ORDER BY toDate(ts) FORMAT JSONEachRow"
        )
        stage_output = pve.guest_exec(
            vmid,
            _clickhouse_command(str(target["env"]), stage_query),
            timeout=300,
        )
        for line in stage_output.splitlines():
            if line.strip():
                stage_counts.append(json.loads(line))
        for partition in partitions:
            pve.guest_exec(
                vmid,
                _clickhouse_command(
                    str(target["env"]),
                    "ALTER TABLE siem.events "
                    f"REPLACE PARTITION '{partition}' FROM {stage_table}",
                ),
                timeout=600,
            )
    finally:
        try:
            pve.guest_exec(
                vmid,
                _clickhouse_command(
                    str(target["env"]),
                    f"DROP TABLE IF EXISTS {stage_table}",
                ),
                timeout=180,
            )
        finally:
            pve.guest_exec(
                vmid,
                f"systemctl start {shlex.quote(service)}",
                timeout=90,
            )
    pve.guest_exec(
        vmid,
        f"systemctl is-active --quiet {shlex.quote(service)} clickhouse-server",
        timeout=90,
    )
    return {
        "before": before,
        "stage": stage_counts,
        "after": _partition_counts(pve, target, partitions),
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Deploy idempotent ClickHouse writes and remove exact event duplicates."
    )
    parser.add_argument("--deduplicate-days", type=int, default=2)
    parser.add_argument(
        "--reconcile-days",
        type=int,
        default=None,
        help="Reconcile primary and standby after maintenance; defaults to deduplicate-days.",
    )
    parser.add_argument("--reconcile-cutoff-minutes", type=int, default=15)
    args = parser.parse_args()
    days = max(0, min(30, int(args.deduplicate_days)))
    reconcile_days = (
        days
        if args.reconcile_days is None
        else max(0, min(30, int(args.reconcile_days)))
    )
    reconcile_cutoff_minutes = max(
        5,
        min(1_440, int(args.reconcile_cutoff_minutes)),
    )
    today = datetime.now(timezone.utc).date()
    partitions = [
        (today - timedelta(days=offset)).isoformat()
        for offset in reversed(range(days))
    ]
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    result: dict[str, Any] = {
        "backup_stamp": stamp,
        "partitions": partitions,
        "targets": {},
    }

    with Proxmox() as pve:
        for target in TARGETS:
            vmid = int(target["vmid"])
            backup_root = f"/var/backups/siem/event-dedupe-{stamp}"
            for relative in RELEASE_FILES:
                _push_file(pve, vmid, relative, backup_root=backup_root)
            pve.guest_exec(
                vmid,
                f"{shlex.quote(str(target['python']))} -m py_compile "
                f"{shlex.quote(REMOTE_ROOT + '/services/writer/worker.py')}",
                timeout=120,
            )
            migration = (ROOT / RELEASE_FILES[1]).read_text(encoding="utf-8")
            pve.guest_exec(
                vmid,
                _clickhouse_command(str(target["env"]), migration, multiquery=True),
                timeout=180,
            )
            pve.guest_exec(
                vmid,
                f"systemctl restart {shlex.quote(str(target['service']))}; "
                f"systemctl is-active --quiet {shlex.quote(str(target['service']))} "
                "clickhouse-server",
                timeout=120,
            )
            result["targets"][str(vmid)] = {
                "service": str(target["service"]),
                "backup": backup_root,
            }

        if partitions:
            for target in TARGETS:
                vmid = int(target["vmid"])
                result["targets"][str(vmid)]["deduplication"] = (
                    _deduplicate_partitions(pve, target, partitions)
                )
        if reconcile_days:
            result["reconciliation"] = _reconcile_events(
                pve,
                days=reconcile_days,
                cutoff_minutes=reconcile_cutoff_minutes,
            )

    print(json.dumps(result, ensure_ascii=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
