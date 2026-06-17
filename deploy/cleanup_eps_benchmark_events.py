from __future__ import annotations

import argparse
import json
import shlex
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

try:
    import paramiko
except ModuleNotFoundError as exc:  # pragma: no cover
    raise SystemExit("paramiko is required for EPS benchmark cleanup") from exc


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REPORT_DIR = ROOT / "runtime-control-plane" / "eps-ladder-live"
DEFAULT_VM3 = "192.168.1.38"

EVENT_TABLES = ("siem.events", "siem.events_cold", "siem.events_shadow")
ALERT_TABLES = ("siem.alerts_raw", "siem.alerts_agg", "siem.alert_history")

EVENT_SEARCH_COLUMNS = (
    "message",
    "normalized_json",
    "event_id",
    "log_source",
    "host_name",
    "tags",
)
ALERT_SEARCH_COLUMNS = (
    "source",
    "context_json",
    "group_key_json",
    "samples_json",
    "entity_key",
    "record_id",
    "note",
)


@dataclass(frozen=True)
class HostSpec:
    host: str
    user: str


@dataclass(frozen=True)
class CleanupScope:
    run_ids: list[str]
    started_at: datetime | None
    finished_at: datetime | None


def _connect(host: HostSpec, key_path: str) -> paramiko.SSHClient:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        host.host,
        username=host.user,
        key_filename=key_path,
        timeout=20,
        banner_timeout=20,
        auth_timeout=20,
        look_for_keys=False,
        allow_agent=False,
    )
    return client


def _run(client: paramiko.SSHClient, command: str, *, timeout_sec: float = 120.0) -> tuple[int, str, str]:
    stdin, stdout, stderr = client.exec_command(command, timeout=timeout_sec)
    stdin.close()
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    return stdout.channel.recv_exit_status(), out, err


def _clickhouse(client: paramiko.SSHClient, query: str, *, timeout_sec: float = 120.0) -> str:
    code, out, err = _run(client, f"clickhouse-client --query {shlex.quote(query)}", timeout_sec=timeout_sec)
    if code != 0:
        raise RuntimeError(err.strip() or out.strip() or f"clickhouse-client exited with {code}")
    return out


def _sql_string(value: str) -> str:
    return str(value).replace("\\", "\\\\").replace("'", "\\'")


def _table_exists(client: paramiko.SSHClient, table: str) -> bool:
    out = _clickhouse(client, f"EXISTS TABLE {table} FORMAT TabSeparated", timeout_sec=30.0)
    return str(out or "").strip().splitlines()[-1:] == ["1"]


def _table_columns(client: paramiko.SSHClient, table: str) -> set[str]:
    database, name = table.split(".", 1)
    query = (
        "SELECT name FROM system.columns "
        f"WHERE database = '{_sql_string(database)}' AND table = '{_sql_string(name)}' "
        "FORMAT TabSeparated"
    )
    return {line.strip() for line in _clickhouse(client, query, timeout_sec=30.0).splitlines() if line.strip()}


def _count(client: paramiko.SSHClient, table: str, where: str) -> int:
    out = _clickhouse(client, f"SELECT count() FROM {table} WHERE {where} FORMAT TabSeparated")
    line = str(out or "0").strip().splitlines()[-1:] or ["0"]
    return int(line[0] or "0")


def _delete(client: paramiko.SSHClient, table: str, where: str, *, mutations_sync: int) -> None:
    _clickhouse(
        client,
        f"ALTER TABLE {table} DELETE WHERE {where} SETTINGS mutations_sync = {int(mutations_sync)}",
        timeout_sec=600.0,
    )


def _parse_datetime(value: object) -> datetime | None:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _format_clickhouse_datetime(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _load_scope(report_paths: list[Path], explicit_run_ids: list[str], *, margin_minutes: int) -> CleanupScope:
    run_ids = {str(item).strip() for item in explicit_run_ids if str(item).strip()}
    started_values: list[datetime] = []
    finished_values: list[datetime] = []
    for path in report_paths:
        if not path.exists():
            raise FileNotFoundError(str(path))
        payload = json.loads(path.read_text(encoding="utf-8"))
        run_id = str(payload.get("run_id") or "").strip()
        if run_id:
            run_ids.add(run_id)
        started_at = _parse_datetime(payload.get("started_at_utc"))
        finished_at = _parse_datetime(payload.get("finished_at_utc"))
        if started_at:
            started_values.append(started_at)
        if finished_at:
            finished_values.append(finished_at)
    margin = timedelta(minutes=max(0, int(margin_minutes)))
    started = min(started_values) - margin if started_values else None
    finished = max(finished_values) + margin if finished_values else None
    return CleanupScope(run_ids=sorted(run_ids), started_at=started, finished_at=finished)


def _time_clause(columns: set[str], *, started_at: datetime | None, finished_at: datetime | None) -> str:
    if started_at is None or finished_at is None:
        return ""
    start = _sql_string(_format_clickhouse_datetime(started_at))
    finish = _sql_string(_format_clickhouse_datetime(finished_at))
    if "ts" in columns:
        return f"(ts >= toDateTime('{start}') AND ts <= toDateTime('{finish}'))"
    if "ts_last" in columns:
        return f"(ts_last >= toDateTime('{start}') AND ts_last <= toDateTime('{finish}'))"
    if "ts_first" in columns:
        return f"(ts_first >= toDateTime('{start}') AND ts_first <= toDateTime('{finish}'))"
    if "changed_ts" in columns:
        return f"(changed_ts >= toDateTime('{start}') AND changed_ts <= toDateTime('{finish}'))"
    if "updated_ts" in columns:
        return f"(updated_ts >= toDateTime('{start}') AND updated_ts <= toDateTime('{finish}'))"
    return ""


def _default_reports() -> list[Path]:
    if not DEFAULT_REPORT_DIR.exists():
        return []
    return sorted(DEFAULT_REPORT_DIR.glob("eps_ladder*.json"))


def _run_id_clause(columns: set[str], search_columns: tuple[str, ...], run_ids: list[str]) -> str:
    clauses: list[str] = []
    for run_id in run_ids:
        marker = _sql_string(run_id)
        for column in search_columns:
            if column in columns:
                clauses.append(f"position(toString({column}), '{marker}') > 0")
    return " OR ".join(clauses)


def _eps_bench_alert_clause(columns: set[str]) -> str:
    clauses: list[str] = []
    for column in ALERT_SEARCH_COLUMNS:
        if column in columns:
            clauses.append(f"positionCaseInsensitiveUTF8(toString({column}), 'eps-bench') > 0")
            clauses.append(f"positionCaseInsensitiveUTF8(toString({column}), 'allowlist:benchmark') > 0")
    return " OR ".join(clauses)


def _build_cleanup_where(
    columns: set[str],
    *,
    search_columns: tuple[str, ...],
    scope: CleanupScope,
    include_eps_bench_alerts: bool,
    table: str,
) -> tuple[str, bool, bool]:
    time_where = _time_clause(columns, started_at=scope.started_at, finished_at=scope.finished_at)
    run_id_where = _run_id_clause(columns, search_columns, scope.run_ids)
    where_parts: list[str] = []
    uses_time_scope = False
    uses_all_time_benchmark_alert_scope = False
    if run_id_where:
        where_parts.append(f"({time_where}) AND ({run_id_where})" if time_where else f"({run_id_where})")
        uses_time_scope = bool(time_where)
    if include_eps_bench_alerts and table in ALERT_TABLES:
        alert_where = _eps_bench_alert_clause(columns)
        if alert_where:
            where_parts.append(f"({alert_where})")
            uses_all_time_benchmark_alert_scope = True
    return " OR ".join(where_parts), uses_time_scope, uses_all_time_benchmark_alert_scope


def _collect_table_plan(
    client: paramiko.SSHClient,
    table: str,
    *,
    search_columns: tuple[str, ...],
    scope: CleanupScope,
    include_eps_bench_alerts: bool,
    execute: bool,
    mutations_sync: int,
) -> dict[str, Any]:
    item: dict[str, Any] = {"table": table, "exists": False, "matched_before": 0, "matched_after": 0, "deleted": False}
    if not _table_exists(client, table):
        item["note"] = "table does not exist"
        return item
    item["exists"] = True
    columns = _table_columns(client, table)
    where, uses_time_scope, uses_all_time_benchmark_alert_scope = _build_cleanup_where(
        columns,
        search_columns=search_columns,
        scope=scope,
        include_eps_bench_alerts=include_eps_bench_alerts,
        table=table,
    )
    if not where:
        item["note"] = "no compatible marker columns"
        return item
    if uses_time_scope:
        item["time_scope"] = {
            "started_at_utc": _format_clickhouse_datetime(scope.started_at),  # type: ignore[arg-type]
            "finished_at_utc": _format_clickhouse_datetime(scope.finished_at),  # type: ignore[arg-type]
        }
    if uses_all_time_benchmark_alert_scope:
        item["benchmark_alert_scope"] = "all_time"
    item["matched_before"] = _count(client, table, where)
    if execute and item["matched_before"]:
        _delete(client, table, where, mutations_sync=mutations_sync)
        item["deleted"] = True
        item["matched_after"] = _count(client, table, where)
    else:
        item["matched_after"] = item["matched_before"]
    return item


def cleanup(args: argparse.Namespace) -> dict[str, Any]:
    report_paths = [Path(item).expanduser() for item in args.report]
    if not report_paths and args.use_default_reports:
        report_paths = _default_reports()
    scope = _load_scope(report_paths, list(args.run_id or []), margin_minutes=int(args.time_margin_minutes))
    if not scope.run_ids:
        raise SystemExit("No run_id values found. Pass --run-id or --report.")

    host = HostSpec(host=str(args.vm3_host), user=str(args.user))
    key_path = str(Path(args.ssh_key).expanduser())
    client = _connect(host, key_path)
    try:
        tables: list[dict[str, Any]] = []
        for table in EVENT_TABLES:
            tables.append(
                _collect_table_plan(
                    client,
                    table,
                    search_columns=EVENT_SEARCH_COLUMNS,
                    scope=scope,
                    include_eps_bench_alerts=False,
                    execute=bool(args.execute),
                    mutations_sync=int(args.mutations_sync),
                )
            )
        if not args.skip_alerts:
            for table in ALERT_TABLES:
                tables.append(
                    _collect_table_plan(
                        client,
                        table,
                        search_columns=ALERT_SEARCH_COLUMNS,
                        scope=scope,
                        include_eps_bench_alerts=True,
                        execute=bool(args.execute),
                        mutations_sync=int(args.mutations_sync),
                    )
                )
    finally:
        client.close()

    return {
        "mode": "execute" if args.execute else "dry-run",
        "run_ids": scope.run_ids,
        "time_scope_utc": {
            "started_at": _format_clickhouse_datetime(scope.started_at) if scope.started_at else "",
            "finished_at": _format_clickhouse_datetime(scope.finished_at) if scope.finished_at else "",
        },
        "report_paths": [str(path) for path in report_paths],
        "tables": tables,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Count or delete EPS benchmark rows from ClickHouse.")
    parser.add_argument("--run-id", action="append", default=[], help="EPS ladder run_id to clean. May be repeated.")
    parser.add_argument("--report", action="append", default=[], help="EPS ladder JSON report to read run_id from. May be repeated.")
    parser.add_argument("--use-default-reports", action="store_true", help="Read all eps_ladder*.json reports from runtime-control-plane/eps-ladder-live.")
    parser.add_argument("--execute", action="store_true", help="Actually delete matched rows. Default is dry-run count only.")
    parser.add_argument("--skip-alerts", action="store_true", help="Do not include EPS benchmark alert rows.")
    parser.add_argument("--time-margin-minutes", type=int, default=120, help="Extra time around report start/finish timestamps.")
    parser.add_argument("--mutations-sync", type=int, choices=(0, 1, 2), default=1)
    parser.add_argument("--ssh-key", default=str(ROOT.parent / ".codex_tmp" / "vpnadmin_ed25519"))
    parser.add_argument("--user", default="rdegon")
    parser.add_argument("--vm3-host", default=DEFAULT_VM3)
    parser.add_argument("--output", default="", help="Optional JSON report path.")
    args = parser.parse_args(argv)

    result = cleanup(args)
    payload = json.dumps(result, ensure_ascii=False, indent=2)
    if str(args.output or "").strip():
        output = Path(args.output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(payload + "\n", encoding="utf-8")
    print(payload)
    return 0


if __name__ == "__main__":
    sys.exit(main())
