from __future__ import annotations

import argparse
import json
import os
import re
import sqlite3
from pathlib import Path
from typing import Iterable

from clickhouse_driver import Client


DEFAULT_MARKERS = (
    "SIEM-E2E-",
    "assignment-full-",
    "eps-bench-",
    "benchmark-run-",
    "synthetic-attack-",
)
TEST_HOST_MARKERS = ("assignment-full", "eps-bench", "benchmark-run", "e2e-source", "e2e-host")
TEST_TAG_MARKERS = ("benchmark", "synthetic", "e2e")
SAFE_VALUE_RE = re.compile(r"^[A-Za-z0-9_.:@/-]+$")


def _sql_string(value: str) -> str:
    return "'" + str(value).replace("\\", "\\\\").replace("'", "\\'") + "'"


def event_test_predicate(markers: Iterable[str], *, recent_days: int = 7) -> str:
    marker_checks = [
        f"positionCaseInsensitiveUTF8(toString(message), {_sql_string(marker)}) > 0"
        for marker in markers
    ]
    tag_checks = [
        f"positionCaseInsensitiveUTF8(toString(tags), {_sql_string(marker)}) > 0"
        for marker in TEST_TAG_MARKERS
    ]
    host_checks: list[str] = []
    for marker in TEST_HOST_MARKERS:
        escaped = _sql_string(f"%{marker}%")
        host_checks.extend(
            (
                f"lowerUTF8(toString(host_name)) LIKE {escaped}",
                f"lowerUTF8(toString(log_source)) LIKE {escaped}",
            )
        )
    return (
        f"(ts >= now() - INTERVAL {max(1, int(recent_days))} DAY AND ("
        + " OR ".join([*marker_checks, *tag_checks, *host_checks])
        + "))"
    )


def asset_test_predicate(markers: Iterable[str]) -> str:
    checks: list[str] = []
    fields = ("asset_id", "hostname", "tags", "notes")
    for marker in markers:
        for field in fields:
            checks.append(f"positionCaseInsensitiveUTF8(toString({field}), {_sql_string(marker)}) > 0")
    for marker in TEST_HOST_MARKERS:
        for field in ("asset_id", "hostname"):
            checks.append(f"positionCaseInsensitiveUTF8(toString({field}), {_sql_string(marker)}) > 0")
    return "(" + " OR ".join(checks) + ")"


def alert_test_predicate(
    markers: Iterable[str],
    *,
    rule_ids: list[int],
    entities: list[str],
    recent_hours: int,
    recent_days: int = 7,
    text_fields: tuple[str, ...] = ("rule_name", "entity_key", "source", "context_json"),
) -> str:
    haystack = "concat(" + ",' ',".join(f"toString({field})" for field in text_fields) + ")"
    checks = [
        f"positionCaseInsensitiveUTF8({haystack}, {_sql_string(marker)}) > 0"
        for marker in markers
    ]
    if rule_ids and entities:
        id_list = ",".join(str(int(item)) for item in sorted(set(rule_ids)))
        entity_list = ",".join(_sql_string(item) for item in sorted(set(entities)))
        checks.append(
            f"(rule_id IN ({id_list}) AND entity_key IN ({entity_list}) "
            f"AND ts_last >= now() - INTERVAL {max(1, int(recent_hours))} HOUR)"
        )
    return (
        f"(ts_last >= now() - INTERVAL {max(1, int(recent_days))} DAY AND ("
        + " OR ".join(checks)
        + "))"
    )


def _client() -> Client:
    return Client(
        host=os.getenv("SIEM_CH_HOST", "127.0.0.1"),
        port=int(os.getenv("SIEM_CH_PORT", "9000") or "9000"),
        user=os.getenv("SIEM_CH_USER", "siem_admin"),
        password=os.getenv("SIEM_CH_PASSWORD", ""),
        database=os.getenv("SIEM_CH_DB", "siem"),
        send_receive_timeout=int(os.getenv("SIEM_CH_SEND_RECEIVE_TIMEOUT_SECONDS", "300") or "300"),
    )


def _count(client: Client, table: str, predicate: str) -> int:
    rows = client.execute(
        f"SELECT count() FROM {table} WHERE {predicate} "
        "SETTINGS max_threads = 4, max_execution_time = 180"
    )
    return int(rows[0][0]) if rows else 0


def _delete(client: Client, table: str, predicate: str) -> None:
    client.execute(f"DELETE FROM {table} WHERE {predicate} SETTINGS lightweight_deletes_sync = 2")


def _clean_stream_state(path: str, pairs: list[tuple[int, str]], *, execute: bool) -> dict[str, int | str]:
    state_path = Path(path)
    result: dict[str, int | str] = {
        "path": str(state_path),
        "threshold_events": 0,
        "last_alert": 0,
    }
    if not state_path.exists() or not pairs:
        return result
    connection = sqlite3.connect(str(state_path), timeout=30)
    try:
        for table in ("threshold_events", "last_alert"):
            count = 0
            for rule_id, entity_key in pairs:
                row = connection.execute(
                    f"SELECT count(*) FROM {table} WHERE rule_id = ? AND entity_key = ?",
                    (int(rule_id), str(entity_key)),
                ).fetchone()
                count += int((row or [0])[0] or 0)
                if execute:
                    connection.execute(
                        f"DELETE FROM {table} WHERE rule_id = ? AND entity_key = ?",
                        (int(rule_id), str(entity_key)),
                    )
            result[table] = count
        if execute:
            connection.commit()
    finally:
        connection.close()
    return result


def _parse_pair(value: str) -> tuple[int, str]:
    raw_rule_id, separator, entity_key = str(value).partition(":")
    if not separator or not raw_rule_id.isdigit() or not entity_key or not SAFE_VALUE_RE.fullmatch(entity_key):
        raise argparse.ArgumentTypeError("state pair must be RULE_ID:ENTITY_KEY using safe characters")
    return int(raw_rule_id), entity_key


def main() -> int:
    parser = argparse.ArgumentParser(description="Remove explicitly marked SIEM test artifacts.")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--marker", action="append", default=[])
    parser.add_argument("--alert-rule-id", type=int, action="append", default=[])
    parser.add_argument("--alert-entity", action="append", default=[])
    parser.add_argument("--alert-recent-hours", type=int, default=2)
    parser.add_argument("--recent-days", type=int, default=7)
    parser.add_argument("--stream-state-pair", type=_parse_pair, action="append", default=[])
    parser.add_argument(
        "--stream-state-path",
        default=os.getenv("SIEM_STREAM_STATE_SQLITE_PATH", "/var/lib/siem-stream-corr/runtime-state.db"),
    )
    args = parser.parse_args()
    markers = [*DEFAULT_MARKERS, *[str(item) for item in args.marker if str(item).strip()]]
    event_predicate = event_test_predicate(markers, recent_days=int(args.recent_days))
    raw_alert_predicate = alert_test_predicate(
        markers,
        rule_ids=list(args.alert_rule_id),
        entities=list(args.alert_entity),
        recent_hours=int(args.alert_recent_hours),
        recent_days=int(args.recent_days),
    )
    aggregate_alert_predicate = alert_test_predicate(
        markers,
        rule_ids=list(args.alert_rule_id),
        entities=list(args.alert_entity),
        recent_hours=int(args.alert_recent_hours),
        recent_days=int(args.recent_days),
        text_fields=("rule_name", "entity_key", "group_key_json", "samples_json"),
    )
    asset_predicate = asset_test_predicate(markers)
    client = _client()
    try:
        tables = {
            "siem.events": event_predicate,
            "siem.events_cold": event_predicate,
            "siem.alerts_raw": raw_alert_predicate,
            "siem.alerts_agg": aggregate_alert_predicate,
            "siem.cmdb_assets": asset_predicate,
        }
        before = {table: _count(client, table, predicate) for table, predicate in tables.items()}
        alert_ids: list[str] = []
        alert_id_columns = {
            "siem.alerts_raw": ("alert_id", raw_alert_predicate),
            "siem.alerts_agg": ("agg_id", aggregate_alert_predicate),
        }
        for table, (id_column, predicate) in alert_id_columns.items():
            alert_ids.extend(
                str(row[0])
                for row in client.execute(f"SELECT toString({id_column}) FROM {table} WHERE {predicate}")
            )
        history_predicate = "0"
        if alert_ids:
            history_predicate = "record_id IN (" + ",".join(_sql_string(item) for item in sorted(set(alert_ids))) + ")"
        before["siem.alert_history"] = _count(client, "siem.alert_history", history_predicate)
        state = _clean_stream_state(
            str(args.stream_state_path),
            list(args.stream_state_pair),
            execute=bool(args.execute),
        )
        if args.execute:
            if alert_ids:
                _delete(client, "siem.alert_history", history_predicate)
            for table, predicate in tables.items():
                if before[table]:
                    _delete(client, table, predicate)
        if args.execute:
            after = {table: _count(client, table, predicate) for table, predicate in tables.items()}
            after["siem.alert_history"] = _count(client, "siem.alert_history", history_predicate)
        else:
            after = dict(before)
    finally:
        client.disconnect()
    print(
        json.dumps(
            {
                "mode": "execute" if args.execute else "dry-run",
                "markers": markers,
                "before": before,
                "after": after,
                "stream_state": state,
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
