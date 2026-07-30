from __future__ import annotations

import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEPLOY_ROOT = Path(__file__).resolve().parent
for candidate in (str(DEPLOY_ROOT), str(ROOT)):
    if candidate not in sys.path:
        sys.path.insert(0, candidate)

from deploy.runtime_imports import import_app_module  # noqa: E402
from env_file_runtime import maybe_load_runtime_env  # noqa: E402

maybe_load_runtime_env()

deps = import_app_module("deps")
ecp = import_app_module("enterprise_control_plane")
operational_filters = import_app_module("operational_filters")

NON_OPERATIONAL_MARKERS = operational_filters.NON_OPERATIONAL_MARKERS
is_non_operational_record = operational_filters.is_non_operational_record


MARKERS = NON_OPERATIONAL_MARKERS
CONTROL_PLANE_COLLECTIONS = (
    "connector_definitions",
    "connector_runs",
    "response_actions",
    "response_executions",
    "response_dlq",
    "local_users",
    "service_accounts",
    "service_account_tokens",
    "saved_searches",
    "cases",
    "entities",
    "risk_signals",
)


def _matches(value: object) -> bool:
    return is_non_operational_record(value)


def _cleanup_control_plane() -> dict[str, int]:
    removed: dict[str, int] = {}
    for collection_name in CONTROL_PLANE_COLLECTIONS:
        rows = list(ecp._collection(collection_name, lambda: []))  # type: ignore[attr-defined]
        kept = [row for row in rows if not _matches(row)]
        removed[collection_name] = len(rows) - len(kept)
        if len(kept) != len(rows):
            ecp._save_collection(collection_name, kept)  # type: ignore[attr-defined]
    return removed


def _cleanup_builder_drafts() -> int:
    removed = 0
    for item in deps.list_builder_drafts():
        if _matches(item):
            deps.delete_builder_draft(str(item.get("id") or ""))
            removed += 1
    return removed


def _table_columns(client, table_name: str) -> set[str]:
    database, table = table_name.split(".", 1)
    rows = client.query(
        "SELECT name FROM system.columns WHERE database = %(database)s AND table = %(table)s",
        parameters={"database": database, "table": table},
    ).result_rows
    return {str(row[0]) for row in rows}


def _clickhouse_quote(value: object) -> str:
    return "'" + str(value).replace("\\", "\\\\").replace("'", "\\'") + "'"


def _build_marker_delete_clause(columns: set[str], field_names: tuple[str, ...]) -> str:
    haystack_fields = [f"toString({field_name})" for field_name in field_names if field_name in columns]
    if not haystack_fields:
        return ""
    haystack = "concat(" + ", ' ', ".join(haystack_fields) + ")"
    clauses: list[str] = []
    for marker in MARKERS:
        clauses.append(f"positionCaseInsensitiveUTF8({haystack}, {_clickhouse_quote(marker)}) > 0")
    return " OR ".join(clauses)


def _cleanup_lookback_days() -> int:
    try:
        value = int(str(os.getenv("SIEM_SYSTEM_CLEANUP_LOOKBACK_DAYS", "3") or "3"))
    except ValueError:
        value = 3
    return max(1, min(31, value))


def _has_pending_mutation(client, table_name: str) -> bool:
    database, table = table_name.split(".", 1)
    try:
        result = client.query(
            """
            SELECT count()
            FROM system.mutations
            WHERE database = %(database)s
              AND table = %(table)s
              AND is_done = 0
            """,
            parameters={"database": database, "table": table},
        ).result_rows
    except Exception as exc:  # noqa: BLE001
        message = str(exc)
        if "ACCESS_DENIED" in message or "Not enough privileges" in message:
            return False
        raise
    return bool(result and int(result[0][0] or 0) > 0)


def _cleanup_clickhouse_table(
    client,
    table: str,
    field_names: tuple[str, ...],
    *,
    time_column: str = "",
) -> str:
    columns = _table_columns(client, table)
    if not columns:
        return "missing-or-empty-schema"
    if _has_pending_mutation(client, table):
        return "deferred: pending mutation"
    marker_clause = _build_marker_delete_clause(columns, field_names)
    if not marker_clause:
        return "no-compatible-columns"
    delete_clause = f"({marker_clause})"
    if time_column and time_column in columns:
        delete_clause = (
            f"{time_column} >= now() - toIntervalDay({_cleanup_lookback_days()}) "
            f"AND {delete_clause}"
        )
    client.command(f"ALTER TABLE {table} DELETE WHERE {delete_clause} SETTINGS mutations_sync = 0")
    return "bounded schema-aware marker cleanup" if time_column else "schema-aware marker cleanup"


def _cleanup_clickhouse() -> dict[str, str]:
    client = deps.get_ch_client()
    results: dict[str, str] = {}
    event_fields = (
        "message",
        "normalized_json",
        "log_source",
        "host_name",
        "device_product",
        "device_vendor",
        "tags",
        "event_code",
        "event_dataset",
        "collector_profile",
        "observer_collector",
        "asset_id",
        "asset_service",
        "process_command",
        "user_name",
        "target_user",
    )
    for table in ("siem.events", "siem.events_cold", "siem.events_shadow"):
        results[table] = _cleanup_clickhouse_table(client, table, event_fields, time_column="ts")
    alert_fields = (
        "source",
        "context_json",
        "group_key_json",
        "samples_json",
        "rule_name",
        "entity_key",
        "assignee",
        "status",
    )
    for table in ("siem.alerts_raw", "siem.alerts_agg"):
        results[table] = _cleanup_clickhouse_table(client, table, alert_fields, time_column="ts_last")
    results[deps.ALERT_HISTORY_TABLE] = _cleanup_clickhouse_table(
        client,
        deps.ALERT_HISTORY_TABLE,
        ("record_id", "changed_by", "next_assignee", "note", "details_json"),
        time_column="changed_ts",
    )
    for table in ("siem.cmdb_assets", "siem.threat_intel_iocs", "siem.active_list_items"):
        results[table] = _cleanup_clickhouse_table(
            client,
            table,
            ("asset_id", "hostname", "ip", "business_service", "notes", "indicator", "provider", "description", "list_name", "value", "label", "tags"),
        )
    for table in ("siem.detection_rule_catalog", "siem.correlation_rules_stream", "siem.correlation_rules_batch"):
        results[table] = _cleanup_clickhouse_table(
            client,
            table,
            ("title", "name", "sigma_id", "tags", "description", "author"),
        )
    return results


def main() -> int:
    control_plane_removed = _cleanup_control_plane()
    builder_drafts_removed = _cleanup_builder_drafts()
    clickhouse_cleanup = _cleanup_clickhouse()
    print(
        json.dumps(
            {
                "control_plane_removed": control_plane_removed,
                "builder_drafts_removed": builder_drafts_removed,
                "clickhouse_cleanup": clickhouse_cleanup,
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
