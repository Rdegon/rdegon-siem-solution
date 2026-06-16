from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from deploy.runtime_imports import import_app_module  # noqa: E402

deps = import_app_module("deps")


PACK_PATH = ROOT / "correlation_rule_packs" / "siem_detection_pack_v1.json"
PACK_AUTHOR = "assignment-pack:siem-detection-pack-v1"
TERMINAL_ALERT_STATUSES = ("closed", "false_positive", "resolved", "suppressed")


def _dedupe_tags(tags: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for tag in tags:
        cleaned = str(tag).strip()
        if not cleaned or cleaned in seen:
            continue
        seen.add(cleaned)
        result.append(cleaned)
    return result


def _placeholder_row(item: dict[str, Any], *, pack_id: str) -> dict[str, Any]:
    source_id = str(item.get("source_id") or "")
    description = str(item.get("description") or item.get("detection_logic") or "")
    asset_groups = [str(group) for group in list(item.get("asset_groups") or []) if str(group)]
    active_catalog_statuses = {"active", "active_batch", "active_correlation", "active_telemetry"}
    is_active_catalog = str(item.get("status") or "").lower() in active_catalog_statuses
    tags = ",".join(
        [
            "assignment.siem_detection_pack_v1",
            f"assignment.source_id.{source_id.lower()}",
            f"assignment.status.{str(item.get('status') or 'planned').lower()}",
            "source.batch_sql" if str(item.get("sql_template") or "").strip() else "source.catalog",
            *[f"asset_group.{group}" for group in asset_groups],
        ]
    )
    return {
        "id": int(item["id"]),
        "title": str(item.get("title") or f"Assignment rule {source_id}"),
        "sigma_id": f"assignment-{source_id.lower()}",
        "status": str(item.get("status") or "planned"),
        "level": str(item.get("severity") or "medium").lower(),
        "source_format": "assignment-pack",
        "logsource_product": "",
        "logsource_service": "",
        "logsource_category": "",
        "sigma_yaml": "",
        "expr": "",
        "entity_field": "host.name",
        "window_s": max(60, int(item.get("window_s") or 300)),
        "threshold": max(1, int(item.get("threshold") or 1)),
        "verification_query": "",
        "tags": tags,
        "description": description,
        "enabled": 1 if is_active_catalog else 0,
        "author": f"{PACK_AUTHOR}:{pack_id}",
    }


def _ensure_batch_rule_table() -> None:
    deps.get_ch_client().command(
        """
        CREATE TABLE IF NOT EXISTS siem.correlation_rules_batch
        (
            id UInt32,
            name String,
            description String,
            enabled UInt8,
            severity LowCardinality(String),
            window_s UInt32,
            sql_template String,
            created_ts DateTime DEFAULT now(),
            updated_ts DateTime DEFAULT now()
        )
        ENGINE = MergeTree
        ORDER BY id
        """
    )


def _publish_batch_rule(item: dict[str, Any]) -> tuple[Any, ...]:
    return (
        int(item["id"]),
        str(item.get("title") or f"Assignment rule {item.get('source_id') or item.get('id')}"),
        str(item.get("description") or item.get("operator_action") or item.get("detection_logic") or ""),
        1,
        str(item.get("severity") or "medium").lower(),
        max(60, int(item.get("window_s") or 300)),
        str(item.get("sql_template") or ""),
    )


def _direct_stream_rule(item: dict[str, Any], *, pack_id: str) -> dict[str, Any]:
    source_id = str(item.get("source_id") or "")
    expr = str(item.get("expr") or "").strip()
    asset_groups = [str(group) for group in list(item.get("asset_groups") or []) if str(group)]
    tags = ",".join(
        [
            "assignment.siem_detection_pack_v1",
            f"assignment.source_id.{source_id.lower()}",
            "source.stream_expr",
            *[f"asset_group.{group}" for group in asset_groups],
        ]
    )
    return {
        "id": int(item["id"]),
        "title": str(item.get("title") or f"Assignment rule {source_id}"),
        "sigma_id": f"assignment-{source_id.lower()}",
        "status": str(item.get("status") or "active"),
        "level": str(item.get("severity") or "medium").lower(),
        "source_format": "stream-expr",
        "logsource_product": "",
        "logsource_service": "",
        "logsource_category": "",
        "sigma_yaml": "",
        "expr": expr,
        "entity_field": str(item.get("entity_field") or "host.name"),
        "window_s": max(60, int(item.get("window_s") or 300)),
        "threshold": max(1, int(item.get("threshold") or 1)),
        "verification_query": "",
        "tags": tags,
        "description": str(item.get("description") or item.get("operator_action") or ""),
        "enabled": 1,
        "author": f"{PACK_AUTHOR}:{pack_id}",
    }


def _publish_stream_rule(item: dict[str, Any], *, pack_id: str) -> dict[str, Any]:
    sigma_yaml = str(item.get("sigma_yaml") or "").strip()
    if not sigma_yaml:
        return _direct_stream_rule(item, pack_id=pack_id)
    rule = deps.convert_sigma_to_stream_rule(
        sigma_yaml,
        threshold=max(1, int(item.get("threshold") or 1)),
        window_s=max(60, int(item.get("window_s") or 300)),
        entity_field=str(item.get("entity_field") or "host.name"),
        rule_id=int(item["id"]),
    )
    rule["author"] = f"{PACK_AUTHOR}:{pack_id}"
    rule["description"] = str(item.get("description") or item.get("operator_action") or rule.get("description") or "")
    rule["level"] = str(item.get("severity") or rule.get("level") or "medium").lower()
    asset_group_tags = [f"asset_group.{group}" for group in list(item.get("asset_groups") or []) if str(group)]
    existing_tags = [tag for tag in str(rule.get("tags") or "").split(",") if tag]
    rule["tags"] = ",".join(_dedupe_tags([*existing_tags, *asset_group_tags]))
    rule["enabled"] = 1
    return rule


def _stream_runtime_row(rule: dict[str, Any]) -> tuple[Any, ...]:
    return (
        int(rule["id"]),
        str(rule.get("title") or f"Assignment rule {rule['id']}"),
        str(rule.get("description") or f"Assignment stream rule for {rule.get('title') or rule['id']}"),
        1,
        str(rule.get("level") or "medium").lower(),
        "threshold",
        max(60, int(rule.get("window_s") or 300)),
        max(1, int(rule.get("threshold") or 1)),
        str(rule.get("expr") or ""),
        str(rule.get("entity_field") or "host.name"),
    )


def _mark_retired_assignment_alerts(retired_ids: set[int]) -> dict[str, int]:
    if not retired_ids:
        return {}
    id_list = ",".join(str(rule_id) for rule_id in sorted(retired_ids))
    terminal = ",".join(f"'{status}'" for status in TERMINAL_ALERT_STATUSES)
    results: dict[str, int] = {}
    deps.ensure_incident_workflow_support()
    for table_name in ("siem.alerts_raw", "siem.alerts_agg"):
        count_query = (
            f"SELECT count() FROM {table_name} "
            f"WHERE rule_id IN ({id_list}) AND lower(status) NOT IN ({terminal})"
        )
        try:
            result = deps.get_ch_client().query(count_query).result_rows
            results[table_name] = int(result[0][0]) if result and result[0] else 0
            deps.get_ch_client().command(
                f"""
                ALTER TABLE {table_name}
                UPDATE
                    status = 'false_positive',
                    assignee = 'system-fp-remediation',
                    updated_ts = now()
                WHERE rule_id IN ({id_list})
                  AND lower(status) NOT IN ({terminal})
                """
            )
        except Exception as exc:  # noqa: BLE001
            results[f"{table_name}:error"] = 1
            print(f"warning: failed to retire assignment alerts in {table_name}: {exc}", file=sys.stderr)
    return results


def main() -> int:
    payload = json.loads(PACK_PATH.read_text(encoding="utf-8"))
    pack_id = str(payload.get("pack_id") or "siem-detection-pack-v1")
    stream_rules = [item for item in payload.get("stream_rules") or [] if isinstance(item, dict)]
    batch_rules = [item for item in payload.get("batch_rules") or [] if isinstance(item, dict)]
    all_ids = [int(item["id"]) for item in [*stream_rules, *batch_rules]]
    if not all_ids:
        raise SystemExit("Pack contains no rules")

    deps.ensure_detection_support_tables()
    _ensure_batch_rule_table()
    min_id = min(all_ids)
    max_id = max(all_ids)
    deps.get_ch_client().command(
        f"ALTER TABLE {deps.DETECTION_RULE_TABLE} DELETE WHERE id BETWEEN {min_id} AND {max_id} "
        "SETTINGS mutations_sync=1"
    )
    deps.get_ch_client().command(
        f"ALTER TABLE siem.correlation_rules_stream DELETE WHERE id BETWEEN {min_id} AND {max_id} "
        "SETTINGS mutations_sync=1"
    )
    deps.get_ch_client().command(
        f"ALTER TABLE siem.correlation_rules_batch DELETE WHERE id BETWEEN {min_id} AND {max_id} "
        "SETTINGS mutations_sync=1"
    )

    converted_stream = [
        _publish_stream_rule(item, pack_id=pack_id)
        for item in stream_rules
        if str(item.get("status") or "").lower() in {"active", "publish_ready_after_host_metrics"}
    ]
    converted_batch = [
        _publish_batch_rule(item)
        for item in batch_rules
        if str(item.get("status") or "").lower() in {"active_batch", "active_correlation", "active_telemetry"}
        and str(item.get("sql_template") or "").strip()
    ]
    placeholders = [_placeholder_row(item, pack_id=pack_id) for item in batch_rules]
    active_stream_ids = {int(rule["id"]) for rule in converted_stream}
    active_batch_ids = {int(rule[0]) for rule in converted_batch}
    active_runtime_ids = active_stream_ids | active_batch_ids
    retired_ids = {rule_id for rule_id in all_ids if rule_id not in active_runtime_ids}

    if converted_stream:
        deps._insert_detection_rule_rows(converted_stream, sync_stream=False)  # type: ignore[attr-defined]
        deps.get_ch_client().insert(
            "siem.correlation_rules_stream",
            [_stream_runtime_row(rule) for rule in converted_stream],
            column_names=[
                "id",
                "name",
                "description",
                "enabled",
                "severity",
                "pattern",
                "window_s",
                "threshold",
                "expr",
                "entity_field",
            ],
        )
    if converted_batch:
        deps.get_ch_client().insert(
            "siem.correlation_rules_batch",
            converted_batch,
            column_names=["id", "name", "description", "enabled", "severity", "window_s", "sql_template"],
        )
    if placeholders:
        deps._insert_detection_rule_rows(placeholders, sync_stream=False)  # type: ignore[attr-defined]
    retired_alerts = _mark_retired_assignment_alerts(retired_ids)

    print(
        json.dumps(
            {
                "pack_id": pack_id,
                "catalog_rules": len(converted_stream) + len(placeholders),
                "published_stream_rules": len(converted_stream),
                "published_batch_rules": len(converted_batch),
                "placeholder_rules": len(placeholders),
                "retired_runtime_rule_ids": len(retired_ids),
                "retired_open_alerts": retired_alerts,
                "min_id": min(all_ids),
                "max_id": max(all_ids),
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
