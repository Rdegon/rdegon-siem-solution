from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
APP_ROOT = ROOT / "services" / "web"
for candidate in (str(APP_ROOT), str(ROOT)):
    while candidate in sys.path:
        sys.path.remove(candidate)
for candidate in (str(APP_ROOT), str(ROOT)):
    sys.path.insert(0, candidate)

try:
    from app import deps  # type: ignore[import-not-found]  # noqa: E402
except ImportError:  # pragma: no cover - compatibility with flat local checkouts
    import deps  # type: ignore[import-not-found,no-redef]  # noqa: E402

try:  # pragma: no cover - production web venv uses clickhouse_connect only.
    import clickhouse_driver  # noqa: F401
except ModuleNotFoundError:  # pragma: no cover
    import types

    clickhouse_driver_stub = types.ModuleType("clickhouse_driver")
    clickhouse_driver_stub.Client = object  # type: ignore[attr-defined]
    sys.modules["clickhouse_driver"] = clickhouse_driver_stub

from services.filter.filter_core import parse_expr


JSON_STRING_FIELDS = {"auth.logon_type", "host.role", "repository.name", "rule.id", "source.family"}


def _quote(value: str) -> str:
    return "'" + str(value).replace("\\", "\\\\").replace("'", "\\'") + "'"


def _field_sql(field: str) -> str:
    mapping = {
        "event.provider": "device_product",
        "event.category": "category",
        "event.type": "subcategory",
        "event.code": "event_code",
        "event.action": "event_action",
        "event.outcome": "event_outcome",
        "severity": "severity",
        "tags": "tags",
        "log_source": "log_source",
        "host.name": "host_name",
        "user.name": "user_name",
        "user.target.name": "target_user",
        "process.name": "process_name",
        "process.executable": "process_executable",
        "process.command_line": "process_command",
        "source.ip": "if(src_ip = 0, '', IPv4NumToString(src_ip))",
        "destination.ip": "if(dst_ip = 0, '', IPv4NumToString(dst_ip))",
        "event.original": "message",
        "message": "message",
    }
    return mapping.get(field, "normalized_json")


def _entity_sql(field: str) -> str:
    return "log_source" if field in JSON_STRING_FIELDS else _field_sql(field)


def _json_field_equals_sql(field: str, value: str, *, negated: bool = False) -> str:
    compact = f'"{field}":"{value}"'
    spaced = f'"{field}": "{value}"'
    predicate = f"(position(normalized_json, {_quote(compact)}) > 0 OR position(normalized_json, {_quote(spaced)}) > 0)"
    return f"NOT {predicate}" if negated else predicate


def _node_sql(node: Any) -> str:
    kind = node[0]
    if kind == "cmp":
        field, op, value = node[1], node[2], str(node[3])
        if field in JSON_STRING_FIELDS:
            if op == "==":
                return _json_field_equals_sql(field, value)
            if op == "!=":
                return _json_field_equals_sql(field, value, negated=True)
            if op in {"contains", "icontains"}:
                fn = "position" if op == "contains" else "positionCaseInsensitive"
                return f"{fn}(normalized_json, {_quote(value)}) > 0"
            if op in {"startswith", "endswith"}:
                return _json_field_equals_sql(field, value)
        sql_field = _field_sql(field)
        if op == "==":
            return f"{sql_field} = {_quote(value)}"
        if op == "!=":
            return f"{sql_field} != {_quote(value)}"
        if op == "contains":
            return f"position({sql_field}, {_quote(value)}) > 0"
        if op == "icontains":
            return f"positionCaseInsensitive({sql_field}, {_quote(value)}) > 0"
        if op == "startswith":
            return f"startsWith({sql_field}, {_quote(value)})"
        if op == "endswith":
            return f"endsWith({sql_field}, {_quote(value)})"
        raise ValueError(f"Unsupported op: {op}")
    if kind == "and":
        return f"({_node_sql(node[1])}) AND ({_node_sql(node[2])})"
    if kind == "or":
        return f"({_node_sql(node[1])}) OR ({_node_sql(node[2])})"
    if kind == "not":
        return f"NOT ({_node_sql(node[1])})"
    raise ValueError(f"Unsupported AST node: {kind}")


def _scalar(client: Any, query: str) -> int:
    result = client.query(query)
    return int((result.result_rows[0][0] if result.result_rows else 0) or 0)


def _counts(client: Any, where_sql: str, entity_field: str, hours: int) -> tuple[int, int]:
    entity = _entity_sql(entity_field)
    result = client.query(
        f"""
        SELECT count(), uniqExact({entity})
        FROM siem.events
        WHERE ts >= now() - INTERVAL {int(hours)} HOUR
          AND ({where_sql})
        """
    )
    row = result.result_rows[0] if result.result_rows else (0, 0)
    return int(row[0] or 0), int(row[1] or 0)


def _counts_seconds(client: Any, where_sql: str, entity_field: str, seconds: int) -> tuple[int, int]:
    entity = _entity_sql(entity_field)
    result = client.query(
        f"""
        SELECT count(), uniqExact({entity})
        FROM siem.events
        WHERE ts >= now() - INTERVAL {max(60, int(seconds))} SECOND
          AND ({where_sql})
        """
    )
    row = result.result_rows[0] if result.result_rows else (0, 0)
    return int(row[0] or 0), int(row[1] or 0)


def _batch_sql_ok(client: Any, sql_template: str, window_s: int) -> str:
    sql = sql_template.replace("{WINDOW_S}", str(int(window_s)))
    try:
        client.command("EXPLAIN SYNTAX " + sql)
    except Exception as exc:  # noqa: BLE001
        return f"{type(exc).__name__}: {exc}"
    return ""


def _risk(rule: dict[str, Any], hits_window: int, hits_24h: int) -> str:
    threshold = int(rule.get("threshold") or 1)
    if hits_window >= threshold:
        return "would_alert_now"
    if int(rule.get("window_s") or 300) >= 86400 and hits_24h >= max(threshold * 3, 10):
        return "live_baseline_noise"
    if hits_24h > 0:
        return "live_matches_below_threshold"
    return "no_live_matches"


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit generated assignment detection pack against live ClickHouse events.")
    parser.add_argument("--pack-path", default="correlation_rule_packs/siem_detection_pack_v1.json")
    parser.add_argument("--report-path", default="")
    parser.add_argument("--top", type=int, default=30)
    args = parser.parse_args()

    pack = json.loads(Path(args.pack_path).read_text(encoding="utf-8"))
    client = deps.get_ch_client()

    stream_items: list[dict[str, Any]] = []
    for rule in pack.get("stream_rules", []):
        expr = str(rule.get("expr") or "")
        item = {
            "id": rule.get("id"),
            "source_id": rule.get("source_id"),
            "title": rule.get("title"),
            "severity": rule.get("severity"),
            "threshold": rule.get("threshold"),
            "window_s": rule.get("window_s"),
        }
        try:
            where_sql = _node_sql(parse_expr(expr))
            entity_field = str(rule.get("entity_field") or "host.name")
            window_s = int(rule.get("window_s") or 300)
            hits_window, entities_window = _counts_seconds(client, where_sql, entity_field, window_s)
            hits_1h, entities_1h = _counts(client, where_sql, entity_field, 1)
            hits_24h, entities_24h = _counts(client, where_sql, str(rule.get("entity_field") or "host.name"), 24)
            item.update(
                {
                    "hits_window": hits_window,
                    "entities_window": entities_window,
                    "hits_1h": hits_1h,
                    "entities_1h": entities_1h,
                    "hits_24h": hits_24h,
                    "entities_24h": entities_24h,
                    "risk": _risk(rule, hits_window, hits_24h),
                }
            )
        except Exception as exc:  # noqa: BLE001
            item.update({"risk": "query_error", "error": f"{type(exc).__name__}: {exc}"})
        stream_items.append(item)

    batch_items: list[dict[str, Any]] = []
    for rule in pack.get("batch_rules", []):
        error = _batch_sql_ok(client, str(rule.get("sql_template") or ""), int(rule.get("window_s") or 300))
        batch_items.append(
            {
                "id": rule.get("id"),
                "source_id": rule.get("source_id"),
                "status": rule.get("status"),
                "severity": rule.get("severity"),
                "sql_ok": not error,
                "error": error,
            }
        )

    stream_summary: dict[str, int] = {}
    for item in stream_items:
        stream_summary[str(item["risk"])] = stream_summary.get(str(item["risk"]), 0) + 1
    batch_summary = {
        "sql_ok": sum(1 for item in batch_items if item["sql_ok"]),
        "sql_error": sum(1 for item in batch_items if not item["sql_ok"]),
    }
    noisy = sorted(
        [item for item in stream_items if item.get("hits_24h", 0) > 0],
        key=lambda item: (int(item.get("hits_1h") or 0), int(item.get("hits_24h") or 0)),
        reverse=True,
    )[: max(0, args.top)]
    report = {
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "pack_path": str(args.pack_path),
        "stream_rules": len(stream_items),
        "batch_rules": len(batch_items),
        "stream_summary": dict(sorted(stream_summary.items())),
        "batch_summary": batch_summary,
        "top_live_matches": noisy,
        "batch_errors": [item for item in batch_items if not item["sql_ok"]][: max(0, args.top)],
    }
    if args.report_path:
        path = Path(args.report_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 1 if batch_summary["sql_error"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
