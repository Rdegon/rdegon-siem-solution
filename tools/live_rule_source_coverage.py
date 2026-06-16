from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from clickhouse_driver import Client

from services.stream_corr.config import StreamCorrSettings
from services.stream_corr.rules import StreamCorrRule, load_stream_rules


def _quote(value: str) -> str:
    return "'" + str(value).replace("\\", "\\\\").replace("'", "\\'") + "'"


JSON_STRING_FIELDS = {"auth.logon_type", "host.role", "repository.name", "rule.id", "source.family"}


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
    if field in JSON_STRING_FIELDS:
        return "log_source"
    return _field_sql(field)


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
            if op == "startswith":
                return _json_field_equals_sql(field, value)
            if op == "endswith":
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


def _collect_cmp_values(node: Any, field: str) -> list[str]:
    kind = node[0]
    if kind == "cmp":
        return [str(node[3])] if node[1] == field and node[2] == "==" else []
    if kind in {"and", "or"}:
        return _collect_cmp_values(node[1], field) + _collect_cmp_values(node[2], field)
    if kind == "not":
        return []
    return []


def _client(settings: StreamCorrSettings) -> Client:
    return Client(
        host=settings.ch_host,
        port=settings.ch_port,
        user=settings.ch_user,
        password=settings.ch_password,
        database=settings.ch_db,
        send_receive_timeout=max(settings.ch_timeout_secs, 60),
    )


def _scalar(client: Client, query: str) -> int:
    try:
        row = client.execute(query)
        return int((row[0] if row else [0])[0] or 0)
    except Exception:
        return -1


def _rule_counts(client: Client, rule: StreamCorrRule, where_sql: str, hours: int) -> tuple[int, int]:
    entity = _entity_sql(rule.entity_field)
    query = f"""
        SELECT count(), uniqExact({entity})
        FROM siem.events
        WHERE ts >= now() - INTERVAL {int(hours)} HOUR
          AND ({where_sql})
    """
    try:
        row = client.execute(query)[0]
        return int(row[0] or 0), int(row[1] or 0)
    except Exception:
        return -1, -1


def _alert_count(client: Client, rule_id: int, hours: int) -> int:
    return _scalar(
        client,
        f"""
        SELECT count()
        FROM siem.alerts_raw
        WHERE ts >= now() - INTERVAL {int(hours)} HOUR
          AND rule_id = {int(rule_id)}
          AND position(context_json, 'e2e-rule-validation') = 0
          AND position(source, 'e2e-') = 0
        """,
    )


def _provider_count(client: Client, providers: list[str], hours: int) -> int:
    if not providers:
        return -1
    values = ", ".join(_quote(item) for item in sorted(set(providers)))
    return _scalar(
        client,
        f"""
        SELECT count()
        FROM siem.events
        WHERE ts >= now() - INTERVAL {int(hours)} HOUR
          AND device_product IN ({values})
        """,
    )


def _provider_type_count(client: Client, providers: list[str], types: list[str], codes: list[str], hours: int) -> int:
    clauses: list[str] = []
    if providers:
        clauses.append("device_product IN (" + ", ".join(_quote(item) for item in sorted(set(providers))) + ")")
    if types:
        clauses.append("subcategory IN (" + ", ".join(_quote(item) for item in sorted(set(types))) + ")")
    if codes:
        clauses.append("event_code IN (" + ", ".join(_quote(item) for item in sorted(set(codes))) + ")")
    if not clauses:
        return -1
    return _scalar(
        client,
        f"""
        SELECT count()
        FROM siem.events
        WHERE ts >= now() - INTERVAL {int(hours)} HOUR
          AND {' AND '.join(clauses)}
        """,
    )


def _reason(item: dict[str, Any]) -> str:
    if item["rule_hits_7d"] < 0:
        return "coverage_query_error"
    if item["rule_hits_7d"] == 0:
        if item["provider_events_7d"] == 0:
            return "no_provider_events_7d"
        if item["provider_type_code_events_7d"] == 0:
            return "no_required_type_or_code_7d"
        return "no_events_matching_full_rule_7d"
    if item["entity_hits_7d"] == 0:
        return "entity_field_empty_on_matches"
    if item["alerts_7d"] == 0:
        return "matches_exist_in_event_store_but_no_real_alert_7d"
    return "has_real_alerts_7d"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--report-path", default="")
    args = parser.parse_args()

    settings = StreamCorrSettings.load()
    client = _client(settings)
    rules = load_stream_rules(settings)
    items: list[dict[str, Any]] = []
    for rule in rules:
        if rule.expr_ast is None:
            items.append({"id": rule.id, "name": rule.name, "reason": "expr_parse_failed"})
            continue
        where_sql = _node_sql(rule.expr_ast)
        providers = _collect_cmp_values(rule.expr_ast, "event.provider")
        types = _collect_cmp_values(rule.expr_ast, "event.type")
        codes = _collect_cmp_values(rule.expr_ast, "event.code")
        rule_hits_24h, entity_hits_24h = _rule_counts(client, rule, where_sql, 24)
        rule_hits_7d, entity_hits_7d = _rule_counts(client, rule, where_sql, 24 * 7)
        item = {
            "id": rule.id,
            "name": rule.name,
            "severity": rule.severity,
            "entity_field": rule.entity_field,
            "threshold": rule.threshold,
            "window_s": rule.window_s,
            "providers": sorted(set(providers)),
            "types": sorted(set(types)),
            "codes": sorted(set(codes)),
            "provider_events_24h": _provider_count(client, providers, 24),
            "provider_events_7d": _provider_count(client, providers, 24 * 7),
            "provider_type_code_events_7d": _provider_type_count(client, providers, types, codes, 24 * 7),
            "rule_hits_24h": rule_hits_24h,
            "entity_hits_24h": entity_hits_24h,
            "rule_hits_7d": rule_hits_7d,
            "entity_hits_7d": entity_hits_7d,
            "alerts_24h": _alert_count(client, rule.id, 24),
            "alerts_7d": _alert_count(client, rule.id, 24 * 7),
        }
        item["reason"] = _reason(item)
        items.append(item)

    summary: dict[str, int] = {}
    for item in items:
        summary[item["reason"]] = summary.get(item["reason"], 0) + 1
    report = {
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "active_rules": len(rules),
        "summary": dict(sorted(summary.items())),
        "items": items,
    }
    if args.report_path:
        path = Path(args.report_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
