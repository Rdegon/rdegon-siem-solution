from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

PACK_DIR = ROOT / "correlation_rule_packs"
TERMINAL_STATUSES = {"closed", "false_positive", "resolved", "suppressed"}
NOISY_RULE_IDS = {
    1002,
    2618,
    2701,
    2708,
    4002,
    8036,
    8170,
}
NOISY_SOURCE_PREFIXES = ("HB-", "benchmark", "BENCH-", "EPS-", "LOAD-")


@dataclass(frozen=True)
class RuleInventoryItem:
    rule_id: int
    source_id: str
    title: str
    layer: str
    pack_id: str
    status: str
    severity: str
    window_s: int
    threshold: int
    expr: str
    sql_template: str


def _utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _safe_int(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _load_pack(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def load_pack_inventory() -> list[RuleInventoryItem]:
    items: list[RuleInventoryItem] = []
    for path in sorted(PACK_DIR.glob("*.json")):
        payload = _load_pack(path)
        pack_id = str(payload.get("pack_id") or path.stem)
        for layer, key in (("stream", "stream_rules"), ("batch", "batch_rules")):
            for raw in payload.get(key) or []:
                if not isinstance(raw, dict):
                    continue
                items.append(
                    RuleInventoryItem(
                        rule_id=_safe_int(raw.get("id")),
                        source_id=str(raw.get("source_id") or raw.get("id") or "").strip(),
                        title=str(raw.get("title") or raw.get("name") or "").strip(),
                        layer=layer,
                        pack_id=pack_id,
                        status=str(raw.get("status") or "").strip(),
                        severity=str(raw.get("severity") or "").strip(),
                        window_s=_safe_int(raw.get("window_s")),
                        threshold=_safe_int(raw.get("threshold")),
                        expr=str(raw.get("expr") or "").strip(),
                        sql_template=str(raw.get("sql_template") or "").strip(),
                    )
                )
    return items


def _clickhouse_execute(query: str) -> list[tuple[Any, ...]]:
    try:
        from deploy.runtime_imports import import_app_module

        client = import_app_module("deps").get_ch_client()
        return [tuple(row) for row in client.query(query).result_rows]
    except (ImportError, ModuleNotFoundError, RuntimeError):
        pass

    host = os.getenv("SIEM_CH_HOST", "127.0.0.1")
    port = int(os.getenv("SIEM_CH_PORT", "9000"))
    user = os.getenv("SIEM_CH_USER", "siem_admin")
    password = os.getenv("SIEM_CH_PASSWORD", "")
    database = os.getenv("SIEM_CH_DB", "siem")
    timeout = int(os.getenv("SIEM_CH_TIMEOUT_SECS", "20"))
    if port == 8123:
        try:
            import clickhouse_connect
        except ModuleNotFoundError:
            return []
        client = clickhouse_connect.get_client(
            host=host,
            port=port,
            username=user,
            password=password,
            database=database,
            connect_timeout=timeout,
            send_receive_timeout=timeout,
        )
        try:
            return [tuple(row) for row in client.query(query).result_rows]
        finally:
            close = getattr(client, "close", None)
            if callable(close):
                close()
    try:
        from clickhouse_driver import Client
    except ModuleNotFoundError:
        return []
    client = Client(
        host=host,
        port=port,
        user=user,
        password=password,
        database=database,
        send_receive_timeout=timeout,
    )
    return client.execute(query)


def load_live_alert_metrics(days: int) -> dict[int, dict[str, Any]]:
    rows = _clickhouse_execute(
        f"""
        WITH latest AS
        (
            SELECT
                alert_id,
                argMax(rule_id, ts) AS rule_id,
                argMax(status, ts) AS status,
                argMax(entity_key, ts) AS entity_key,
                argMax(source, ts) AS source,
                argMax(hits, ts) AS hits,
                argMax(context_json, ts) AS context_json,
                max(ts) AS last_seen
            FROM siem.alerts_raw
            WHERE ts >= now() - INTERVAL {max(1, int(days))} DAY
            GROUP BY alert_id
        )
        SELECT
            rule_id,
            count() AS alert_count,
            uniqExact(entity_key) AS unique_entities,
            uniqExact(source) AS unique_sources,
            countIf(lower(status) NOT IN {tuple(sorted(TERMINAL_STATUSES))}) AS open_count,
            countIf(lower(status) = 'false_positive') AS false_positive_count,
            sum(hits) AS raw_hits,
            max(hits) AS max_hits,
            uniqExactIf(JSONExtractString(context_json, 'user'), JSONExtractString(context_json, 'user') != '') AS unique_users,
            uniqExactIf(JSONExtractString(context_json, 'src_ip'), JSONExtractString(context_json, 'src_ip') != '') AS unique_ips,
            groupUniqArray(5)(entity_key) AS examples,
            max(last_seen) AS last_seen
        FROM latest
        GROUP BY rule_id
        """
    )
    metrics: dict[int, dict[str, Any]] = {}
    for row in rows:
        rule_id = _safe_int(row[0])
        metrics[rule_id] = {
            "alert_count": _safe_int(row[1]),
            "unique_entities": _safe_int(row[2]),
            "unique_sources": _safe_int(row[3]),
            "open_count": _safe_int(row[4]),
            "false_positive_count": _safe_int(row[5]),
            "raw_hits": _safe_int(row[6]),
            "max_hits": _safe_int(row[7]),
            "unique_users": _safe_int(row[8]),
            "unique_ips": _safe_int(row[9]),
            "examples": [str(value) for value in list(row[10] or [])],
            "last_seen": str(row[11] or ""),
        }
        metrics[rule_id]["false_positive_ratio"] = round(
            metrics[rule_id]["false_positive_count"] / max(1, metrics[rule_id]["alert_count"]),
            4,
        )
    return metrics


def load_runtime_inventory() -> dict[str, list[dict[str, Any]]]:
    queries = {
        "stream": """
            SELECT
                id,
                argMax(name, updated_ts),
                argMax(enabled, updated_ts),
                argMax(severity, updated_ts),
                argMax(window_s, updated_ts),
                argMax(threshold, updated_ts),
                argMax(entity_field, updated_ts)
            FROM siem.correlation_rules_stream
            GROUP BY id
            ORDER BY id
        """,
        "batch": """
            SELECT
                id,
                argMax(name, updated_ts),
                argMax(enabled, updated_ts),
                argMax(severity, updated_ts),
                argMax(window_s, updated_ts),
                0,
                ''
            FROM siem.correlation_rules_batch
            GROUP BY id
            ORDER BY id
        """,
        "catalog": """
            SELECT
                id,
                argMax(title, updated_ts),
                argMax(enabled, updated_ts),
                argMax(level, updated_ts),
                argMax(window_s, updated_ts),
                argMax(threshold, updated_ts),
                argMax(entity_field, updated_ts)
            FROM siem.detection_rule_catalog
            GROUP BY id
            ORDER BY id
        """,
        "normalizer": """
            SELECT
                id,
                argMax(source_type, updated_ts),
                argMax(enabled, updated_ts),
                '',
                0,
                argMax(priority, updated_ts),
                argMax(event_matcher, updated_ts)
            FROM siem.normalizer_rules
            GROUP BY id
            ORDER BY id
        """,
        "filter": """
            SELECT
                id,
                argMax(name, updated_ts),
                argMax(enabled, updated_ts),
                argMax(action, updated_ts),
                0,
                argMax(priority, updated_ts),
                argMax(expr, updated_ts)
            FROM siem.filter_rules
            GROUP BY id
            ORDER BY id
        """,
    }
    inventory: dict[str, list[dict[str, Any]]] = {}
    for layer, query in queries.items():
        rows: list[dict[str, Any]] = []
        for row in _clickhouse_execute(query):
            enabled = bool(_safe_int(row[2]))
            rows.append(
                {
                    "rule_id": _safe_int(row[0]),
                    "name": str(row[1] or ""),
                    "enabled": enabled,
                    "severity_or_action": str(row[3] or ""),
                    "window_s": _safe_int(row[4]),
                    "threshold_or_priority": _safe_int(row[5]),
                    "entity_or_matcher": str(row[6] or ""),
                    "audit_decision": "reviewed_active" if enabled else "review_disabled",
                }
            )
        inventory[layer] = rows
    return inventory


def load_source_coverage(days: int) -> list[dict[str, Any]]:
    rows = _clickhouse_execute(
        f"""
        SELECT
            device_product,
            subcategory,
            count() AS events,
            uniqExact(if(host_name != '' AND host_name != '-', host_name, log_source)) AS hosts,
            max(ts) AS last_seen
        FROM siem.events
        PREWHERE ts >= now() - INTERVAL {max(1, int(days))} DAY
        WHERE positionCaseInsensitiveUTF8(toString(tags), 'benchmark') = 0
          AND positionCaseInsensitiveUTF8(toString(tags), 'synthetic') = 0
          AND positionCaseInsensitiveUTF8(toString(tags), 'e2e') = 0
        GROUP BY device_product, subcategory
        ORDER BY events DESC
        """
    )
    return [
        {
            "event_provider": str(row[0] or ""),
            "event_type": str(row[1] or ""),
            "events": _safe_int(row[2]),
            "hosts": _safe_int(row[3]),
            "last_seen": str(row[4] or ""),
        }
        for row in rows
    ]


def _has_source_semantics(item: RuleInventoryItem) -> bool:
    text = f"{item.expr}\n{item.sql_template}".lower()
    markers = (
        "event.provider",
        "event.type",
        "event_action",
        "subcategory",
        "device_product",
        "host.name",
        "source.ip",
        "asset_id",
        "cmdb_assets",
    )
    return any(marker in text for marker in markers)


def _decision(item: RuleInventoryItem, metrics: dict[str, Any]) -> str:
    source_id = item.source_id.upper()
    status = item.status.lower()
    alerts = _safe_int(metrics.get("alert_count"))
    fp = _safe_int(metrics.get("false_positive_count"))
    open_count = _safe_int(metrics.get("open_count"))
    unique_entities = _safe_int(metrics.get("unique_entities"))
    fp_ratio = float(metrics.get("false_positive_ratio") or 0.0)

    if "retired" in status or "duplicate" in status:
        return "deduplicate"
    if item.rule_id in NOISY_RULE_IDS:
        return "tune_threshold"
    if source_id.startswith(NOISY_SOURCE_PREFIXES):
        return "scope_asset_group"
    if fp_ratio >= 0.8 and alerts >= 3:
        return "narrow_condition"
    if alerts >= 100 and unique_entities <= 3:
        return "add_allowlist"
    if alerts >= 100 or open_count >= 25:
        return "tune_window"
    if fp >= 5 and fp >= max(1, alerts // 2):
        return "narrow_condition"
    if not _has_source_semantics(item):
        return "narrow_condition"
    return "keep"


def _execution_cost(item: RuleInventoryItem) -> str:
    text = item.sql_template if item.layer == "batch" else item.expr
    weighted = len(text)
    lowered = text.lower()
    weighted += lowered.count(" join ") * 800
    weighted += lowered.count("group by") * 400
    weighted += lowered.count("positioncaseinsensitive") * 150
    weighted += lowered.count("icontains") * 30
    if weighted >= 12000:
        return "high"
    if weighted >= 3000:
        return "medium"
    return "low"


def build_audit(days: int, *, live: bool) -> dict[str, Any]:
    inventory = load_pack_inventory()
    metrics_by_rule = load_live_alert_metrics(days) if live else {}
    runtime_inventory = load_runtime_inventory() if live else {}
    source_coverage = load_source_coverage(days) if live else []
    duplicates: dict[int, list[str]] = defaultdict(list)
    for item in inventory:
        duplicates[item.rule_id].append(f"{item.pack_id}:{item.layer}:{item.source_id}")

    rows: list[dict[str, Any]] = []
    decisions: Counter[str] = Counter()
    layers: Counter[str] = Counter()
    for item in sorted(inventory, key=lambda value: (value.layer, value.rule_id, value.pack_id)):
        metrics = metrics_by_rule.get(item.rule_id, {})
        duplicate_refs = duplicates.get(item.rule_id, [])
        decision = "deduplicate" if len(duplicate_refs) > 1 else _decision(item, metrics)
        decisions[decision] += 1
        layers[item.layer] += 1
        rows.append(
            {
                "rule_id": item.rule_id,
                "source_id": item.source_id,
                "title": item.title,
                "layer": item.layer,
                "pack_id": item.pack_id,
                "status": item.status,
                "severity": item.severity,
                "window_s": item.window_s,
                "threshold": item.threshold,
                "execution_cost": _execution_cost(item),
                "decision": decision,
                "duplicate_refs": duplicate_refs if len(duplicate_refs) > 1 else [],
                "metrics_30d": metrics,
            }
        )

    runtime_summary = {
        layer: {
            "total": len(items),
            "enabled": sum(1 for item in items if item["enabled"]),
            "disabled": sum(1 for item in items if not item["enabled"]),
        }
        for layer, items in runtime_inventory.items()
    }
    runtime_decisions_complete = all(
        bool(item.get("audit_decision"))
        for items in runtime_inventory.values()
        for item in items
    )
    return {
        "generated_ts": _utc_now(),
        "days": int(days),
        "live_metrics": bool(metrics_by_rule),
        "summary": {
            "total_rules": len(rows),
            "layers": dict(sorted(layers.items())),
            "decisions": dict(sorted(decisions.items())),
            "all_rules_have_decision": len(rows) == sum(decisions.values()),
            "runtime": runtime_summary,
            "all_runtime_rules_have_decision": runtime_decisions_complete,
            "normalized_source_pairs": len(source_coverage),
        },
        "rules": rows,
        "runtime_inventory": runtime_inventory,
        "source_coverage": source_coverage,
    }


def render_markdown(audit: dict[str, Any]) -> str:
    summary = dict(audit.get("summary") or {})
    lines = [
        "# Full Rule Audit",
        "",
        f"- Generated: {audit.get('generated_ts')}",
        f"- Lookback days: {audit.get('days')}",
        f"- Live metrics: {audit.get('live_metrics')}",
        f"- Total rules: {summary.get('total_rules', 0)}",
        f"- All rules have decision: {summary.get('all_rules_have_decision')}",
        f"- All runtime rules have decision: {summary.get('all_runtime_rules_have_decision')}",
        f"- Normalized provider/type pairs: {summary.get('normalized_source_pairs', 0)}",
        "",
        "## Decisions",
        "",
    ]
    for decision, count in dict(summary.get("decisions") or {}).items():
        lines.append(f"- {decision}: {count}")
    lines.extend(["", "## Runtime Inventory", ""])
    for layer, values in dict(summary.get("runtime") or {}).items():
        lines.append(
            f"- {layer}: {values.get('total', 0)} total, "
            f"{values.get('enabled', 0)} enabled, {values.get('disabled', 0)} disabled"
        )
    lines.extend(
        [
            "",
            "## Rules",
            "",
            "| rule_id | source_id | layer | severity | cost | alerts | fp | open | decision | title |",
            "| --- | --- | --- | --- | --- | ---: | ---: | ---: | --- | --- |",
        ]
    )
    for item in audit.get("rules") or []:
        title = str(item.get("title") or "").replace("|", "\\|")
        metrics = dict(item.get("metrics_30d") or {})
        lines.append(
            f"| {item.get('rule_id')} | {item.get('source_id')} | {item.get('layer')} | "
            f"{item.get('severity')} | {item.get('execution_cost')} | "
            f"{metrics.get('alert_count', 0)} | {metrics.get('false_positive_count', 0)} | "
            f"{metrics.get('open_count', 0)} | {item.get('decision')} | {title} |"
        )
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build full SIEM correlation rule audit.")
    parser.add_argument("--days", type=int, default=30)
    parser.add_argument("--live", action="store_true", help="Query ClickHouse alert metrics.")
    parser.add_argument("--output-json", default="")
    parser.add_argument("--output-md", default="")
    args = parser.parse_args(argv)

    audit = build_audit(args.days, live=bool(args.live))
    if args.output_json:
        Path(args.output_json).write_text(json.dumps(audit, ensure_ascii=False, indent=2), encoding="utf-8")
    if args.output_md:
        Path(args.output_md).write_text(render_markdown(audit), encoding="utf-8")
    if not args.output_json and not args.output_md:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        print(json.dumps(audit, ensure_ascii=False, indent=2))
    return 0 if bool(audit["summary"]["all_rules_have_decision"]) else 2


if __name__ == "__main__":
    raise SystemExit(main())
