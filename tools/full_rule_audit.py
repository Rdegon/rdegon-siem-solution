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
        SELECT
            rule_id,
            count() AS alert_count,
            uniqExact(entity_key) AS unique_entities,
            uniqExact(source) AS unique_sources,
            countIf(lower(status) NOT IN {tuple(sorted(TERMINAL_STATUSES))}) AS open_count,
            countIf(lower(status) = 'false_positive') AS false_positive_count,
            max(hits) AS max_hits,
            max(ts_last) AS last_seen
        FROM siem.alerts_raw
        WHERE ts >= now() - INTERVAL {max(1, int(days))} DAY
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
            "max_hits": _safe_int(row[6]),
            "last_seen": str(row[7] or ""),
        }
    return metrics


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

    if "retired" in status or "duplicate" in status:
        return "deduplicate"
    if item.rule_id in NOISY_RULE_IDS:
        return "tune_threshold"
    if source_id.startswith(NOISY_SOURCE_PREFIXES):
        return "scope_asset_group"
    if alerts >= 100 and unique_entities <= 3:
        return "add_allowlist"
    if alerts >= 100 or open_count >= 25:
        return "tune_window"
    if fp >= 5 and fp >= max(1, alerts // 2):
        return "narrow_condition"
    if not _has_source_semantics(item):
        return "narrow_condition"
    return "keep"


def build_audit(days: int, *, live: bool) -> dict[str, Any]:
    inventory = load_pack_inventory()
    metrics_by_rule = load_live_alert_metrics(days) if live else {}
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
                "decision": decision,
                "duplicate_refs": duplicate_refs if len(duplicate_refs) > 1 else [],
                "metrics_30d": metrics,
            }
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
        },
        "rules": rows,
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
        "",
        "## Decisions",
        "",
    ]
    for decision, count in dict(summary.get("decisions") or {}).items():
        lines.append(f"- {decision}: {count}")
    lines.extend(["", "## Rules", "", "| rule_id | source_id | layer | severity | decision | title |", "| --- | --- | --- | --- | --- | --- |"])
    for item in audit.get("rules") or []:
        title = str(item.get("title") or "").replace("|", "\\|")
        lines.append(
            f"| {item.get('rule_id')} | {item.get('source_id')} | {item.get('layer')} | "
            f"{item.get('severity')} | {item.get('decision')} | {title} |"
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
