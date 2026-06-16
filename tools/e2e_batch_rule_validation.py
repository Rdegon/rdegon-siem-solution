from __future__ import annotations

import argparse
import asyncio
import json
import os
import re
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from clickhouse_driver import Client

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from services.transport_runtime import create_transport_producer, transport_health_snapshot


PACK_PATH = Path("correlation_rule_packs/siem_detection_pack_v1.json")


PREFIX_PROVIDER = {
    "PVE": "linux.pvedaemon",
    "AUTH": "linux.auth",
    "SVC": "linux.systemd",
    "PROC": "linux.auditd",
    "DCK": "docker",
    "WIN": "windows",
    "IDS": "network.suricata",
    "DNS": "network.dns",
    "EDGE": "network.edge",
    "GW": "network.gateway",
    "PG": "database.postgresql",
    "MONGO": "database.mongodb",
    "DB": "database",
    "CH": "database.clickhouse",
    "KFK": "kafka",
    "ING": "siem.ingest",
    "WR": "siem.writer",
    "STR": "siem.stream",
    "ALERT": "siem.alert",
    "MET": "siem.metrics",
    "HB": "siem.heartbeat",
    "IAM": "keycloak",
    "VAULT": "vault",
    "PILOT": "pilot",
    "NC": "nextcloud",
    "NAV": "navidrome",
    "MC": "minecraft",
    "BCK": "backup",
    "CORR": "siem.correlation",
}

GROUP_HOST = {
    "proxmox": "pve",
    "siem_core": "siem-storage",
    "windows": "win-test",
    "linux_common": "siem-storage",
    "public_services": "openclaw-gateway",
    "game": "gamepanel-01",
    "vuln": "vuln-mgr-01",
    "pilot": "pilot-web-01",
    "edge_gateway": "openclaw-gateway",
    "devops": "gitea",
    "identity": "keycloak",
}


def _utc_iso(epoch: float | None = None) -> str:
    dt = datetime.fromtimestamp(epoch or time.time(), tz=timezone.utc)
    return dt.isoformat().replace("+00:00", "Z")


def _clickhouse_client() -> Client:
    return Client(
        host=os.environ["SIEM_CH_HOST"],
        port=int(os.environ.get("SIEM_CH_NATIVE_PORT") or os.environ.get("SIEM_CH_PORT") or "9000"),
        user=os.environ["SIEM_CH_USER"],
        password=os.environ["SIEM_CH_PASSWORD"],
        database=os.environ.get("SIEM_CH_DB", "siem"),
        send_receive_timeout=max(int(os.environ.get("SIEM_CH_TIMEOUT_SECS", "300") or "300"), 300),
    )


def _load_pack(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"Pack payload must be an object: {path}")
    return payload


def _prefix(source_id: str) -> str:
    return str(source_id or "").split("-", 1)[0].upper()


def _sql_string(value: str) -> str:
    return str(value).replace("'", "''")


def _event_rules(batch_rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [rule for rule in batch_rules if "FROM siem.events" in str(rule.get("sql_template") or "")]


def _child_alert_rules(batch_rules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        rule
        for rule in batch_rules
        if "FROM siem.alerts_raw" in str(rule.get("sql_template") or "")
        and "FROM siem.events" not in str(rule.get("sql_template") or "")
    ]


def _provider_for_rule(rule: dict[str, Any]) -> str:
    sql = str(rule.get("sql_template") or "")
    match = re.search(r"device_product\s*=\s*'((?:[^']|'')+)'", sql)
    if match:
        return match.group(1).replace("''", "'")
    return PREFIX_PROVIDER.get(_prefix(str(rule.get("source_id") or "")), "siem")


def _message_terms(rule: dict[str, Any]) -> list[str]:
    sql = str(rule.get("sql_template") or "")
    terms = [
        item.replace("''", "'")
        for item in re.findall(
            r"positionCaseInsensitiveUTF8\(toString\((?:message|normalized_json)\),\s*'((?:[^']|'')+)'\)",
            sql,
        )
    ]
    fallback_text = " ".join(
        str(rule.get(key) or "")
        for key in ("source_id", "title", "description", "detection_logic", "sources")
    )
    terms.extend(re.findall(r"[A-Za-z0-9_./:=+-]{3,}", fallback_text))
    deduped: list[str] = []
    seen: set[str] = set()
    for term in terms:
        clean = str(term or "").strip()
        key = clean.lower()
        if not clean or key in seen:
            continue
        seen.add(key)
        deduped.append(clean)
    return deduped[:80]


def _scope_term_from_sql(rule: dict[str, Any]) -> str:
    sql = str(rule.get("sql_template") or "")
    terms = [
        item.replace("''", "'").strip()
        for item in re.findall(
            r"positionCaseInsensitiveUTF8\(lowerUTF8\(if\(host_name.*?\)\),\s*'((?:[^']|'')+)'\)",
            sql,
            flags=re.DOTALL,
        )
    ]
    preferred = [
        "pve",
        "siem-storage",
        "siem-web",
        "win-test",
        "openclaw-gateway",
        "gamepanel-01",
        "vuln-mgr-01",
        "pilot-web-01",
        "gitea",
        "keycloak",
    ]
    lowered = {term.lower(): term for term in terms}
    for item in preferred:
        if item in lowered:
            return lowered[item]
    for term in terms:
        if term and len(term) <= 48:
            return term
    groups = list(rule.get("asset_groups") or [])
    for group in groups:
        host = GROUP_HOST.get(str(group))
        if host:
            return host
    return "siem-storage"


def _synth_event(rule: dict[str, Any], run_id: str, index: int, event_epoch: float) -> dict[str, str]:
    rule_id = int(rule["id"])
    source_id = str(rule.get("source_id") or rule_id)
    provider = _provider_for_rule(rule)
    host_base = _scope_term_from_sql(rule)
    host = f"{host_base}-e2e-{run_id}-r{rule_id}"
    marker = f"e2e-batch-rule-validation {run_id} rule {rule_id} {source_id}"
    terms = " ".join(_message_terms(rule))
    message = f"{marker} {terms}"
    ts = _utc_iso(event_epoch)
    return {
        "ts": ts,
        "@timestamp": ts,
        "event.created": ts,
        "event.id": f"{run_id}-{rule_id}-{index}",
        "event.code": str(rule_id),
        "event.provider": provider,
        "event.category": provider,
        "event.type": "assignment_batch_e2e",
        "event.action": source_id,
        "event.outcome": "success",
        "event.original": message,
        "message": message,
        "device.vendor": provider.split(".", 1)[0],
        "device.product": provider,
        "log_source": f"{provider}-{host}",
        "host.name": host,
        "source.ip": f"198.18.{rule_id // 256}.{rule_id % 256}",
        "destination.ip": f"198.19.{rule_id // 256}.{rule_id % 256}",
        "source.port": str(40000 + (index % 10000)),
        "destination.port": str(1000 + (rule_id % 50000)),
        "user.name": f"e2e-user-{run_id}-r{rule_id}",
        "user.target.name": f"e2e-target-{run_id}-r{rule_id}",
        "process.name": "assignment-batch-e2e",
        "process.executable": f"/opt/e2e/{source_id}",
        "process.command_line": message,
        "tags": "e2e.validation.assignment_batch",
        "details": json.dumps(
            {
                "e2e_run_id": run_id,
                "e2e_rule_id": rule_id,
                "source_id": source_id,
                "validation": "assignment_batch_source_event",
            },
            ensure_ascii=True,
            separators=(",", ":"),
        ),
        "e2e.run_id": run_id,
        "e2e.rule_id": str(rule_id),
        "e2e.validation": "batch_rules",
    }


async def _publish_events(rules: list[dict[str, Any]], run_id: str, event_epoch: float) -> int:
    producer = create_transport_producer(None)
    published = 0
    try:
        for rule in rules:
            threshold = max(1, int(rule.get("threshold") or 1))
            for index in range(1, threshold + 1):
                await producer.publish("filtered", _synth_event(rule, run_id, index, event_epoch))
                published += 1
                if published % 1000 == 0:
                    print(json.dumps({"stage": "publish_progress", "published": published}, ensure_ascii=False), flush=True)
    finally:
        await producer.close()
    return published


def _run_event_filter(run_id: str) -> str:
    rid = _sql_string(run_id)
    return (
        "("
        f"positionCaseInsensitiveUTF8(toString(message), '{rid}') > 0 OR "
        f"positionCaseInsensitiveUTF8(toString(normalized_json), '{rid}') > 0 OR "
        f"positionCaseInsensitiveUTF8(toString(log_source), '{rid}') > 0 OR "
        f"positionCaseInsensitiveUTF8(toString(host_name), '{rid}') > 0"
        ")"
    )


def _run_alert_filter(run_id: str, *, include_context: bool = True) -> str:
    rid = _sql_string(run_id)
    parts = [
        f"positionCaseInsensitiveUTF8(toString(source), '{rid}') > 0",
        f"positionCaseInsensitiveUTF8(toString(entity_key), '{rid}') > 0",
    ]
    if include_context:
        parts.insert(0, f"positionCaseInsensitiveUTF8(toString(context_json), '{rid}') > 0")
    return "(" + " OR ".join(parts) + ")"


def _prepare_event_sql(rule: dict[str, Any], run_id: str) -> str:
    sql = str(rule.get("sql_template") or "").replace("{WINDOW_S}", str(max(60, int(rule.get("window_s") or 300))))
    clause = "      AND " + _run_event_filter(run_id) + "\n"
    sql, count = re.subn(
        r"(WHERE\s+ts\s+>=\s+now\(\)\s+-\s+INTERVAL\s+\d+\s+SECOND\s*\n)",
        r"\1" + clause,
        sql,
        count=1,
        flags=re.IGNORECASE,
    )
    if count != 1:
        raise ValueError(f"Unable to inject run_id event filter for rule {rule.get('id')}")
    return sql


def _prepare_child_sql(rule: dict[str, Any], run_id: str) -> str:
    sql = str(rule.get("sql_template") or "").replace("{WINDOW_S}", str(max(60, int(rule.get("window_s") or 300))))
    # The candidate SELECT defines a context_json alias using aggregate
    # functions. Filtering on context_json in the same SELECT can bind to
    # that alias in newer ClickHouse analyzers, so restrict child input by
    # base source/entity columns here.
    clause = "      AND " + _run_alert_filter(run_id, include_context=False) + "\n"
    sql, count = re.subn(
        r"(WHERE\s+ts_last\s+>=\s+now\(\)\s+-\s+INTERVAL\s+\d+\s+SECOND\s*\n)",
        r"\1" + clause,
        sql,
        count=1,
        flags=re.IGNORECASE,
    )
    if count != 1:
        raise ValueError(f"Unable to inject run_id alert filter for rule {rule.get('id')}")
    return sql


def _wait_for_events(client: Client, run_id: str, expected: int, timeout_s: int, poll_s: float) -> int:
    deadline = time.time() + max(0, timeout_s)
    last = 0
    while True:
        last = int(
            client.execute(
                """
                SELECT count()
                FROM siem.events
                WHERE position(message, %(run_id)s) > 0
                   OR position(normalized_json, %(run_id)s) > 0
                   OR position(log_source, %(run_id)s) > 0
                   OR position(host_name, %(run_id)s) > 0
                """,
                {"run_id": run_id},
            )[0][0]
        )
        print(
            json.dumps({"stage": "event_poll", "stored_events": last, "expected_events": expected}, ensure_ascii=False),
            flush=True,
        )
        if last >= expected or time.time() >= deadline:
            return last
        time.sleep(max(1.0, poll_s))


def _fetch_rule_alert(client: Client, rule_id: int, run_id: str, since_epoch: float) -> dict[str, Any] | None:
    since = datetime.fromtimestamp(since_epoch, tz=timezone.utc).replace(tzinfo=None)
    rows = client.execute(
        """
        SELECT
            count() AS alerts_count,
            max(hits) AS max_hits,
            any(entity_key) AS sample_entity,
            any(source) AS sample_source,
            max(ts) AS last_ts
        FROM siem.alerts_raw
        WHERE rule_id = %(rule_id)s
          AND ts >= %(since)s
          AND (
            position(context_json, %(run_id)s) > 0
            OR position(source, %(run_id)s) > 0
            OR position(entity_key, %(run_id)s) > 0
          )
        """,
        {"rule_id": rule_id, "run_id": run_id, "since": since},
    )
    if not rows or int(rows[0][0]) <= 0:
        return None
    row = rows[0]
    return {
        "alerts_count": int(row[0]),
        "max_hits": int(row[1]),
        "sample_entity": str(row[2]),
        "sample_source": str(row[3]),
        "last_ts": str(row[4]),
    }


def _execute_event_rules(client: Client, rules: list[dict[str, Any]], run_id: str, since_epoch: float) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for index, rule in enumerate(rules, start=1):
        rule_id = int(rule["id"])
        error = ""
        try:
            client.execute(_prepare_event_sql(rule, run_id))
        except Exception as exc:  # noqa: BLE001
            error = str(exc)
        alert = _fetch_rule_alert(client, rule_id, run_id, since_epoch)
        item = {
            "id": rule_id,
            "source_id": str(rule.get("source_id") or ""),
            "title": str(rule.get("title") or ""),
            "status": "ok" if alert and not error else "failed",
            "input_mode": "source_event_transport",
            "threshold": int(rule.get("threshold") or 1),
            "window_s": int(rule.get("window_s") or 0),
            "alert_created": bool(alert),
            "alert": alert or {},
            "execution_error": error,
        }
        items.append(item)
        if index % 10 == 0 or item["status"] != "ok":
            print(
                json.dumps(
                    {
                        "stage": "event_rule_execute",
                        "processed": index,
                        "total": len(rules),
                        "rule_id": rule_id,
                        "status": item["status"],
                    },
                    ensure_ascii=False,
                ),
                flush=True,
            )
    return items


def _referenced_child_ids(rule: dict[str, Any]) -> list[int]:
    sql = str(rule.get("sql_template") or "")
    ids: list[int] = []
    for group in re.findall(r"rule_id\s+IN\s+\(([^)]*)\)", sql, flags=re.IGNORECASE):
        for raw in re.findall(r"\d+", group):
            value = int(raw)
            if value not in ids:
                ids.append(value)
    return ids


def _insert_child_alerts(client: Client, rules: list[dict[str, Any]], run_id: str) -> int:
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    rows: list[tuple[Any, ...]] = []
    for rule in rules:
        parent_id = int(rule["id"])
        entity = f"e2e-correlation-{run_id}-r{parent_id}"
        for child_id in _referenced_child_ids(rule):
            rows.append(
                (
                    now,
                    str(uuid.uuid4()),
                    child_id,
                    f"e2e child alert {child_id} for {parent_id}",
                    "medium",
                    now,
                    now,
                    int(rule.get("window_s") or 300),
                    entity,
                    1,
                    json.dumps(
                        {
                            "event_type": "assignment_e2e_child_alert",
                            "run_id": run_id,
                            "parent_rule_id": parent_id,
                            "child_rule_id": child_id,
                        },
                        ensure_ascii=False,
                        separators=(",", ":"),
                    ),
                    f"e2e-correlation-source-{run_id}-r{parent_id}",
                    "open",
                )
            )
    if not rows:
        return 0
    client.execute(
        """
        INSERT INTO siem.alerts_raw
        (ts, alert_id, rule_id, rule_name, severity, ts_first, ts_last, window_s, entity_key, hits, context_json, source, status)
        VALUES
        """,
        rows,
    )
    return len(rows)


def _execute_child_rules(client: Client, rules: list[dict[str, Any]], run_id: str, since_epoch: float) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for index, rule in enumerate(rules, start=1):
        rule_id = int(rule["id"])
        error = ""
        try:
            client.execute(_prepare_child_sql(rule, run_id))
        except Exception as exc:  # noqa: BLE001
            error = str(exc)
        alert = _fetch_rule_alert(client, rule_id, run_id, since_epoch)
        item = {
            "id": rule_id,
            "source_id": str(rule.get("source_id") or ""),
            "title": str(rule.get("title") or ""),
            "status": "ok" if alert and not error else "failed",
            "input_mode": "correlation_child_alerts",
            "child_rule_ids": _referenced_child_ids(rule),
            "threshold": int(rule.get("threshold") or 1),
            "window_s": int(rule.get("window_s") or 0),
            "alert_created": bool(alert),
            "alert": alert or {},
            "execution_error": error,
        }
        items.append(item)
        if index % 10 == 0 or item["status"] != "ok":
            print(
                json.dumps(
                    {
                        "stage": "child_rule_execute",
                        "processed": index,
                        "total": len(rules),
                        "rule_id": rule_id,
                        "status": item["status"],
                    },
                    ensure_ascii=False,
                ),
                flush=True,
            )
    return items


def _close_test_alerts(client: Client, run_id: str) -> dict[str, int]:
    result: dict[str, int] = {}
    rid = _sql_string(run_id)
    raw_run_marker = (
        f"position(context_json, '{rid}') > 0 OR "
        f"position(source, '{rid}') > 0 OR "
        f"position(entity_key, '{rid}') > 0"
    )
    raw_e2e_marker = (
        "(position(context_json, 'e2e ') > 0 AND position(context_json, 'validation') > 0) OR "
        "(position(source, 'e2e ') > 0 AND position(source, 'validation') > 0) OR "
        "(position(entity_key, 'e2e ') > 0 AND position(entity_key, 'validation') > 0)"
    )
    agg_run_marker = (
        f"position(samples_json, '{rid}') > 0 OR "
        f"position(group_key_json, '{rid}') > 0 OR "
        f"position(entity_key, '{rid}') > 0"
    )
    agg_e2e_marker = (
        "(position(samples_json, 'e2e ') > 0 AND position(samples_json, 'validation') > 0) OR "
        "(position(group_key_json, 'e2e ') > 0 AND position(group_key_json, 'validation') > 0) OR "
        "(position(entity_key, 'e2e ') > 0 AND position(entity_key, 'validation') > 0)"
    )
    raw_where = (
        "rule_id BETWEEN 8001 AND 8487 AND "
        f"(({raw_run_marker}) OR ({raw_e2e_marker}))"
    )
    agg_where = (
        "rule_id BETWEEN 8001 AND 8487 AND "
        f"(({agg_run_marker}) OR ({agg_e2e_marker}))"
    )
    for table, where in (("siem.alerts_raw", raw_where), ("siem.alerts_agg", agg_where)):
        count = int(client.execute(f"SELECT count() FROM {table} WHERE {where}")[0][0])
        result[table] = count
        if count:
            client.execute(
                f"""
                ALTER TABLE {table}
                UPDATE status = 'false_positive',
                       assignee = 'assignment-full-e2e-validation',
                       updated_ts = now()
                WHERE {where}
                SETTINGS mutations_sync = 1
                """
            )
    return result


def _delete_test_events(client: Client, run_id: str) -> int:
    where = (
        f"position(message, '{_sql_string(run_id)}') > 0 OR "
        f"position(normalized_json, '{_sql_string(run_id)}') > 0 OR "
        f"position(log_source, '{_sql_string(run_id)}') > 0 OR "
        f"position(host_name, '{_sql_string(run_id)}') > 0"
    )
    count = int(client.execute(f"SELECT count() FROM siem.events WHERE {where}")[0][0])
    if count:
        client.execute(f"ALTER TABLE siem.events DELETE WHERE {where} SETTINGS mutations_sync = 1")
    return count


async def main() -> int:
    parser = argparse.ArgumentParser(description="Source-event E2E validation for assignment batch/correlation rules.")
    parser.add_argument("--run-id", default=datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"))
    parser.add_argument("--pack-path", default=str(PACK_PATH))
    parser.add_argument("--publish", action="store_true")
    parser.add_argument("--wait-seconds", type=int, default=1200)
    parser.add_argument("--poll-interval", type=float, default=10.0)
    parser.add_argument("--report-path", default="")
    parser.add_argument("--cleanup-alerts", action="store_true")
    parser.add_argument("--cleanup-events", action="store_true")
    parser.add_argument("--event-time-offset-seconds", type=int, default=7200)
    args = parser.parse_args()

    client = _clickhouse_client()
    pack = _load_pack(Path(args.pack_path))
    batch_rules = [dict(rule) for rule in list(pack.get("batch_rules") or []) if isinstance(rule, dict)]
    event_rules = _event_rules(batch_rules)
    child_rules = _child_alert_rules(batch_rules)
    started_epoch = time.time()
    event_epoch = started_epoch + max(0, int(args.event_time_offset_seconds))
    expected_events = sum(max(1, int(rule.get("threshold") or 1)) for rule in event_rules)
    published_events = 0
    stored_events = 0

    if args.publish:
        published_events = await _publish_events(event_rules, args.run_id, event_epoch)
        stored_events = _wait_for_events(client, args.run_id, expected_events, args.wait_seconds, args.poll_interval)

    event_items = _execute_event_rules(client, event_rules, args.run_id, started_epoch - 30)
    inserted_child_alerts = _insert_child_alerts(client, child_rules, args.run_id)
    child_items = _execute_child_rules(client, child_rules, args.run_id, started_epoch - 30)
    items = event_items + child_items
    failed = [item for item in items if item["status"] != "ok"]
    cleanup_alerts: dict[str, int] = {}
    cleanup_events = 0
    if args.cleanup_alerts:
        cleanup_alerts = _close_test_alerts(client, args.run_id)
    if args.cleanup_events:
        cleanup_events = _delete_test_events(client, args.run_id)

    report = {
        "run_id": args.run_id,
        "started_utc": datetime.fromtimestamp(started_epoch, tz=timezone.utc).isoformat(),
        "finished_utc": datetime.now(timezone.utc).isoformat(),
        "active_batch_rules": len(batch_rules),
        "event_sql_rules": len(event_rules),
        "child_alert_correlation_rules": len(child_rules),
        "expected_source_events": expected_events,
        "published_events": published_events,
        "stored_events": stored_events,
        "inserted_child_alerts": inserted_child_alerts,
        "ok_rules": len(items) - len(failed),
        "failed_rules": len(failed),
        "transport": {
            "backend": transport_health_snapshot(None).get("backend"),
            "consumer_backend": transport_health_snapshot(None).get("consumer_backend"),
            "filtered_target": transport_health_snapshot(None).get("filtered_target"),
            "kafka_bootstrap_servers": transport_health_snapshot(None).get("kafka_bootstrap_servers"),
        },
        "cleanup_alerts": cleanup_alerts,
        "cleanup_events": cleanup_events,
        "failed": failed,
        "items": items,
    }
    if args.report_path:
        path = Path(args.report_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2), flush=True)
    return 0 if report["failed_rules"] == 0 and (not args.publish or stored_events >= expected_events) else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
