from __future__ import annotations

import argparse
import asyncio
import json
import time
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from clickhouse_driver import Client

from services.stream_corr.config import StreamCorrSettings
from services.stream_corr.rules import StreamCorrRule, load_stream_rules, matches_rule
from services.transport_runtime import create_transport_producer, transport_health_snapshot


MARKER_FIELDS = (
    "host.name",
    "log_source",
    "process.command_line",
    "event.action",
    "user.name",
    "user.target.name",
)


def _field_contains(value: str, expected: str, *, case_sensitive: bool) -> bool:
    if case_sensitive:
        return expected in value
    return expected.lower() in value.lower()


def _set_value(
    event: dict[str, str],
    equal_locks: set[str],
    field: str,
    value: str,
    *,
    equal_lock: bool = False,
) -> bool:
    current = event.get(field)
    if current is not None and current != value:
        if field in equal_locks or equal_lock:
            return False
        value = f"{current} {value}"
    event[field] = value
    if equal_lock:
        equal_locks.add(field)
    return True


def _apply_cmp(
    event: dict[str, str],
    equal_locks: set[str],
    compared_fields: set[str],
    field: str,
    op: str,
    value: str,
    *,
    negated: bool = False,
) -> bool:
    compared_fields.add(field)
    current = event.get(field, "")

    if op == "==":
        if negated:
            if current == value:
                if field in equal_locks:
                    return False
                event[field] = f"{value}_not_e2e"
            elif field not in event:
                event[field] = f"{value}_not_e2e"
            return True
        return _set_value(event, equal_locks, field, value, equal_lock=True)

    if op == "!=":
        if negated:
            return _set_value(event, equal_locks, field, value, equal_lock=True)
        if current == value:
            if field in equal_locks:
                return False
            event[field] = f"{value}_not_e2e"
        elif field not in event:
            event[field] = f"{value}_not_e2e"
        return True

    if op in {"contains", "icontains"}:
        case_sensitive = op == "contains"
        if negated:
            if current and _field_contains(current, value, case_sensitive=case_sensitive):
                return False
            if field not in event:
                event[field] = ""
            return True
        if current:
            if _field_contains(current, value, case_sensitive=case_sensitive):
                return True
            if field in equal_locks:
                return False
            event[field] = f"{current} {value}"
            return True
        event[field] = f"e2e {value} validation"
        return True

    if op == "startswith":
        if negated:
            if current.startswith(value):
                return False
            if field not in event:
                event[field] = f"not_{value}"
            return True
        if current:
            if current.startswith(value):
                return True
            if field in equal_locks:
                return False
        event[field] = f"{value}_e2e_validation"
        return True

    if op == "endswith":
        if negated:
            if current.endswith(value):
                return False
            if field not in event:
                event[field] = f"{value}_not"
            return True
        if current:
            if current.endswith(value):
                return True
            if field in equal_locks:
                return False
        event[field] = f"e2e_validation_{value}"
        return True

    return False


def _satisfy_node(
    node: Any,
    event: dict[str, str],
    equal_locks: set[str],
    compared_fields: set[str],
) -> tuple[bool, dict[str, str], set[str], set[str]]:
    kind = node[0]
    if kind == "cmp":
        next_event = dict(event)
        next_locks = set(equal_locks)
        next_compared = set(compared_fields)
        ok = _apply_cmp(next_event, next_locks, next_compared, node[1], node[2], node[3])
        return ok, next_event, next_locks, next_compared

    if kind == "not":
        child = node[1]
        if child[0] == "cmp":
            next_event = dict(event)
            next_locks = set(equal_locks)
            next_compared = set(compared_fields)
            ok = _apply_cmp(next_event, next_locks, next_compared, child[1], child[2], child[3], negated=True)
            return ok, next_event, next_locks, next_compared
        # Complex negations are uncommon in the rule pack. Leave fields unchanged
        # and rely on the final matches_rule() check to reject unsupported cases.
        return True, dict(event), set(equal_locks), set(compared_fields)

    if kind == "and":
        ok, left_event, left_locks, left_compared = _satisfy_node(node[1], event, equal_locks, compared_fields)
        if not ok:
            return False, event, equal_locks, compared_fields
        return _satisfy_node(node[2], left_event, left_locks, left_compared)

    if kind == "or":
        for branch in (node[1], node[2]):
            ok, branch_event, branch_locks, branch_compared = _satisfy_node(
                branch,
                dict(event),
                set(equal_locks),
                set(compared_fields),
            )
            if ok:
                return True, branch_event, branch_locks, branch_compared
        return False, event, equal_locks, compared_fields

    return False, event, equal_locks, compared_fields


def _unique_value(field: str, run_id: str, rule_id: int) -> str:
    suffix = f"{run_id}-r{rule_id}"
    if field in {"source.ip", "destination.ip"}:
        return f"198.18.{rule_id // 256}.{rule_id % 256}"
    if field == "rule.id":
        return f"e2e-{suffix}"
    return f"e2e-{suffix}"


def _add_defaults(
    event: dict[str, str],
    equal_locks: set[str],
    compared_fields: set[str],
    rule: StreamCorrRule,
    run_id: str,
) -> None:
    marker = f"e2e-rule-validation-{run_id}-rule-{rule.id}"
    defaults = {
        "tags": "",
        "event.kind": "event",
        "event.category": "process",
        "event.action": "e2e_validation",
        "event.outcome": "success",
        "event.code": str(rule.id),
        "event.id": f"{run_id}-{rule.id}",
        "host.name": f"e2e-host-{run_id}-r{rule.id}",
        "log_source": f"e2e-source-{run_id}",
        "source.ip": _unique_value("source.ip", run_id, rule.id),
        "destination.ip": _unique_value("destination.ip", run_id, rule.id),
        "user.name": f"e2e-user-{run_id}-r{rule.id}",
        "user.target.name": f"e2e-target-{run_id}-r{rule.id}",
        "process.name": "e2e-validation.exe",
        "process.executable": f"/tmp/e2e-validation-{run_id}-r{rule.id}",
        "process.command_line": marker,
        "repository.name": f"e2e-repo-{run_id}-r{rule.id}",
        "message": marker,
    }
    for field, value in defaults.items():
        if field not in event:
            event[field] = value

    if rule.entity_field not in event:
        event[rule.entity_field] = _unique_value(rule.entity_field, run_id, rule.id)

    # Make every generated alert searchable by run_id in current worker context
    # without altering fields that are equality-constrained by the rule.
    if not any(run_id in str(event.get(field, "")) for field in MARKER_FIELDS + (rule.entity_field,)):
        for field in MARKER_FIELDS:
            if field not in equal_locks and field not in compared_fields:
                event[field] = marker
                break


def synthesize_event(rule: StreamCorrRule, run_id: str, event_epoch: float) -> tuple[dict[str, str], str | None]:
    if rule.expr_ast is None:
        return {}, "expr_parse_failed"
    ok, event, equal_locks, compared_fields = _satisfy_node(rule.expr_ast, {}, set(), set())
    if not ok:
        return event, "expr_unsatisfied"
    _add_defaults(event, equal_locks, compared_fields, rule, run_id)
    ts = datetime.fromtimestamp(event_epoch, tz=timezone.utc).isoformat().replace("+00:00", "Z")
    event["ts"] = ts
    event["@timestamp"] = ts
    event["event.created"] = ts
    event["e2e.run_id"] = run_id
    event["e2e.rule_id"] = str(rule.id)
    event["e2e.validation"] = "stream_rules"
    if not str(event.get(rule.entity_field) or ""):
        event[rule.entity_field] = _unique_value(rule.entity_field, run_id, rule.id)
    if not matches_rule(rule, event):
        return event, "synthetic_event_does_not_match_rule"
    return event, None


def _clickhouse_client(settings: StreamCorrSettings) -> Client:
    return Client(
        host=settings.ch_host,
        port=settings.ch_port,
        user=settings.ch_user,
        password=settings.ch_password,
        database=settings.ch_db,
        send_receive_timeout=max(settings.ch_timeout_secs, 60),
    )


def _fetch_alerts(client: Client, run_id: str, since_epoch: float) -> dict[int, dict[str, Any]]:
    since = datetime.fromtimestamp(since_epoch, tz=timezone.utc).replace(tzinfo=None)
    rows = client.execute(
        """
        SELECT
            rule_id,
            any(rule_name) AS rule_name,
            max(hits) AS max_hits,
            count() AS alerts_count,
            any(entity_key) AS sample_entity,
            max(ts) AS last_ts
        FROM siem.alerts_raw
        WHERE ts >= %(since)s
          AND (
            position(context_json, %(run_id)s) > 0
            OR position(source, %(run_id)s) > 0
            OR position(entity_key, %(run_id)s) > 0
          )
        GROUP BY rule_id
        """,
        {"since": since, "run_id": run_id},
    )
    return {
        int(row[0]): {
            "rule_name": str(row[1]),
            "max_hits": int(row[2]),
            "alerts_count": int(row[3]),
            "sample_entity": str(row[4]),
            "last_ts": str(row[5]),
        }
        for row in rows
    }


def _sql_string(value: str) -> str:
    return value.replace("\\", "\\\\").replace("'", "\\'")


def _close_test_alerts(client: Client, run_id: str) -> dict[str, int]:
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
    where_by_table = {
        "siem.alerts_raw": (
            f"rule_id BETWEEN 8001 AND 8487 AND "
            f"(({raw_run_marker}) OR ({raw_e2e_marker}))"
        ),
        "siem.alerts_agg": (
            f"rule_id BETWEEN 8001 AND 8487 AND "
            f"(({agg_run_marker}) OR ({agg_e2e_marker}))"
        ),
    }
    result: dict[str, int] = {}
    for table, where in where_by_table.items():
        count = int(client.execute(f"SELECT count() FROM {table} WHERE {where}")[0][0])
        result[table] = count
        if count:
            client.execute(
                f"""
                ALTER TABLE {table}
                UPDATE status = 'false_positive',
                       assignee = 'assignment-full-stream-e2e-validation',
                       updated_ts = now()
                WHERE {where}
                SETTINGS mutations_sync = 1
                """
            )
    return result


def _delete_test_events(client: Client, run_id: str) -> int:
    rid = _sql_string(run_id)
    where = (
        f"position(message, '{rid}') > 0 OR "
        f"position(normalized_json, '{rid}') > 0 OR "
        f"position(log_source, '{rid}') > 0 OR "
        f"position(host_name, '{rid}') > 0"
    )
    count = int(client.execute(f"SELECT count() FROM siem.events WHERE {where}")[0][0])
    if count:
        client.execute(f"ALTER TABLE siem.events DELETE WHERE {where} SETTINGS mutations_sync = 1")
    return count


async def _publish_events(rules: list[StreamCorrRule], events: dict[int, dict[str, str]], publish_multiplier: int) -> int:
    producer = create_transport_producer(StreamCorrSettings.load())
    published = 0
    try:
        for rule in rules:
            base_event = events[rule.id]
            repetitions = max(1, int(rule.threshold)) * max(1, publish_multiplier)
            for index in range(repetitions):
                payload = dict(base_event)
                payload["event.sequence"] = str(index + 1)
                payload["event.id"] = f"{base_event['e2e.run_id']}-{rule.id}-{index + 1}"
                await producer.publish("filtered", payload)
                published += 1
                if published % 1000 == 0:
                    print(json.dumps({"stage": "publish_progress", "published": published}, ensure_ascii=False), flush=True)
    finally:
        await producer.close()
    return published


def _build_report(
    *,
    run_id: str,
    rules: list[StreamCorrRule],
    generated: dict[int, dict[str, str]],
    generation_errors: dict[int, str],
    alerts: dict[int, dict[str, Any]],
    published_events: int,
    started_epoch: float,
    transport: dict[str, Any],
    cleanup_alerts: dict[str, int] | None = None,
    cleanup_events: int = 0,
) -> dict[str, Any]:
    items: list[dict[str, Any]] = []
    for rule in rules:
        alert = alerts.get(rule.id)
        error = generation_errors.get(rule.id)
        status = "ok" if alert and not error else "failed"
        items.append(
            {
                "id": rule.id,
                "name": rule.name,
                "severity": rule.severity,
                "entity_field": rule.entity_field,
                "threshold": rule.threshold,
                "window_s": rule.window_s,
                "expr": rule.expr_text,
                "synthetic_match": rule.id in generated and not error,
                "generation_error": error,
                "alert_created": bool(alert),
                "alert": alert or {},
                "status": status,
            }
        )
    failed = [item for item in items if item["status"] != "ok"]
    return {
        "run_id": run_id,
        "started_utc": datetime.fromtimestamp(started_epoch, tz=timezone.utc).isoformat(),
        "finished_utc": datetime.now(timezone.utc).isoformat(),
        "active_rules": len(rules),
        "published_events": published_events,
        "alerts_by_rule": len(alerts),
        "ok_rules": len(items) - len(failed),
        "failed_rules": len(failed),
        "transport": {
            "backend": transport.get("backend"),
            "consumer_backend": transport.get("consumer_backend"),
            "filtered_target": transport.get("filtered_target"),
            "kafka_bootstrap_servers": transport.get("kafka_bootstrap_servers"),
        },
        "cleanup_alerts": cleanup_alerts or {},
        "cleanup_events": cleanup_events,
        "failed": failed,
        "items": items,
    }


async def main() -> int:
    parser = argparse.ArgumentParser(description="End-to-end validation for active SIEM stream correlation rules.")
    parser.add_argument("--run-id", default=datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ"))
    parser.add_argument("--publish", action="store_true", help="Publish synthetic events into the filtered transport.")
    parser.add_argument("--wait-seconds", type=int, default=600)
    parser.add_argument("--poll-interval", type=float, default=5.0)
    parser.add_argument("--report-path", default="")
    parser.add_argument("--publish-multiplier", type=int, default=1)
    parser.add_argument("--rule-id-min", type=int, default=0)
    parser.add_argument("--rule-id-max", type=int, default=0)
    parser.add_argument("--cleanup-alerts", action="store_true")
    parser.add_argument("--cleanup-events", action="store_true")
    parser.add_argument("--event-time-offset-seconds", type=int, default=7200)
    args = parser.parse_args()

    settings = StreamCorrSettings.load()
    rules = load_stream_rules(settings)
    if args.rule_id_min:
        rules = [rule for rule in rules if rule.id >= args.rule_id_min]
    if args.rule_id_max:
        rules = [rule for rule in rules if rule.id <= args.rule_id_max]
    client = _clickhouse_client(settings)
    transport = transport_health_snapshot(settings)
    started_epoch = time.time()
    event_epoch = started_epoch + max(0, args.event_time_offset_seconds)

    generated: dict[int, dict[str, str]] = {}
    generation_errors: dict[int, str] = {}
    for rule in rules:
        event, error = synthesize_event(rule, args.run_id, event_epoch)
        if error:
            generation_errors[rule.id] = error
        else:
            generated[rule.id] = event

    if generation_errors:
        report = _build_report(
            run_id=args.run_id,
            rules=rules,
            generated=generated,
            generation_errors=generation_errors,
            alerts={},
            published_events=0,
            started_epoch=started_epoch,
            transport=transport,
        )
        print(json.dumps(report, ensure_ascii=False, indent=2), flush=True)
        return 2

    published_events = 0
    if args.publish:
        published_events = await _publish_events(rules, generated, args.publish_multiplier)

    alerts: dict[int, dict[str, Any]] = {}
    deadline = time.time() + max(0, args.wait_seconds)
    while True:
        alerts = _fetch_alerts(client, args.run_id, started_epoch - 30)
        missing = len(rules) - len(alerts)
        print(
            json.dumps(
                {"stage": "alert_poll", "alerts_by_rule": len(alerts), "missing_rules": missing},
                ensure_ascii=False,
            ),
            flush=True,
        )
        if not args.publish or missing <= 0 or time.time() >= deadline:
            break
        await asyncio.sleep(max(1.0, args.poll_interval))

    cleanup_alerts: dict[str, int] = {}
    cleanup_events = 0
    if args.cleanup_alerts:
        cleanup_alerts = _close_test_alerts(client, args.run_id)
    if args.cleanup_events:
        cleanup_events = _delete_test_events(client, args.run_id)

    report = _build_report(
        run_id=args.run_id,
        rules=rules,
        generated=generated,
        generation_errors=generation_errors,
        alerts=alerts,
        published_events=published_events,
        started_epoch=started_epoch,
        transport=transport,
        cleanup_alerts=cleanup_alerts,
        cleanup_events=cleanup_events,
    )
    if args.report_path:
        path = Path(args.report_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2), flush=True)
    return 0 if report["failed_rules"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
