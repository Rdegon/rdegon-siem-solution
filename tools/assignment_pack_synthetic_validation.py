from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

try:  # pragma: no cover - VM4 web venv uses clickhouse_connect only.
    import clickhouse_driver  # noqa: F401
except ModuleNotFoundError:  # pragma: no cover
    import types

    clickhouse_driver_stub = types.ModuleType("clickhouse_driver")
    clickhouse_driver_stub.Client = object  # type: ignore[attr-defined]
    sys.modules["clickhouse_driver"] = clickhouse_driver_stub

try:
    from services.filter.filter_core import eval_expr, parse_expr  # noqa: E402
except ModuleNotFoundError:  # pragma: no cover - VM4 may have another top-level services package.
    FILTER_ROOT = ROOT / "services" / "filter"
    sys.path.insert(0, str(FILTER_ROOT))
    from filter_core import eval_expr, parse_expr  # type: ignore[import-not-found]  # noqa: E402


def _field_contains(value: str, expected: str, *, case_sensitive: bool) -> bool:
    return expected in value if case_sensitive else expected.lower() in value.lower()


def _set_value(event: dict[str, str], locks: set[str], field: str, value: str, *, lock: bool = False) -> bool:
    current = event.get(field)
    if current is not None and current != value:
        if field in locks or lock:
            return False
        value = f"{current} {value}"
    event[field] = value
    if lock:
        locks.add(field)
    return True


def _apply_cmp(
    event: dict[str, str],
    locks: set[str],
    compared: set[str],
    field: str,
    op: str,
    value: str,
    *,
    negated: bool = False,
) -> bool:
    compared.add(field)
    current = event.get(field, "")
    if op == "==":
        if negated:
            if current == value:
                if field in locks:
                    return False
                event[field] = f"{value}_not_synthetic"
            elif field not in event:
                event[field] = f"{value}_not_synthetic"
            return True
        return _set_value(event, locks, field, value, lock=True)
    if op == "!=":
        if negated:
            return _set_value(event, locks, field, value, lock=True)
        if current == value:
            if field in locks:
                return False
            event[field] = f"{value}_not_synthetic"
        elif field not in event:
            event[field] = f"{value}_not_synthetic"
        return True
    if op in {"contains", "icontains"}:
        case_sensitive = op == "contains"
        if negated:
            if current and _field_contains(current, value, case_sensitive=case_sensitive):
                return False
            event.setdefault(field, "")
            return True
        if current:
            if _field_contains(current, value, case_sensitive=case_sensitive):
                return True
            if field in locks:
                return False
            event[field] = f"{current} {value}"
            return True
        event[field] = f"synthetic {value} validation"
        return True
    if op == "startswith":
        if negated:
            event.setdefault(field, f"not_{value}")
            return not event[field].startswith(value)
        event[field] = f"{value}_synthetic"
        return True
    if op == "endswith":
        if negated:
            event.setdefault(field, f"{value}_not")
            return not event[field].endswith(value)
        event[field] = f"synthetic_{value}"
        return True
    return False


def _satisfy_node(
    node: Any,
    event: dict[str, str],
    locks: set[str],
    compared: set[str],
) -> tuple[bool, dict[str, str], set[str], set[str]]:
    kind = node[0]
    if kind == "cmp":
        next_event = dict(event)
        next_locks = set(locks)
        next_compared = set(compared)
        ok = _apply_cmp(next_event, next_locks, next_compared, node[1], node[2], str(node[3]))
        return ok, next_event, next_locks, next_compared
    if kind == "not":
        child = node[1]
        if child[0] == "cmp":
            next_event = dict(event)
            next_locks = set(locks)
            next_compared = set(compared)
            ok = _apply_cmp(next_event, next_locks, next_compared, child[1], child[2], str(child[3]), negated=True)
            return ok, next_event, next_locks, next_compared
        return True, dict(event), set(locks), set(compared)
    if kind == "and":
        ok, left_event, left_locks, left_compared = _satisfy_node(node[1], event, locks, compared)
        if not ok:
            return False, event, locks, compared
        return _satisfy_node(node[2], left_event, left_locks, left_compared)
    if kind == "or":
        for branch in (node[1], node[2]):
            ok, branch_event, branch_locks, branch_compared = _satisfy_node(
                branch,
                dict(event),
                set(locks),
                set(compared),
            )
            if ok:
                return True, branch_event, branch_locks, branch_compared
        return False, event, locks, compared
    return False, event, locks, compared


def _stream_synthetic_check(rule: dict[str, Any]) -> dict[str, Any]:
    ast = parse_expr(str(rule.get("expr") or ""))
    ok, event, locks, compared = _satisfy_node(ast, {}, set(), set())
    marker = f"synthetic-assignment-rule-{rule['id']}"
    defaults = {
        "tags": "",
        "event.kind": "event",
        "event.action": "synthetic_validation",
        "event.outcome": "success",
        "event.original": marker,
        "message": marker,
        "host.name": f"synthetic-host-{rule['id']}",
        "log_source": f"synthetic-source-{rule['id']}",
        "source.ip": f"198.18.{int(rule['id']) // 256}.{int(rule['id']) % 256}",
        "destination.ip": f"198.19.{int(rule['id']) // 256}.{int(rule['id']) % 256}",
        "user.name": f"synthetic-user-{rule['id']}",
        "user.target.name": f"synthetic-target-{rule['id']}",
        "process.command_line": marker,
    }
    for field, value in defaults.items():
        event.setdefault(field, value)
    entity_field = str(rule.get("entity_field") or "host.name")
    event.setdefault(entity_field, defaults.get(entity_field, marker))
    matched = bool(ok and eval_expr(ast, event))
    return {
        "id": rule.get("id"),
        "source_id": rule.get("source_id"),
        "synthetic_event_generated": bool(ok),
        "synthetic_event_matches": matched,
        "compared_fields": sorted(compared),
        "locked_fields": sorted(locks),
        "sample_event": {key: event[key] for key in sorted(event) if key in compared or key == entity_field},
    }


def _batch_synthetic_check(rule: dict[str, Any]) -> dict[str, Any]:
    sql = str(rule.get("sql_template") or "")
    status = str(rule.get("status") or "")
    threshold = int(rule.get("threshold") or 1)
    has_threshold = f"HAVING hits >= {threshold}" in sql or "HAVING matched_rules >=" in sql
    return {
        "id": rule.get("id"),
        "source_id": rule.get("source_id"),
        "status": status,
        "sql_template_present": bool(sql.strip()),
        "writes_alerts_raw": "INSERT INTO siem.alerts_raw" in sql,
        "has_window_placeholder": "{WINDOW_S}" in sql,
        "has_threshold_guard": has_threshold,
        "synthetic_sql_ready": bool(sql.strip() and "INSERT INTO siem.alerts_raw" in sql and has_threshold),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Offline synthetic validation for assignment detection pack.")
    parser.add_argument("--pack-path", default="correlation_rule_packs/siem_detection_pack_v1.json")
    parser.add_argument("--report-path", default="")
    args = parser.parse_args()

    pack = json.loads(Path(args.pack_path).read_text(encoding="utf-8"))
    stream_items: list[dict[str, Any]] = []
    stream_errors: list[dict[str, Any]] = []
    for rule in pack.get("stream_rules", []):
        try:
            item = _stream_synthetic_check(rule)
        except Exception as exc:  # noqa: BLE001
            item = {"id": rule.get("id"), "source_id": rule.get("source_id"), "error": f"{type(exc).__name__}: {exc}"}
        stream_items.append(item)
        if not item.get("synthetic_event_matches"):
            stream_errors.append(item)

    batch_items = [_batch_synthetic_check(rule) for rule in pack.get("batch_rules", [])]
    batch_errors = [item for item in batch_items if not item.get("synthetic_sql_ready")]
    report = {
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "pack_path": args.pack_path,
        "stream_rules": len(stream_items),
        "stream_synthetic_ok": len(stream_items) - len(stream_errors),
        "stream_synthetic_failed": len(stream_errors),
        "batch_rules": len(batch_items),
        "batch_synthetic_sql_ready": len(batch_items) - len(batch_errors),
        "batch_synthetic_sql_failed": len(batch_errors),
        "stream_errors": stream_errors,
        "batch_errors": batch_errors,
        "sample_stream_items": stream_items[:20],
    }
    if args.report_path:
        path = Path(args.report_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if not stream_errors and not batch_errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
