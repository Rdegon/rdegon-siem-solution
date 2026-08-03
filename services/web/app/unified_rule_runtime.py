from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable

from .correlation_pack_runtime import PACK_DIR


ACTIVE_AUTHORED_STATES = {"active", "publish_ready_after_host_metrics"}
RULE_IDENTITY_RE = re.compile(r"^(?:rule:)?([1-9][0-9]{0,9})$")


class RuleInventoryError(RuntimeError):
    pass


class RuleNotFoundError(RuleInventoryError):
    pass


class RuleConflictError(RuleInventoryError):
    pass


def _deps():
    from . import deps as deps_module

    return deps_module


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _client(client=None):
    return client or _deps().get_ch_client()


def _rows(client, sql: str) -> list[dict[str, Any]]:
    return [dict(row) for row in client.query(sql).named_results()]


def _latest_by_id(rows: Iterable[dict[str, Any]]) -> tuple[dict[int, dict[str, Any]], int]:
    grouped: dict[int, list[dict[str, Any]]] = {}
    for row in rows:
        rule_id = int(row.get("id") or 0)
        if rule_id > 0:
            grouped.setdefault(rule_id, []).append(dict(row))
    latest: dict[int, dict[str, Any]] = {}
    duplicate_rows = 0
    for rule_id, candidates in grouped.items():
        candidates.sort(key=lambda row: str(row.get("updated_ts") or row.get("created_ts") or ""), reverse=True)
        latest[rule_id] = candidates[0]
        duplicate_rows += max(0, len(candidates) - 1)
    return latest, duplicate_rows


def _query_sources(client) -> tuple[dict[str, dict[int, dict[str, Any]]], dict[str, Any]]:
    queries = {
        "stream": """
            SELECT id, name, description, enabled, severity, pattern, window_s,
                   threshold, expr, entity_field, created_ts, updated_ts
            FROM siem.correlation_rules_stream
            ORDER BY id, updated_ts DESC
        """,
        "batch": """
            SELECT id, name, description, enabled, severity, window_s,
                   sql_template, created_ts, updated_ts
            FROM siem.correlation_rules_batch
            ORDER BY id, updated_ts DESC
        """,
        "catalog": """
            SELECT id, title, sigma_id, status, level, source_format,
                   logsource_product, logsource_service, logsource_category,
                   expr, entity_field, window_s, threshold, tags, description,
                   enabled, author, created_ts, updated_ts
            FROM siem.detection_rule_catalog
            ORDER BY id, updated_ts DESC
        """,
    }
    sources: dict[str, dict[int, dict[str, Any]]] = {}
    issues: list[dict[str, str]] = []
    duplicates: dict[str, int] = {}
    for name, sql in queries.items():
        try:
            sources[name], duplicates[name] = _latest_by_id(_rows(client, sql))
        except Exception as exc:  # noqa: BLE001
            sources[name] = {}
            duplicates[name] = 0
            issues.append({"source": name, "error": str(exc)})
    return sources, {"duplicate_rows_collapsed": duplicates, "issues": issues}


def _processing_links(client) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for kind, table in (("normalizer", "siem.normalizer_rules"), ("filter", "siem.filter_rules")):
        try:
            rows = _rows(client, f"SELECT count() AS total, countIf(enabled = 1) AS enabled FROM {table}")
            row = rows[0] if rows else {}
            result.append(
                {
                    "kind": kind,
                    "table": table,
                    "total": int(row.get("total") or 0),
                    "enabled": int(row.get("enabled") or 0),
                    "counted_as_detection_rules": False,
                }
            )
        except Exception as exc:  # noqa: BLE001
            result.append(
                {
                    "kind": kind,
                    "table": table,
                    "total": None,
                    "enabled": None,
                    "counted_as_detection_rules": False,
                    "error": str(exc),
                }
            )
    return result


def _noise_metrics(client, *, days: int) -> dict[int, dict[str, Any]]:
    safe_days = max(1, min(int(days or 30), 90))
    sql = f"""
        SELECT rule_id,
               count() AS alert_count,
               sum(hits) AS hit_count,
               uniqExact(alert_id) AS unique_alerts,
               uniqExact(entity_key) AS unique_entities,
               countIf(lower(status) = 'false_positive') AS false_positive_count,
               countIf(lower(status) IN ('suppressed', 'suppressed_by_tuning')) AS suppressed_count,
               max(ts_last) AS last_alert_ts
        FROM siem.alerts_raw
        WHERE ts_last >= now() - INTERVAL {safe_days} DAY
        GROUP BY rule_id
    """
    try:
        metrics: dict[int, dict[str, Any]] = {}
        for row in _rows(client, sql):
            rule_id = int(row.get("rule_id") or 0)
            if rule_id <= 0:
                continue
            alert_count = int(row.get("alert_count") or 0)
            false_positive_count = int(row.get("false_positive_count") or 0)
            suppressed_count = int(row.get("suppressed_count") or 0)
            metrics[rule_id] = {
                "window_days": safe_days,
                "alert_count": alert_count,
                "hit_count": int(row.get("hit_count") or 0),
                "unique_alerts": int(row.get("unique_alerts") or 0),
                "unique_entities": int(row.get("unique_entities") or 0),
                "false_positive_count": false_positive_count,
                "false_positive_ratio": round(false_positive_count / alert_count, 4) if alert_count else 0.0,
                "suppressed_count": suppressed_count,
                "suppressed_ratio": round(suppressed_count / alert_count, 4) if alert_count else 0.0,
                "last_alert_ts": str(row.get("last_alert_ts") or ""),
                "source": "siem.alerts_raw",
            }
        return metrics
    except Exception:
        return {}


def _pack_index(pack_dir: Path) -> tuple[dict[int, list[dict[str, Any]]], list[dict[str, str]]]:
    index: dict[int, list[dict[str, Any]]] = {}
    issues: list[dict[str, str]] = []
    if not pack_dir.exists():
        return index, issues
    for path in sorted(pack_dir.glob("*.json")):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(payload, dict) or not str(payload.get("pack_id") or "").strip():
                continue
            pack = {
                "pack_id": str(payload.get("pack_id") or "").strip(),
                "pack_title": str(payload.get("title") or "").strip(),
                "pack_version": str(payload.get("version") or "1.0.0").strip(),
                "pack_status": str(payload.get("status") or "draft").strip().lower(),
                "pack_owner": str(payload.get("owner") or "").strip(),
                "file_name": path.name,
                "file_updated_ts": datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).isoformat().replace("+00:00", "Z"),
            }
            for engine, field in (("stream", "stream_rules"), ("batch", "batch_rules")):
                for raw in list(payload.get(field) or []):
                    if not isinstance(raw, dict) or int(raw.get("id") or 0) <= 0:
                        continue
                    rule = dict(pack)
                    rule.update(
                        {
                            "engine": engine,
                            "rule_id": int(raw.get("id") or 0),
                            "title": str(raw.get("title") or raw.get("name") or "").strip(),
                            "description": str(raw.get("description") or raw.get("operator_action") or "").strip(),
                            "severity": str(raw.get("severity") or "").strip().lower(),
                            "status": str(raw.get("status") or "draft").strip().lower(),
                            "window_s": int(raw.get("window_s") or 0),
                            "threshold": int(raw.get("threshold") or 0),
                            "replacement_rule_id": int(raw.get("replacement_rule_id") or 0),
                            "replacement_reason": str(raw.get("replacement_reason") or "").strip(),
                        }
                    )
                    index.setdefault(rule["rule_id"], []).append(rule)
        except Exception as exc:  # noqa: BLE001
            issues.append({"file_name": path.name, "error": str(exc)})
    return index, issues


def _identity(value: str | int) -> tuple[str, int]:
    match = RULE_IDENTITY_RE.fullmatch(str(value or "").strip())
    if not match:
        raise RuleInventoryError("Rule identity must be rule:<positive numeric id>")
    rule_id = int(match.group(1))
    return f"rule:{rule_id}", rule_id


def _pick_pack(records: list[dict[str, Any]], catalog: dict[str, Any]) -> dict[str, Any] | None:
    if not records:
        return None
    author = str(catalog.get("author") or "")
    if author.startswith("operational-pack:"):
        pack_id = author.split(":", 1)[1]
        matches = [record for record in records if record["pack_id"] == pack_id]
        if len(matches) == 1:
            return matches[0]
    unique_packs = {record["pack_id"] for record in records}
    return records[0] if len(unique_packs) == 1 else None


def _coalesce(*values: Any, default: Any = "") -> Any:
    for value in values:
        if value is not None and str(value).strip() != "":
            return value
    return default


def list_unified_rules(
    *,
    search: str = "",
    status: str = "",
    engine: str = "",
    pack_id: str = "",
    limit: int = 1000,
    offset: int = 0,
    noise_days: int = 30,
    client=None,
    pack_dir: Path | None = None,
) -> dict[str, Any]:
    ch = _client(client)
    sources, diagnostics = _query_sources(ch)
    packs, pack_issues = _pack_index(pack_dir or PACK_DIR)
    noise = _noise_metrics(ch, days=noise_days)
    rule_ids = sorted(set().union(*(set(rows) for rows in sources.values()), set(packs)))
    items: list[dict[str, Any]] = []
    for rule_id in rule_ids:
        stream = sources["stream"].get(rule_id, {})
        batch = sources["batch"].get(rule_id, {})
        catalog = sources["catalog"].get(rule_id, {})
        provenance = packs.get(rule_id, [])
        selected_pack = _pick_pack(provenance, catalog)
        engines = [name for name, row in (("stream", stream), ("batch", batch)) if row]
        if not engines:
            engines = sorted({str(record.get("engine") or "") for record in provenance if record.get("engine")})
        runtime_enabled = [bool(row.get("enabled")) for row in (stream, batch) if row]
        enabled = any(runtime_enabled)
        authored_statuses = {str(record.get("status") or "") for record in provenance}
        authored_active = bool(authored_statuses & ACTIVE_AUTHORED_STATES)
        catalog_enabled = bool(catalog.get("enabled")) if catalog else None
        issues: list[str] = []
        if len({record["pack_id"] for record in provenance}) > 1:
            issues.append("pack_provenance_conflict")
        if runtime_enabled and catalog_enabled is not None and catalog_enabled != enabled:
            issues.append("catalog_runtime_enabled_drift")
        if enabled and provenance and not authored_active:
            issues.append("authored_runtime_status_drift")
        if stream and batch:
            issues.append("shared_runtime_id_collapsed")
        replacement_id = max((int(record.get("replacement_rule_id") or 0) for record in provenance), default=0)
        if {"catalog_runtime_enabled_drift", "authored_runtime_status_drift"} & set(issues):
            state = "drift"
        elif enabled:
            state = "active"
        elif replacement_id > 0 or authored_statuses & {"retired", "deprecated", "replaced"}:
            state = "retired"
        elif stream or batch:
            state = "disabled"
        elif catalog or provenance:
            state = "unpublished"
        else:
            state = "unknown"
        updated_candidates = [
            str(row.get("updated_ts") or "") for row in (stream, batch, catalog) if row
        ] + [str(record.get("file_updated_ts") or "") for record in provenance]
        title = _coalesce(stream.get("name"), batch.get("name"), catalog.get("title"), selected_pack and selected_pack.get("title"), default=f"Rule {rule_id}")
        severity = str(_coalesce(stream.get("severity"), batch.get("severity"), catalog.get("level"), selected_pack and selected_pack.get("severity"), default="info")).lower()
        item = {
            "identity": f"rule:{rule_id}",
            "rule_id": rule_id,
            "title": str(title),
            "description": str(_coalesce(stream.get("description"), batch.get("description"), catalog.get("description"), selected_pack and selected_pack.get("description"))),
            "enabled": enabled,
            "status": state,
            "severity": severity,
            "kind": "hybrid" if len(engines) > 1 else (engines[0] if engines else "catalog"),
            "engines": engines,
            "version": str((selected_pack or {}).get("pack_version") or "runtime"),
            "source": "runtime" if stream or batch else ("catalog" if catalog else "authored_pack"),
            "pack": {
                "id": str((selected_pack or {}).get("pack_id") or ""),
                "title": str((selected_pack or {}).get("pack_title") or ""),
                "version": str((selected_pack or {}).get("pack_version") or ""),
                "owner": str((selected_pack or {}).get("pack_owner") or ""),
                "provenance": provenance,
            },
            "updated_ts": max(updated_candidates, default=""),
            "runtime": {
                "stream": stream or None,
                "batch": batch or None,
                "catalog": catalog or None,
                "source_records": [f"{name}:{rule_id}" for name, row in (("stream", stream), ("batch", batch), ("catalog", catalog)) if row],
            },
            "replacement": {
                "replacement_identity": f"rule:{replacement_id}" if replacement_id > 0 else "",
                "reason": next((str(record.get("replacement_reason") or "") for record in provenance if int(record.get("replacement_rule_id") or 0) == replacement_id), ""),
            },
            "execution_cost": {"state": "unavailable", "reason": "per-rule execution telemetry is not instrumented"},
            "noise": noise.get(rule_id, {"window_days": max(1, min(int(noise_days or 30), 90)), "alert_count": 0, "source": "siem.alerts_raw"}),
            "issues": issues,
            "capabilities": {
                "publish": bool(selected_pack and "stream" in engines and authored_active),
                "enable": bool(selected_pack and "stream" in engines),
                "disable": bool(selected_pack and "stream" in engines),
                "batch_write": False,
            },
        }
        items.append(item)

    needle = search.strip().lower()
    if needle:
        items = [item for item in items if needle in f"{item['identity']} {item['title']} {item['description']} {item['pack']['id']}".lower()]
    if status:
        items = [item for item in items if item["status"] == status.strip().lower()]
    if engine:
        items = [item for item in items if engine.strip().lower() in item["engines"]]
    if pack_id:
        items = [item for item in items if any(str(row.get("pack_id") or "") == pack_id for row in item["pack"]["provenance"])]
    total = len(items)
    safe_offset = max(0, int(offset or 0))
    safe_limit = max(1, min(int(limit or 1000), 5000))
    page = items[safe_offset:safe_offset + safe_limit]
    active_coverage = {item["identity"] for item in items if item["enabled"]}
    return {
        "items": page,
        "total": total,
        "limit": safe_limit,
        "offset": safe_offset,
        "summary": {
            "rule_count": total,
            "enabled_rule_count": len(active_coverage),
            "published_runtime_count": sum(1 for item in items if item["runtime"]["stream"] or item["runtime"]["batch"]),
            "coverage_count": len(active_coverage),
            "stream_count": sum(1 for item in items if "stream" in item["engines"]),
            "batch_count": sum(1 for item in items if "batch" in item["engines"]),
            "catalog_count": sum(1 for item in items if item["runtime"]["catalog"]),
            "linked_processing": _processing_links(ch),
        },
        "diagnostics": {**diagnostics, "pack_issues": pack_issues},
        "generated_ts": _now_iso(),
    }


def get_unified_rule(identity: str | int, *, client=None, pack_dir: Path | None = None) -> dict[str, Any]:
    stable_identity, _ = _identity(identity)
    inventory = list_unified_rules(client=client, pack_dir=pack_dir, limit=5000)
    item = next((row for row in inventory["items"] if row["identity"] == stable_identity), None)
    if item is None:
        raise RuleNotFoundError(f"Unknown rule: {stable_identity}")
    return item


def _pack_payload_for_rule(item: dict[str, Any], pack_dir: Path) -> tuple[Path, dict[str, Any]]:
    provenance = list(item.get("pack", {}).get("provenance") or [])
    pack_ids = {str(row.get("pack_id") or "") for row in provenance}
    selected_id = str(item.get("pack", {}).get("id") or "")
    if not selected_id or len(pack_ids) != 1:
        raise RuleConflictError("Rule has no unambiguous authored pack owner")
    path = pack_dir / next(str(row.get("file_name") or "") for row in provenance if row.get("pack_id") == selected_id)
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise RuleConflictError("Pack payload is invalid")
    return path, payload


def _audit(actor: str, action: str, identity: str, details: dict[str, Any]) -> None:
    from .control_plane_governance_runtime import append_audit_event

    append_audit_event(
        actor=actor,
        action=action,
        object_type="correlation_rule",
        object_id=identity,
        summary=f"Correlation rule {action}",
        details=details,
    )


def publish_unified_rule(
    identity: str | int,
    *,
    actor: str,
    client=None,
    pack_dir: Path | None = None,
    publisher: Callable[[str], dict[str, Any]] | None = None,
) -> dict[str, Any]:
    item = get_unified_rule(identity, client=client, pack_dir=pack_dir)
    if not item["capabilities"]["publish"]:
        raise RuleConflictError("Rule cannot be published by the stream pack publisher in its current state")
    pack = str(item["pack"]["id"])
    if publisher is None:
        from .correlation_pack_runtime import publish_correlation_pack

        publisher = publish_correlation_pack
    result = publisher(pack)
    _audit(actor, "published", item["identity"], {"pack_id": pack, "engines": item["engines"]})
    return {"status": "published", "identity": item["identity"], "pack_id": pack, "result": result}


def set_unified_rule_enabled(
    identity: str | int,
    *,
    enabled: bool,
    actor: str,
    reason: str = "",
    replacement_identity: str = "",
    client=None,
    pack_dir: Path | None = None,
    publisher: Callable[[str], dict[str, Any]] | None = None,
    saver: Callable[..., dict[str, Any]] | None = None,
) -> dict[str, Any]:
    root = pack_dir or PACK_DIR
    item = get_unified_rule(identity, client=client, pack_dir=root)
    if "stream" not in item["engines"] or not item["pack"]["id"]:
        raise RuleConflictError("Only stream rules with an authored pack can be toggled safely")
    replacement_id = 0
    if not enabled:
        if len(reason.strip()) < 8:
            raise RuleInventoryError("Disabling a rule requires a meaningful reason")
        if not replacement_identity:
            raise RuleInventoryError("Disabling a rule requires an active replacement rule")
        replacement = get_unified_rule(replacement_identity, client=client, pack_dir=root)
        if replacement["identity"] == item["identity"] or not replacement["enabled"]:
            raise RuleConflictError("Replacement rule must be a different active rule")
        replacement_id = int(replacement["rule_id"])
    _, payload = _pack_payload_for_rule(item, root)
    original = json.loads(json.dumps(payload))
    changed = False
    for raw in list(payload.get("stream_rules") or []):
        if isinstance(raw, dict) and int(raw.get("id") or 0) == int(item["rule_id"]):
            raw["status"] = "active" if enabled else "retired"
            if enabled:
                raw.pop("replacement_rule_id", None)
                raw.pop("replacement_reason", None)
            else:
                raw["replacement_rule_id"] = replacement_id
                raw["replacement_reason"] = reason.strip()
            changed = True
            break
    if not changed:
        raise RuleConflictError("Rule is not present in the pack stream_rules section")
    if saver is None or publisher is None:
        from .correlation_pack_runtime import publish_correlation_pack, save_correlation_pack

        saver = saver or save_correlation_pack
        publisher = publisher or publish_correlation_pack
    pack_id = str(payload.get("pack_id") or "")
    try:
        saver(payload, actor=actor)
        publish_result = publisher(pack_id)
    except Exception:
        saver(original, actor=f"{actor}:rollback")
        try:
            publisher(pack_id)
        except Exception:  # noqa: BLE001
            pass
        raise
    action = "enabled" if enabled else "retired_with_replacement"
    _audit(
        actor,
        action,
        item["identity"],
        {"pack_id": pack_id, "reason": reason.strip(), "replacement_identity": f"rule:{replacement_id}" if replacement_id else ""},
    )
    return {
        "status": action,
        "identity": item["identity"],
        "enabled": enabled,
        "pack_id": pack_id,
        "replacement_identity": f"rule:{replacement_id}" if replacement_id else "",
        "result": publish_result,
    }
