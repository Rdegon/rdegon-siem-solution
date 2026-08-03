
from __future__ import annotations

import json
import hashlib
import logging
import re
import threading
from time import time, time_ns
import uuid

from fastapi import APIRouter, Body, Depends, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from starlette.concurrency import run_in_threadpool

from .auth import canonical_ui_redirect_path, get_current_user
from .. import deps as deps_module
from ..security import require_permissions
from ..deps import (
    INCIDENT_STATUS_TRANSITIONS,
    fetch_alert_history,
    fetch_alerts_agg,
    fetch_alerts_raw,
    fetch_incident_detail_bundle,
    update_alert_assignment,
)
from ..incident_ai_runtime import run_incident_host_action
from ..incident_delivery_runtime import (
    enrich_incidents_with_delivery,
    record_incident_delivery,
)
try:
    from ..operational_filters import is_non_operational_record
except ImportError:  # pragma: no cover - local test fallback
    from operational_filters import is_non_operational_record  # type: ignore[no-redef]
from ..templates import templates
from ..ui_text import ui_context

router = APIRouter()
logger = logging.getLogger("siem_web.incidents")

_INCIDENT_LIST_CACHE: dict[str, tuple[float, dict]] = {}
INCIDENT_LIST_CACHE_TTL_SECONDS = 30
INCIDENT_WORKFLOW_NOTE_PREFIX = "sentinel:incident-workflow:v1:"
INCIDENT_WORKFLOW_MAX_ALERTS = 500
INCIDENT_SEVERITIES = {"info", "low", "medium", "high", "critical"}
_INCIDENT_WORKFLOW_LOCK = threading.RLock()


class IncidentWorkflowConflict(ValueError):
    pass


def _workflow_json(value: dict) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _workflow_fingerprint(operation: str, payload: dict) -> str:
    material = {
        key: value
        for key, value in payload.items()
        if key not in {"idempotency_key", "expected_revision", "target_expected_revision"}
    }
    encoded = _workflow_json({"operation": operation, "payload": material})
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _load_incident_workflow_events() -> list[dict]:
    query = f"""
        SELECT changed_ts, record_id, rule_id, changed_by, note
        FROM {deps_module.ALERT_HISTORY_TABLE}
        WHERE startsWith(note, {deps_module._sql_quote(INCIDENT_WORKFLOW_NOTE_PREFIX)})
        ORDER BY changed_ts ASC
        LIMIT 20000
    """
    events: list[dict] = []
    for row in deps_module.get_ch_client().query(query).named_results():
        note = str(row.get("note") or "")
        if not note.startswith(INCIDENT_WORKFLOW_NOTE_PREFIX):
            continue
        try:
            event = json.loads(note[len(INCIDENT_WORKFLOW_NOTE_PREFIX):])
        except (TypeError, ValueError, json.JSONDecodeError):
            continue
        if not isinstance(event, dict):
            continue
        event.setdefault("incident_id", str(row.get("record_id") or ""))
        event["changed_ts"] = deps_module._fmt(row.get("changed_ts"))
        event["changed_by"] = str(row.get("changed_by") or event.get("changed_by") or "")
        event["rule_id"] = int(row.get("rule_id") or event.get("rule_id") or 0)
        events.append(event)
    events.sort(
        key=lambda event: (
            str(event.get("changed_ts") or ""),
            int(event.get("sequence_ns") or 0),
            str(event.get("event_id") or ""),
        )
    )
    return events


def _empty_workflow_state(incident_id: str) -> dict:
    return {
        "incident_id": incident_id,
        "manual": False,
        "title": "",
        "severity": "",
        "status": "",
        "base_alert_ids": [],
        "linked_alert_ids": [],
        "unlinked_alert_ids": [],
        "merged_into": "",
        "operations": [],
        "revision": "0",
    }


def _append_unique(values: list[str], value: str) -> None:
    if value and value not in values:
        values.append(value)


def _build_incident_workflow_states(events: list[dict]) -> dict[str, dict]:
    states: dict[str, dict] = {}

    def state_for(incident_id: str) -> dict:
        return states.setdefault(incident_id, _empty_workflow_state(incident_id))

    for event in events:
        operation = str(event.get("operation") or "")
        incident_id = str(event.get("incident_id") or "").strip()
        if not incident_id or not operation:
            continue
        state = state_for(incident_id)
        state["operations"].append(event)
        if operation == "create":
            state["manual"] = True
            state["title"] = str(event.get("title") or "")
            state["severity"] = str(event.get("severity") or "")
            state["status"] = str(event.get("status") or "open")
            state["base_alert_ids"] = [str(value) for value in event.get("alert_ids", []) if str(value).strip()]
        elif operation == "severity":
            state["severity"] = str(event.get("severity") or "")
        elif operation == "link":
            alert_id = str(event.get("alert_id") or "").strip()
            _append_unique(state["linked_alert_ids"], alert_id)
            state["unlinked_alert_ids"] = [value for value in state["unlinked_alert_ids"] if value != alert_id]
        elif operation == "unlink":
            alert_id = str(event.get("alert_id") or "").strip()
            _append_unique(state["unlinked_alert_ids"], alert_id)
            state["linked_alert_ids"] = [value for value in state["linked_alert_ids"] if value != alert_id]
        elif operation == "merge":
            target_id = str(event.get("target_incident_id") or "").strip()
            state["merged_into"] = target_id
            if target_id:
                target = state_for(target_id)
                target["operations"].append(event)
                for alert_id in event.get("alert_ids", []):
                    _append_unique(target["linked_alert_ids"], str(alert_id).strip())

    for state in states.values():
        event_ids = [str(event.get("event_id") or "") for event in state["operations"]]
        if event_ids:
            state["revision"] = hashlib.sha256("|".join(event_ids).encode("utf-8")).hexdigest()[:16]
    return states


def _effective_alert_ids(state: dict, base_alert_ids: list[str] | None = None) -> list[str]:
    values: list[str] = []
    for alert_id in [*(base_alert_ids or []), *state.get("base_alert_ids", []), *state.get("linked_alert_ids", [])]:
        _append_unique(values, str(alert_id).strip())
    excluded = {str(value) for value in state.get("unlinked_alert_ids", [])}
    return [value for value in values if value not in excluded]


def _raw_alerts_by_ids(alert_ids: list[str]) -> list[dict]:
    unique_ids: list[str] = []
    for alert_id in alert_ids:
        _append_unique(unique_ids, str(alert_id).strip())
    if not unique_ids:
        return []
    if len(unique_ids) > INCIDENT_WORKFLOW_MAX_ALERTS:
        raise ValueError(f"At most {INCIDENT_WORKFLOW_MAX_ALERTS} raw alerts can be attached to one incident operation")
    values = ", ".join(deps_module._sql_quote(value) for value in unique_ids)
    query = f"""
        SELECT
            ts, toString(alert_id) AS alert_id, rule_id, rule_name, lower(severity) AS severity,
            ts_first, ts_last, window_s, entity_key, hits, context_json, source,
            lower(status) AS status, assignee, updated_ts
        FROM siem.alerts_raw
        WHERE toString(alert_id) IN ({values})
        ORDER BY ts_last DESC
        LIMIT {len(unique_ids)}
    """
    rows: list[dict] = []
    for row in deps_module.get_ch_client().query(query).named_results():
        item = dict(row)
        for key in ("ts", "ts_first", "ts_last", "updated_ts"):
            item[key] = deps_module._fmt(item.get(key))
        item["alert_id"] = str(item.get("alert_id") or "")
        item["rule_id"] = int(item.get("rule_id") or 0)
        item["hits"] = int(item.get("hits") or 0)
        item["context"] = _json_loads_safe(item.get("context_json"))
        rows.append(item)
    by_id = {str(row.get("alert_id")): row for row in rows}
    return [by_id[alert_id] for alert_id in unique_ids if alert_id in by_id]


def _find_aggregate_incident(incident_id: str) -> dict | None:
    for row in fetch_alerts_agg(limit=5000, window="30d"):
        identifiers = {
            str(row.get("agg_id") or ""),
            str(row.get("record_id") or ""),
            str(row.get("storage_agg_id") or ""),
            str(row.get("entity_key") or ""),
        }
        if incident_id in identifiers:
            return row
    return None


def _base_incident_alert_ids(incident: dict | None) -> list[str]:
    if not incident:
        return []
    alert_ids = [str(value) for value in incident.get("alert_ids", []) if str(value).strip()]
    if alert_ids:
        return alert_ids
    matched = deps_module._match_alert_ids_for_materialized_incident(incident, limit=INCIDENT_WORKFLOW_MAX_ALERTS)
    if not matched:
        incident_key = str(incident.get("agg_id") or incident.get("record_id") or "")
        matched = deps_module._match_alert_ids_for_incident_scope(
            incident_key,
            window="30d",
            limit=INCIDENT_WORKFLOW_MAX_ALERTS,
        )
    return [str(value) for value in matched]


def _workflow_incident_exists(incident_id: str, states: dict[str, dict]) -> tuple[dict | None, dict]:
    state = states.get(incident_id, _empty_workflow_state(incident_id))
    incident = _find_aggregate_incident(incident_id)
    if incident is None and not state.get("manual"):
        raise ValueError(f"Incident not found: {incident_id}")
    return incident, state


def _require_idempotency(payload: dict) -> str:
    key = str(payload.get("idempotency_key") or "").strip()
    if not key:
        raise ValueError("idempotency_key is required")
    if len(key) > 160:
        raise ValueError("idempotency_key is too long")
    return key


def _existing_idempotent_event(events: list[dict], key: str, fingerprint: str) -> dict | None:
    existing = next((event for event in events if str(event.get("idempotency_key") or "") == key), None)
    if not existing:
        return None
    if str(existing.get("fingerprint") or "") != fingerprint:
        raise IncidentWorkflowConflict("Idempotency key was already used for a different operation")
    return existing


def _require_revision(state: dict, payload: dict, key: str = "expected_revision") -> None:
    expected = str(payload.get(key) or "").strip()
    if not expected:
        raise ValueError(f"{key} is required")
    actual = str(state.get("revision") or "0")
    if expected != actual:
        raise IncidentWorkflowConflict(f"Incident changed concurrently: expected revision {expected}, current revision {actual}")


def _clear_incident_caches() -> None:
    _INCIDENT_LIST_CACHE.clear()
    for name in ("_ALERT_HISTORY_CACHE", "_ALERTS_AGG_CACHE", "_INCIDENT_DETAIL_CACHE"):
        cache = getattr(deps_module, name, None)
        if hasattr(cache, "clear"):
            cache.clear()


def _append_workflow_event(event: dict, *, actor: str, rule_id: int = 0) -> None:
    deps_module.ensure_incident_workflow_support()
    deps_module.get_ch_client().insert(
        deps_module.ALERT_HISTORY_TABLE,
        [[
            "incident",
            str(event["incident_id"]),
            int(rule_id or event.get("rule_id") or 0),
            str(event.get("previous_state") or ""),
            str(event.get("operation") or ""),
            "",
            "",
            actor,
            INCIDENT_WORKFLOW_NOTE_PREFIX + _workflow_json(event),
        ]],
        column_names=[
            "view", "record_id", "rule_id", "previous_status", "next_status",
            "previous_assignee", "next_assignee", "changed_by", "note",
        ],
    )
    _clear_incident_caches()


def _workflow_result(event: dict, events: list[dict], *, idempotent: bool = False) -> dict:
    states = _build_incident_workflow_states([*events, *([] if event in events else [event])])
    incident_id = str(event.get("incident_id") or "")
    state = states.get(incident_id, _empty_workflow_state(incident_id))
    return {
        "status": "ok",
        "operation": event.get("operation"),
        "incident_id": incident_id,
        "target_incident_id": event.get("target_incident_id", ""),
        "alert_id": event.get("alert_id", ""),
        "severity": event.get("severity", ""),
        "revision": state.get("revision", "0"),
        "idempotent": idempotent,
        "event_id": event.get("event_id", ""),
    }


def _new_workflow_event(operation: str, incident_id: str, payload: dict, actor: str) -> dict:
    key = _require_idempotency(payload)
    return {
        "version": 1,
        "event_id": uuid.uuid4().hex,
        "sequence_ns": time_ns(),
        "operation": operation,
        "incident_id": incident_id,
        "idempotency_key": key,
        "fingerprint": _workflow_fingerprint(operation, payload),
        "changed_by": actor,
    }


def _safe_error(label: str, exc: Exception) -> dict[str, str]:
    debug_id = uuid.uuid4().hex[:10]
    logger.exception("%s failed [%s]", label, debug_id)
    return {
        "error": f"{label} failed. Debug id: {debug_id}",
        "debug_id": debug_id,
    }


VPN_NOISE_PATTERN = re.compile(
    r"("
    r"linux audit user login failures|"
    r"audit_user_login_failure|"
    r"audit_user_err|"
    r"user_login failure|"
    r"ssh invalid user|"
    r"linux ssh login failure burst|"
    r"linux ssh invalid user burst|"
    r"linux multi-host ssh brute force|"
    r"ssh brute force"
    r")",
    re.IGNORECASE,
)
VPN_SOURCE_PATTERN = re.compile(
    r"(vpn|xray|wireguard|openvpn|openclaw-gateway|lab-edge-01|asset-vpn-host|vpn-host-khanov|"
    r"vm15611031|45\.89\.111\.208|176\.108\.250\.215|192\.168\.1\.102|10\.20\.30\.124)",
    re.IGNORECASE,
)
MAINTENANCE_ALERT_PATTERN = re.compile(
    r"("
    r"/opt/siem/siem-solution|"
    r"deploy/|"
    r"pytest|"
    r"playwright|"
    r"npm run|"
    r"node build\.cjs|"
    r"host-runtime-smoke|"
    r"storage-ha-smoke|"
    r"transport-shadow-smoke|"
    r"greenbone-runtime-smoke|"
    r"eps-bench|"
    r"e2e(?:[-_ ]?correlation)?|"
    r"assignment[-_ ]?full|"
    r"full[-_ ]?(?:batch|stream)[-_ ]?e2e|"
    r"(?:^|[-_ ])validation(?:$|[-_ ])|"
    r"benchmark-smoke|"
    r"cleanup-smoke|"
    r"codex-smoke|"
    r"vm1-smoke|"
    r"vm4-smoke|"
    r"vm4 foundation smoke|"
    r"smoke webhook source|"
    r"smoke approval gate|"
    r"smoke token|"
    r"smoke-runtime-|"
    r"kafka[_ -]?shadow|"
    r"kafka[_ -]?wave[_ -]?smoke|"
    r"clickhouse-client --host|"
    r"python3 - <<\\\\'py\\\\'|"
    r"systemctl status siem-|"
    r"siem-host-runtime-agent\.service|"
    r"install -m 0644 /tmp/siem-[^\s]+|"
    r"auditctl -R /etc/audit/audit\.rules|"
    r"vm[1-5]_[a-z0-9_\-]+"
    r")",
    re.IGNORECASE,
)


def _json_loads_safe(value):
    if isinstance(value, dict):
        return value
    text = str(value or "").strip()
    if not text:
        return {}
    try:
        return json.loads(text)
    except Exception:
        return {}


def _is_vpn_noise_alert(row: dict) -> bool:
    rule_name = str(row.get("rule_name") or "")
    if not VPN_NOISE_PATTERN.search(rule_name):
        return False
    haystack = [rule_name, str(row.get("entity_key") or ""), str(row.get("source") or "")]
    context = row.get("context") or _json_loads_safe(row.get("context_json"))
    group_key = row.get("group_key") or _json_loads_safe(row.get("group_key_json"))
    for value in (
        context.get("source"),
        context.get("host_name"),
        context.get("log_source"),
        context.get("observer_collector"),
        context.get("collector_profile"),
        context.get("source.ip"),
        context.get("source_ip"),
    ):
        if value:
            haystack.append(str(value))
    for value in group_key.get("sources", []) if isinstance(group_key, dict) else []:
        haystack.append(str(value))
    return VPN_SOURCE_PATTERN.search(" ".join(haystack)) is not None


def _alert_haystack(row: dict) -> str:
    values = [
        row.get("rule_name"),
        row.get("source"),
        row.get("entity_key"),
        row.get("assignee"),
        row.get("status"),
        row.get("severity"),
        row.get("severity_agg"),
        row.get("context_json"),
        row.get("group_key_json"),
        row.get("samples_json"),
    ]
    for container in (
        row.get("context") or _json_loads_safe(row.get("context_json")),
        row.get("group_key") or _json_loads_safe(row.get("group_key_json")),
        row.get("cluster") or {},
    ):
        if isinstance(container, dict):
            values.extend(container.values())
    samples = row.get("samples")
    if isinstance(samples, list):
        values.extend(samples)
    else:
        decoded_samples = _json_loads_safe(row.get("samples_json"))
        if isinstance(decoded_samples, list):
            values.extend(decoded_samples)
    return json.dumps(values, ensure_ascii=False).lower()


def _is_internal_maintenance_alert(row: dict) -> bool:
    return is_non_operational_record(row) or MAINTENANCE_ALERT_PATTERN.search(_alert_haystack(row)) is not None


HEALTH_SIGNAL_RULE_IDS = {
    2101,
    8001,
    8002,
    8003,
    8004,
    8305,
    8355,
    *range(8418, 8438),
}
HEALTH_SIGNAL_PATTERN = re.compile(
    r"\b(?:host cpu pressure|source_silence|host_cpu_pressure|sustained_(?:cpu|memory|iowait|load)_pressure)\b"
    r"|\bhb-\d+\b"
    r"|^met-\d+\b",
    re.IGNORECASE,
)
INFORMATIONAL_ALERT_RULE_IDS = {8067}


def _is_health_signal_alert(row: dict) -> bool:
    try:
        rule_id = int(row.get("rule_id") or 0)
    except (TypeError, ValueError):
        rule_id = 0
    if rule_id in HEALTH_SIGNAL_RULE_IDS:
        return True
    haystack = _alert_haystack(row)
    if HEALTH_SIGNAL_PATTERN.search(haystack):
        return True
    context = row.get("context") or _json_loads_safe(row.get("context_json"))
    event_type = str(context.get("event_type") or "") if isinstance(context, dict) else ""
    return event_type in {
        "linux_systemd_unit_failed",
        "service_failure",
        "source_silence",
        "host_cpu_pressure",
        "sustained_iowait_pressure",
    }


def _is_informational_alert(row: dict) -> bool:
    try:
        rule_id = int(row.get("rule_id") or 0)
    except (TypeError, ValueError):
        rule_id = 0
    severity = str(
        row.get("severity_agg") or row.get("severity") or ""
    ).strip().lower()
    return rule_id in INFORMATIONAL_ALERT_RULE_IDS or severity in {"info", "informational"}


def _matches_alert_query(row: dict, query: str) -> bool:
    token = str(query or "").strip().lower()
    if not token:
        return True
    values = [
        row.get("rule_name"),
        row.get("source"),
        row.get("entity_key"),
        row.get("assignee"),
        row.get("status"),
        row.get("severity"),
        row.get("severity_agg"),
    ]
    cluster = row.get("cluster") or {}
    group_key = row.get("group_key") or {}
    context = row.get("context") or {}
    for container in (cluster, group_key, context):
        if isinstance(container, dict):
            for value in container.values():
                if isinstance(value, list):
                    values.extend(value)
                else:
                    values.append(value)
    haystack = " ".join(str(value or "") for value in values).lower()
    return token in haystack


def _filter_rows(rows: list[dict], scope: str, query: str) -> list[dict]:
    filtered = [
        row
        for row in rows
        if _matches_alert_query(row, query) and not _is_informational_alert(row)
    ]
    if scope == "vpn-noise":
        return [row for row in filtered if _is_vpn_noise_alert(row)]
    operational = [row for row in filtered if not _is_internal_maintenance_alert(row)]
    if scope == "health":
        return [row for row in operational if _is_health_signal_alert(row)]
    return [row for row in operational if not _is_health_signal_alert(row)]


def _fast_list_metrics(rows: list[dict]) -> dict:
    open_statuses = {"closed", "false_positive"}
    return {
        "agg_total": len(rows),
        "agg_open": sum(1 for row in rows if str(row.get("status") or "new").lower() not in open_statuses),
        "raw_total": sum(int(row.get("raw_alerts_total") or row.get("count_alerts") or 1) for row in rows),
        "critical_raw": sum(1 for row in rows if str(row.get("severity_agg") or row.get("severity") or "").lower() == "critical"),
        "new_raw": sum(1 for row in rows if str(row.get("status") or "").lower() == "new"),
    }


def _manual_incident_row(state: dict, raw_alerts: list[dict]) -> dict:
    if not raw_alerts:
        raise ValueError(f"Manual incident has no existing raw alerts: {state.get('incident_id')}")
    severities = [str(row.get("severity") or "info").lower() for row in raw_alerts]
    severity = str(state.get("severity") or "").lower()
    if not severity:
        severity = max(severities, key=lambda value: {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(value, 0))
    rule_names = list(dict.fromkeys(str(row.get("rule_name") or "") for row in raw_alerts if str(row.get("rule_name") or "")))
    sources = list(dict.fromkeys(str(row.get("source") or "") for row in raw_alerts if str(row.get("source") or "")))
    entities = list(dict.fromkeys(str(row.get("entity_key") or "") for row in raw_alerts if str(row.get("entity_key") or "")))
    hits = sum(int(row.get("hits") or 0) for row in raw_alerts)
    incident_id = str(state.get("incident_id") or "")
    return {
        "ts": max((str(row.get("ts") or "") for row in raw_alerts), default=""),
        "agg_id": incident_id,
        "record_id": incident_id,
        "storage_agg_id": "",
        "rule_id": int(raw_alerts[0].get("rule_id") or 0),
        "rule_name": str(state.get("title") or (rule_names[0] if rule_names else incident_id)),
        "title": str(state.get("title") or (rule_names[0] if rule_names else incident_id)),
        "severity_agg": severity,
        "ts_first": min((str(row.get("ts_first") or row.get("ts") or "") for row in raw_alerts), default=""),
        "ts_last": max((str(row.get("ts_last") or row.get("ts") or "") for row in raw_alerts), default=""),
        "count_alerts": len(raw_alerts),
        "raw_alerts_total": len(raw_alerts),
        "count_events": hits,
        "raw_hits_total": hits,
        "unique_entities": len(entities) or 1,
        "entity_key": entities[0] if len(entities) == 1 else incident_id,
        "group_key": {
            "incident_key": incident_id,
            "manual": True,
            "alert_ids": [str(row.get("alert_id") or "") for row in raw_alerts],
            "rule_names": rule_names,
            "sources": sources,
            "entity_keys": entities,
        },
        "samples": [row.get("context") or {} for row in raw_alerts[:3]],
        "status": str(state.get("status") or "open"),
        "assignee": "",
        "updated_ts": str(state.get("operations", [{}])[-1].get("changed_ts") or ""),
        "sources": sources,
        "source_summary": ", ".join(sources[:4]),
        "alert_ids": [str(row.get("alert_id") or "") for row in raw_alerts],
        "workflow": {
            "revision": state.get("revision", "0"),
            "manual": True,
            "merged_into": state.get("merged_into", ""),
        },
    }


def _overlay_incident_workflow(rows: list[dict], *, include_terminal: bool) -> list[dict]:
    events = _load_incident_workflow_events()
    if not events:
        return rows
    states = _build_incident_workflow_states(events)
    result: list[dict] = []
    seen: set[str] = set()
    for source in rows:
        row = dict(source)
        incident_id = str(row.get("agg_id") or row.get("record_id") or "")
        state = states.get(incident_id, _empty_workflow_state(incident_id))
        seen.add(incident_id)
        if state.get("severity"):
            row["severity_agg"] = state["severity"]
        if state.get("operations"):
            effective_ids = _effective_alert_ids(state, _base_incident_alert_ids(row))
            row["alert_ids"] = effective_ids
            row["count_alerts"] = len(effective_ids)
            row["raw_alerts_total"] = len(effective_ids)
        if state.get("merged_into"):
            row["status"] = "merged"
            row["merged_into"] = state["merged_into"]
        row["workflow"] = {
            "revision": state.get("revision", "0"),
            "manual": bool(state.get("manual")),
            "merged_into": state.get("merged_into", ""),
        }
        if not state.get("merged_into") or include_terminal:
            result.append(row)

    for incident_id, state in states.items():
        if incident_id in seen or not state.get("manual"):
            continue
        alert_ids = _effective_alert_ids(state)
        raw_alerts = _raw_alerts_by_ids(alert_ids)
        if len(raw_alerts) != len(alert_ids):
            continue
        row = _manual_incident_row(state, raw_alerts)
        if not state.get("merged_into") or include_terminal:
            if state.get("merged_into"):
                row["status"] = "merged"
                row["merged_into"] = state["merged_into"]
            result.append(row)
    result.sort(key=lambda row: str(row.get("ts_last") or row.get("ts") or ""), reverse=True)
    return result


def _overlay_raw_alert_workflow(rows: list[dict]) -> list[dict]:
    states = _build_incident_workflow_states(_load_incident_workflow_events())
    if not states:
        return rows
    memberships: dict[str, list[str]] = {}
    for incident_id, state in states.items():
        if state.get("merged_into"):
            continue
        for alert_id in _effective_alert_ids(state):
            memberships.setdefault(alert_id, []).append(incident_id)
    result = []
    for source in rows:
        row = dict(source)
        alert_id = str(row.get("alert_id") or "")
        row["incident_ids"] = memberships.get(alert_id, [])
        row["incident_id"] = (row["incident_ids"] or [""])[0]
        result.append(row)
    return result


def _workflow_audit_entries(state: dict) -> list[dict]:
    return [
        {
            "changed_ts": event.get("changed_ts", ""),
            "changed_by": event.get("changed_by", ""),
            "operation": event.get("operation", ""),
            "incident_id": event.get("incident_id", ""),
            "target_incident_id": event.get("target_incident_id", ""),
            "alert_id": event.get("alert_id", ""),
            "severity": event.get("severity", ""),
            "note": event.get("reason", ""),
            "event_id": event.get("event_id", ""),
        }
        for event in reversed(state.get("operations", []))
    ]


def _incident_detail_with_workflow(view: str, record_id: str, **kwargs) -> dict:
    states = _build_incident_workflow_states(_load_incident_workflow_events())
    state = states.get(record_id, _empty_workflow_state(record_id))
    manual = bool(state.get("manual"))
    if manual:
        alert_ids = _effective_alert_ids(state)
        raw_alerts = _raw_alerts_by_ids(alert_ids)
        if not raw_alerts or len(raw_alerts) != len(alert_ids):
            raise ValueError(f"Manual incident evidence is incomplete: {record_id}")
        detail = fetch_incident_detail_bundle("raw", alert_ids[0], **kwargs)
        incident = _manual_incident_row(state, raw_alerts)
        detail["view"] = "agg"
        detail["item"] = incident
        detail["incident"] = incident
        detail["summary"] = {
            **dict(detail.get("summary") or {}),
            "trigger_reason": incident["title"],
            "description": "Manual incident created from existing SIEM alerts.",
        }
    else:
        detail = fetch_incident_detail_bundle(view, record_id, **kwargs)
        incident = dict(detail.get("item") or detail.get("incident") or {})
        canonical_id = str(incident.get("agg_id") or incident.get("record_id") or record_id)
        if canonical_id != record_id and canonical_id in states:
            state = states[canonical_id]
            record_id = canonical_id
        base_ids = [
            str(row.get("alert_id") or "")
            for row in (detail.get("raw_alerts") or {}).get("items", [])
            if str(row.get("alert_id") or "").strip()
        ]
        alert_ids = _effective_alert_ids(state, base_ids)
        raw_alerts = _raw_alerts_by_ids(alert_ids)

    if state.get("severity"):
        incident["severity_agg"] = state["severity"]
        incident["severity"] = state["severity"]
    if state.get("merged_into"):
        incident["status"] = "merged"
        incident["merged_into"] = state["merged_into"]
    incident["workflow"] = {
        "revision": state.get("revision", "0"),
        "manual": manual,
        "merged_into": state.get("merged_into", ""),
        "alert_ids": alert_ids,
        "operations": _workflow_audit_entries(state),
    }
    detail["item"] = incident
    detail["incident"] = incident
    current_raw = {
        str(row.get("alert_id") or ""): row
        for row in (detail.get("raw_alerts") or {}).get("items", [])
        if str(row.get("alert_id") or "")
    }
    for row in raw_alerts:
        current_raw[str(row.get("alert_id") or "")] = row
    ordered_raw = [current_raw[alert_id] for alert_id in alert_ids if alert_id in current_raw]
    detail["raw_alerts"] = {
        **dict(detail.get("raw_alerts") or {}),
        "items": ordered_raw,
        "total": len(alert_ids),
    }
    detail["workflow"] = incident["workflow"]
    detail["audit_log"] = [*_workflow_audit_entries(state), *list(detail.get("audit_log") or [])]
    detail["permissions"] = {
        **dict(detail.get("permissions") or {}),
        "required_write_permission": "response:run",
    }
    return detail


def _create_manual_incident(payload: dict, *, actor: str) -> dict:
    with _INCIDENT_WORKFLOW_LOCK:
        alert_ids = [str(value).strip() for value in payload.get("alert_ids", []) if str(value).strip()]
        alert_ids = list(dict.fromkeys(alert_ids))
        if not alert_ids:
            raise ValueError("alert_ids must contain at least one existing raw alert ID")
        if len(alert_ids) > INCIDENT_WORKFLOW_MAX_ALERTS:
            raise ValueError(f"At most {INCIDENT_WORKFLOW_MAX_ALERTS} alerts can be used")
        severity = str(payload.get("severity") or "").strip().lower()
        if severity and severity not in INCIDENT_SEVERITIES:
            raise ValueError(f"Unsupported severity: {severity}")
        key = _require_idempotency(payload)
        incident_id = f"manual:{hashlib.sha256(key.encode('utf-8')).hexdigest()[:20]}"
        event = _new_workflow_event("create", incident_id, payload, actor)
        events = _load_incident_workflow_events()
        existing = _existing_idempotent_event(events, key, event["fingerprint"])
        if existing:
            return _workflow_result(existing, events, idempotent=True)
        states = _build_incident_workflow_states(events)
        if incident_id in states:
            raise IncidentWorkflowConflict(f"Incident already exists: {incident_id}")
        raw_alerts = _raw_alerts_by_ids(alert_ids)
        found = {str(row.get("alert_id") or "") for row in raw_alerts}
        missing = [alert_id for alert_id in alert_ids if alert_id not in found]
        if missing:
            raise ValueError(f"Raw alerts not found: {', '.join(missing[:10])}")
        title = str(payload.get("title") or "").strip() or str(raw_alerts[0].get("rule_name") or incident_id)
        event.update({
            "alert_ids": alert_ids,
            "title": title[:300],
            "severity": severity,
            "status": "open",
            "rule_id": int(raw_alerts[0].get("rule_id") or 0),
            "reason": str(payload.get("reason") or "").strip()[:1000],
        })
        _append_workflow_event(event, actor=actor, rule_id=event["rule_id"])
        result = _workflow_result(event, events)
        result["item"] = _manual_incident_row(_build_incident_workflow_states([*events, event])[incident_id], raw_alerts)
        return result


def _change_incident_severity(incident_id: str, payload: dict, *, actor: str) -> dict:
    with _INCIDENT_WORKFLOW_LOCK:
        severity = str(payload.get("severity") or "").strip().lower()
        if severity not in INCIDENT_SEVERITIES:
            raise ValueError(f"Unsupported severity: {severity}")
        key = _require_idempotency(payload)
        event = _new_workflow_event("severity", incident_id, payload, actor)
        events = _load_incident_workflow_events()
        existing = _existing_idempotent_event(events, key, event["fingerprint"])
        if existing:
            return _workflow_result(existing, events, idempotent=True)
        states = _build_incident_workflow_states(events)
        incident, state = _workflow_incident_exists(incident_id, states)
        _require_revision(state, payload)
        previous = str(state.get("severity") or (incident or {}).get("severity_agg") or (incident or {}).get("severity") or "info")
        if severity == previous:
            raise IncidentWorkflowConflict(f"Incident severity is already {severity}")
        event.update({
            "severity": severity,
            "previous_severity": previous,
            "previous_state": previous,
            "rule_id": int((incident or {}).get("rule_id") or 0),
            "reason": str(payload.get("reason") or "").strip()[:1000],
        })
        _append_workflow_event(event, actor=actor, rule_id=event["rule_id"])
        return _workflow_result(event, events)


def _change_incident_alert_link(incident_id: str, payload: dict, *, actor: str, operation: str) -> dict:
    with _INCIDENT_WORKFLOW_LOCK:
        alert_id = str(payload.get("alert_id") or "").strip()
        if not alert_id:
            raise ValueError("alert_id is required")
        key = _require_idempotency(payload)
        event = _new_workflow_event(operation, incident_id, payload, actor)
        events = _load_incident_workflow_events()
        existing = _existing_idempotent_event(events, key, event["fingerprint"])
        if existing:
            return _workflow_result(existing, events, idempotent=True)
        states = _build_incident_workflow_states(events)
        incident, state = _workflow_incident_exists(incident_id, states)
        _require_revision(state, payload)
        raw_alerts = _raw_alerts_by_ids([alert_id])
        if not raw_alerts:
            raise ValueError(f"Raw alert not found: {alert_id}")
        effective_ids = _effective_alert_ids(state, _base_incident_alert_ids(incident))
        if operation == "link" and alert_id in effective_ids:
            raise IncidentWorkflowConflict(f"Raw alert is already linked to incident: {alert_id}")
        if operation == "unlink" and alert_id not in effective_ids:
            raise IncidentWorkflowConflict(f"Raw alert is not linked to incident: {alert_id}")
        if operation == "link":
            for other_id, other_state in states.items():
                if other_id != incident_id and not other_state.get("merged_into") and alert_id in other_state.get("linked_alert_ids", []):
                    raise IncidentWorkflowConflict(f"Raw alert is explicitly linked to another incident: {other_id}")
        event.update({
            "alert_id": alert_id,
            "rule_id": int(raw_alerts[0].get("rule_id") or (incident or {}).get("rule_id") or 0),
            "reason": str(payload.get("reason") or "").strip()[:1000],
        })
        _append_workflow_event(event, actor=actor, rule_id=event["rule_id"])
        return _workflow_result(event, events)


def _merge_incidents(source_id: str, payload: dict, *, actor: str) -> dict:
    with _INCIDENT_WORKFLOW_LOCK:
        target_id = str(payload.get("target_incident_id") or "").strip()
        if not target_id:
            raise ValueError("target_incident_id is required")
        if target_id == source_id:
            raise IncidentWorkflowConflict("An incident cannot be merged into itself")
        key = _require_idempotency(payload)
        event = _new_workflow_event("merge", source_id, payload, actor)
        events = _load_incident_workflow_events()
        existing = _existing_idempotent_event(events, key, event["fingerprint"])
        if existing:
            return _workflow_result(existing, events, idempotent=True)
        states = _build_incident_workflow_states(events)
        source, source_state = _workflow_incident_exists(source_id, states)
        target, target_state = _workflow_incident_exists(target_id, states)
        _require_revision(source_state, payload)
        if payload.get("target_expected_revision") is not None:
            _require_revision(target_state, payload, "target_expected_revision")
        if source_state.get("merged_into"):
            raise IncidentWorkflowConflict(f"Incident is already merged into {source_state['merged_into']}")
        cursor = target_id
        visited = {source_id}
        while cursor:
            if cursor in visited:
                raise IncidentWorkflowConflict("Merge would create an incident cycle")
            visited.add(cursor)
            cursor = str(states.get(cursor, {}).get("merged_into") or "")
        source_alert_ids = _effective_alert_ids(source_state, _base_incident_alert_ids(source))
        if not source_alert_ids:
            raise ValueError("Source incident has no existing raw alerts")
        event.update({
            "target_incident_id": target_id,
            "alert_ids": source_alert_ids,
            "rule_id": int((source or {}).get("rule_id") or (target or {}).get("rule_id") or 0),
            "reason": str(payload.get("reason") or "").strip()[:1000],
        })
        _append_workflow_event(event, actor=actor, rule_id=event["rule_id"])
        result = _workflow_result(event, events)
        updated_states = _build_incident_workflow_states([*events, event])
        result["target_revision"] = updated_states[target_id]["revision"]
        result["merged_alerts"] = len(source_alert_ids)
        return result


@router.get('/alerts', response_class=HTMLResponse)
async def alerts_page(
    request: Request,
    view: str = Query('agg'),
    focus: str = Query(''),
    q: str = Query(''),
    scope: str = Query('main'),
    user=Depends(get_current_user),
) -> HTMLResponse:
    target = canonical_ui_redirect_path(f"{request.url.path}{f'?{request.url.query}' if request.url.query else ''}")
    return RedirectResponse(url=target, status_code=307)


@router.get('/alerts_raw', include_in_schema=False)
async def alerts_raw_redirect(request: Request, user=Depends(get_current_user)):
    return RedirectResponse(url=canonical_ui_redirect_path("/alerts_raw"), status_code=307)


@router.get('/alerts_agg', include_in_schema=False)
async def alerts_agg_redirect(request: Request, user=Depends(get_current_user)):
    return RedirectResponse(url=canonical_ui_redirect_path("/alerts_agg"), status_code=307)


@router.get('/api/incidents', response_class=JSONResponse)
async def incidents_api(
    view: str = Query('agg'),
    q: str = Query(''),
    scope: str = Query('main'),
    window: str = Query('24h'),
    from_ts: str = Query(''),
    to_ts: str = Query(''),
    limit: int = Query(200, ge=1, le=1000),
    include_terminal: bool = Query(False),
    user=Depends(get_current_user),
) -> JSONResponse:
    safe_view = 'raw' if view == 'raw' else 'agg'
    safe_scope = scope if scope in {'main', 'vpn-noise', 'health'} else 'main'
    safe_limit = max(10, min(int(limit or 200), 1000))
    fetch_limit = min(1200, max(safe_limit * 2, 200))
    cache_key = json.dumps(
        [safe_view, safe_scope, q, window, from_ts, to_ts, safe_limit, include_terminal],
        ensure_ascii=False,
        sort_keys=True,
    )
    now_ts = time()
    cached = _INCIDENT_LIST_CACHE.get(cache_key)
    if cached and now_ts - cached[0] < INCIDENT_LIST_CACHE_TTL_SECONDS:
        return JSONResponse(cached[1])
    try:
        fetcher = (
            fetch_alerts_raw
            if safe_view == 'raw'
            else deps_module._fetch_alerts_agg_from_raw_scan
            if include_terminal
            else fetch_alerts_agg
        )
        rows = await run_in_threadpool(
            fetcher,
            limit=fetch_limit,
            window=window,
            from_ts=from_ts,
            to_ts=to_ts,
        )
        rows = await run_in_threadpool(
            _overlay_raw_alert_workflow if safe_view == "raw" else _overlay_incident_workflow,
            rows,
            **({} if safe_view == "raw" else {"include_terminal": include_terminal}),
        )
        filtered_rows = _filter_rows(rows, safe_scope, q)
        if safe_scope == "main":
            items, notification_delivery = await run_in_threadpool(
                enrich_incidents_with_delivery,
                filtered_rows[:safe_limit],
                view=safe_view,
            )
            notification_delivery["applicable"] = True
        else:
            items = filtered_rows[:safe_limit]
            notification_delivery = {
                "channel": "telegram",
                "queue_count": 0,
                "delivered": 0,
                "pending": 0,
                "failed": 0,
                "synchronized": True,
                "applicable": False,
            }
        payload = {
            'view': safe_view,
            'scope': safe_scope,
            'query': q,
            'window': window,
            'from_ts': from_ts,
            'to_ts': to_ts,
            'limit': safe_limit,
            'requested_limit': safe_limit,
            'include_terminal': include_terminal,
            'available_count': len(filtered_rows),
            'returned_count': len(items),
            'items': items,
            'metrics': _fast_list_metrics(filtered_rows),
            'notification_delivery': notification_delivery,
            'status_transitions': {key: sorted(values) for key, values in INCIDENT_STATUS_TRANSITIONS.items()},
        }
        _INCIDENT_LIST_CACHE[cache_key] = (now_ts, payload)
        if len(_INCIDENT_LIST_CACHE) > 64:
            oldest_key = min(_INCIDENT_LIST_CACHE, key=lambda key: _INCIDENT_LIST_CACHE[key][0])
            _INCIDENT_LIST_CACHE.pop(oldest_key, None)
        return JSONResponse(payload)
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({'error': str(exc)}, status_code=400)


@router.post('/api/notification-delivery/incidents', response_class=JSONResponse)
async def incident_notification_delivery_api(
    payload: dict = Body(default={}),
    user=Depends(require_permissions('incidents:update')),
) -> JSONResponse:
    try:
        item = await run_in_threadpool(
            record_incident_delivery,
            payload,
            actor=str(getattr(user, 'username', 'service') or 'service'),
        )
        _INCIDENT_LIST_CACHE.clear()
        return JSONResponse({'status': 'recorded', 'item': item})
    except ValueError as exc:
        return JSONResponse({'error': str(exc)}, status_code=400)
    except Exception as exc:  # noqa: BLE001
        return JSONResponse(_safe_error("Incident notification delivery", exc), status_code=503)


@router.get('/api/incidents/{view}/{record_id:path}', response_class=JSONResponse)
async def incident_detail_api(
    view: str,
    record_id: str,
    window: str = Query('24h'),
    from_ts: str = Query(''),
    to_ts: str = Query(''),
    event_limit: int = Query(200, ge=1, le=500),
    alert_limit: int = Query(500, ge=1, le=1000),
    include_evidence: bool = Query(True),
    user=Depends(get_current_user),
) -> JSONResponse:
    safe_view = 'raw' if view == 'raw' else 'agg'
    try:
        return JSONResponse(
            await run_in_threadpool(
                _incident_detail_with_workflow,
                safe_view,
                record_id,
                window=window,
                from_ts=from_ts,
                to_ts=to_ts,
                event_limit=event_limit,
                alert_limit=alert_limit,
                include_evidence=include_evidence,
            )
        )
    except ValueError as exc:
        return JSONResponse({'error': str(exc)}, status_code=404)
    except Exception as exc:  # noqa: BLE001
        return JSONResponse(_safe_error("Incident detail", exc), status_code=400)


@router.get('/api/incidents/{record_id:path}', response_class=JSONResponse)
async def incident_detail_default_api(
    record_id: str,
    window: str = Query('24h'),
    from_ts: str = Query(''),
    to_ts: str = Query(''),
    event_limit: int = Query(200, ge=1, le=500),
    alert_limit: int = Query(500, ge=1, le=1000),
    include_evidence: bool = Query(True),
    user=Depends(get_current_user),
) -> JSONResponse:
    try:
        return JSONResponse(
            await run_in_threadpool(
                _incident_detail_with_workflow,
                'agg',
                record_id,
                window=window,
                from_ts=from_ts,
                to_ts=to_ts,
                event_limit=event_limit,
                alert_limit=alert_limit,
                include_evidence=include_evidence,
            )
        )
    except ValueError as exc:
        return JSONResponse({'error': str(exc)}, status_code=404)
    except Exception as exc:  # noqa: BLE001
        return JSONResponse(_safe_error("Incident detail", exc), status_code=400)


@router.post('/api/alerts/{view}/{record_id:path}', response_class=JSONResponse)
async def update_alert_api(
    view: str,
    record_id: str,
    payload: dict = Body(default={}),
    user=Depends(require_permissions('incidents:update')),
) -> JSONResponse:
    if view not in {'raw', 'agg'}:
        return JSONResponse({'error': 'Unsupported alert view'}, status_code=400)
    try:
        requested_assignee = str(payload.get('assignee', '') or '')
        if requested_assignee in {'current_user', 'me'}:
            requested_assignee = str(getattr(user, 'username', 'web') or 'web')
        result = update_alert_assignment(
            view,
            record_id,
            status=str(payload.get('status', 'new') or 'new'),
            assignee=requested_assignee,
            changed_by=str(getattr(user, 'username', 'web') or 'web'),
            note=str(payload.get('note', '') or ''),
        )
        _INCIDENT_LIST_CACHE.clear()
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({'error': str(exc)}, status_code=400)
    return JSONResponse(result)


@router.get('/api/alerts/{view}/{record_id:path}/history', response_class=JSONResponse)
async def alert_history_api(view: str, record_id: str, user=Depends(get_current_user)) -> JSONResponse:
    if view not in {'raw', 'agg'}:
        return JSONResponse({'error': 'Unsupported alert view'}, status_code=400)
    try:
        return JSONResponse({'history': fetch_alert_history(view, record_id)})
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({'error': str(exc)}, status_code=400)


def _workflow_error_response(label: str, exc: Exception) -> JSONResponse:
    if isinstance(exc, IncidentWorkflowConflict):
        return JSONResponse({"error": str(exc), "conflict": True}, status_code=409)
    if isinstance(exc, ValueError):
        return JSONResponse({"error": str(exc)}, status_code=400)
    return JSONResponse(_safe_error(label, exc), status_code=503)


@router.post('/api/incident-workflow/incidents', response_class=JSONResponse)
async def create_manual_incident_api(
    payload: dict = Body(default={}),
    user=Depends(require_permissions('response:run')),
) -> JSONResponse:
    try:
        result = await run_in_threadpool(
            _create_manual_incident,
            payload,
            actor=str(getattr(user, 'username', 'web') or 'web'),
        )
        return JSONResponse(result, status_code=200 if result.get("idempotent") else 201)
    except Exception as exc:  # noqa: BLE001
        return _workflow_error_response("Manual incident creation", exc)


@router.post('/api/incident-workflow/incidents/{incident_id:path}/severity', response_class=JSONResponse)
async def change_incident_severity_api(
    incident_id: str,
    payload: dict = Body(default={}),
    user=Depends(require_permissions('response:run')),
) -> JSONResponse:
    try:
        return JSONResponse(
            await run_in_threadpool(
                _change_incident_severity,
                incident_id,
                payload,
                actor=str(getattr(user, 'username', 'web') or 'web'),
            )
        )
    except Exception as exc:  # noqa: BLE001
        return _workflow_error_response("Incident severity update", exc)


@router.post('/api/incident-workflow/incidents/{incident_id:path}/alerts/link', response_class=JSONResponse)
async def link_raw_alert_api(
    incident_id: str,
    payload: dict = Body(default={}),
    user=Depends(require_permissions('response:run')),
) -> JSONResponse:
    try:
        return JSONResponse(
            await run_in_threadpool(
                _change_incident_alert_link,
                incident_id,
                payload,
                actor=str(getattr(user, 'username', 'web') or 'web'),
                operation="link",
            )
        )
    except Exception as exc:  # noqa: BLE001
        return _workflow_error_response("Raw alert link", exc)


@router.post('/api/incident-workflow/incidents/{incident_id:path}/alerts/unlink', response_class=JSONResponse)
async def unlink_raw_alert_api(
    incident_id: str,
    payload: dict = Body(default={}),
    user=Depends(require_permissions('response:run')),
) -> JSONResponse:
    try:
        return JSONResponse(
            await run_in_threadpool(
                _change_incident_alert_link,
                incident_id,
                payload,
                actor=str(getattr(user, 'username', 'web') or 'web'),
                operation="unlink",
            )
        )
    except Exception as exc:  # noqa: BLE001
        return _workflow_error_response("Raw alert unlink", exc)


@router.post('/api/incident-workflow/incidents/{incident_id:path}/merge', response_class=JSONResponse)
async def merge_incidents_api(
    incident_id: str,
    payload: dict = Body(default={}),
    user=Depends(require_permissions('response:run')),
) -> JSONResponse:
    try:
        return JSONResponse(
            await run_in_threadpool(
                _merge_incidents,
                incident_id,
                payload,
                actor=str(getattr(user, 'username', 'web') or 'web'),
            )
        )
    except Exception as exc:  # noqa: BLE001
        return _workflow_error_response("Incident merge", exc)


@router.post('/api/incident-ops/{view}/{record_id:path}/host-action', response_class=JSONResponse)
async def incident_host_action_api(
    view: str,
    record_id: str,
    payload: dict = Body(default={}),
    user=Depends(require_permissions('response:run')),
) -> JSONResponse:
    safe_view = 'raw' if view == 'raw' else 'agg'
    action = str(payload.get('action') or 'snapshot').strip().lower() or 'snapshot'
    try:
        result = run_incident_host_action(
            safe_view,
            record_id,
            action,
            requested_by=str(getattr(user, 'username', 'web') or 'web'),
        )
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({'error': str(exc)}, status_code=400)
    return JSONResponse(result)
