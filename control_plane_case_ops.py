from __future__ import annotations

from collections import Counter
import json
from typing import Any

try:
    from . import enterprise_control_plane as core
except ImportError:  # pragma: no cover - local test fallback
    import enterprise_control_plane as core  # type: ignore[no-redef]

CONTROL_PLANE_SCHEMA_VERSION = core.CONTROL_PLANE_SCHEMA_VERSION
_collection = core._collection
_find_by_id = core._find_by_id
_json_clone = core._json_clone
_new_id = core._new_id
_now = core._now
_now_iso = core._now_iso
_parse_ts = core._parse_ts
_safe_slug = core._safe_slug
_save_collection = core._save_collection
append_audit_event = core.append_audit_event
_default_cases = core._default_cases
_default_entities = core._default_entities
_default_risk_signals = core._default_risk_signals
_risk_level = core._risk_level
_normalize_case_status = core._normalize_case_status
_normalize_priority = core._normalize_priority
_normalize_severity = core._normalize_severity


def _normalize_case(payload: dict[str, Any], existing: dict[str, Any] | None = None, *, actor: str = "system") -> dict[str, Any]:
    case_id = str(payload.get("id") or (existing.get("id") if existing else "") or _new_id("case")).strip()
    now = _now_iso()
    audit = list(existing.get("audit_trail") if existing else [])
    audit.append(
        {
            "id": _new_id("audit"),
            "ts": now,
            "actor": actor,
            "action": "updated" if existing else "created",
            "summary": str(payload.get("title") or (existing.get("title") if existing else case_id) or case_id),
        }
    )
    return {
        "id": case_id,
        "type": "case",
        "schema_version": CONTROL_PLANE_SCHEMA_VERSION,
        "title": str(payload.get("title") or (existing.get("title") if existing else case_id) or case_id),
        "summary": str(payload.get("summary") or (existing.get("summary") if existing else "") or ""),
        "status": _normalize_case_status(str(payload.get("status") or (existing.get("status") if existing else "new") or "new")),
        "severity": _normalize_severity(str(payload.get("severity") or (existing.get("severity") if existing else "medium") or "medium")),
        "priority": _normalize_priority(payload.get("priority") if payload.get("priority") is not None else (existing.get("priority") if existing else 3)),
        "assignee": str(payload.get("assignee") or (existing.get("assignee") if existing else "") or ""),
        "sla_due_ts": str(payload.get("sla_due_ts") or (existing.get("sla_due_ts") if existing else "") or ""),
        "tags": [str(item).strip() for item in (payload.get("tags") or (existing.get("tags") if existing else [])) if str(item).strip()],
        "mitre": [str(item).strip() for item in (payload.get("mitre") or (existing.get("mitre") if existing else [])) if str(item).strip()],
        "source": str(payload.get("source") or (existing.get("source") if existing else "manual") or "manual"),
        "related_entities": [str(item).strip() for item in (payload.get("related_entities") or (existing.get("related_entities") if existing else [])) if str(item).strip()],
        "related_iocs": [str(item).strip() for item in (payload.get("related_iocs") or (existing.get("related_iocs") if existing else [])) if str(item).strip()],
        "source_alerts": _json_clone(payload.get("source_alerts") or (existing.get("source_alerts") if existing else [])),
        "comments": _json_clone(existing.get("comments") if existing else []),
        "tasks": _json_clone(existing.get("tasks") if existing else []),
        "evidence": _json_clone(existing.get("evidence") if existing else []),
        "created_by": str(existing.get("created_by") if existing else actor),
        "created_ts": str(existing.get("created_ts") if existing else now),
        "updated_ts": now,
        "audit_trail": audit[-120:],
    }


def list_cases(*, status: str = "", assignee: str = "", q: str = "", limit: int = 200) -> list[dict[str, Any]]:
    rows = _collection("cases", _default_cases)
    token = str(q or "").strip().lower()
    safe_status = str(status or "").strip().lower()
    safe_assignee = str(assignee or "").strip().lower()
    filtered = rows
    if safe_status:
        filtered = [item for item in filtered if str(item.get("status") or "").lower() == safe_status]
    if safe_assignee:
        filtered = [item for item in filtered if str(item.get("assignee") or "").lower() == safe_assignee]
    if token:
        filtered = [item for item in filtered if token in json.dumps(item, ensure_ascii=False).lower()]
    filtered.sort(key=lambda item: _parse_ts(str(item.get("updated_ts") or item.get("created_ts") or "")), reverse=True)
    return _json_clone(filtered[: max(1, min(500, limit))])


def get_case(case_id: str) -> dict[str, Any] | None:
    item = _find_by_id(_collection("cases", _default_cases), case_id)
    return _json_clone(item) if item else None


def save_case(payload: dict[str, Any], *, actor: str = "system") -> dict[str, Any]:
    rows = _collection("cases", _default_cases)
    case_id = str(payload.get("id") or "").strip()
    existing = _find_by_id(rows, case_id) if case_id else None
    item = _normalize_case(payload, existing, actor=actor)
    rows = [row for row in rows if str(row.get("id") or "") != item["id"]]
    rows.append(item)
    _save_collection("cases", rows)
    append_audit_event(
        actor=actor,
        action="case.saved",
        object_type="case",
        object_id=item["id"],
        summary=item["title"],
        details={"status": item["status"], "severity": item["severity"], "assignee": item["assignee"]},
    )
    return _json_clone(item)


def append_case_comment(case_id: str, *, body: str, author: str) -> dict[str, Any]:
    if not str(body or "").strip():
        raise ValueError("Comment body is empty")
    rows = _collection("cases", _default_cases)
    case_item = _find_by_id(rows, case_id)
    if case_item is None:
        raise ValueError(f"Case not found: {case_id}")
    comment = {"id": _new_id("comment"), "ts": _now_iso(), "author": str(author or "system"), "body": str(body).strip()}
    case_item["comments"] = list(case_item.get("comments") or [])
    case_item["comments"].append(comment)
    case_item["updated_ts"] = _now_iso()
    case_item["audit_trail"] = list(case_item.get("audit_trail") or [])
    case_item["audit_trail"].append({"id": _new_id("audit"), "ts": _now_iso(), "actor": author, "action": "commented", "summary": comment["body"][:120]})
    _save_collection("cases", [case_item if str(item.get("id") or "") == case_id else item for item in rows])
    append_audit_event(
        actor=author,
        action="case.comment_added",
        object_type="case",
        object_id=case_id,
        summary=comment["body"][:120],
        details={"comment_id": comment["id"]},
    )
    return _json_clone(case_item)


def append_case_task(case_id: str, *, title: str, assignee: str = "", due_ts: str = "", actor: str = "system") -> dict[str, Any]:
    if not str(title or "").strip():
        raise ValueError("Task title is empty")
    rows = _collection("cases", _default_cases)
    case_item = _find_by_id(rows, case_id)
    if case_item is None:
        raise ValueError(f"Case not found: {case_id}")
    task = {
        "id": _new_id("task"),
        "title": str(title).strip(),
        "status": "open",
        "assignee": str(assignee or "").strip(),
        "due_ts": str(due_ts or "").strip(),
        "created_ts": _now_iso(),
    }
    case_item["tasks"] = list(case_item.get("tasks") or [])
    case_item["tasks"].append(task)
    case_item["updated_ts"] = _now_iso()
    case_item["audit_trail"] = list(case_item.get("audit_trail") or [])
    case_item["audit_trail"].append({"id": _new_id("audit"), "ts": _now_iso(), "actor": actor, "action": "task_added", "summary": task["title"]})
    _save_collection("cases", [case_item if str(item.get("id") or "") == case_id else item for item in rows])
    append_audit_event(
        actor=actor,
        action="case.task_added",
        object_type="case",
        object_id=case_id,
        summary=task["title"],
        details={"task_id": task["id"], "assignee": task["assignee"]},
    )
    return _json_clone(case_item)


def attach_case_evidence(case_id: str, *, title: str, kind: str = "note", content: str = "", actor: str = "system") -> dict[str, Any]:
    if not str(title or "").strip():
        raise ValueError("Evidence title is empty")
    rows = _collection("cases", _default_cases)
    case_item = _find_by_id(rows, case_id)
    if case_item is None:
        raise ValueError(f"Case not found: {case_id}")
    evidence = {"id": _new_id("evidence"), "title": str(title).strip(), "kind": str(kind or "note").strip().lower(), "content": str(content or ""), "created_ts": _now_iso(), "created_by": actor}
    case_item["evidence"] = list(case_item.get("evidence") or [])
    case_item["evidence"].append(evidence)
    case_item["updated_ts"] = _now_iso()
    case_item["audit_trail"] = list(case_item.get("audit_trail") or [])
    case_item["audit_trail"].append({"id": _new_id("audit"), "ts": _now_iso(), "actor": actor, "action": "evidence_added", "summary": evidence["title"]})
    _save_collection("cases", [case_item if str(item.get("id") or "") == case_id else item for item in rows])
    append_audit_event(
        actor=actor,
        action="case.evidence_added",
        object_type="case",
        object_id=case_id,
        summary=evidence["title"],
        details={"evidence_id": evidence["id"], "kind": evidence["kind"]},
    )
    return _json_clone(case_item)


def list_entities(*, entity_type: str = "", q: str = "", limit: int = 200) -> list[dict[str, Any]]:
    rows = _collection("entities", _default_entities)
    safe_type = str(entity_type or "").strip().lower()
    token = str(q or "").strip().lower()
    filtered = rows
    if safe_type:
        filtered = [item for item in filtered if str(item.get("entity_type") or "").lower() == safe_type]
    if token:
        filtered = [item for item in filtered if token in json.dumps(item, ensure_ascii=False).lower()]
    filtered.sort(key=lambda item: (float(item.get("risk_score") or 0), _parse_ts(str(item.get("last_seen_ts") or item.get("updated_ts") or ""))), reverse=True)
    return _json_clone(filtered[: max(1, min(500, limit))])


def _signal_context(signal: dict[str, Any]) -> dict[str, Any]:
    context = signal.get("context") or {}
    return dict(context) if isinstance(context, dict) else {}


def _extract_signal_values(signals: list[dict[str, Any]], keys: tuple[str, ...], *, limit: int = 8) -> list[str]:
    values: list[str] = []
    for signal in signals:
        context = _signal_context(signal)
        for key in keys:
            raw_value = context.get(key) if key in context else signal.get(key)
            if isinstance(raw_value, list):
                candidates = raw_value
            else:
                candidates = [raw_value]
            for candidate in candidates:
                text = str(candidate or "").strip()
                if text and text not in values:
                    values.append(text)
                    if len(values) >= limit:
                        return values
    return values


def _extract_signal_actor_ips(signals: list[dict[str, Any]]) -> list[str]:
    return _extract_signal_values(signals, ("src_ip", "actor_ip", "ip", "client_ip"))


def _extract_signal_sources(signals: list[dict[str, Any]]) -> list[str]:
    values: list[str] = []
    for signal in signals:
        for candidate in (signal.get("source"), _signal_context(signal).get("log_source"), _signal_context(signal).get("collector_profile")):
            text = str(candidate or "").strip()
            if text and text not in values:
                values.append(text)
    return values[:8]


def _extract_signal_users(signals: list[dict[str, Any]]) -> list[str]:
    return _extract_signal_values(signals, ("user", "user_name", "src_user", "actor_user", "username", "target_user"))


def _extract_signal_destinations(signals: list[dict[str, Any]]) -> list[str]:
    return _extract_signal_values(signals, ("dst_ip", "dest_ip", "destination_ip", "destination", "dst_host", "hostname", "domain", "remote_host"))


def _extract_signal_services(signals: list[dict[str, Any]]) -> list[str]:
    return _extract_signal_values(signals, ("service", "service_name", "dst_port_name", "target_service", "pipeline_name"))


def _extract_signal_assets(signals: list[dict[str, Any]]) -> list[str]:
    return _extract_signal_values(signals, ("asset_id", "host_name", "hostname", "target_host", "device_name"))


def _extract_signal_indicators(signals: list[dict[str, Any]]) -> list[str]:
    return _extract_signal_values(
        signals,
        ("ti_indicator", "indicator", "ioc", "ioc_value", "sha256", "md5", "domain", "url"),
        limit=12,
    )


def _extract_signal_vulnerabilities(signals: list[dict[str, Any]]) -> list[str]:
    return _extract_signal_values(signals, ("cve", "cves", "vulnerability", "finding_key"), limit=12)


def _extract_signal_processes(signals: list[dict[str, Any]]) -> list[str]:
    return _extract_signal_values(signals, ("process_name", "process", "process_executable", "image", "command"), limit=12)


def _extract_signal_parent_processes(signals: list[dict[str, Any]]) -> list[str]:
    return _extract_signal_values(signals, ("parent_process_name", "parent_process", "parent_image", "parent_command"), limit=12)


def _extract_outbound_destinations(signals: list[dict[str, Any]]) -> list[str]:
    return _extract_signal_values(signals, ("dst_ip", "destination_ip", "domain", "url", "remote_host"), limit=12)


def _signal_text(signal: dict[str, Any]) -> str:
    context = _signal_context(signal)
    return " ".join(
        str(part or "")
        for part in (
            signal.get("kind"),
            signal.get("summary"),
            signal.get("source"),
            context.get("event_action"),
            context.get("event_outcome"),
            context.get("process_name"),
            context.get("parent_process_name"),
            context.get("service"),
        )
    ).lower()


def _build_entity_baseline(entity: dict[str, Any], signals: list[dict[str, Any]]) -> dict[str, Any]:
    open_signals = [item for item in signals if str(item.get("status") or "open") == "open"]
    signal_kinds = {str(item.get("kind") or "signal").strip().lower() for item in signals if str(item.get("kind") or "").strip()}
    actor_ips = _extract_signal_actor_ips(signals)
    sources = _extract_signal_sources(signals)
    users = _extract_signal_users(signals)
    destinations = _extract_signal_destinations(signals)
    services = _extract_signal_services(signals)
    assets = _extract_signal_assets(signals)
    indicators = _extract_signal_indicators(signals)
    vulnerabilities = _extract_signal_vulnerabilities(signals)
    processes = _extract_signal_processes(signals)
    parent_processes = _extract_signal_parent_processes(signals)
    outbound_destinations = _extract_outbound_destinations(signals)
    name_tokens = " ".join(
        [
            str(entity.get("display_name") or ""),
            str(entity.get("name") or ""),
            str(dict(entity.get("attributes") or {}).get("role") or ""),
        ]
    ).lower()
    summaries = [_signal_text(item) for item in signals]
    privileged = any(token in name_tokens for token in ("admin", "root", "priv", "svc", "service"))
    anomaly_score = round(min(100.0, float(entity.get("risk_score") or 0) * 0.55 + len(open_signals) * 12 + len(actor_ips) * 5), 1)
    novelty_score = round(min(100.0, len(signal_kinds) * 16 + len(sources) * 7 + len(actor_ips) * 8), 1)
    failed_auth_count = sum(
        1
        for text in summaries
        if any(token in text for token in ("auth", "credential", "login", "signin", "kerberos", "ssh"))
        and any(token in text for token in ("fail", "invalid", "denied", "spray", "brute"))
    )
    behavior_drift_score = round(
        min(100.0, novelty_score * 0.45 + len(destinations) * 7 + len(processes) * 6 + len(parent_processes) * 4 + len(indicators) * 5),
        1,
    )
    rare_activity_score = round(
        min(100.0, len(signal_kinds) * 12 + len(indicators) * 9 + len(vulnerabilities) * 8 + (14 if len(processes) <= 2 and processes else 0)),
        1,
    )
    lateral_movement_precursor = bool(
        (len(actor_ips) >= 2 and len(assets) >= 2)
        or any(token in " ".join(summaries) for token in ("winrm", "psexec", "rdp", "remote service", "lateral", "wmic"))
    )
    privilege_escalation_precursor = bool(
        privileged or any(token in " ".join(summaries) for token in ("sudo", "privilege", "elevat", "token theft", "uac"))
    )
    behavioral_findings = [
        finding
        for finding, enabled in (
            ("failed_auth_burst", failed_auth_count >= 3),
            ("behavior_drift", behavior_drift_score >= 55.0),
            ("rare_activity", rare_activity_score >= 55.0),
            ("lateral_movement_precursor", lateral_movement_precursor),
            ("privilege_escalation_precursor", privilege_escalation_precursor),
        )
        if enabled
    ]
    return {
        "window": "rolling-30d",
        "peer_group": f"{str(entity.get('entity_type') or 'entity')}::{str(entity.get('criticality') or 'medium')}",
        "expected_signals_per_day": round(max(0.5, len(signals) / 14.0), 1),
        "current_open_signals": len(open_signals),
        "anomaly_score": anomaly_score,
        "novelty_score": novelty_score,
        "behavior_drift_score": behavior_drift_score,
        "rare_activity_score": rare_activity_score,
        "failed_auth_count": failed_auth_count,
        "failed_auth_burst": failed_auth_count >= 3,
        "lateral_movement_precursor": lateral_movement_precursor,
        "privilege_escalation_precursor": privilege_escalation_precursor,
        "privileged": privileged,
        "host_telemetry_ready": bool(str(entity.get("entity_type") or "").strip().lower() == "host" or any("host" in str(item.get("kind") or "") for item in signals)),
        "actor_ip_ready": bool(actor_ips),
        "user_context_ready": bool(users),
        "destination_context_ready": bool(destinations),
        "process_lineage_ready": bool(processes),
        "indicator_context_ready": bool(indicators),
        "vuln_context_ready": bool(vulnerabilities),
        "outbound_destination_ready": bool(outbound_destinations),
        "evidence_density": round(
            (len(actor_ips) + len(users) + len(destinations) + len(services) + len(assets) + len(indicators) + len(vulnerabilities) + len(processes))
            / max(1, len(signals)),
            2,
        ),
        "sources": sources,
        "actor_ips": actor_ips,
        "users": users,
        "destinations": destinations,
        "outbound_destinations": outbound_destinations,
        "services": services,
        "assets": assets,
        "indicators": indicators,
        "vulnerabilities": vulnerabilities,
        "processes": processes,
        "parent_processes": parent_processes,
        "behavioral_findings": behavioral_findings,
    }


def _build_entity_evidence_graph(entity: dict[str, Any], signals: list[dict[str, Any]]) -> dict[str, Any]:
    entity_node_id = str(entity.get("id") or "entity")
    nodes: list[dict[str, Any]] = [
        {
            "id": entity_node_id,
            "type": str(entity.get("entity_type") or "entity"),
            "label": str(entity.get("display_name") or entity.get("name") or entity_node_id),
            "tone": str(entity.get("risk_level") or "default"),
        }
    ]
    edges: list[dict[str, Any]] = []
    seen_nodes = {entity_node_id}

    def add_node(node_id: str, node_type: str, label: str, tone: str) -> None:
        if node_id not in seen_nodes:
            nodes.append({"id": node_id, "type": node_type, "label": label, "tone": tone})
            seen_nodes.add(node_id)

    for case_id in [str(item).strip() for item in (entity.get("linked_cases") or []) if str(item).strip()]:
        node_id = f"case::{case_id}"
        add_node(node_id, "case", case_id, "warning")
        edges.append({"source": entity_node_id, "target": node_id, "label": "linked_case"})
    for source in _extract_signal_sources(signals):
        node_id = f"source::{source}"
        add_node(node_id, "source", source, "info")
        edges.append({"source": node_id, "target": entity_node_id, "label": "observed"})
    for ip in _extract_signal_actor_ips(signals):
        node_id = f"ip::{ip}"
        add_node(node_id, "ip", ip, "critical")
        edges.append({"source": node_id, "target": entity_node_id, "label": "acts_on"})
    for user_name in _extract_signal_users(signals):
        node_id = f"user::{user_name}"
        add_node(node_id, "user", user_name, "warning")
        edges.append({"source": node_id, "target": entity_node_id, "label": "authenticates_to" if str(entity.get("entity_type") or "") != "host" else "user_to_host"})
    for destination in _extract_signal_destinations(signals):
        node_id = f"dst::{destination}"
        add_node(node_id, "destination", destination, "info")
        edges.append({"source": entity_node_id, "target": node_id, "label": "host_outbound_destination" if str(entity.get("entity_type") or "") == "host" else "connects_to"})
    for service in _extract_signal_services(signals):
        node_id = f"svc::{service}"
        add_node(node_id, "service", service, "default")
        edges.append({"source": entity_node_id, "target": node_id, "label": "uses_service"})
    for asset in _extract_signal_assets(signals):
        node_id = f"asset::{asset}"
        add_node(node_id, "asset", asset, "default")
        edges.append({"source": entity_node_id, "target": node_id, "label": "linked_asset"})
    for indicator in _extract_signal_indicators(signals):
        node_id = f"indicator::{indicator}"
        add_node(node_id, "indicator", indicator, "critical")
        edges.append({"source": node_id, "target": entity_node_id, "label": "indicator_to_host"})
    for vulnerability in _extract_signal_vulnerabilities(signals):
        vuln_node = f"vuln::{vulnerability}"
        add_node(vuln_node, "vulnerability", vulnerability, "warning")
        edges.append({"source": entity_node_id, "target": vuln_node, "label": "vulnerability_context"})
        for asset in _extract_signal_assets(signals):
            asset_node = f"asset::{asset}"
            add_node(asset_node, "asset", asset, "default")
            edges.append({"source": asset_node, "target": vuln_node, "label": "asset_to_vulnerability"})
    for process_name in _extract_signal_processes(signals):
        process_node = f"process::{process_name}"
        add_node(process_node, "process", process_name, "warning")
        edges.append({"source": entity_node_id, "target": process_node, "label": "spawned_process"})
    for parent_name in _extract_signal_parent_processes(signals):
        parent_node = f"parent::{parent_name}"
        add_node(parent_node, "process_parent", parent_name, "default")
        for process_name in _extract_signal_processes(signals):
            process_node = f"process::{process_name}"
            add_node(process_node, "process", process_name, "warning")
            edges.append({"source": process_node, "target": parent_node, "label": "process_to_parent"})
    return {"nodes": nodes[:16], "edges": edges[:24]}


def _build_entity_hypotheses(entity: dict[str, Any], signals: list[dict[str, Any]], baseline: dict[str, Any]) -> list[dict[str, Any]]:
    summaries = " ".join(str(item.get("summary") or item.get("kind") or "") for item in signals).lower()
    hypotheses: list[dict[str, Any]] = []
    if bool(baseline.get("failed_auth_burst")):
        hypotheses.append({"title": "Password spray or auth burst", "confidence": 0.79, "rationale": "The entity shows repeated failed authentication activity above the UEBA burst threshold."})
    if "auth" in summaries or "credential" in summaries or "ssh" in summaries:
        hypotheses.append({"title": "Credential abuse or access misuse", "confidence": 0.72, "rationale": "Authentication-oriented signals dominate the entity trail."})
    if "process" in summaries or "exec" in summaries or "command" in summaries:
        hypotheses.append({"title": "Execution lineage needs review", "confidence": 0.66, "rationale": "Process or command execution signals are present in the risk trail."})
    if bool(baseline.get("lateral_movement_precursor")):
        hypotheses.append({"title": "Lateral movement precursor", "confidence": 0.74, "rationale": "Source diversity, remote execution markers or cross-host context suggest propagation activity."})
    if bool(baseline.get("indicator_context_ready")) and bool(baseline.get("outbound_destination_ready")):
        hypotheses.append({"title": "Indicator-linked outbound activity", "confidence": 0.69, "rationale": "Threat indicators and outbound destinations are both materialized in the evidence trail."})
    if len(list(baseline.get("actor_ips") or [])) >= 2 or len(list(baseline.get("sources") or [])) >= 2:
        hypotheses.append({"title": "Multi-source activity may indicate propagation or automation", "confidence": 0.61, "rationale": "The entity is touched by multiple source systems or actor IP addresses."})
    if not hypotheses:
        hypotheses.append({"title": "Entity risk posture elevated", "confidence": 0.55, "rationale": f"Rolling risk score is {entity.get('risk_score') or 0} with {entity.get('signals_recent') or 0} recent signal(s)."})
    return hypotheses[:3]


def get_entity(entity_id: str) -> dict[str, Any] | None:
    item = _find_by_id(_collection("entities", _default_entities), entity_id)
    if item is None:
        return None
    cloned = _json_clone(item)
    signals = list_risk_signals(entity_id=entity_id, limit=200)
    baseline = _build_entity_baseline(cloned, signals)
    cloned["signals"] = signals
    cloned["baseline"] = baseline
    cloned["relationships"] = {
        "sources": baseline["sources"],
        "actor_ips": baseline["actor_ips"],
        "users": baseline["users"],
        "destinations": baseline["destinations"],
        "outbound_destinations": baseline["outbound_destinations"],
        "services": baseline["services"],
        "assets": baseline["assets"],
        "indicators": baseline["indicators"],
        "vulnerabilities": baseline["vulnerabilities"],
        "processes": baseline["processes"],
        "parent_processes": baseline["parent_processes"],
        "linked_cases": list(cloned.get("linked_cases") or []),
    }
    cloned["evidence_graph"] = _build_entity_evidence_graph(cloned, signals)
    cloned["hypotheses"] = _build_entity_hypotheses(cloned, signals, baseline)
    cloned["investigation_bundle"] = {
        "summary": {
            "signal_count": len(signals),
            "open_signals": int(baseline.get("current_open_signals") or 0),
            "anomaly_score": float(baseline.get("anomaly_score") or 0.0),
            "evidence_density": float(baseline.get("evidence_density") or 0.0),
        },
        "actors": list(baseline.get("actor_ips") or []),
        "users": list(baseline.get("users") or []),
        "destinations": list(baseline.get("destinations") or []),
        "outbound_destinations": list(baseline.get("outbound_destinations") or []),
        "services": list(baseline.get("services") or []),
        "assets": list(baseline.get("assets") or []),
        "indicators": list(baseline.get("indicators") or []),
        "vulnerabilities": list(baseline.get("vulnerabilities") or []),
        "processes": list(baseline.get("processes") or []),
        "parent_processes": list(baseline.get("parent_processes") or []),
        "behavioral_findings": list(baseline.get("behavioral_findings") or []),
        "pivot_keys": [
            *list(baseline.get("actor_ips") or []),
            *list(baseline.get("users") or []),
            *list(baseline.get("destinations") or []),
            *list(baseline.get("indicators") or []),
        ][:12],
    }
    return cloned


def _normalize_entity(payload: dict[str, Any], existing: dict[str, Any] | None = None) -> dict[str, Any]:
    entity_type = str(payload.get("entity_type") or (existing.get("entity_type") if existing else "host") or "host").strip().lower()
    entity_name = str(payload.get("name") or (existing.get("name") if existing else "") or "").strip()
    entity_id = str(payload.get("id") or (existing.get("id") if existing else "") or _safe_slug(f"{entity_type}-{entity_name}", default=_new_id("entity"))).strip()
    risk_score = float(payload.get("risk_score") if payload.get("risk_score") is not None else (existing.get("risk_score") if existing else 0) or 0)
    return {
        "id": entity_id,
        "type": "entity",
        "schema_version": CONTROL_PLANE_SCHEMA_VERSION,
        "entity_type": entity_type,
        "name": entity_name or entity_id,
        "display_name": str(payload.get("display_name") or (existing.get("display_name") if existing else entity_name) or entity_name or entity_id),
        "criticality": str(payload.get("criticality") or (existing.get("criticality") if existing else "medium") or "medium"),
        "risk_score": round(max(0.0, min(100.0, risk_score)), 1),
        "risk_level": _risk_level(risk_score),
        "status": str(payload.get("status") or (existing.get("status") if existing else "active") or "active"),
        "tags": [str(item).strip() for item in (payload.get("tags") or (existing.get("tags") if existing else [])) if str(item).strip()],
        "attributes": dict(payload.get("attributes") or (existing.get("attributes") if existing else {})),
        "signals_recent": int(payload.get("signals_recent") if payload.get("signals_recent") is not None else (existing.get("signals_recent") if existing else 0) or 0),
        "linked_cases": [str(item).strip() for item in (payload.get("linked_cases") or (existing.get("linked_cases") if existing else [])) if str(item).strip()],
        "last_seen_ts": str(payload.get("last_seen_ts") or (existing.get("last_seen_ts") if existing else "") or ""),
        "updated_ts": _now_iso(),
        "timeline": _json_clone(existing.get("timeline") if existing else []),
    }


def save_entity(payload: dict[str, Any]) -> dict[str, Any]:
    rows = _collection("entities", _default_entities)
    entity_id = str(payload.get("id") or "").strip()
    existing = _find_by_id(rows, entity_id) if entity_id else None
    item = _normalize_entity(payload, existing)
    rows = [row for row in rows if str(row.get("id") or "") != item["id"]]
    rows.append(item)
    _save_collection("entities", rows)
    return _json_clone(item)


def list_risk_signals(*, entity_id: str = "", limit: int = 100) -> list[dict[str, Any]]:
    rows = _collection("risk_signals", _default_risk_signals)
    filtered = rows
    safe_entity_id = str(entity_id or "").strip()
    if safe_entity_id:
        filtered = [item for item in rows if str(item.get("entity_id") or "") == safe_entity_id]
    filtered.sort(key=lambda item: _parse_ts(str(item.get("ts") or "")), reverse=True)
    return _json_clone(filtered[: max(1, min(500, limit))])


def record_risk_signal(payload: dict[str, Any], *, actor: str = "system") -> dict[str, Any]:
    entities = _collection("entities", _default_entities)
    entity_type = str(payload.get("entity_type") or "host").strip().lower()
    entity_name = str(payload.get("entity_name") or payload.get("name") or payload.get("entity_id") or "").strip()
    entity_id = str(payload.get("entity_id") or _safe_slug(f"{entity_type}-{entity_name}", default=_new_id("entity"))).strip()
    entity = _find_by_id(entities, entity_id)
    if entity is None:
        entity = _normalize_entity({"id": entity_id, "entity_type": entity_type, "name": entity_name or entity_id, "display_name": entity_name or entity_id, "attributes": dict(payload.get("attributes") or {})})
        entities.append(entity)

    score = float(payload.get("score") or 0)
    signal = {
        "id": _new_id("signal"),
        "type": "risk_signal",
        "schema_version": CONTROL_PLANE_SCHEMA_VERSION,
        "entity_id": entity_id,
        "entity_type": entity_type,
        "entity_name": entity_name or entity.get("name") or entity_id,
        "kind": str(payload.get("kind") or "rule_match").strip().lower(),
        "severity": _normalize_severity(str(payload.get("severity") or "medium")),
        "score": round(max(0.0, min(100.0, score)), 1),
        "status": str(payload.get("status") or "open").strip().lower(),
        "summary": str(payload.get("summary") or payload.get("message") or "").strip(),
        "source": str(payload.get("source") or "manual").strip(),
        "rule_id": str(payload.get("rule_id") or "").strip(),
        "ts": str(payload.get("ts") or _now_iso()).strip(),
        "case_promotion_eligible": bool(payload.get("case_promotion_eligible", score >= 60)),
        "context": _json_clone(payload.get("context") or {}),
        "created_by": actor,
    }
    signals = _collection("risk_signals", _default_risk_signals)
    signals.append(signal)
    signals = sorted(signals, key=lambda item: _parse_ts(str(item.get("ts") or "")), reverse=True)[:1000]
    _save_collection("risk_signals", signals)

    entity_signals = [item for item in signals if str(item.get("entity_id") or "") == entity_id and str(item.get("status") or "") not in {"dismissed", "closed"}]
    aggregate_score = round(min(100.0, sum(float(item.get("score") or 0) for item in entity_signals)), 1)
    entity["risk_score"] = aggregate_score
    entity["risk_level"] = _risk_level(aggregate_score)
    entity["signals_recent"] = len(entity_signals)
    entity["last_seen_ts"] = signal["ts"]
    entity["updated_ts"] = _now_iso()
    entity["timeline"] = list(entity.get("timeline") or [])
    entity["timeline"].append({"id": _new_id("timeline"), "ts": signal["ts"], "kind": "risk_signal", "summary": signal["summary"] or signal["kind"], "score": signal["score"], "severity": signal["severity"]})
    _save_collection("entities", [entity if str(item.get("id") or "") == entity_id else item for item in entities])
    append_audit_event(
        actor=actor,
        action="entity.signal_recorded",
        object_type="risk_signal",
        object_id=signal["id"],
        summary=signal["summary"] or signal["kind"],
        details={"entity_id": entity_id, "score": signal["score"], "severity": signal["severity"], "source": signal["source"]},
    )
    return {"signal": _json_clone(signal), "entity": _json_clone(entity)}


def promote_entity_to_case(entity_id: str, *, created_by: str = "system", title: str = "") -> dict[str, Any]:
    entity = get_entity(entity_id)
    if entity is None:
        raise ValueError(f"Entity not found: {entity_id}")
    signals = [item for item in list_risk_signals(entity_id=entity_id, limit=20) if item.get("case_promotion_eligible")]
    top_summaries = [str(item.get("summary") or item.get("kind") or "signal").strip() for item in signals[:3] if str(item.get("summary") or item.get("kind") or "").strip()]
    case_item = save_case(
        {
            "title": title.strip() or f"Risk insight: {entity.get('display_name') or entity.get('name') or entity_id}",
            "summary": "; ".join(top_summaries) or f"Promoted from entity risk score {entity.get('risk_score')}.",
            "status": "new",
            "severity": _risk_level(float(entity.get("risk_score") or 0)) if float(entity.get("risk_score") or 0) >= 40 else "medium",
            "priority": 1 if float(entity.get("risk_score") or 0) >= 80 else 2 if float(entity.get("risk_score") or 0) >= 60 else 3,
            "source": "entity_promotion",
            "related_entities": [entity_id],
            "tags": ["risk-promotion", str(entity.get("entity_type") or "entity")],
            "source_alerts": [{"kind": "risk_signal", "signal_id": item["id"]} for item in signals],
        },
        actor=created_by,
    )
    entities = _collection("entities", _default_entities)
    current = _find_by_id(entities, entity_id)
    if current is not None:
        current["linked_cases"] = list(current.get("linked_cases") or [])
        if case_item["id"] not in current["linked_cases"]:
            current["linked_cases"].append(case_item["id"])
        current["updated_ts"] = _now_iso()
        _save_collection("entities", [current if str(item.get("id") or "") == entity_id else item for item in entities])
    append_audit_event(
        actor=created_by,
        action="entity.promoted_to_case",
        object_type="entity",
        object_id=entity_id,
        summary=case_item["title"],
        details={"case_id": case_item["id"], "risk_score": entity.get("risk_score")},
    )
    return case_item


def get_entities_overview() -> dict[str, Any]:
    items = list_entities(limit=300)
    signals = list_risk_signals(limit=200)
    level_counts = Counter(str(item.get("risk_level") or "none") for item in items)
    baselines = [_build_entity_baseline(item, [signal for signal in signals if str(signal.get("entity_id") or "") == str(item.get("id") or "")]) for item in items]
    graph_edges = sum(len(_build_entity_evidence_graph(item, [signal for signal in signals if str(signal.get("entity_id") or "") == str(item.get("id") or "")]).get("edges") or []) for item in items[:50])
    return {
        "items": items,
        "signals": signals[:60],
        "metrics": {
            "total": len(items),
            "high_risk": sum(1 for item in items if str(item.get("risk_level") or "") in {"critical", "high"}),
            "open_signals": sum(1 for item in signals if str(item.get("status") or "") == "open"),
            "promotion_candidates": sum(1 for item in signals if item.get("case_promotion_eligible")),
            "anomalous_entities": sum(1 for item in baselines if float(item.get("anomaly_score") or 0) >= 70),
            "privileged_entities": sum(1 for item in baselines if bool(item.get("privileged"))),
            "graph_edges": graph_edges,
            "actor_context_ready": sum(1 for item in baselines if bool(item.get("actor_ip_ready"))),
            "destination_context_ready": sum(1 for item in baselines if bool(item.get("destination_context_ready"))),
            "indicator_context_ready": sum(1 for item in baselines if bool(item.get("indicator_context_ready"))),
            "vuln_context_ready": sum(1 for item in baselines if bool(item.get("vuln_context_ready"))),
            "process_lineage_ready": sum(1 for item in baselines if bool(item.get("process_lineage_ready"))),
            "outbound_destination_ready": sum(1 for item in baselines if bool(item.get("outbound_destination_ready"))),
            "behavioral_models_ready": sum(
                1
                for item in baselines
                if bool(item.get("failed_auth_burst"))
                or bool(item.get("lateral_movement_precursor"))
                or float(item.get("behavior_drift_score") or 0.0) >= 50.0
                or float(item.get("rare_activity_score") or 0.0) >= 50.0
            ),
            "investigation_ready": sum(
                1
                for item in baselines
                if bool(item.get("actor_ip_ready")) and bool(item.get("destination_context_ready")) and float(item.get("evidence_density") or 0.0) >= 1.0
            ),
        },
        "breakdowns": {
            "risk_level": [{"label": label, "count": count} for label, count in level_counts.most_common()],
            "entity_type": [{"label": label, "count": count} for label, count in Counter(str(item.get("entity_type") or "unknown") for item in items).most_common()],
        },
    }


