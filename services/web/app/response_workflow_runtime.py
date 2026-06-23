from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any


DEFAULT_RESPONSE_POLICY_PACKS: list[dict[str, Any]] = [
    {
        "id": "identity-containment",
        "title": "Identity Containment",
        "category": "Containment",
        "description": "Approval-heavy actions for identity disable, token revocation, and access suspension.",
        "recommended_trigger_kinds": ["detection_alert", "case"],
        "default_approval_mode": "two_man",
    },
    {
        "id": "endpoint-containment",
        "title": "Endpoint Containment",
        "category": "Containment",
        "description": "Host isolation and emergency endpoint response workflows.",
        "recommended_trigger_kinds": ["detection_alert", "case", "entity_risk"],
        "default_approval_mode": "two_man",
    },
    {
        "id": "vulnerability-response",
        "title": "Vulnerability Response",
        "category": "Vulnerability",
        "description": "Greenbone import, policy application, escalation, and remediation orchestration.",
        "recommended_trigger_kinds": ["vulnerability_finding", "report"],
        "default_approval_mode": "single",
    },
    {
        "id": "platform-resilience",
        "title": "Platform Resilience",
        "category": "Platform",
        "description": "Transport, storage, and recovery response actions for platform health regressions.",
        "recommended_trigger_kinds": ["platform_health", "manual"],
        "default_approval_mode": "single",
    },
    {
        "id": "recovery-verification",
        "title": "Recovery Verification",
        "category": "Recovery",
        "description": "Backup, restore, and failover verification procedures.",
        "recommended_trigger_kinds": ["backup", "platform_health"],
        "default_approval_mode": "single",
    },
]


def _string(value: Any) -> str:
    return str(value or "").strip()


def _string_list(values: Any) -> list[str]:
    if isinstance(values, str):
        raw = values.split(",")
    elif isinstance(values, (list, tuple, set)):
        raw = list(values)
    else:
        raw = []
    deduped: list[str] = []
    seen: set[str] = set()
    for item in raw:
        text = _string(item)
        if not text:
            continue
        key = text.lower()
        if key in seen:
            continue
        seen.add(key)
        deduped.append(text)
    return deduped


def _now() -> datetime:
    return datetime.now(tz=timezone.utc)


def _now_iso() -> str:
    return _now().replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _safe_int(value: Any, default: int, *, minimum: int = 0, maximum: int = 5000) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        parsed = int(default)
    return max(minimum, min(maximum, parsed))


def _normalize_role_list(values: Any) -> list[str]:
    return [item.lower() for item in _string_list(values)]


def _has_runtime_value(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, (list, tuple, set, dict)):
        return bool(value)
    return bool(_string(value))


def infer_policy_pack_id(action: dict[str, Any] | None) -> str:
    payload = dict(action or {})
    explicit = _string(payload.get("policy_pack_id") or payload.get("policy_pack") or payload.get("template_category"))
    if explicit:
        return explicit.lower()
    haystack = " ".join(
        [
            _string(payload.get("title")).lower(),
            _string(payload.get("description")).lower(),
            _string(payload.get("kind")).lower(),
            " ".join(_string(step.get("kind")).lower() for step in (payload.get("steps") or []) if isinstance(step, dict)),
        ]
    )
    if any(token in haystack for token in ("identity", "account", "disable-user", "idp", "suspend")):
        return "identity-containment"
    if any(token in haystack for token in ("endpoint", "host isolation", "edr", "quarantine", "isolate")):
        return "endpoint-containment"
    if any(token in haystack for token in ("vuln", "greenbone", "openvas", "scanner", "remediation")):
        return "vulnerability-response"
    if any(token in haystack for token in ("backup", "restore", "failover", "recovery")):
        return "recovery-verification"
    return "platform-resilience"


def normalize_response_approval(
    raw: Any,
    *,
    required: bool,
    dangerous: bool,
) -> dict[str, Any]:
    payload = dict(raw or {})
    required_value = bool(payload.get("required", required))
    default_min_approvers = 2 if dangerous else 1
    min_approvers = _safe_int(payload.get("min_approvers"), default_min_approvers, minimum=1, maximum=5)
    if not required_value:
        min_approvers = 0
    mode = _string(payload.get("mode") or ("two_man" if min_approvers >= 2 else "single")).lower() or "single"
    justification_required = bool(payload.get("justification_required", dangerous))
    expires_minutes = _safe_int(payload.get("expires_minutes"), 30 if dangerous else 120, minimum=5, maximum=1440) if required_value else 0
    return {
        "required": required_value,
        "mode": mode,
        "min_approvers": min_approvers,
        "required_roles": _normalize_role_list(payload.get("required_roles")),
        "notify_channels": _string_list(payload.get("notify_channels")),
        "justification_required": justification_required,
        "expires_minutes": expires_minutes,
        "role_separation_required": bool(payload.get("role_separation_required", min_approvers >= 2 or bool(_normalize_role_list(payload.get("required_roles"))))),
        "allowed_trigger_kinds": [item.lower() for item in _string_list(payload.get("allowed_trigger_kinds"))],
    }


def normalize_action_linkage(raw: Any) -> dict[str, Any]:
    payload = dict(raw or {})
    linkage = {
        "case_id": _string(payload.get("case_id")),
        "alert_id": _string(payload.get("alert_id")),
        "incident_id": _string(payload.get("incident_id") or payload.get("agg_id")),
        "detection_id": _string(payload.get("detection_id") or payload.get("rule_id")),
        "finding_key": _string(payload.get("finding_key")),
        "report_id": _string(payload.get("report_id")),
        "asset_id": _string(payload.get("asset_id")),
        "asset_ip": _string(payload.get("asset_ip") or payload.get("dst_ip")),
        "asset_hostname": _string(payload.get("asset_hostname") or payload.get("host_name")),
        "entity_id": _string(payload.get("entity_id")),
        "entity_type": _string(payload.get("entity_type")),
        "entity_name": _string(payload.get("entity_name")),
        "source_event_id": _string(payload.get("source_event_id") or payload.get("event_id")),
        "trigger_id": _string(payload.get("trigger_id")),
        "trigger_kind": _string(payload.get("trigger_kind")),
        "case_ids": _string_list(payload.get("case_ids")),
        "related_findings": _string_list(payload.get("related_findings")),
        "related_alerts": _string_list(payload.get("related_alerts")),
    }
    return {key: value for key, value in linkage.items() if _has_runtime_value(value)}


def build_execution_linkage(action: dict[str, Any], payload: dict[str, Any]) -> dict[str, Any]:
    merged = normalize_action_linkage(action.get("default_linkage") or {})
    if isinstance(payload.get("linkage"), dict):
        merged.update(normalize_action_linkage(payload.get("linkage") or {}))
    for key in ("case_id", "alert_id", "incident_id", "detection_id", "finding_key", "report_id", "asset_id", "asset_ip", "asset_hostname", "entity_id", "entity_type", "entity_name", "source_event_id"):
        if _string(payload.get(key)):
            merged[key] = _string(payload.get(key))
    if not merged.get("trigger_id"):
        merged["trigger_id"] = (
            _string(merged.get("alert_id"))
            or _string(merged.get("finding_key"))
            or _string(merged.get("case_id"))
            or _string(payload.get("trigger_id"))
        )
    if not merged.get("trigger_kind"):
        if merged.get("finding_key") or merged.get("report_id"):
            merged["trigger_kind"] = "vulnerability_finding"
        elif merged.get("alert_id") or merged.get("detection_id") or merged.get("incident_id"):
            merged["trigger_kind"] = "detection_alert"
        elif merged.get("case_id"):
            merged["trigger_kind"] = "case"
        else:
            merged["trigger_kind"] = "manual"
    summary_parts = []
    for key in ("trigger_kind", "case_id", "alert_id", "finding_key", "asset_id", "entity_name"):
        value = _string(merged.get(key))
        if value:
            summary_parts.append(f"{key}={value}")
    if summary_parts:
        merged["summary"] = "; ".join(summary_parts[:4])
    return merged


def build_approval_state(config: dict[str, Any], *, actor: str, note: str = "") -> dict[str, Any]:
    required = bool(config.get("required"))
    expires_minutes = _safe_int(config.get("expires_minutes"), 0, minimum=0, maximum=1440)
    expires_ts = ""
    if required and expires_minutes > 0:
        expires_ts = (_now() + timedelta(minutes=expires_minutes)).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    return {
        "required": required,
        "mode": _string(config.get("mode") or "single") or "single",
        "min_approvers": _safe_int(config.get("min_approvers"), 1, minimum=0, maximum=5),
        "required_roles": _normalize_role_list(config.get("required_roles")),
        "role_separation_required": bool(config.get("role_separation_required", False)),
        "allowed_trigger_kinds": [item.lower() for item in _string_list(config.get("allowed_trigger_kinds"))],
        "notify_channels": _string_list(config.get("notify_channels")),
        "justification_required": bool(config.get("justification_required", False)),
        "requested_by": _string(actor) or "system",
        "requested_ts": _now_iso(),
        "request_note": _string(note),
        "expires_ts": expires_ts,
        "state": "awaiting_approval" if required else "not_required",
        "approvals": [],
        "rejections": [],
        "approval_progress": "0/0" if not required else f"0/{_safe_int(config.get('min_approvers'), 1, minimum=1, maximum=5)}",
    }


def approval_is_expired(state: dict[str, Any]) -> bool:
    expires_ts = _string(state.get("expires_ts"))
    if not expires_ts:
        return False
    text = expires_ts[:-1] + "+00:00" if expires_ts.endswith("Z") else expires_ts
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return False
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc) < _now()


def _approval_progress(state: dict[str, Any]) -> str:
    approvals = [dict(item) for item in (state.get("approvals") or []) if isinstance(item, dict)]
    min_approvers = _safe_int(state.get("min_approvers"), 1, minimum=0, maximum=5)
    return f"{len(approvals)}/{min_approvers}"


def _approval_has_required_roles(state: dict[str, Any]) -> bool:
    required_roles = _normalize_role_list(state.get("required_roles"))
    if not required_roles:
        return True
    approvals = [dict(item) for item in (state.get("approvals") or []) if isinstance(item, dict)]
    approved_roles = {str(item.get("actor_role") or "").strip().lower() for item in approvals if str(item.get("actor_role") or "").strip()}
    return all(role in approved_roles for role in required_roles)


def _approval_has_role_separation(state: dict[str, Any]) -> bool:
    if not bool(state.get("role_separation_required")):
        return True
    approvals = [dict(item) for item in (state.get("approvals") or []) if isinstance(item, dict)]
    actor_roles = {str(item.get("actor_role") or "").strip().lower() for item in approvals if str(item.get("actor_role") or "").strip()}
    if actor_roles:
        return len(actor_roles) >= min(2, max(1, _safe_int(state.get("min_approvers"), 1, minimum=1, maximum=5)))
    actors = {str(item.get("actor") or "").strip().lower() for item in approvals if str(item.get("actor") or "").strip()}
    return len(actors) >= min(2, max(1, _safe_int(state.get("min_approvers"), 1, minimum=1, maximum=5)))


def record_approval(
    state: dict[str, Any],
    *,
    actor: str,
    note: str = "",
    actor_role: str = "",
    principal_type: str = "user",
    break_glass: bool = False,
) -> dict[str, Any]:
    updated = dict(state or {})
    approvals = [dict(item) for item in (updated.get("approvals") or []) if isinstance(item, dict)]
    actor_value = _string(actor) or "system"
    if any(_string(item.get("actor")).lower() == actor_value.lower() for item in approvals):
        return updated
    approvals.append(
        {
            "actor": actor_value,
            "ts": _now_iso(),
            "note": _string(note),
            "actor_role": _string(actor_role).lower(),
            "principal_type": _string(principal_type) or "user",
            "break_glass": bool(break_glass),
        }
    )
    updated["approvals"] = approvals
    min_approvers = _safe_int(updated.get("min_approvers"), 1, minimum=0, maximum=5)
    updated["approval_progress"] = _approval_progress(updated)
    updated["state"] = "approved" if min_approvers and len(approvals) >= min_approvers and _approval_has_required_roles(updated) and _approval_has_role_separation(updated) else "awaiting_approval"
    return updated


def record_rejection(state: dict[str, Any], *, actor: str, reason: str) -> dict[str, Any]:
    updated = dict(state or {})
    rejections = [dict(item) for item in (updated.get("rejections") or []) if isinstance(item, dict)]
    rejections.append({"actor": _string(actor) or "system", "ts": _now_iso(), "reason": _string(reason)})
    updated["rejections"] = rejections
    updated["state"] = "rejected"
    updated["approval_progress"] = updated.get("approval_progress") or "0/0"
    return updated


def approval_ready(state: dict[str, Any]) -> bool:
    if not bool(state.get("required")):
        return True
    if approval_is_expired(state):
        return False
    if str(state.get("state") or "") != "approved":
        return False
    approvals = [dict(item) for item in (state.get("approvals") or []) if isinstance(item, dict)]
    if len(approvals) < _safe_int(state.get("min_approvers"), 1, minimum=1, maximum=5):
        return False
    if not _approval_has_required_roles(state):
        return False
    if not _approval_has_role_separation(state):
        return False
    return True


def build_response_policy_packs(actions: list[dict[str, Any]]) -> list[dict[str, Any]]:
    pack_index: dict[str, dict[str, Any]] = {str(item["id"]): dict(item) for item in DEFAULT_RESPONSE_POLICY_PACKS}
    for action in actions:
        pack_id = infer_policy_pack_id(action)
        pack = pack_index.setdefault(
            pack_id,
            {
                "id": pack_id,
                "title": pack_id.replace("-", " ").title(),
                "category": "Custom",
                "description": "Custom response policy pack",
                "recommended_trigger_kinds": [],
                "default_approval_mode": "single",
            },
        )
        pack.setdefault("action_ids", [])
        pack.setdefault("action_titles", [])
        pack.setdefault("required_roles", [])
        pack.setdefault("approval_modes", [])
        pack.setdefault("trigger_kinds", [])
        pack["action_ids"].append(_string(action.get("id")))
        pack["action_titles"].append(_string(action.get("title") or action.get("id")))
        approval = dict(action.get("approval") or {})
        required_roles = _normalize_role_list(approval.get("required_roles"))
        pack["required_roles"] = sorted({*list(pack.get("required_roles") or []), *required_roles})
        approval_mode = _string(approval.get("mode"))
        if approval_mode:
            pack["approval_modes"] = sorted({*list(pack.get("approval_modes") or []), approval_mode})
        pack["trigger_kinds"] = sorted({*list(pack.get("trigger_kinds") or []), *[item.lower() for item in _string_list(action.get("trigger_kinds"))]})
    rows = list(pack_index.values())
    for item in rows:
        item["action_count"] = len(item.get("action_ids") or [])
        item["action_ids"] = [value for value in item.get("action_ids") or [] if value]
        item["action_titles"] = [value for value in item.get("action_titles") or [] if value][:8]
        item["required_roles"] = [value for value in item.get("required_roles") or [] if value]
        item["approval_modes"] = [value for value in item.get("approval_modes") or [] if value]
        item["trigger_kinds"] = [value for value in item.get("trigger_kinds") or [] if value]
    rows.sort(key=lambda item: (_string(item.get("category")), _string(item.get("title"))))
    return rows
