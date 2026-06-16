from __future__ import annotations

from collections import Counter
from datetime import timedelta
import sqlite3
import time
import urllib.parse
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
_sample_records = core._sample_records
_resolve_config_value = core._resolve_config_value
_resolve_required_secrets = core._resolve_required_secrets
_resolve_runtime_object = core._resolve_runtime_object
_resolve_secret_value = core._resolve_secret_value
_safe_timeout_seconds = core._safe_timeout_seconds
_extract_records = core._extract_records
_http_request = core._http_request
_decode_http_payload = core._decode_http_payload
_normalize_connector_secret_requirements = core._normalize_connector_secret_requirements
_merge_seed_rows = core._merge_seed_rows
append_audit_event = core.append_audit_event
_default_connector_definitions = core._default_connector_definitions
_default_connector_runs = core._default_connector_runs


def _is_nonproduction_connector(item: dict[str, Any]) -> bool:
    connector_id = str(item.get("id") or "").strip().lower()
    title = str(item.get("title") or "").strip().lower()
    group = str(item.get("group") or "").strip().lower()
    source_family = str(item.get("source_family") or "").strip().lower()
    stage = str(item.get("stage") or "").strip().lower()
    if connector_id.startswith(("smoke-", "test-", "qa-")):
        return True
    if title.startswith(("smoke ", "test ", "qa ")):
        return True
    if group in {"smoke", "test", "qa"}:
        return True
    if source_family in {"smoke", "test", "qa"}:
        return True
    return stage in {"smoke", "test", "qa"}


def _production_connectors(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [dict(item) for item in items if not _is_nonproduction_connector(dict(item or {}))]


def _sync_vulnerability_targets_runtime(limit: int = 500) -> dict[str, Any]:
    try:
        from .deps import sync_vulnerability_targets
    except ImportError:  # pragma: no cover - local test fallback
        from deps import sync_vulnerability_targets  # type: ignore[no-redef]

    return dict(sync_vulnerability_targets(limit=limit))


def _import_greenbone_reports_runtime(limit: int = 20) -> dict[str, Any]:
    try:
        from .deps import import_greenbone_reports
    except ImportError:  # pragma: no cover - local test fallback
        from deps import import_greenbone_reports  # type: ignore[no-redef]

    return dict(import_greenbone_reports(limit=limit))


def _build_vulnerability_runtime_status_runtime(days: int = 14) -> dict[str, Any]:
    try:
        from .vuln_runtime import build_vulnerability_runtime_status
    except ImportError:  # pragma: no cover - local test fallback
        from vuln_runtime import build_vulnerability_runtime_status  # type: ignore[no-redef]

    return dict(build_vulnerability_runtime_status(days=days))


def _list_response_actions() -> list[dict[str, Any]]:
    try:
        from .control_plane_response_ops import list_response_actions as list_response_actions_impl
    except ImportError:  # pragma: no cover - local test fallback
        from control_plane_response_ops import list_response_actions as list_response_actions_impl  # type: ignore[no-redef]

    return list_response_actions_impl()


def list_integration_templates() -> list[dict[str, Any]]:
    rows = [
        {
            "id": item["id"],
            "family": item.get("family", "source"),
            "block_type": item.get("block_type", ""),
            "stage": item.get("stage", ""),
            "group": item.get("group", ""),
            "title": item.get("title", item["id"]),
            "description": item.get("description", ""),
            "protocols": list(item.get("protocols") or []),
            "mode": item.get("mode", ""),
            "source_family": item.get("source_family", ""),
            "enabled": bool(item.get("enabled", True)),
            "status": item.get("status", "planned"),
            "runtime": _json_clone(item.get("runtime") or {}),
            "secret_requirements": _json_clone(item.get("secret_requirements") or []),
        }
        for item in list_connector_definitions()
    ]
    rows.extend(
        {
            "id": item["id"],
            "family": "action",
            "block_type": f"{item.get('kind', 'action')}_output",
            "stage": "publish",
            "group": "outbound",
            "title": item.get("title", item["id"]),
            "description": item.get("description", ""),
            "protocols": [str(item.get("kind") or "action")],
            "mode": "output",
            "source_family": "notification",
            "enabled": bool(item.get("enabled", True)),
            "status": "ready" if item.get("enabled", True) else "planned",
            "runtime": {"direction": "outbound", "health": _json_clone(item.get("health") or {})},
            "secret_requirements": _json_clone(item.get("secret_requirements") or []),
        }
        for item in _list_response_actions()
    )
    return rows


def _normalize_connector_definition(item: dict[str, Any]) -> dict[str, Any]:
    normalized = _json_clone(item)
    telemetry = dict(normalized.get("telemetry") or {})
    normalized["telemetry"] = {
        "collection_depth": str(telemetry.get("collection_depth") or "basic").strip().lower() or "basic",
        "coverage_score": int(telemetry.get("coverage_score") or 0),
        "parsing_coverage_pct": float(telemetry.get("parsing_coverage_pct") or 0.0),
        "telemetry_quality_pct": float(telemetry.get("telemetry_quality_pct") or 0.0),
        "realtime": bool(telemetry.get("realtime", False)),
        "actor_ip_ready": bool(telemetry.get("actor_ip_ready", False)),
        "entity_mapping_ready": bool(telemetry.get("entity_mapping_ready", False)),
        "host_telemetry_ready": bool(telemetry.get("host_telemetry_ready", False)),
        "event_families": [str(value).strip() for value in (telemetry.get("event_families") or []) if str(value).strip()],
        "evidence_fields": [str(value).strip() for value in (telemetry.get("evidence_fields") or []) if str(value).strip()],
        "enrichment": [str(value).strip() for value in (telemetry.get("enrichment") or []) if str(value).strip()],
        "investigation_pivots": [str(value).strip() for value in (telemetry.get("investigation_pivots") or []) if str(value).strip()],
    }
    operations = dict(normalized.get("operations") or {})
    normalized["operations"] = {
        "release_stage": str(operations.get("release_stage") or "draft").strip().lower() or "draft",
        "bundle_id": str(operations.get("bundle_id") or "").strip(),
        "owner": str(operations.get("owner") or "platform-engineering").strip() or "platform-engineering",
        "playbooks": [str(value).strip() for value in (operations.get("playbooks") or []) if str(value).strip()],
        "compliance_controls": [str(value).strip() for value in (operations.get("compliance_controls") or []) if str(value).strip()],
        "runbook_id": str(operations.get("runbook_id") or "").strip(),
        "onboarding_template": str(operations.get("onboarding_template") or "").strip(),
        "support_tier": str(operations.get("support_tier") or "community").strip().lower() or "community",
    }
    normalized["release_gate"] = _build_connector_release_gate(normalized)
    normalized["status"] = _derive_connector_status(normalized)
    connector_id = str(normalized.get("id") or "").strip().lower()
    if connector_id != "greenbone-openvas-import":
        return normalized
    runtime = dict(normalized.get("runtime") or {})
    health = dict(runtime.get("health") or {})
    request_cfg = dict(runtime.get("request") or {})
    last_error = str(health.get("last_error") or "").strip()
    if str(normalized.get("block_type") or "").strip().lower() == "rest_pull" and not (
        str(request_cfg.get("url") or "").strip() or str(request_cfg.get("url_env") or "").strip()
    ):
        normalized["block_type"] = "vuln_runtime"
        runtime.setdefault("operation", "sync_import")
        if str(normalized.get("status") or "").strip().lower() == "error":
            normalized["status"] = "ready"
            health["last_status"] = "never"
            health["success_rate_24h"] = 0
            health["consecutive_failures"] = 0
            if not last_error or "runtime.request.url" in last_error:
                health["last_error"] = ""
    runtime["health"] = health
    normalized["runtime"] = runtime
    normalized["status"] = _derive_connector_status(normalized)
    return normalized


def _derive_connector_status(item: dict[str, Any]) -> str:
    if not bool(item.get("enabled", True)):
        return "disabled"
    status = str(item.get("status") or "").strip().lower()
    if status in {"healthy", "degraded", "error", "disabled"}:
        return status
    runtime = dict(item.get("runtime") or {})
    health = dict(runtime.get("health") or {})
    last_status = str(health.get("last_status") or "").strip().lower()
    if last_status in CONNECTOR_SUCCESS_STATUSES:
        return "healthy"
    if last_status in {"error", "failed", "blocked"}:
        return "error"
    if last_status in {"warning", "partial", "partial_failure"}:
        return "degraded"
    operations = dict(item.get("operations") or {})
    telemetry = dict(item.get("telemetry") or {})
    release_gate = dict(item.get("release_gate") or {})
    release_stage = str(operations.get("release_stage") or "").strip().lower()
    release_status = str(release_gate.get("status") or "").strip().lower()
    if release_stage in {"active", "live", "staged", "validated"}:
        return "ready"
    if release_status in {"ready_for_live", "live_with_gaps", "ready_for_stage", "stage_with_gaps", "ready_for_validation"}:
        return "ready"
    if int(telemetry.get("coverage_score") or 0) >= 70 and str(operations.get("bundle_id") or "").strip():
        return "ready"
    if status in {"planned", "scheduled"}:
        return "ready"
    return status or "ready"


def _merge_connector_seed(seed: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    merged = _json_clone(seed)
    merged.update(_json_clone(current))
    merged["telemetry"] = {
        **dict(seed.get("telemetry") or {}),
        **dict(current.get("telemetry") or {}),
    }
    merged["operations"] = {
        **dict(seed.get("operations") or {}),
        **dict(current.get("operations") or {}),
    }
    merged["runtime"] = {
        **dict(seed.get("runtime") or {}),
        **dict(current.get("runtime") or {}),
    }
    merged["mappings"] = {
        **dict(seed.get("mappings") or {}),
        **dict(current.get("mappings") or {}),
    }
    legacy_connector = bool(
        float(dict(current.get("telemetry") or {}).get("parsing_coverage_pct") or 0.0) <= 0.0
        and float(dict(current.get("telemetry") or {}).get("telemetry_quality_pct") or 0.0) <= 0.0
        and not list(dict(current.get("telemetry") or {}).get("investigation_pivots") or [])
        and not str(dict(current.get("operations") or {}).get("runbook_id") or "").strip()
        and not str(dict(current.get("operations") or {}).get("onboarding_template") or "").strip()
    )
    if legacy_connector:
        seed_telemetry = dict(seed.get("telemetry") or {})
        seed_operations = dict(seed.get("operations") or {})
        merged["telemetry"] = {
            **dict(current.get("telemetry") or {}),
            **seed_telemetry,
        }
        merged["operations"] = {
            **dict(current.get("operations") or {}),
            **seed_operations,
        }
        for field in ("event_families", "evidence_fields", "enrichment", "investigation_pivots"):
            current_values = [str(value).strip() for value in (dict(current.get("telemetry") or {}).get(field) or []) if str(value).strip()]
            seed_values = [str(value).strip() for value in (seed_telemetry.get(field) or []) if str(value).strip()]
            merged["telemetry"][field] = current_values or seed_values
        for field in ("playbooks", "compliance_controls"):
            current_values = [str(value).strip() for value in (dict(current.get("operations") or {}).get(field) or []) if str(value).strip()]
            seed_values = [str(value).strip() for value in (seed_operations.get(field) or []) if str(value).strip()]
            merged["operations"][field] = current_values or seed_values
    if not list(merged.get("secret_requirements") or []):
        merged["secret_requirements"] = list(seed.get("secret_requirements") or [])
    return merged


def _build_connector_release_gate(item: dict[str, Any]) -> dict[str, Any]:
    telemetry = dict(item.get("telemetry") or {})
    operations = dict(item.get("operations") or {})
    release_stage = str(operations.get("release_stage") or "draft").strip().lower() or "draft"
    ready_for_validation = bool(
        int(telemetry.get("coverage_score") or 0) >= 35
        and float(telemetry.get("parsing_coverage_pct") or 0.0) >= 35.0
        and float(telemetry.get("telemetry_quality_pct") or 0.0) >= 35.0
        and bool(list(telemetry.get("event_families") or []))
        and bool(str(operations.get("owner") or "").strip())
    )
    ready_for_stage = bool(
        ready_for_validation
        and int(telemetry.get("coverage_score") or 0) >= 60
        and float(telemetry.get("parsing_coverage_pct") or 0.0) >= 60.0
        and float(telemetry.get("telemetry_quality_pct") or 0.0) >= 60.0
        and bool(list(telemetry.get("evidence_fields") or []))
        and bool(list(telemetry.get("investigation_pivots") or []))
        and bool(str(operations.get("bundle_id") or "").strip())
        and bool(str(operations.get("runbook_id") or "").strip())
    )
    ready_for_live = bool(
        ready_for_stage
        and int(telemetry.get("coverage_score") or 0) >= 80
        and float(telemetry.get("parsing_coverage_pct") or 0.0) >= 80.0
        and float(telemetry.get("telemetry_quality_pct") or 0.0) >= 80.0
        and bool(telemetry.get("actor_ip_ready"))
        and bool(telemetry.get("entity_mapping_ready"))
        and bool(list(operations.get("playbooks") or []))
        and bool(list(operations.get("compliance_controls") or []))
        and bool(str(operations.get("onboarding_template") or "").strip())
    )
    missing: list[str] = []
    if not bool(str(operations.get("bundle_id") or "").strip()):
        missing.append("bundle_id")
    if not bool(str(operations.get("owner") or "").strip()):
        missing.append("owner")
    if not bool(str(operations.get("runbook_id") or "").strip()):
        missing.append("runbook_id")
    if not bool(str(operations.get("onboarding_template") or "").strip()):
        missing.append("onboarding_template")
    if not bool(list(operations.get("playbooks") or [])):
        missing.append("playbooks")
    if not bool(list(operations.get("compliance_controls") or [])):
        missing.append("compliance_controls")
    if not bool(list(telemetry.get("event_families") or [])):
        missing.append("event_families")
    if not bool(list(telemetry.get("evidence_fields") or [])):
        missing.append("evidence_fields")
    if not bool(list(telemetry.get("investigation_pivots") or [])):
        missing.append("investigation_pivots")
    if not bool(telemetry.get("actor_ip_ready")):
        missing.append("actor_ip_ready")
    if not bool(telemetry.get("entity_mapping_ready")):
        missing.append("entity_mapping_ready")
    status = "draft"
    if ready_for_live or release_stage in {"active", "live"}:
        status = "ready_for_live" if ready_for_live else "live_with_gaps"
    elif ready_for_stage or release_stage in {"staged", "active"}:
        status = "ready_for_stage" if ready_for_stage else "stage_with_gaps"
    elif ready_for_validation or release_stage in {"validated", "staged", "active"}:
        status = "ready_for_validation" if ready_for_validation else "validation_with_gaps"
    return {
        "status": status,
        "ready_for_validation": ready_for_validation,
        "ready_for_stage": ready_for_stage,
        "ready_for_live": ready_for_live,
        "missing": missing,
    }


def _connector_enterprise_ready(item: dict[str, Any]) -> bool:
    telemetry = dict(item.get("telemetry") or {})
    operations = dict(item.get("operations") or {})
    release_gate = dict(item.get("release_gate") or _build_connector_release_gate(item))
    return bool(
        int(telemetry.get("coverage_score") or 0) >= 75
        and float(telemetry.get("parsing_coverage_pct") or 0.0) >= 75.0
        and float(telemetry.get("telemetry_quality_pct") or 0.0) >= 75.0
        and bool(telemetry.get("entity_mapping_ready"))
        and bool(telemetry.get("evidence_fields"))
        and bool(operations.get("owner"))
        and bool(operations.get("bundle_id"))
        and bool(release_gate.get("ready_for_live"))
    )


def _connector_top_gaps(items: list[dict[str, Any]]) -> list[str]:
    gaps: list[str] = []
    if any(not bool(dict(item.get("telemetry") or {}).get("actor_ip_ready")) for item in items):
        gaps.append("Actor/source IP attribution is not universal across connector families.")
    if any(not bool(dict(item.get("telemetry") or {}).get("host_telemetry_ready")) for item in items):
        gaps.append("Host telemetry coverage is incomplete for some endpoint and platform sources.")
    if any(not bool(dict(item.get("operations") or {}).get("bundle_id")) for item in items):
        gaps.append("Some connectors are not yet governed by a content bundle release lane.")
    if any(not bool(dict(item.get("operations") or {}).get("playbooks")) for item in items):
        gaps.append("Several connectors still lack bound response playbooks.")
    if any(not bool(dict(item.get("operations") or {}).get("runbook_id")) for item in items):
        gaps.append("Runbook ownership is still incomplete for parts of the connector estate.")
    if any(not bool(dict(item.get("operations") or {}).get("onboarding_template")) for item in items):
        gaps.append("Some connector families still lack structured onboarding templates.")
    if any(float(dict(item.get("telemetry") or {}).get("parsing_coverage_pct") or 0.0) < 70.0 for item in items):
        gaps.append("Parsing coverage is uneven and still below enterprise validation targets for some sources.")
    if any(float(dict(item.get("telemetry") or {}).get("telemetry_quality_pct") or 0.0) < 70.0 for item in items):
        gaps.append("Telemetry quality scoring still shows enrichment or field-contract gaps.")
    return gaps[:4]


REQUIRED_CONNECTOR_ECOSYSTEM: dict[str, str] = {
    "ad-domain-services-audit": "Active Directory",
    "entra-id-audit": "Entra ID",
    "mail-security-events": "Mail security",
    "proxy-web-gateway": "Proxy / secure web gateway",
    "firewall-perimeter-events": "Firewall / NGFW",
    "endpoint-edr-stream": "EDR / XDR",
    "saas-audit-events": "SaaS audit",
    "cloud-control-plane": "Cloud audit",
    "kubernetes-audit": "Kubernetes audit",
    "cicd-pipeline-audit": "CI/CD audit",
}


def _build_connector_hard_gates(items: list[dict[str, Any]]) -> dict[str, Any]:
    connector_ids = {str(item.get("id") or "").strip() for item in items if str(item.get("id") or "").strip()}
    live_ids = {
        str(item.get("id") or "").strip()
        for item in items
        if bool(dict(item.get("release_gate") or {}).get("ready_for_live"))
    }
    missing = [
        title
        for connector_id, title in REQUIRED_CONNECTOR_ECOSYSTEM.items()
        if connector_id not in connector_ids
    ]
    not_live = [
        title
        for connector_id, title in REQUIRED_CONNECTOR_ECOSYSTEM.items()
        if connector_id in connector_ids and connector_id not in live_ids
    ]
    actor_ip_ready = sum(1 for item in items if bool(dict(item.get("telemetry") or {}).get("actor_ip_ready")))
    host_telemetry_ready = sum(1 for item in items if bool(dict(item.get("telemetry") or {}).get("host_telemetry_ready")))
    investigation_ready = sum(1 for item in items if bool(list(dict(item.get("telemetry") or {}).get("investigation_pivots") or [])))
    total = len(items)
    ecosystem_present = len(connector_ids & set(REQUIRED_CONNECTOR_ECOSYSTEM))
    ecosystem_live_ready = len(live_ids & set(REQUIRED_CONNECTOR_ECOSYSTEM))
    parsing_avg = round(
        sum(float(dict(item.get("telemetry") or {}).get("parsing_coverage_pct") or 0.0) for item in items) / max(total, 1),
        1,
    )
    quality_avg = round(
        sum(float(dict(item.get("telemetry") or {}).get("telemetry_quality_pct") or 0.0) for item in items) / max(total, 1),
        1,
    )
    telemetry_gate_pass = bool(
        parsing_avg >= 80.0
        and quality_avg >= 80.0
        and actor_ip_ready >= max(1, int(total * 0.7))
        and investigation_ready >= max(1, int(total * 0.7))
    )
    return {
        "required_domains": len(REQUIRED_CONNECTOR_ECOSYSTEM),
        "ecosystem_present": ecosystem_present,
        "ecosystem_live_ready": ecosystem_live_ready,
        "ecosystem_missing": missing,
        "ecosystem_live_blockers": not_live,
        "ecosystem_coverage_pct": round((ecosystem_present / max(len(REQUIRED_CONNECTOR_ECOSYSTEM), 1)) * 100.0, 1),
        "ecosystem_live_ready_pct": round((ecosystem_live_ready / max(len(REQUIRED_CONNECTOR_ECOSYSTEM), 1)) * 100.0, 1),
        "actor_ip_ready_pct": round((actor_ip_ready / max(total, 1)) * 100.0, 1),
        "host_telemetry_ready_pct": round((host_telemetry_ready / max(total, 1)) * 100.0, 1),
        "investigation_ready_pct": round((investigation_ready / max(total, 1)) * 100.0, 1),
        "parsing_gate_status": "pass" if parsing_avg >= 80.0 else "fail",
        "quality_gate_status": "pass" if quality_avg >= 80.0 else "fail",
        "telemetry_gate_status": "pass" if telemetry_gate_pass else "fail",
        "hard_gate_status": "pass" if not missing and not not_live and telemetry_gate_pass else "fail",
    }


def list_connector_definitions() -> list[dict[str, Any]]:
    seed_rows = _default_connector_definitions()
    rows = _merge_seed_rows(_collection("connector_definitions", _default_connector_definitions), seed_rows)
    seed_by_id = {str(item.get("id") or ""): item for item in seed_rows}
    normalized_rows = [
        _normalize_connector_definition(_merge_connector_seed(seed_by_id[str(item.get("id") or "")], item))
        if str(item.get("id") or "") in seed_by_id
        else _normalize_connector_definition(item)
        for item in rows
    ]
    if normalized_rows != rows:
        _save_collection("connector_definitions", normalized_rows)
        rows = normalized_rows
    return sorted(rows, key=lambda item: (str(item.get("family") or ""), str(item.get("title") or item.get("id") or "")))


def get_connector_definition(connector_id: str) -> dict[str, Any] | None:
    item = _find_by_id(list_connector_definitions(), connector_id)
    return _json_clone(item) if item else None


def save_connector_definition(payload: dict[str, Any]) -> dict[str, Any]:
    rows = list_connector_definitions()
    connector_id = _safe_slug(str(payload.get("id") or payload.get("title") or ""), default=_new_id("connector"))
    existing = _find_by_id(rows, connector_id)
    now = _now_iso()
    runtime = dict(existing.get("runtime") if existing else {})
    runtime.update(dict(payload.get("runtime") or {}))
    runtime.setdefault("health", existing.get("runtime", {}).get("health", {}) if existing else {})
    runtime["health"] = {
        "last_run_ts": str(runtime.get("health", {}).get("last_run_ts") or ""),
        "last_status": str(runtime.get("health", {}).get("last_status") or "never"),
        "success_rate_24h": float(runtime.get("health", {}).get("success_rate_24h") or 0),
        "consecutive_failures": int(runtime.get("health", {}).get("consecutive_failures") or 0),
    }
    item = {
        "id": connector_id,
        "type": "connector_definition",
        "schema_version": CONTROL_PLANE_SCHEMA_VERSION,
        "family": str(payload.get("family") or (existing.get("family") if existing else "source") or "source"),
        "block_type": str(payload.get("block_type") or (existing.get("block_type") if existing else "custom_connector") or "custom_connector"),
        "stage": str(payload.get("stage") or (existing.get("stage") if existing else "ingest") or "ingest"),
        "group": str(payload.get("group") or (existing.get("group") if existing else "custom") or "custom"),
        "source_family": str(payload.get("source_family") or (existing.get("source_family") if existing else "custom_api") or "custom_api"),
        "title": str(payload.get("title") or connector_id),
        "description": str(payload.get("description") or ""),
        "protocols": [str(item).strip() for item in (payload.get("protocols") or (existing.get("protocols") if existing else [])) if str(item).strip()],
        "mode": str(payload.get("mode") or (existing.get("mode") if existing else "push") or "push"),
        "enabled": bool(payload.get("enabled", existing.get("enabled", True) if existing else True)),
        "status": str(payload.get("status") or (existing.get("status") if existing else "planned") or "planned"),
        "runtime": runtime,
        "mappings": dict(existing.get("mappings") if existing else {}),
        "labels": [str(item).strip() for item in (payload.get("labels") or (existing.get("labels") if existing else [])) if str(item).strip()],
        "updated_ts": now,
        "secret_requirements": _normalize_connector_secret_requirements(
            payload.get("secret_requirements") or (existing.get("secret_requirements") if existing else [])
        ),
        "telemetry": {
            **(dict(existing.get("telemetry") or {}) if existing else {}),
            **dict(payload.get("telemetry") or {}),
        },
        "operations": {
            **(dict(existing.get("operations") or {}) if existing else {}),
            **dict(payload.get("operations") or {}),
        },
    }
    item["mappings"].update(dict(payload.get("mappings") or {}))
    item = _normalize_connector_definition(item)
    rows = [row for row in rows if str(row.get("id") or "") != connector_id]
    rows.append(item)
    _save_collection("connector_definitions", rows)
    append_audit_event(
        actor=str(payload.get("_audit_actor") or "system"),
        action="connector.saved",
        object_type="connector_definition",
        object_id=item["id"],
        summary=item["title"],
        details={"family": item["family"], "mode": item["mode"], "status": item["status"]},
    )
    return _json_clone(item)


def delete_connector_definition(connector_id: str, *, actor: str = "system") -> dict[str, Any]:
    safe_connector_id = str(connector_id or "").strip()
    if not safe_connector_id:
        raise ValueError("Connector id is required")
    seed_ids = {str(item.get("id") or "") for item in _default_connector_definitions()}
    if safe_connector_id in seed_ids:
        raise ValueError("Built-in connectors cannot be deleted")
    rows = list_connector_definitions()
    existing = _find_by_id(rows, safe_connector_id)
    if existing is None:
        raise ValueError(f"Connector not found: {safe_connector_id}")
    _save_collection(
        "connector_definitions",
        [item for item in rows if str(item.get("id") or "") != safe_connector_id],
    )
    _save_collection(
        "connector_runs",
        [item for item in _collection("connector_runs", _default_connector_runs) if str(item.get("connector_id") or "") != safe_connector_id],
    )
    append_audit_event(
        actor=str(actor or "system"),
        action="connector.deleted",
        object_type="connector_definition",
        object_id=safe_connector_id,
        summary=str(existing.get("title") or safe_connector_id),
        details={"family": str(existing.get("family") or ""), "group": str(existing.get("group") or "")},
    )
    return {"status": "deleted", "id": safe_connector_id}


def list_connector_runs(*, connector_id: str = "", limit: int = 50) -> list[dict[str, Any]]:
    rows = _collection("connector_runs", _default_connector_runs)
    filtered = rows
    safe_connector_id = str(connector_id or "").strip()
    if safe_connector_id:
        filtered = [item for item in rows if str(item.get("connector_id") or "") == safe_connector_id]
    filtered.sort(key=lambda item: _parse_ts(str(item.get("finished_ts") or item.get("started_ts") or "")), reverse=True)
    return _json_clone(filtered[: max(1, min(500, limit))])


CONNECTOR_SUCCESS_STATUSES = {"success", "dry_run", "accepted", "executed"}


def _resolve_connector_runtime(connector: dict[str, Any]) -> dict[str, Any]:
    return dict(_resolve_runtime_object(connector.get("runtime") or {}))


def _execute_rest_connector(connector: dict[str, Any], payload: dict[str, Any], *, dry_run: bool) -> dict[str, Any]:
    runtime = _resolve_connector_runtime(connector)
    request_cfg = dict(runtime.get("request") or {})
    response_cfg = dict(runtime.get("response") or {})
    url = str(_resolve_config_value(request_cfg, "url", "") or "").strip()
    if not url:
        raise ValueError("REST connector requires runtime.request.url or runtime.request.url_env")
    method = str(_resolve_config_value(request_cfg, "method", "GET") or "GET").upper()
    headers = {str(key): str(value) for key, value in dict(_resolve_config_value(request_cfg, "headers", {}) or {}).items()}
    auth_cfg = dict(request_cfg.get("auth") or {})
    if str(auth_cfg.get("type") or "").lower() == "bearer":
        token_env = str(auth_cfg.get("token_env") or "").strip()
        token, _ = _resolve_secret_value(token_env or "SIEM_VENDOR_API_TOKEN")
        if token:
            headers.setdefault("Authorization", f"Bearer {token}")
    query_params = dict(_resolve_config_value(request_cfg, "params", {}) or {})
    if query_params:
        parsed = urllib.parse.urlparse(url)
        merged = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
        merged.update({str(key): str(value) for key, value in query_params.items()})
        url = urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(merged)))
    body = _resolve_config_value(request_cfg, "body", payload.get("body"))
    timeout_seconds = _safe_timeout_seconds(_resolve_config_value(request_cfg, "timeout_ms", 10000))
    verify_tls = bool(request_cfg.get("verify_tls", True))
    if dry_run:
        return {
            "status": "dry_run",
            "message": f"Validated REST connector target {url}",
            "stats": {"executor": "rest_pull", "method": method, "url": url, "accepted_events": 0},
            "payload_sample": None,
        }
    response = _http_request(url=url, method=method, headers=headers, body=body, timeout_seconds=timeout_seconds, verify_tls=verify_tls)
    decoded = _decode_http_payload(response.get("body", b""), str(response.get("content_type") or ""))
    records = _extract_records(decoded, str(response_cfg.get("records_path") or ""))
    status = "success" if 200 <= int(response.get("http_status") or 0) < 300 else "error"
    return {
        "status": status,
        "message": f"Fetched {len(records)} record(s) from {url}",
        "stats": {
            "executor": "rest_pull",
            "method": method,
            "url": url,
            "http_status": int(response.get("http_status") or 0),
            "latency_ms": float(response.get("latency_ms") or 0),
            "accepted_events": len(records),
            "bytes_received": len(response.get("body") or b""),
        },
        "payload_sample": _sample_records(records or decoded),
        "result": {"response": _sample_records(decoded), "records_path": str(response_cfg.get("records_path") or "")},
    }


def _execute_vuln_runtime_connector(connector: dict[str, Any], payload: dict[str, Any], *, dry_run: bool) -> dict[str, Any]:
    runtime = _resolve_connector_runtime(connector)
    operation = str(runtime.get("operation") or "sync_import").strip().lower() or "sync_import"
    sync_limit = max(1, int(payload.get("sync_limit") or payload.get("limit") or 500))
    import_limit = max(1, int(payload.get("import_limit") or payload.get("report_limit") or 20))
    days = max(1, int(payload.get("days") or 14))
    runtime_status = _build_vulnerability_runtime_status_runtime(days=days)
    probe = dict(runtime_status.get("probe") or {})
    probe_status = str(probe.get("status") or "").strip().lower() or "unknown"
    if dry_run:
        return {
            "status": "dry_run",
            "message": f"Validated vulnerability runtime connector {connector.get('id') or 'unknown'}",
            "stats": {
                "executor": "vuln_runtime",
                "operation": operation,
                "probe_status": probe_status,
                "accepted_events": int(runtime_status.get("reports_total") or 0),
            },
            "payload_sample": {
                "probe_status": probe_status,
                "reports_total": int(runtime_status.get("reports_total") or 0),
                "fleet_coverage": _json_clone(runtime_status.get("fleet_coverage") or {}),
            },
            "result": {"runtime": runtime_status},
        }
    sync_result: dict[str, Any] = {}
    import_result: dict[str, Any] = {}
    if operation in {"sync", "sync_import"}:
        sync_result = _sync_vulnerability_targets_runtime(limit=sync_limit)
    if operation in {"import", "sync_import"}:
        import_result = _import_greenbone_reports_runtime(limit=import_limit)
    runtime_status = _build_vulnerability_runtime_status_runtime(days=days)
    imported_runs = int(import_result.get("imported") or 0)
    synced_targets = len(sync_result.get("items") or [])
    message_parts = []
    if operation in {"sync", "sync_import"}:
        message_parts.append(f"sync={synced_targets}")
    if operation in {"import", "sync_import"}:
        message_parts.append(f"imported={imported_runs}")
    return {
        "status": "success" if probe_status in {"ok", "healthy", "configured"} else "warning",
        "message": f"Vulnerability runtime completed ({', '.join(message_parts)})",
        "stats": {
            "executor": "vuln_runtime",
            "operation": operation,
            "probe_status": probe_status,
            "synced_targets": synced_targets,
            "imported_runs": imported_runs,
            "accepted_events": imported_runs,
        },
        "payload_sample": {
            "sync": _sample_records(sync_result.get("items") or []),
            "import": _sample_records(import_result.get("runs") or []),
        },
        "result": {
            "sync": sync_result,
            "import": import_result,
            "runtime": runtime_status,
        },
    }


def _execute_sql_connector(connector: dict[str, Any], payload: dict[str, Any], *, dry_run: bool) -> dict[str, Any]:
    runtime = _resolve_connector_runtime(connector)
    connection_cfg = dict(runtime.get("connection") or {})
    driver = str(connection_cfg.get("driver") or "").strip().lower()
    dsn = str(_resolve_config_value(connection_cfg, "dsn", "") or "").strip()
    db_path = str(_resolve_config_value(connection_cfg, "path", "") or "").strip()
    if dsn.startswith("sqlite:///") and not db_path:
        db_path = dsn[len("sqlite:///") :]
    if not driver and (dsn.startswith("sqlite:///") or db_path):
        driver = "sqlite"
    if driver not in {"sqlite", "sqlite3"}:
        raise ValueError("SQL connector currently supports only sqlite runtime.connection.driver=sqlite")
    query = str(runtime.get("query") or payload.get("query") or "").strip()
    if not query:
        raise ValueError("SQL connector requires runtime.query")
    if not db_path:
        raise ValueError("SQL connector requires runtime.connection.path or sqlite:/// DSN")
    if dry_run:
        return {
            "status": "dry_run",
            "message": f"Validated sqlite query against {db_path}",
            "stats": {"executor": "sql_source", "driver": driver, "db_path": db_path, "accepted_events": 0},
            "payload_sample": None,
        }
    started = time.perf_counter()
    conn = sqlite3.connect(db_path)
    try:
        cursor = conn.execute(query)
        columns = [str(item[0]) for item in (cursor.description or [])]
        rows = [dict(zip(columns, row)) for row in cursor.fetchall()]
    finally:
        conn.close()
    latency_ms = round((time.perf_counter() - started) * 1000.0, 1)
    return {
        "status": "success",
        "message": f"Fetched {len(rows)} row(s) from sqlite source",
        "stats": {"executor": "sql_source", "driver": driver, "db_path": db_path, "latency_ms": latency_ms, "accepted_events": len(rows)},
        "payload_sample": _sample_records(rows),
        "result": {"columns": columns, "row_count": len(rows)},
    }


def _execute_webhook_source(connector: dict[str, Any], payload: dict[str, Any], *, dry_run: bool) -> dict[str, Any]:
    events = payload.get("events")
    if events is None:
        events = payload.get("payload_sample")
    if events is None:
        events = payload.get("body")
    if events is None:
        events = payload
    records = events if isinstance(events, list) else [events] if events else []
    return {
        "status": "dry_run" if dry_run else "accepted",
        "message": f"Validated webhook source {connector.get('id')}",
        "stats": {"executor": "webhook_source", "accepted_events": len(records)},
        "payload_sample": _sample_records(records),
    }


def _execute_connector_runtime(connector: dict[str, Any], payload: dict[str, Any], *, dry_run: bool) -> dict[str, Any]:
    block_type = str(connector.get("block_type") or "").strip().lower()
    if block_type in {"rest_pull"}:
        return _execute_rest_connector(connector, payload, dry_run=dry_run)
    if block_type in {"vuln_runtime"}:
        return _execute_vuln_runtime_connector(connector, payload, dry_run=dry_run)
    if block_type in {"sql_source"}:
        return _execute_sql_connector(connector, payload, dry_run=dry_run)
    if block_type in {"webhook_source", "custom_connector"} or str(connector.get("mode") or "").lower() == "push":
        return _execute_webhook_source(connector, payload, dry_run=dry_run)
    raise ValueError(f"Connector executor is not implemented for block_type={block_type or 'unknown'}")


def record_connector_run(
    connector_id: str,
    *,
    status: str = "success",
    actor: str = "system",
    trigger: str = "manual",
    dry_run: bool = False,
    message: str = "",
    stats: dict[str, Any] | None = None,
    payload_sample: Any | None = None,
    result: dict[str, Any] | None = None,
    error: str = "",
) -> dict[str, Any]:
    connectors = list_connector_definitions()
    connector = _find_by_id(connectors, connector_id)
    if connector is None:
        raise ValueError(f"Unknown connector: {connector_id}")
    started_ts = _now_iso()
    safe_status = str(status or "success").strip().lower()
    if dry_run and safe_status == "success":
        safe_status = "dry_run"
    run = {
        "id": _new_id("run"),
        "type": "connector_run",
        "schema_version": CONTROL_PLANE_SCHEMA_VERSION,
        "connector_id": connector_id,
        "status": safe_status,
        "actor": str(actor or "system"),
        "trigger": str(trigger or "manual"),
        "dry_run": bool(dry_run),
        "message": str(message or ""),
        "stats": dict(stats or {}),
        "payload_sample": _json_clone(payload_sample) if payload_sample is not None else None,
        "result": _json_clone(result or {}),
        "error": str(error or ""),
        "started_ts": started_ts,
        "finished_ts": _now_iso(),
    }
    rows = _collection("connector_runs", _default_connector_runs)
    rows.append(run)
    rows = sorted(rows, key=lambda item: _parse_ts(str(item.get("finished_ts") or item.get("started_ts") or "")), reverse=True)[:500]
    _save_collection("connector_runs", rows)

    recent_runs = [item for item in rows if str(item.get("connector_id") or "") == connector_id]
    last_day = _now() - timedelta(hours=24)
    recent_window = [item for item in recent_runs if _parse_ts(str(item.get("finished_ts") or item.get("started_ts") or "")) >= last_day]
    successful = [item for item in recent_window if str(item.get("status") or "") in CONNECTOR_SUCCESS_STATUSES]
    connector["runtime"] = dict(connector.get("runtime") or {})
    connector["runtime"]["health"] = {
        "last_run_ts": run["finished_ts"],
        "last_status": safe_status,
        "success_rate_24h": round((len(successful) / max(len(recent_window), 1)) * 100, 1),
        "consecutive_failures": 0 if safe_status in CONNECTOR_SUCCESS_STATUSES else int(connector.get("runtime", {}).get("health", {}).get("consecutive_failures") or 0) + 1,
        "last_error": str(error or ""),
    }
    connector["status"] = (
        "disabled"
        if not connector.get("enabled", True)
        else "error"
        if safe_status in {"error", "failed", "blocked"}
        else "degraded"
        if safe_status in {"warning", "partial"}
        else "healthy"
    )
    connector["updated_ts"] = _now_iso()
    _save_collection("connector_definitions", [connector if str(item.get("id") or "") == connector_id else item for item in connectors])
    append_audit_event(
        actor=actor,
        action="connector.run",
        object_type="connector_run",
        object_id=run["id"],
        summary=f"{connector_id} -> {safe_status}",
        details={"connector_id": connector_id, "status": safe_status, "trigger": trigger, "dry_run": bool(dry_run), "stats": dict(run.get("stats") or {})},
    )
    return {"run": _json_clone(run), "connector": _json_clone(connector), "result": _json_clone(result or {})}


def run_connector_definition(
    connector_id: str,
    *,
    actor: str = "system",
    trigger: str = "manual",
    dry_run: bool = True,
    payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    connector = get_connector_definition(connector_id)
    if connector is None:
        raise ValueError(f"Unknown connector: {connector_id}")
    if not connector.get("enabled", True):
        return record_connector_run(
            connector_id,
            status="blocked",
            actor=actor,
            trigger=trigger,
            dry_run=dry_run,
            message="Connector is disabled",
            stats={"executor": "runtime"},
            payload_sample=payload,
            error="Connector is disabled",
        )
    secrets, missing = _resolve_required_secrets(connector.get("secret_requirements") or [])
    if missing and not dry_run:
        labels = ", ".join(item["label"] for item in missing)
        return record_connector_run(
            connector_id,
            status="blocked",
            actor=actor,
            trigger=trigger,
            dry_run=False,
            message=f"Missing required secrets: {labels}",
            stats={"executor": "runtime", "missing_secrets": missing},
            payload_sample=payload,
            error=f"Missing required secrets: {labels}",
        )
    execution_payload = dict(payload or {})
    if secrets:
        execution_payload.setdefault("_resolved_secrets", secrets)
    try:
        executed = _execute_connector_runtime(connector, execution_payload, dry_run=dry_run)
        return record_connector_run(
            connector_id,
            status=str(executed.get("status") or "success"),
            actor=actor,
            trigger=trigger,
            dry_run=dry_run,
            message=str(executed.get("message") or ""),
            stats=dict(executed.get("stats") or {}),
            payload_sample=executed.get("payload_sample"),
            result=dict(executed.get("result") or {}),
        )
    except Exception as exc:  # noqa: BLE001
        return record_connector_run(
            connector_id,
            status="error",
            actor=actor,
            trigger=trigger,
            dry_run=dry_run,
            message=str(exc),
            stats={"executor": "runtime"},
            payload_sample=payload,
            error=str(exc),
        )


def get_connectors_overview() -> dict[str, Any]:
    catalog_items = list_connector_definitions()
    items = _production_connectors(catalog_items)
    production_connector_ids = {str(item.get("id") or "") for item in items if str(item.get("id") or "").strip()}
    recent_runs = [
        item
        for item in list_connector_runs(limit=120)
        if not production_connector_ids or str(item.get("connector_id") or "") in production_connector_ids
    ]
    actions = _list_response_actions()
    status_counts = Counter(str(item.get("status") or "unknown") for item in items)
    group_counts = Counter(str(item.get("group") or "general") for item in items)
    family_counts = Counter(str(item.get("family") or "source") for item in items)
    depth_counts = Counter(str(dict(item.get("telemetry") or {}).get("collection_depth") or "basic") for item in items)
    release_stage_counts = Counter(str(dict(item.get("operations") or {}).get("release_stage") or "draft") for item in items)
    healthy_count = sum(1 for item in items if str(item.get("status") or "") in {"healthy", "ready"})
    telemetry_scores = [int(dict(item.get("telemetry") or {}).get("coverage_score") or 0) for item in items]
    parsing_scores = [float(dict(item.get("telemetry") or {}).get("parsing_coverage_pct") or 0.0) for item in items]
    quality_scores = [float(dict(item.get("telemetry") or {}).get("telemetry_quality_pct") or 0.0) for item in items]
    enterprise_ready = sum(1 for item in items if _connector_enterprise_ready(item))
    managed_by_bundle = sum(1 for item in items if str(dict(item.get("operations") or {}).get("bundle_id") or "").strip())
    playbook_bound = sum(1 for item in items if list(dict(item.get("operations") or {}).get("playbooks") or []))
    compliance_mapped = sum(1 for item in items if list(dict(item.get("operations") or {}).get("compliance_controls") or []))
    actor_ip_ready = sum(1 for item in items if bool(dict(item.get("telemetry") or {}).get("actor_ip_ready")))
    host_telemetry_ready = sum(1 for item in items if bool(dict(item.get("telemetry") or {}).get("host_telemetry_ready")))
    realtime_ready = sum(1 for item in items if bool(dict(item.get("telemetry") or {}).get("realtime")))
    evidence_ready = sum(1 for item in items if bool(list(dict(item.get("telemetry") or {}).get("evidence_fields") or [])))
    investigation_ready = sum(1 for item in items if bool(list(dict(item.get("telemetry") or {}).get("investigation_pivots") or [])))
    runbook_ready = sum(1 for item in items if bool(str(dict(item.get("operations") or {}).get("runbook_id") or "").strip()))
    onboarding_ready = sum(1 for item in items if bool(str(dict(item.get("operations") or {}).get("onboarding_template") or "").strip()))
    release_gate_ready = sum(1 for item in items if bool(dict(item.get("release_gate") or {}).get("ready_for_live")))
    hard_gates = _build_connector_hard_gates(items)
    try:
        from .control_plane_content_ops import list_content_bundles as _list_content_bundles
    except ImportError:  # pragma: no cover - local test fallback
        from control_plane_content_ops import list_content_bundles as _list_content_bundles  # type: ignore[no-redef]

    bundles = _list_content_bundles()
    return {
        "items": items,
        "recent_runs": recent_runs[:20],
        "actions": actions,
        "bundles": bundles,
        "metrics": {
            "total": len(items),
            "catalog_total": len(catalog_items),
            "ignored_nonprod": max(0, len(catalog_items) - len(items)),
            "enabled": sum(1 for item in items if item.get("enabled", True)),
            "healthy": healthy_count,
            "degraded": sum(1 for item in items if str(item.get("status") or "") == "degraded"),
            "planned": sum(1 for item in items if str(item.get("status") or "") == "planned"),
            "successful_runs_24h": sum(1 for item in recent_runs if str(item.get("status") or "") in CONNECTOR_SUCCESS_STATUSES),
            "telemetry_coverage_avg": round(sum(telemetry_scores) / len(telemetry_scores), 1) if telemetry_scores else 0.0,
            "parsing_coverage_avg": round(sum(parsing_scores) / len(parsing_scores), 1) if parsing_scores else 0.0,
            "telemetry_quality_avg": round(sum(quality_scores) / len(quality_scores), 1) if quality_scores else 0.0,
            "enterprise_ready": enterprise_ready,
            "managed_by_bundle": managed_by_bundle,
            "playbook_bound": playbook_bound,
            "compliance_mapped": compliance_mapped,
            "realtime_ready": realtime_ready,
            "actor_ip_ready": actor_ip_ready,
            "host_telemetry_ready": host_telemetry_ready,
            "evidence_ready": evidence_ready,
            "investigation_ready": investigation_ready,
            "runbook_ready": runbook_ready,
            "onboarding_ready": onboarding_ready,
            "release_gate_ready": release_gate_ready,
            "ecosystem_present": int(hard_gates.get("ecosystem_present") or 0),
            "ecosystem_live_ready": int(hard_gates.get("ecosystem_live_ready") or 0),
        },
        "breakdowns": {
            "status": [{"label": label, "count": count} for label, count in status_counts.most_common()],
            "group": [{"label": label, "count": count} for label, count in group_counts.most_common()],
            "family": [{"label": label, "count": count} for label, count in family_counts.most_common()],
            "collection_depth": [{"label": label, "count": count} for label, count in depth_counts.most_common()],
            "release_stage": [{"label": label, "count": count} for label, count in release_stage_counts.most_common()],
        },
        "posture": {
            "gaps": _connector_top_gaps(items),
            "bundle_coverage_pct": round((managed_by_bundle / len(items)) * 100.0, 1) if items else 0.0,
            "evidence_ready_pct": round((evidence_ready / len(items)) * 100.0, 1) if items else 0.0,
            "realtime_ready_pct": round((realtime_ready / len(items)) * 100.0, 1) if items else 0.0,
            "compliance_ready_pct": round((compliance_mapped / len(items)) * 100.0, 1) if items else 0.0,
            "parsing_coverage_pct": round((sum(parsing_scores) / len(parsing_scores)), 1) if parsing_scores else 0.0,
            "telemetry_quality_pct": round((sum(quality_scores) / len(quality_scores)), 1) if quality_scores else 0.0,
            "investigation_ready_pct": round((investigation_ready / len(items)) * 100.0, 1) if items else 0.0,
            "release_gate_ready_pct": round((release_gate_ready / len(items)) * 100.0, 1) if items else 0.0,
            "runbook_ready_pct": round((runbook_ready / len(items)) * 100.0, 1) if items else 0.0,
            "onboarding_ready_pct": round((onboarding_ready / len(items)) * 100.0, 1) if items else 0.0,
            "ecosystem_coverage_pct": float(hard_gates.get("ecosystem_coverage_pct") or 0.0),
            "ecosystem_live_ready_pct": float(hard_gates.get("ecosystem_live_ready_pct") or 0.0),
            "actor_ip_ready_pct": float(hard_gates.get("actor_ip_ready_pct") or 0.0),
            "host_telemetry_ready_pct": float(hard_gates.get("host_telemetry_ready_pct") or 0.0),
            "hard_gate_status": str(hard_gates.get("hard_gate_status") or "fail"),
            "ecosystem_missing": list(hard_gates.get("ecosystem_missing") or []),
            "ecosystem_live_blockers": list(hard_gates.get("ecosystem_live_blockers") or []),
            "telemetry_gate_status": str(hard_gates.get("telemetry_gate_status") or "fail"),
        },
    }


