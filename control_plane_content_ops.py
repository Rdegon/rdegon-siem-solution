from __future__ import annotations

import hashlib
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
_now_iso = core._now_iso
_safe_slug = core._safe_slug
_save_collection = core._save_collection
append_audit_event = core.append_audit_event
_default_content_bundles = core._default_content_bundles
_default_saved_searches = core._default_saved_searches
_merge_seed_rows = core._merge_seed_rows


_BUNDLE_STAGE_ORDER = {"active": 0, "staged": 1, "validated": 2, "draft": 3, "retired": 4}


def _coerce_string_list(value: Any) -> list[str]:
    if isinstance(value, str):
        source = [part.strip() for part in value.split(",")]
    else:
        source = [str(item).strip() for item in (value or [])]
    return [item for item in source if item]


def _normalize_bundle_stage(value: Any, *, fallback: str = "draft") -> str:
    stage = str(value or "").strip().lower()
    if stage in {"draft", "validated", "staged", "active", "retired"}:
        return stage
    return fallback


def _bundle_status_from_stage(stage: str) -> str:
    return {
        "draft": "planned",
        "validated": "ready",
        "staged": "staged",
        "active": "active",
        "retired": "retired",
    }.get(stage, "planned")


def _merge_bundle_seed(seed: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    merged = _json_clone(seed)
    merged.update(_json_clone(current))
    legacy_bundle = not any(
        (
            list(current.get("coverage_domains") or []),
            list(current.get("personas") or []),
            dict(current.get("integrity") or {}),
            list(current.get("qa_datasets") or []),
            list(current.get("rollback_targets") or []),
        )
    )
    for field in ("coverage_domains", "personas", "qa_datasets", "rollback_targets"):
        current_values = _coerce_string_list(current.get(field))
        seed_values = _coerce_string_list(seed.get(field))
        merged[field] = current_values or seed_values
    merged["quality_gates"] = {
        **dict(seed.get("quality_gates") or {}),
        **dict(current.get("quality_gates") or {}),
    }
    merged["integrity"] = {
        **dict(seed.get("integrity") or {}),
        **dict(current.get("integrity") or {}),
    }
    if legacy_bundle:
        merged["signed"] = bool(seed.get("signed", merged.get("signed", False)))
        if dict(seed.get("integrity") or {}):
            merged["integrity"] = {**dict(merged.get("integrity") or {}), **dict(seed.get("integrity") or {})}
        if dict(seed.get("quality_gates") or {}):
            merged["quality_gates"] = {**dict(merged.get("quality_gates") or {}), **dict(seed.get("quality_gates") or {})}
        for field in ("linked_pack_id", "release_ring", "owner", "description"):
            if not str(merged.get(field) or "").strip() and str(seed.get(field) or "").strip():
                merged[field] = seed.get(field)
    if bool(dict(seed.get("integrity") or {}).get("signed")) and not bool(dict(current.get("integrity") or {}).get("signed")):
        merged["signed"] = bool(seed.get("signed", True))
        merged["integrity"] = {**dict(merged.get("integrity") or {}), **dict(seed.get("integrity") or {})}
        merged["quality_gates"] = {**dict(merged.get("quality_gates") or {}), "signed": bool(seed.get("signed", True))}
    return merged


def _normalize_quality_gates(value: Any, *, stage: str) -> dict[str, Any]:
    gates = dict(value or {})
    ci_status = str(gates.get("ci_status") or ("passed" if stage in {"validated", "staged", "active"} else "planned")).strip().lower()
    validation_status = str(gates.get("validation_status") or ("validated" if stage in {"validated", "staged", "active"} else "pending")).strip().lower()
    approval_status = str(gates.get("approval_status") or ("approved" if stage in {"staged", "active"} else "pending")).strip().lower()
    return {
        "ci_status": ci_status,
        "validation_status": validation_status,
        "approval_status": approval_status,
        "signed": bool(gates.get("signed", stage == "active")),
        "test_coverage_pct": int(gates.get("test_coverage_pct") or (90 if stage in {"validated", "staged", "active"} else 0)),
        "regression_status": str(gates.get("regression_status") or ("passed" if stage in {"staged", "active"} else "planned")).strip().lower(),
        "qa_status": str(gates.get("qa_status") or ("ready" if stage in {"validated", "staged", "active"} else "pending")).strip().lower(),
    }


def _normalize_bundle_integrity(
    value: Any,
    *,
    bundle_id: str,
    version: str,
    title: str,
    signed: bool,
    existing: dict[str, Any] | None = None,
) -> dict[str, Any]:
    integrity = dict(value or {})
    previous = dict(existing or {})
    digest_source = f"{bundle_id}:{version}:{title}".encode("utf-8", errors="ignore")
    return {
        "signed": bool(integrity.get("signed", previous.get("signed", signed))),
        "signing_profile": str(integrity.get("signing_profile") or previous.get("signing_profile") or "platform-release").strip() or "platform-release",
        "signed_by": str(integrity.get("signed_by") or previous.get("signed_by") or ("content-release" if signed else "")).strip(),
        "digest": str(integrity.get("digest") or previous.get("digest") or hashlib.sha256(digest_source).hexdigest()).strip(),
        "artifact_uri": str(integrity.get("artifact_uri") or previous.get("artifact_uri") or f"cp://content-bundles/{bundle_id}/{version}").strip(),
        "attestation_ref": str(integrity.get("attestation_ref") or previous.get("attestation_ref") or "").strip(),
    }


def _normalize_bundle_qa_datasets(value: Any, *, existing: Any = None) -> list[str]:
    datasets = _coerce_string_list(value if value is not None else existing)
    return datasets[:12]


def _normalize_bundle_rollbacks(value: Any, *, bundle_id: str, existing: Any = None) -> list[str]:
    rollbacks = _coerce_string_list(value if value is not None else existing)
    if rollbacks:
        return rollbacks[:8]
    return [f"{bundle_id}-previous"]


def _build_bundle_release_gate(
    *,
    bundle: dict[str, Any],
    quality_gates: dict[str, Any],
    integrity: dict[str, Any],
    qa_datasets: list[str],
    rollback_targets: list[str],
) -> dict[str, Any]:
    objects = int(bundle.get("objects") or 0)
    ready_for_validation = bool(objects > 0 and list(bundle.get("coverage_domains") or []) and list(bundle.get("personas") or []))
    ready_for_stage = bool(
        ready_for_validation
        and str(quality_gates.get("ci_status") or "") == "passed"
        and str(quality_gates.get("validation_status") or "") == "validated"
        and str(quality_gates.get("regression_status") or "") == "passed"
        and int(quality_gates.get("test_coverage_pct") or 0) >= 80
        and bool(qa_datasets)
    )
    ready_for_live = bool(
        ready_for_stage
        and str(quality_gates.get("approval_status") or "") == "approved"
        and bool(integrity.get("signed"))
        and bool(rollback_targets)
        and str(bundle.get("release_ring") or "").strip()
    )
    missing: list[str] = []
    if not ready_for_validation:
        if objects <= 0:
            missing.append("bundle_objects")
        if not list(bundle.get("coverage_domains") or []):
            missing.append("coverage_domains")
        if not list(bundle.get("personas") or []):
            missing.append("personas")
    if ready_for_validation and not ready_for_stage:
        if str(quality_gates.get("ci_status") or "") != "passed":
            missing.append("ci")
        if str(quality_gates.get("validation_status") or "") != "validated":
            missing.append("validation")
        if str(quality_gates.get("regression_status") or "") != "passed":
            missing.append("regression")
        if int(quality_gates.get("test_coverage_pct") or 0) < 80:
            missing.append("test_coverage")
        if not qa_datasets:
            missing.append("qa_datasets")
    if ready_for_stage and not ready_for_live:
        if str(quality_gates.get("approval_status") or "") != "approved":
            missing.append("approval")
        if not bool(integrity.get("signed")):
            missing.append("signature")
        if not rollback_targets:
            missing.append("rollback_targets")
    status = "live_ready" if ready_for_live else "stage_ready" if ready_for_stage else "validation_ready" if ready_for_validation else "blocked"
    return {
        "status": status,
        "ready_for_validation": ready_for_validation,
        "ready_for_stage": ready_for_stage,
        "ready_for_live": ready_for_live,
        "missing": missing,
    }


def _normalize_content_bundle(payload: dict[str, Any], existing: dict[str, Any] | None = None) -> dict[str, Any]:
    bundle_id = _safe_slug(str(payload.get("id") or payload.get("title") or (existing.get("id") if existing else "")), default=_new_id("bundle"))
    incoming_status = str(payload.get("status") or (existing.get("status") if existing else "") or "").strip().lower()
    inferred_stage = {
        "active": "active",
        "ready": "validated",
        "staged": "staged",
        "retired": "retired",
        "planned": "draft",
    }.get(incoming_status, "")
    stage = _normalize_bundle_stage(payload.get("stage") or (existing.get("stage") if existing else "") or inferred_stage or "draft")
    quality_gates = _normalize_quality_gates(payload.get("quality_gates") or (existing.get("quality_gates") if existing else {}), stage=stage)
    signed = bool(payload.get("signed", quality_gates.get("signed", existing.get("signed", False) if existing else False)))
    bundle = {
        "id": bundle_id,
        "type": "content_bundle",
        "schema_version": CONTROL_PLANE_SCHEMA_VERSION,
        "bundle_type": str(payload.get("bundle_type") or (existing.get("bundle_type") if existing else "detection_pack") or "detection_pack"),
        "version": str(payload.get("version") or (existing.get("version") if existing else "1.0.0") or "1.0.0"),
        "title": str(payload.get("title") or (existing.get("title") if existing else bundle_id) or bundle_id),
        "description": str(payload.get("description") or (existing.get("description") if existing else "") or ""),
        "objects": int(payload.get("objects") if payload.get("objects") is not None else (existing.get("objects") if existing else 0) or 0),
        "signed": signed,
        "status": str(payload.get("status") or (existing.get("status") if existing else _bundle_status_from_stage(stage)) or _bundle_status_from_stage(stage)),
        "stage": stage,
        "release_ring": str(payload.get("release_ring") or (existing.get("release_ring") if existing else "soc-core") or "soc-core"),
        "owner": str(payload.get("owner") or (existing.get("owner") if existing else "content-engineering") or "content-engineering"),
        "change_ticket": str(payload.get("change_ticket") or (existing.get("change_ticket") if existing else "") or ""),
        "linked_pack_id": str(payload.get("linked_pack_id") or (existing.get("linked_pack_id") if existing else "") or ""),
        "coverage_domains": _coerce_string_list(payload.get("coverage_domains") or (existing.get("coverage_domains") if existing else [])),
        "personas": _coerce_string_list(payload.get("personas") or (existing.get("personas") if existing else [])),
        "quality_gates": quality_gates,
        "last_validation_ts": str(payload.get("last_validation_ts") or (existing.get("last_validation_ts") if existing else (_now_iso() if stage in {"validated", "staged", "active"} else "")) or ""),
        "updated_ts": _now_iso(),
        "release_notes": str(payload.get("release_notes") or (existing.get("release_notes") if existing else "") or ""),
    }
    integrity = _normalize_bundle_integrity(
        payload.get("integrity"),
        bundle_id=bundle_id,
        version=str(bundle.get("version") or ""),
        title=str(bundle.get("title") or bundle_id),
        signed=signed,
        existing=dict(existing.get("integrity") or {}) if existing else None,
    )
    qa_datasets = _normalize_bundle_qa_datasets(payload.get("qa_datasets"), existing=existing.get("qa_datasets") if existing else [])
    rollback_targets = _normalize_bundle_rollbacks(payload.get("rollback_targets"), bundle_id=bundle_id, existing=existing.get("rollback_targets") if existing else [])
    quality_gates["signed"] = bool(integrity.get("signed"))
    bundle["signed"] = bool(integrity.get("signed"))
    bundle["integrity"] = integrity
    bundle["qa_datasets"] = qa_datasets
    bundle["rollback_targets"] = rollback_targets
    bundle["release_gate"] = _build_bundle_release_gate(
        bundle=bundle,
        quality_gates=quality_gates,
        integrity=integrity,
        qa_datasets=qa_datasets,
        rollback_targets=rollback_targets,
    )
    return bundle


def _normalize_saved_search(payload: dict[str, Any], existing: dict[str, Any] | None = None) -> dict[str, Any]:
    search_id = _safe_slug(str(payload.get("id") or payload.get("title") or (existing.get("id") if existing else "")), default=_new_id("search"))
    return {
        "id": search_id,
        "type": "saved_search",
        "schema_version": CONTROL_PLANE_SCHEMA_VERSION,
        "title": str(payload.get("title") or (existing.get("title") if existing else search_id) or search_id),
        "description": str(payload.get("description") or (existing.get("description") if existing else "") or ""),
        "storage": str(payload.get("storage") or (existing.get("storage") if existing else "hot") or "hot"),
        "window": str(payload.get("window") or (existing.get("window") if existing else "24h") or "24h"),
        "query": str(payload.get("query") or (existing.get("query") if existing else "") or ""),
        "schedule": str(payload.get("schedule") or (existing.get("schedule") if existing else "") or ""),
        "tags": _coerce_string_list(payload.get("tags") or (existing.get("tags") if existing else [])),
        "owner": str(payload.get("owner") or (existing.get("owner") if existing else "soc-ops") or "soc-ops"),
        "persona": str(payload.get("persona") or (existing.get("persona") if existing else "analyst") or "analyst"),
        "lifecycle_stage": str(payload.get("lifecycle_stage") or (existing.get("lifecycle_stage") if existing else "published") or "published"),
        "bundle_ids": _coerce_string_list(payload.get("bundle_ids") or (existing.get("bundle_ids") if existing else [])),
        "updated_ts": _now_iso(),
    }


def list_content_bundles() -> list[dict[str, Any]]:
    seed_rows = _default_content_bundles()
    rows = _merge_seed_rows(_collection("content_bundles", _default_content_bundles), seed_rows)
    seed_by_id = {str(item.get("id") or ""): item for item in seed_rows}
    normalized_rows = [
        _normalize_content_bundle(_merge_bundle_seed(seed_by_id[str(item.get("id") or "")], item), item)
        if str(item.get("id") or "") in seed_by_id
        else _normalize_content_bundle(item, item)
        for item in rows
    ]
    if normalized_rows != rows:
        _save_collection("content_bundles", normalized_rows)
        rows = normalized_rows
    rows.sort(key=lambda item: (_BUNDLE_STAGE_ORDER.get(str(item.get("stage") or "draft"), 99), str(item.get("bundle_type") or ""), str(item.get("title") or "")))
    return _json_clone(rows)


def list_saved_searches() -> list[dict[str, Any]]:
    rows = _merge_seed_rows(_collection("saved_searches", _default_saved_searches), _default_saved_searches())
    normalized_rows = [_normalize_saved_search(item, item) for item in rows]
    if normalized_rows != rows:
        _save_collection("saved_searches", normalized_rows)
        rows = normalized_rows
    rows.sort(key=lambda item: str(item.get("title") or item.get("id") or ""))
    return _json_clone(rows)


def save_content_bundle(payload: dict[str, Any]) -> dict[str, Any]:
    rows = list_content_bundles()
    bundle_id = _safe_slug(str(payload.get("id") or payload.get("title") or ""), default=_new_id("bundle"))
    existing = _find_by_id(rows, bundle_id)
    item = _normalize_content_bundle({**dict(payload or {}), "id": bundle_id}, existing)
    rows = [row for row in rows if str(row.get("id") or "") != bundle_id]
    rows.append(item)
    _save_collection("content_bundles", rows)
    append_audit_event(
        actor=str(payload.get("_audit_actor") or "system"),
        action="content_bundle.saved",
        object_type="content_bundle",
        object_id=item["id"],
        summary=item["title"],
        details={
            "bundle_type": item["bundle_type"],
            "version": item["version"],
            "stage": item["stage"],
            "release_ring": item["release_ring"],
        },
    )
    return _json_clone(item)


def promote_content_bundle(bundle_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    rows = list_content_bundles()
    existing = _find_by_id(rows, bundle_id)
    if existing is None:
        raise ValueError(f"Content bundle not found: {bundle_id}")
    requested_stage = _normalize_bundle_stage(payload.get("stage") or payload.get("target_stage") or "validated", fallback=str(existing.get("stage") or "draft"))
    item = _normalize_content_bundle(
        {
            **existing,
            **dict(payload or {}),
            "id": bundle_id,
            "stage": requested_stage,
            "status": _bundle_status_from_stage(requested_stage),
            "release_ring": str(payload.get("release_ring") or existing.get("release_ring") or "soc-core"),
            "release_notes": str(payload.get("release_notes") or existing.get("release_notes") or ""),
            "change_ticket": str(payload.get("change_ticket") or existing.get("change_ticket") or ""),
            "last_validation_ts": _now_iso() if requested_stage in {"validated", "staged", "active"} else str(existing.get("last_validation_ts") or ""),
        },
        existing,
    )
    rows = [row for row in rows if str(row.get("id") or "") != bundle_id]
    rows.append(item)
    _save_collection("content_bundles", rows)
    append_audit_event(
        actor=str(payload.get("_audit_actor") or "system"),
        action="content_bundle.promoted",
        object_type="content_bundle",
        object_id=item["id"],
        summary=item["title"],
        details={"stage": item["stage"], "release_ring": item["release_ring"], "change_ticket": item["change_ticket"]},
    )
    return _json_clone(item)


def save_saved_search(payload: dict[str, Any]) -> dict[str, Any]:
    rows = list_saved_searches()
    search_id = _safe_slug(str(payload.get("id") or payload.get("title") or ""), default=_new_id("search"))
    existing = _find_by_id(rows, search_id)
    item = _normalize_saved_search({**dict(payload or {}), "id": search_id}, existing)
    rows = [row for row in rows if str(row.get("id") or "") != search_id]
    rows.append(item)
    _save_collection("saved_searches", rows)
    append_audit_event(
        actor=str(payload.get("_audit_actor") or "system"),
        action="saved_search.saved",
        object_type="saved_search",
        object_id=item["id"],
        summary=item["title"],
        details={"storage": item["storage"], "window": item["window"], "schedule": item["schedule"], "persona": item["persona"]},
    )
    return _json_clone(item)
