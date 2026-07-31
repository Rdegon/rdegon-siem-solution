from __future__ import annotations

import json
import os
import time
from functools import partial
from pathlib import Path
from threading import Lock
from typing import Any
from urllib.parse import quote

from fastapi import APIRouter, Body, Depends, Form, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from starlette.concurrency import run_in_threadpool

from ..asset_catalog_runtime import (
    archive_events_to_cold,
    fetch_active_list_items,
    fetch_asset_categories,
    fetch_assets,
    fetch_cmdb_assets,
    fetch_collector_inventory,
    fetch_detection_rules,
    fetch_geo_country_detail,
    fetch_geo_ip_detail,
    fetch_geo_source_activity,
    fetch_geo_vpn_destinations,
    fetch_normalizer_rules,
    fetch_resource_overview,
    fetch_source_inventory,
    fetch_threat_intel_entries,
    fetch_threat_intel_overview,
    fetch_top_sources,
    import_cmdb_assets,
    import_threat_intel_entries,
    list_builder_drafts,
    publish_builder_draft,
    save_active_list_item,
    save_builder_draft,
    save_cmdb_asset,
    save_normalizer_rule,
    save_sigma_rule,
    save_threat_intel_indicator,
    sync_observed_assets_to_cmdb,
    test_builder_draft_payload,
    test_detection_rule,
    validate_builder_draft_payload,
)
from .auth import canonical_ui_redirect_path, get_current_user
from ..asset_binding_overrides import (
    delete_binding_override,
    list_binding_overrides,
    save_binding_override,
    update_binding_override,
)
from ..config import CONFIG
from ..deps_runtime_docs_ops import delete_builder_draft
from ..control_plane_governance_runtime import get_secret_inventory, list_audit_events
from ..ingest_runtime import (
    get_ingest_overview,
    list_ingest_collectors,
    list_ingest_dlq,
    list_ingest_sources,
    replay_ingest_dlq,
    remediate_ingest_dlq,
    suppress_ingest_dlq,
)
from ..security import require_permissions
from ..stale_runtime_cache import StaleRuntimeCache
from ..source_discovery import (
    execute_source_onboarding,
    list_source_discovery_candidates,
    prepare_source_onboarding,
    scan_source_candidates,
)
from ..proxmox_fleet_runtime import list_proxmox_fleet_inventory, sync_proxmox_fleet_inventory
from ..host_access_runtime import delete_host_access_profile, list_host_access_profiles, save_host_access_profile
from ..topology_runtime import build_network_topology
from ..topology_layout_runtime import get_topology_layout, save_topology_layout
from ..correlation_pack_runtime import (
    get_correlation_pack,
    list_correlation_packs,
    publish_correlation_pack,
    save_correlation_pack,
    test_correlation_pack,
    validate_correlation_pack,
)
from ..templates import templates
from ..ui_text import ui_context

router = APIRouter()

_SOURCES_INVENTORY_CACHE_TTL_SEC = int(os.getenv("SIEM_SOURCES_INVENTORY_CACHE_TTL_SEC", "300") or "300")
_SOURCES_INVENTORY_CACHE_FILE = Path(
    os.getenv("SIEM_SOURCES_INVENTORY_CACHE_FILE", "/opt/siem/runtime-docs/sources_inventory_cache.json")
)
_SOURCES_INVENTORY_CACHE_LOCK = Lock()
_ASSETS_CATALOG_CACHE_TTL_SEC = int(os.getenv("SIEM_ASSETS_CATALOG_CACHE_TTL_SEC", "180") or "180")
_ASSETS_CATALOG_CACHE_FILE = Path(
    os.getenv("SIEM_ASSETS_CATALOG_CACHE_FILE", "/opt/siem/runtime-docs/assets_catalog_cache.json")
)
_ASSETS_CATALOG_CACHE_LOCK = Lock()
_ASSET_SURFACE_CACHE = StaleRuntimeCache(
    Path(
        os.getenv(
            "SIEM_ASSET_SURFACE_CACHE_FILE",
            "/opt/siem/runtime-docs/asset_surface_cache.json",
        )
    ),
    ttl_seconds=int(os.getenv("SIEM_ASSET_SURFACE_CACHE_TTL_SEC", "120") or "120"),
)
_INGEST_SURFACE_CACHE = StaleRuntimeCache(
    Path(
        os.getenv(
            "SIEM_INGEST_SURFACE_CACHE_FILE",
            "/opt/siem/runtime-docs/ingest_surface_cache.json",
        )
    ),
    ttl_seconds=int(
        os.getenv("SIEM_INGEST_SURFACE_CACHE_TTL_SEC", "15") or "15"
    ),
    max_stale_seconds=300,
)


def _bounded_query_metadata(
    *,
    requested_limit: int,
    applied_limit: int,
    requested_hours: int | None = None,
    applied_hours: int | None = None,
) -> dict[str, Any]:
    metadata: dict[str, Any] = {
        "requested_limit": requested_limit,
        "applied_limit": applied_limit,
        "limit_clamped": requested_limit != applied_limit,
    }
    if requested_hours is not None and applied_hours is not None:
        metadata.update(
            {
                "requested_hours": requested_hours,
                "applied_hours": applied_hours,
                "hours_clamped": requested_hours != applied_hours,
            }
        )
    return metadata


def _read_sources_inventory_cache(cache_key: str) -> dict[str, Any] | None:
    if _SOURCES_INVENTORY_CACHE_TTL_SEC <= 0:
        return None
    try:
        if not _SOURCES_INVENTORY_CACHE_FILE.exists():
            return None
        if time.time() - _SOURCES_INVENTORY_CACHE_FILE.stat().st_mtime > _SOURCES_INVENTORY_CACHE_TTL_SEC:
            return None
        payload = json.loads(_SOURCES_INVENTORY_CACHE_FILE.read_text(encoding="utf-8"))
        if not isinstance(payload, dict):
            return None
        cached = payload.get(cache_key)
        return cached if isinstance(cached, dict) else None
    except Exception:  # noqa: BLE001
        return None


def _write_sources_inventory_cache(cache_key: str, value: dict[str, Any]) -> None:
    if _SOURCES_INVENTORY_CACHE_TTL_SEC <= 0:
        return
    try:
        _SOURCES_INVENTORY_CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        payload: dict[str, Any] = {}
        if _SOURCES_INVENTORY_CACHE_FILE.exists():
            loaded = json.loads(_SOURCES_INVENTORY_CACHE_FILE.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                payload = loaded
        payload[cache_key] = value
        tmp_path = _SOURCES_INVENTORY_CACHE_FILE.with_suffix(f".{os.getpid()}.tmp")
        tmp_path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
        tmp_path.replace(_SOURCES_INVENTORY_CACHE_FILE)
    except Exception:  # noqa: BLE001
        return


def _read_assets_catalog_cache() -> dict[str, Any] | None:
    if _ASSETS_CATALOG_CACHE_TTL_SEC <= 0:
        return None
    try:
        if not _ASSETS_CATALOG_CACHE_FILE.exists():
            return None
        if time.time() - _ASSETS_CATALOG_CACHE_FILE.stat().st_mtime > _ASSETS_CATALOG_CACHE_TTL_SEC:
            return None
        payload = json.loads(_ASSETS_CATALOG_CACHE_FILE.read_text(encoding="utf-8"))
        return payload if isinstance(payload, dict) else None
    except Exception:  # noqa: BLE001
        return None


def _write_assets_catalog_cache(value: dict[str, Any]) -> None:
    if _ASSETS_CATALOG_CACHE_TTL_SEC <= 0:
        return
    try:
        _ASSETS_CATALOG_CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = _ASSETS_CATALOG_CACHE_FILE.with_suffix(f".{os.getpid()}.tmp")
        tmp_path.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")
        tmp_path.replace(_ASSETS_CATALOG_CACHE_FILE)
    except Exception:  # noqa: BLE001
        return


def _build_assets_catalog_payload() -> dict[str, Any]:
    return {
        "collectors": fetch_collector_inventory(hours=24),
        "sources": fetch_source_inventory(limit=120, hours=24),
        "detection_rules": fetch_detection_rules(limit=120),
        "normalizers": fetch_normalizer_rules(limit=120),
        "active_lists": fetch_active_list_items(limit=120),
        "cmdb_assets": fetch_cmdb_assets(limit=120),
        "threat_intel": fetch_threat_intel_entries(limit=120),
    }


DEFAULT_SIGMA_RULE_YAML = """
title: Linux Custom Auditd Rule
id: sigma-linux-custom-auditd
status: experimental
logsource:
  product: linux
  service: auditd
detection:
  selection:
    event.provider: linux.auditd
    event.type: audit_execve
    process.command_line|contains: curl
  condition: selection
level: medium
tags:
  - attack.execution
  - custom
""".strip()

RULE_ENTITY_FIELDS = [
    "log_source",
    "source.ip",
    "user.name",
    "user.target.name",
]

ASSET_TAB_TO_PAGE = {
    "overview": "assets.tab.overview",
    "devices": "assets.tab.devices",
    "collectors": "assets.tab.collectors",
    "rules": "assets.tab.rules",
    "normalizers": "assets.tab.normalizers",
    "active-lists": "assets.tab.active_lists",
    "cmdb": "assets.tab.cmdb",
    "threat-intel": "assets.tab.threat_intel",
}


def _safe_asset_tab(value: str | None) -> str:
    candidate = str(value or "overview").strip().lower()
    return candidate if candidate in ASSET_TAB_TO_PAGE else "overview"


def _assets_tabs(request: Request, tab: str) -> list[dict[str, str | bool]]:
    labels = ui_context(request, None, "assets")["t"]
    return [
        {"id": tab_id, "label": labels[label_key], "href": f"/assets?tab={quote(tab_id)}", "active": tab_id == tab}
        for tab_id, label_key in ASSET_TAB_TO_PAGE.items()
    ]


def _render_assets_page(
    request: Request,
    user: dict[str, Any],
    *,
    error: str | None = None,
    status: str | None = None,
    rule_form: dict[str, Any] | None = None,
    asset_tab: str = "overview",
    focus_kind: str = "",
    focus_id: str = "",
) -> HTMLResponse:
    assets = []
    asset_categories = []
    detection_rules = []
    normalizer_rules = []
    active_list_items = []
    cmdb_assets = []
    threat_intel_entries = []
    collectors = []
    load_error = error
    try:
        assets = fetch_assets(limit=80, hours=24)
        asset_categories = fetch_asset_categories()
        detection_rules = fetch_detection_rules(limit=250)
        normalizer_rules = fetch_normalizer_rules(limit=160)
        active_list_items = fetch_active_list_items(limit=250)
        cmdb_assets = fetch_cmdb_assets(limit=250)
        threat_intel_entries = fetch_threat_intel_entries(limit=250)
        collectors = fetch_collector_inventory(hours=24)
    except Exception as exc:  # noqa: BLE001
        load_error = load_error or f"Unable to load assets and detection catalog: {exc!s}"
    draft = {"sigma_yaml": DEFAULT_SIGMA_RULE_YAML, "threshold": 1, "window_s": 300, "entity_field": "log_source"}
    if rule_form:
        draft.update(rule_form)
    return templates.TemplateResponse(
        "assets.html",
        ui_context(
            request,
            user,
            "assets",
            assets=assets,
            asset_categories=asset_categories,
            detection_rules=detection_rules,
            normalizer_rules=normalizer_rules,
            active_list_items=active_list_items,
            cmdb_assets=cmdb_assets,
            threat_intel_entries=threat_intel_entries,
            collectors=collectors,
            entity_fields=RULE_ENTITY_FIELDS,
            rule_form=draft,
            error=load_error,
            status=status,
            asset_tab=asset_tab,
            asset_tabs=_assets_tabs(request, asset_tab),
            focus_kind=focus_kind,
            focus_id=focus_id,
        ),
    )


@router.get("/api/ingest/overview", response_class=JSONResponse)
async def ingest_overview_api(user=Depends(require_permissions("ingest:view"))) -> JSONResponse:
    try:
        return JSONResponse(await run_in_threadpool(get_ingest_overview))
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=502)


@router.get("/api/ingest/sources", response_class=JSONResponse)
async def ingest_sources_api(limit: int = Query(200, ge=1, le=500), user=Depends(require_permissions("ingest:view"))) -> JSONResponse:
    try:
        return JSONResponse(
            await run_in_threadpool(list_ingest_sources, limit=limit)
        )
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=502)


@router.get("/api/ingest/collectors", response_class=JSONResponse)
async def ingest_collectors_api(limit: int = Query(200, ge=1, le=500), user=Depends(require_permissions("ingest:view"))) -> JSONResponse:
    try:
        return JSONResponse(
            await run_in_threadpool(list_ingest_collectors, limit=limit)
        )
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=502)


@router.get("/api/ingest/dlq", response_class=JSONResponse)
async def ingest_dlq_api(limit: int = Query(200, ge=1, le=500), user=Depends(require_permissions("ingest:view"))) -> JSONResponse:
    try:
        return JSONResponse(
            await _INGEST_SURFACE_CACHE.get_or_refresh(
                f"dlq:{limit}",
                partial(list_ingest_dlq, limit=limit),
            )
        )
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=502)


@router.post("/api/ingest/dlq/replay", response_class=JSONResponse)
async def ingest_dlq_replay_api(payload: dict = Body(default={}), user=Depends(require_permissions("ingest:replay"))) -> JSONResponse:
    try:
        ids = payload.get("ids") or []
        if not isinstance(ids, list):
            return JSONResponse({"error": "ids must be a list"}, status_code=400)
        return JSONResponse(
            replay_ingest_dlq(
                ids=[str(item) for item in ids if str(item).strip()],
                limit=int(payload.get("limit") or 20),
                actor=str(getattr(user, "username", "web") or "web"),
            )
        )
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=502)


@router.post("/api/ingest/dlq/suppress", response_class=JSONResponse)
async def ingest_dlq_suppress_api(payload: dict = Body(default={}), user=Depends(require_permissions("ingest:replay"))) -> JSONResponse:
    try:
        ids = payload.get("ids") or []
        if not isinstance(ids, list):
            return JSONResponse({"error": "ids must be a list"}, status_code=400)
        return JSONResponse(
            suppress_ingest_dlq(
                ids=[str(item) for item in ids if str(item).strip()],
                limit=int(payload.get("limit") or 20),
                actor=str(getattr(user, "username", "web") or "web"),
            )
        )
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=502)


@router.post("/api/ingest/dlq/remediate", response_class=JSONResponse)
async def ingest_dlq_remediate_api(payload: dict = Body(default={}), user=Depends(require_permissions("ingest:replay"))) -> JSONResponse:
    try:
        return JSONResponse(
            remediate_ingest_dlq(
                actor=str(getattr(user, "username", "web") or "web"),
                replay_limit=int(payload.get("replay_limit") or 50),
                suppress_limit=int(payload.get("suppress_limit") or 50),
            )
        )
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=502)


@router.get("/api/secrets/required", response_class=JSONResponse)
async def secrets_inventory_api(user=Depends(require_permissions("health:view"))) -> JSONResponse:
    return JSONResponse(get_secret_inventory())


@router.get("/api/audit/events", response_class=JSONResponse)
async def audit_events_api(
    object_type: str = Query(""),
    actor: str = Query(""),
    limit: int = Query(200, ge=1, le=500),
    user=Depends(require_permissions("audit:view")),
) -> JSONResponse:
    return JSONResponse(list_audit_events(object_type=object_type, actor=actor, limit=limit))


@router.get("/api/lists/active", response_class=JSONResponse)
async def active_lists_api(user=Depends(get_current_user)) -> JSONResponse:
    return JSONResponse({"items": fetch_active_list_items()})


@router.post("/api/lists/active", response_class=JSONResponse)
async def save_active_list_api(payload: dict = Body(default={}), user=Depends(require_permissions("active_lists:write"))) -> JSONResponse:
    try:
        item = save_active_list_item(
            list_name=str(payload.get("list_name") or payload.get("name") or "active-list"),
            list_kind=str(payload.get("list_kind") or payload.get("kind") or "watch"),
            item_type=str(payload.get("indicator_type") or payload.get("type") or "ip"),
            item_value=str(payload.get("indicator") or payload.get("value") or ""),
            item_label=str(payload.get("description") or payload.get("label") or ""),
            tags=",".join(payload.get("tags") or []) if isinstance(payload.get("tags"), list) else str(payload.get("tags") or ""),
        )
        return JSONResponse(item)
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.get("/api/assets/catalog", response_class=JSONResponse)
async def assets_catalog_api(user=Depends(require_permissions("assets:view"))) -> JSONResponse:
    try:
        cached = _read_assets_catalog_cache()
        if cached is not None:
            return JSONResponse(cached)
        payload = await run_in_threadpool(_build_assets_catalog_payload)
        with _ASSETS_CATALOG_CACHE_LOCK:
            _write_assets_catalog_cache(payload)
        return JSONResponse(payload)
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.post("/api/assets/normalizers", response_class=JSONResponse)
async def save_normalizer_rule_api(payload: dict = Body(default={}), user=Depends(require_permissions("normalizers:write"))) -> JSONResponse:
    try:
        uem_mapping = payload.get("uem_mapping") or {}
        if isinstance(uem_mapping, str):
            uem_mapping = json.loads(uem_mapping or "{}")
        return JSONResponse(
            save_normalizer_rule(
                rule_id=int(payload.get("id")) if str(payload.get("id") or "").strip() else None,
                priority=int(payload.get("priority") or 1),
                source_type=str(payload.get("source_type") or ""),
                event_matcher=str(payload.get("event_matcher") or ""),
                uem_mapping=uem_mapping,
                enabled=bool(payload.get("enabled", True)),
            )
        )
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.get("/api/assets/inventory", response_class=JSONResponse)
async def assets_inventory_api(
    hours: int = Query(24, ge=1, le=720),
    limit: int = Query(200, ge=1, le=5000),
    user=Depends(require_permissions("assets:view")),
) -> JSONResponse:
    try:
        safe_limit = min(limit, 500)
        payload = await _ASSET_SURFACE_CACHE.get_or_refresh(
            f"assets-inventory:{hours}:{safe_limit}",
            lambda: {"items": fetch_assets(limit=safe_limit, hours=hours)},
        )
        return JSONResponse(
            {
                **payload,
                "query": _bounded_query_metadata(
                    requested_limit=limit,
                    applied_limit=safe_limit,
                ),
            }
        )
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.get("/api/assets/binding-overrides", response_class=JSONResponse)
async def asset_binding_overrides_api(
    scope: str = Query(""),
    include_disabled: bool = Query(True),
    limit: int = Query(200, ge=1, le=2000),
    user=Depends(require_permissions("assets:view")),
) -> JSONResponse:
    items = list_binding_overrides(scope=scope, include_disabled=include_disabled, limit=limit)
    return JSONResponse(
        {
            "items": items,
            "metrics": {
                "total": len(items),
                "enabled": sum(1 for item in items if bool(item.get("enabled", True))),
                "disabled": sum(1 for item in items if not bool(item.get("enabled", True))),
                "source_discovery": sum(1 for item in items if str(item.get("scope") or "") == "source_discovery"),
                "vulnerability": sum(1 for item in items if str(item.get("scope") or "") == "vulnerability"),
            },
        }
    )


@router.post("/api/assets/binding-overrides", response_class=JSONResponse)
async def save_asset_binding_override_api(
    payload: dict = Body(default={}),
    user=Depends(require_permissions("cmdb:write")),
) -> JSONResponse:
    try:
        return JSONResponse(save_binding_override(dict(payload or {}), actor=str(getattr(user, "username", "web") or "web")))
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.post("/api/assets/binding-overrides/{override_id}", response_class=JSONResponse)
async def update_asset_binding_override_api(
    override_id: str,
    payload: dict = Body(default={}),
    user=Depends(require_permissions("cmdb:write")),
) -> JSONResponse:
    try:
        return JSONResponse(
            update_binding_override(
                override_id,
                dict(payload or {}),
                actor=str(getattr(user, "username", "web") or "web"),
            )
        )
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.delete("/api/assets/binding-overrides/{override_id}", response_class=JSONResponse)
async def delete_asset_binding_override_api(
    override_id: str,
    user=Depends(require_permissions("cmdb:write")),
) -> JSONResponse:
    try:
        return JSONResponse(delete_binding_override(override_id, actor=str(getattr(user, "username", "web") or "web")))
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.get("/api/sources", response_class=JSONResponse)
async def sources_inventory_api(
    hours: int = Query(24, ge=1, le=720),
    limit: int = Query(220, ge=1, le=5000),
    user=Depends(require_permissions("assets:view")),
) -> JSONResponse:
    try:
        safe_limit = min(limit, 500)
        cache_key = json.dumps([hours, safe_limit], sort_keys=True)
        cached = _read_sources_inventory_cache(cache_key)
        if cached is not None:
            return JSONResponse(
                {
                    **cached,
                    "query": _bounded_query_metadata(
                        requested_limit=limit,
                        applied_limit=safe_limit,
                    ),
                }
            )
        payload = {
            "items": await run_in_threadpool(
                fetch_source_inventory,
                limit=safe_limit,
                hours=hours,
            ),
        }
        with _SOURCES_INVENTORY_CACHE_LOCK:
            _write_sources_inventory_cache(cache_key, payload)
        return JSONResponse(
            {
                **payload,
                "query": _bounded_query_metadata(
                    requested_limit=limit,
                    applied_limit=safe_limit,
                ),
            }
        )
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.get("/api/sources/discovery", response_class=JSONResponse)
async def sources_discovery_api(limit: int = Query(220, ge=1, le=5000), user=Depends(require_permissions("assets:view"))) -> JSONResponse:
    try:
        safe_limit = min(limit, 500)
        payload = list_source_discovery_candidates(limit=safe_limit)
        payload["query"] = _bounded_query_metadata(
            requested_limit=limit,
            applied_limit=safe_limit,
        )
        return JSONResponse(payload)
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.get("/api/sources/proxmox-fleet", response_class=JSONResponse)
async def proxmox_fleet_inventory_api(
    limit: int = Query(500, ge=1, le=5000),
    user=Depends(require_permissions("assets:view")),
) -> JSONResponse:
    try:
        return JSONResponse(
            await _ASSET_SURFACE_CACHE.get_or_refresh(
                f"proxmox-fleet:{limit}",
                partial(list_proxmox_fleet_inventory, limit=limit),
            )
        )
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.post("/api/sources/proxmox-fleet/sync", response_class=JSONResponse)
async def proxmox_fleet_inventory_sync_api(user=Depends(require_permissions("sources:discover"))) -> JSONResponse:
    try:
        connected_sources = fetch_source_inventory(limit=500, hours=168)
        return JSONResponse(
            sync_proxmox_fleet_inventory(
                actor=str(getattr(user, "username", "unknown") or "unknown"),
                connected_sources=connected_sources,
            )
        )
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.post("/api/sources/discovery/scan", response_class=JSONResponse)
async def sources_discovery_scan_api(payload: dict = Body(default={}), user=Depends(require_permissions("sources:discover"))) -> JSONResponse:
    try:
        return JSONResponse(
            scan_source_candidates(
                str(payload.get("cidr") or "192.168.3.0/24,10.20.10.0/24,10.20.20.0/24,10.20.30.0/24").strip(),
                ports=[int(item) for item in (payload.get("ports") or []) if str(item).strip()],
                timeout_seconds=float(payload.get("timeout_seconds") or 0.35),
                max_hosts=int(payload.get("max_hosts") or 256),
                actor=str(getattr(user, "username", "unknown") or "unknown"),
            )
        )
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.post("/api/sources/discovery/{candidate_id}/prepare", response_class=JSONResponse)
async def sources_discovery_prepare_api(candidate_id: str, payload: dict = Body(default={}), user=Depends(require_permissions("sources:discover"))) -> JSONResponse:
    try:
        return JSONResponse(
            prepare_source_onboarding(
                candidate_id,
                actor=str(getattr(user, "username", "unknown") or "unknown"),
                requested_telemetry=payload.get("requested_telemetry") or payload.get("telemetry_selection"),
            )
        )
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.post("/api/sources/discovery/jobs/{job_id}/execute", response_class=JSONResponse)
async def sources_discovery_execute_api(job_id: str, payload: dict = Body(default={}), user=Depends(require_permissions("sources:discover"))) -> JSONResponse:
    try:
        return JSONResponse(
            execute_source_onboarding(
                job_id,
                actor=str(getattr(user, "username", "unknown") or "unknown"),
                credentials=dict(payload.get("credentials") or {}),
                dry_run=bool(payload.get("dry_run", True)),
            )
        )
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.get("/api/collectors", response_class=JSONResponse)
async def collectors_inventory_api(hours: int = Query(24, ge=1, le=720), user=Depends(require_permissions("assets:view"))) -> JSONResponse:
    try:
        return JSONResponse(
            await _ASSET_SURFACE_CACHE.get_or_refresh(
                f"collectors:{hours}",
                lambda: {
                    "items": fetch_collector_inventory(hours=hours)
                },
            )
        )
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.get("/api/geo/sources", response_class=JSONResponse)
async def geo_sources_api(hours: int = Query(24, ge=1, le=720), limit: int = Query(20, ge=1, le=100), user=Depends(get_current_user)) -> JSONResponse:
    try:
        return JSONResponse(
            await _ASSET_SURFACE_CACHE.get_or_refresh(
                f"geo-sources:{hours}:{limit}",
                partial(
                    fetch_geo_source_activity,
                    hours=hours,
                    limit=limit,
                ),
            )
        )
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.get("/api/topology/network", response_class=JSONResponse)
async def network_topology_api(
    hours: int = Query(24, ge=1, le=720),
    limit: int = Query(240, ge=20, le=5000),
    user=Depends(require_permissions("assets:view")),
) -> JSONResponse:
    try:
        safe_limit = min(limit, 600)
        payload = await _ASSET_SURFACE_CACHE.get_or_refresh(
            f"network-topology:{hours}:{safe_limit}",
            partial(
                build_network_topology,
                hours=hours,
                limit=safe_limit,
            ),
        )
        return JSONResponse(
            {
                **payload,
                "query": _bounded_query_metadata(
                    requested_limit=limit,
                    applied_limit=safe_limit,
                ),
            }
        )
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.get("/api/topology/layout", response_class=JSONResponse)
async def topology_layout_api(
    workspace: str = Query("network", max_length=80),
    user=Depends(require_permissions("assets:view")),
) -> JSONResponse:
    try:
        return JSONResponse(
            await run_in_threadpool(get_topology_layout, workspace)
        )
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=500)


@router.put("/api/topology/layout", response_class=JSONResponse)
async def save_topology_layout_api(
    payload: dict = Body(default={}),
    user=Depends(require_permissions("cmdb:write")),
) -> JSONResponse:
    try:
        return JSONResponse(
            await run_in_threadpool(
                save_topology_layout,
                dict(payload or {}),
                actor=str(getattr(user, "username", "web") or "web"),
            )
        )
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=500)


@router.get("/api/topology/host-access", response_class=JSONResponse)
async def topology_host_access_profiles_api(
    limit: int = Query(500, ge=1, le=2000),
    host_id: str = Query(""),
    ip: str = Query(""),
    user=Depends(require_permissions("response:view")),
) -> JSONResponse:
    try:
        return JSONResponse(list_host_access_profiles(limit=limit, host_id=host_id, ip=ip))
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.post("/api/topology/host-access", response_class=JSONResponse)
async def save_topology_host_access_profile_api(
    payload: dict = Body(default={}),
    user=Depends(require_permissions("cmdb:write", "response:run")),
) -> JSONResponse:
    try:
        return JSONResponse(save_host_access_profile(dict(payload or {}), actor=str(getattr(user, "username", "web") or "web")))
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    except RuntimeError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=500)


@router.delete("/api/topology/host-access/{profile_id}", response_class=JSONResponse)
async def delete_topology_host_access_profile_api(
    profile_id: str,
    user=Depends(require_permissions("cmdb:write", "response:run")),
) -> JSONResponse:
    try:
        return JSONResponse(delete_host_access_profile(profile_id, actor=str(getattr(user, "username", "web") or "web")))
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, status_code=404)
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=500)


@router.get("/api/geo/ip/{ip_text}", response_class=JSONResponse)
async def geo_ip_detail_api(ip_text: str, hours: int = Query(72, ge=1, le=720), user=Depends(get_current_user)) -> JSONResponse:
    try:
        return JSONResponse(fetch_geo_ip_detail(ip_text=ip_text, hours=hours))
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.get("/api/geo/vpn", response_class=JSONResponse)
async def geo_vpn_api(hours: int = Query(24, ge=1, le=720), limit: int = Query(20, ge=1, le=100), user=Depends(get_current_user)) -> JSONResponse:
    try:
        return JSONResponse(
            await _ASSET_SURFACE_CACHE.get_or_refresh(
                f"geo-vpn:{hours}:{limit}",
                partial(
                    fetch_geo_vpn_destinations,
                    hours=hours,
                    limit=limit,
                ),
            )
        )
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.get("/api/geo/countries/{country_name}", response_class=JSONResponse)
async def geo_country_detail_api(
    country_name: str,
    kind: str = Query("source", pattern="^(source|vpn)$"),
    hours: int = Query(24, ge=1, le=720),
    limit: int = Query(60, ge=1, le=500),
    user=Depends(get_current_user),
) -> JSONResponse:
    try:
        return JSONResponse(fetch_geo_country_detail(country=country_name, hours=hours, limit=limit, kind=kind))
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.get("/api/threat-intel/overview", response_class=JSONResponse)
async def threat_intel_overview_api(
    hours: int = Query(24, ge=1, le=720),
    limit: int = Query(20, ge=1, le=5000),
    user=Depends(require_permissions("assets:view")),
) -> JSONResponse:
    try:
        safe_hours = min(hours, 72)
        safe_limit = min(limit, 100)
        payload = await _ASSET_SURFACE_CACHE.get_or_refresh(
            f"threat-intel:{safe_hours}:{safe_limit}",
            partial(
                fetch_threat_intel_overview,
                limit=safe_limit,
                hours=safe_hours,
            ),
        )
        return JSONResponse(
            {
                **payload,
                "query": _bounded_query_metadata(
                    requested_limit=limit,
                    applied_limit=safe_limit,
                    requested_hours=hours,
                    applied_hours=safe_hours,
                ),
            }
        )
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.get("/api/builders/drafts", response_class=JSONResponse)
async def builder_drafts_api(user=Depends(require_permissions("rules:write"))) -> JSONResponse:
    try:
        return JSONResponse({"items": list_builder_drafts()})
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.post("/api/builders/drafts", response_class=JSONResponse)
async def save_builder_draft_api(payload: dict = Body(...), user=Depends(require_permissions("rules:write"))) -> JSONResponse:
    try:
        draft = save_builder_draft(
            title=str(payload.get("title") or ""),
            description=str(payload.get("description") or ""),
            kind=str(payload.get("kind") or "generic"),
            blocks=[dict(item) for item in (payload.get("blocks") or []) if isinstance(item, dict)],
            draft_id=str(payload.get("id") or ""),
            status=str(payload.get("status") or "draft"),
        )
        return JSONResponse(draft)
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.delete("/api/builders/drafts/{draft_id}", response_class=JSONResponse)
async def delete_builder_draft_api(draft_id: str, user=Depends(require_permissions("rules:write"))) -> JSONResponse:
    try:
        delete_builder_draft(draft_id)
        return JSONResponse({"status": "ok", "draft_id": draft_id})
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.post("/api/builders/validate", response_class=JSONResponse)
async def validate_builder_api(payload: dict = Body(...), user=Depends(require_permissions("rules:write"))) -> JSONResponse:
    try:
        return JSONResponse(
            validate_builder_draft_payload(
                title=str(payload.get("title") or ""),
                description=str(payload.get("description") or ""),
                kind=str(payload.get("kind") or "generic"),
                blocks=[dict(item) for item in (payload.get("blocks") or []) if isinstance(item, dict)],
            )
        )
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.post("/api/builders/test", response_class=JSONResponse)
async def test_builder_api(payload: dict = Body(...), user=Depends(require_permissions("rules:test"))) -> JSONResponse:
    try:
        return JSONResponse(
            test_builder_draft_payload(
                title=str(payload.get("title") or ""),
                description=str(payload.get("description") or ""),
                kind=str(payload.get("kind") or "generic"),
                blocks=[dict(item) for item in (payload.get("blocks") or []) if isinstance(item, dict)],
            )
        )
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.post("/api/builders/publish/{draft_id}", response_class=JSONResponse)
async def publish_builder_api(draft_id: str, user=Depends(require_permissions("rules:write"))) -> JSONResponse:
    try:
        return JSONResponse(publish_builder_draft(draft_id))
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.get("/api/correlation/packs", response_class=JSONResponse)
async def correlation_packs_api(user=Depends(require_permissions("rules:write"))) -> JSONResponse:
    try:
        return JSONResponse({"items": list_correlation_packs()})
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.get("/api/correlation/packs/{pack_id}", response_class=JSONResponse)
async def correlation_pack_detail_api(pack_id: str, user=Depends(require_permissions("rules:write"))) -> JSONResponse:
    try:
        return JSONResponse({"item": get_correlation_pack(pack_id)})
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, status_code=404)
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.post("/api/correlation/packs", response_class=JSONResponse)
async def save_correlation_pack_api(payload: dict = Body(...), user=Depends(require_permissions("rules:write"))) -> JSONResponse:
    try:
        return JSONResponse(save_correlation_pack(dict(payload or {}), actor=str(getattr(user, "username", "web") or "web")))
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.post("/api/correlation/packs/{pack_id}/validate", response_class=JSONResponse)
async def validate_correlation_pack_api(pack_id: str, payload: dict = Body(default={}), user=Depends(require_permissions("rules:write"))) -> JSONResponse:
    try:
        pack_payload = dict(payload or {})
        if pack_payload:
            pack_payload.setdefault("pack_id", pack_id)
        return JSONResponse(validate_correlation_pack(pack_id=pack_id, payload=pack_payload or None))
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.post("/api/correlation/packs/{pack_id}/test", response_class=JSONResponse)
async def test_correlation_pack_api(pack_id: str, payload: dict = Body(default={}), user=Depends(require_permissions("rules:test"))) -> JSONResponse:
    try:
        pack_payload = dict(payload or {})
        if pack_payload:
            pack_payload.setdefault("pack_id", pack_id)
        return JSONResponse(test_correlation_pack(pack_id, payload=pack_payload or None))
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.post("/api/correlation/packs/{pack_id}/publish", response_class=JSONResponse)
async def publish_correlation_pack_api(pack_id: str, user=Depends(require_permissions("rules:write"))) -> JSONResponse:
    try:
        return JSONResponse(publish_correlation_pack(pack_id))
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.get("/assets", response_class=HTMLResponse)
async def assets_page(
    request: Request,
    tab: str = Query("overview"),
    focus_kind: str = Query(""),
    focus_id: str = Query(""),
    created_rule_id: int | None = None,
    user=Depends(get_current_user),
) -> HTMLResponse:
    target = canonical_ui_redirect_path(f"{request.url.path}{f'?{request.url.query}' if request.url.query else ''}")
    return RedirectResponse(url=target, status_code=307)


@router.post("/api/rules/{rule_id}/test", response_class=JSONResponse)
async def test_rule_api(rule_id: int, user=Depends(require_permissions("rules:test"))) -> JSONResponse:
    try:
        return JSONResponse(test_detection_rule(rule_id))
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.post("/api/resources/archive-hot", response_class=JSONResponse)
async def archive_hot_events_api(payload: dict = Body(default={}), user=Depends(require_permissions("storage:archive"))) -> JSONResponse:
    try:
        return JSONResponse(archive_events_to_cold(max(1, int(payload.get("older_than_hours", CONFIG.hot_retention_hours) or CONFIG.hot_retention_hours))))
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.get("/resources", response_class=HTMLResponse)
async def resources_page(request: Request, user=Depends(get_current_user)) -> RedirectResponse:
    target = canonical_ui_redirect_path(f"{request.url.path}{f'?{request.url.query}' if request.url.query else ''}")
    return RedirectResponse(url=target, status_code=307)


@router.get("/sources", response_class=HTMLResponse)
async def sources_page(request: Request, user=Depends(get_current_user)) -> RedirectResponse:
    target = canonical_ui_redirect_path(f"{request.url.path}{f'?{request.url.query}' if request.url.query else ''}")
    return RedirectResponse(url=target, status_code=307)


@router.get("/collectors", response_class=HTMLResponse)
async def collectors_page(request: Request, user=Depends(get_current_user)) -> RedirectResponse:
    target = canonical_ui_redirect_path(f"{request.url.path}{f'?{request.url.query}' if request.url.query else ''}")
    return RedirectResponse(url=target, status_code=307)
