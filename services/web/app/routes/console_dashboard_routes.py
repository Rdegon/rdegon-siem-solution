from __future__ import annotations

import json
import os
from functools import partial
from time import time
from pathlib import Path
from threading import Lock
from typing import Any
from urllib.parse import quote

from fastapi import APIRouter, Body, Depends, Form, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from .auth import canonical_ui_redirect_path, get_current_user
from ..query.dashboard import (
    delete_dashboard_definition,
    describe_dashboard_widgets,
    fetch_dashboard_snapshot,
    fetch_platform_status,
    list_dashboards,
    save_dashboard_definition,
)
from ..security import require_permissions
from ..stale_runtime_cache import StaleRuntimeCache
from ..templates import templates
from ..ui_text import ui_context

router = APIRouter()

_DASHBOARD_SUMMARY_CACHE: dict[str, tuple[float, dict[str, Any]]] = {}
_DASHBOARD_RUNTIME_CACHE = StaleRuntimeCache(
    Path(
        os.getenv(
            "SIEM_DASHBOARD_RUNTIME_CACHE_FILE",
            "/opt/siem/runtime-docs/dashboard_runtime_cache.json",
        )
    ),
    ttl_seconds=int(
        os.getenv("SIEM_DASHBOARD_RUNTIME_CACHE_TTL_SEC", "120") or "120"
    ),
)
_PLATFORM_STATUS_CACHE_TTL_SEC = int(os.getenv("SIEM_PLATFORM_STATUS_CACHE_TTL_SEC", "300") or "300")
_PLATFORM_STATUS_CACHE_FILE = Path(
    os.getenv("SIEM_PLATFORM_STATUS_CACHE_FILE", "/opt/siem/runtime-docs/platform_status_cache.json")
)
_PLATFORM_STATUS_CACHE_LOCK = Lock()


def _read_platform_status_cache() -> dict[str, Any] | None:
    if _PLATFORM_STATUS_CACHE_TTL_SEC <= 0:
        return None
    try:
        if not _PLATFORM_STATUS_CACHE_FILE.exists():
            return None
        if time() - _PLATFORM_STATUS_CACHE_FILE.stat().st_mtime > _PLATFORM_STATUS_CACHE_TTL_SEC:
            return None
        payload = json.loads(_PLATFORM_STATUS_CACHE_FILE.read_text(encoding="utf-8"))
        return payload if isinstance(payload, dict) else None
    except Exception:  # noqa: BLE001
        return None


def _write_platform_status_cache(payload: dict[str, Any]) -> None:
    if _PLATFORM_STATUS_CACHE_TTL_SEC <= 0:
        return
    try:
        _PLATFORM_STATUS_CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = _PLATFORM_STATUS_CACHE_FILE.with_suffix(f".{os.getpid()}.tmp")
        tmp_path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
        tmp_path.replace(_PLATFORM_STATUS_CACHE_FILE)
    except Exception:  # noqa: BLE001
        return


def _principal_payload(user: Any) -> dict[str, Any]:
    return {
        "username": str(getattr(user, "username", "guest") or "guest"),
        "role": str(getattr(user, "role", "guest") or "guest"),
        "permissions": list(getattr(user, "permissions", []) or []),
        "principal_type": str(getattr(user, "principal_type", "user") or "user"),
        "service_account_id": str(getattr(user, "service_account_id", "") or ""),
        "auth_mechanism": str(getattr(user, "auth_mechanism", "cookie") or "cookie"),
        "issuer": str(getattr(user, "issuer", "") or ""),
        "groups": list(getattr(user, "groups", []) or []),
        "break_glass": bool(getattr(user, "break_glass", False)),
        "session_expires_ts": str(getattr(user, "session_expires_ts", "") or ""),
        "section_access": list(getattr(user, "section_access", []) or []),
        "system_grants": list(getattr(user, "system_grants", []) or []),
    }


def _dashboard_context(request: Request, user: dict[str, Any]) -> dict[str, Any]:
    dashboards = list_dashboards()
    selected_id = str(request.query_params.get("dashboard", dashboards[0]["id"] if dashboards else "security-overview") or "").strip()
    selected = next((row for row in dashboards if row["id"] == selected_id), dashboards[0] if dashboards else None)
    context = ui_context(
        request,
        user,
        "dashboards",
        metrics={},
        timeline=[],
        alert_timeline=[],
        severity_breakdown=[],
        alert_severity_breakdown=[],
        alert_status_breakdown=[],
        top_sources=[],
        top_target_ports=[],
        top_vpn_sites=[],
        top_categories=[],
        recent_alerts=[],
        platform_status={},
        dashboards=dashboards,
        selected_dashboard=selected,
        dashboard_widget_catalog=[
            {"id": "kpis", "label": "KPI cards"},
            {"id": "severity_breakdown", "label": "Severity breakdown"},
            {"id": "timelines", "label": "Event and alert timelines"},
            {"id": "sources", "label": "Top sources"},
            {"id": "ports", "label": "Targeted ports"},
            {"id": "categories", "label": "Top categories"},
            {"id": "incidents_preview", "label": "Queue preview"},
            {"id": "incident_queue", "label": "Incident queue"},
            {"id": "vpn_sites", "label": "VPN visited sites"},
        ],
        error=None,
    )
    context.update(fetch_dashboard_snapshot())
    return context


@router.get("/", include_in_schema=False)
async def index(request: Request, user=Depends(get_current_user)) -> RedirectResponse:
    return RedirectResponse(url=canonical_ui_redirect_path(str(request.url.path or "/")), status_code=307)


@router.get("/dashboards", response_class=HTMLResponse)
async def dashboard_page(request: Request, user=Depends(get_current_user)) -> RedirectResponse:
    target = canonical_ui_redirect_path(f"{request.url.path}{f'?{request.url.query}' if request.url.query else ''}")
    return RedirectResponse(url=target, status_code=307)


@router.post("/dashboards", response_class=HTMLResponse)
async def create_dashboard(
    request: Request,
    dashboard_title: str = Form(...),
    dashboard_description: str = Form(""),
    widgets: list[str] = Form([]),
    user=Depends(require_permissions("dashboards:write")),
) -> HTMLResponse:
    try:
        dashboard = save_dashboard_definition(
            title=dashboard_title,
            description=dashboard_description,
            widgets=widgets,
        )
    except Exception as exc:  # noqa: BLE001
        context = _dashboard_context(request, user)
        context["error"] = f"Unable to save dashboard: {exc!s}"
        context["dashboard_form"] = {
            "title": dashboard_title,
            "description": dashboard_description,
            "widgets": [str(item).strip() for item in widgets if str(item).strip()],
        }
        return templates.TemplateResponse("dashboard.html", context, status_code=400)
    return RedirectResponse(url=f"/dashboards?dashboard={quote(dashboard['id'])}", status_code=303)


@router.post("/dashboards/delete", response_class=HTMLResponse)
async def delete_dashboard(
    dashboard_id: str = Form(...),
    user=Depends(require_permissions("dashboards:write")),
) -> RedirectResponse:
    delete_dashboard_definition(dashboard_id)
    return RedirectResponse(url="/dashboards", status_code=303)


@router.get("/api/platform/status", response_class=JSONResponse)
async def platform_status_api(user=Depends(get_current_user)) -> JSONResponse:
    try:
        cached = _read_platform_status_cache()
        if cached is not None:
            return JSONResponse(cached)
        payload = fetch_platform_status()
        with _PLATFORM_STATUS_CACHE_LOCK:
            _write_platform_status_cache(payload)
        return JSONResponse(payload)
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc), "clickhouse_ok": False}, status_code=500)


@router.get("/api/dashboard/summary", response_class=JSONResponse)
async def dashboard_summary_api(
    window: str = Query("24h"),
    from_ts: str = Query(""),
    to_ts: str = Query(""),
    bucket_minutes: int = Query(60, ge=5, le=720),
    recent_limit: int = Query(10, ge=5, le=60),
    user=Depends(get_current_user),
) -> JSONResponse:
    try:
        cache_key = json.dumps(
            [window, from_ts, to_ts, bucket_minutes, recent_limit],
            ensure_ascii=False,
            sort_keys=True,
        )
        now_ts = time()
        cached = _DASHBOARD_SUMMARY_CACHE.get(cache_key)
        if cached and now_ts - cached[0] < 300:
            return JSONResponse(cached[1])
        payload = await _DASHBOARD_RUNTIME_CACHE.get_or_refresh(
            cache_key,
            partial(
                fetch_dashboard_snapshot,
                window=window,
                from_ts=from_ts,
                to_ts=to_ts,
                bucket_minutes=bucket_minutes,
                recent_limit=recent_limit,
            ),
        )
        _DASHBOARD_SUMMARY_CACHE[cache_key] = (now_ts, payload)
        if len(_DASHBOARD_SUMMARY_CACHE) > 32:
            oldest_key = min(_DASHBOARD_SUMMARY_CACHE, key=lambda key: _DASHBOARD_SUMMARY_CACHE[key][0])
            _DASHBOARD_SUMMARY_CACHE.pop(oldest_key, None)
        return JSONResponse(payload)
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=500)


@router.get("/api/dashboards", response_class=JSONResponse)
async def dashboard_registry_api(user=Depends(get_current_user)) -> JSONResponse:
    try:
        return JSONResponse({"dashboards": list_dashboards(), "widget_catalog": describe_dashboard_widgets()})
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=500)


@router.post("/api/dashboards", response_class=JSONResponse)
async def save_dashboard_api(
    payload: dict = Body(...),
    user=Depends(require_permissions("dashboards:write")),
) -> JSONResponse:
    try:
        dashboard = save_dashboard_definition(
            dashboard_id=str(payload.get("id") or ""),
            title=str(payload.get("title") or ""),
            description=str(payload.get("description") or ""),
            widgets=[str(item) for item in (payload.get("widgets") or []) if str(item).strip()],
            layout=[dict(item) for item in (payload.get("layout") or []) if isinstance(item, dict)],
        )
        return JSONResponse(dashboard)
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.delete("/api/dashboards/{dashboard_id}", response_class=JSONResponse)
async def delete_dashboard_api(
    dashboard_id: str,
    user=Depends(require_permissions("dashboards:write")),
) -> JSONResponse:
    try:
        delete_dashboard_definition(dashboard_id)
        return JSONResponse({"status": "ok", "dashboard_id": dashboard_id})
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.get("/api/ui/bootstrap", response_class=JSONResponse)
async def ui_bootstrap_api(request: Request, user=Depends(get_current_user)) -> JSONResponse:
    context = ui_context(request, user, "dashboards")
    principal = _principal_payload(user)
    return JSONResponse(
        {
            "user": principal,
            "ui_lang": context["ui_lang"],
            "theme": str(request.cookies.get("theme", "dark") or "dark"),
            "labels": {
                "brand": context["t"]["brand.title"],
                "dashboards": context["t"]["nav.dashboards"],
                "incidents": context["t"]["nav.incidents"],
                "events": context["t"]["nav.events"],
                "control_panel": "Control Panel",
                "sources": context["t"]["nav.sources"],
                "collectors": context["t"]["nav.collectors"],
                "assets": context["t"]["nav.assets"],
                "vulnerabilities": "Vulnerabilities",
                "builders": "Builders",
                "reports": context["t"]["nav.reports"],
                "documentation": context["t"]["nav.documentation"],
                "resources": context["t"]["nav.resources"],
            },
        }
    )
