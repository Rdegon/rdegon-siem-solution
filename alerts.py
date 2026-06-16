
from __future__ import annotations

import json
import logging
import re
from time import time
import uuid

from fastapi import APIRouter, Body, Depends, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from starlette.concurrency import run_in_threadpool

from .auth import canonical_ui_redirect_path, get_current_user
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
    filtered = [row for row in rows if _matches_alert_query(row, query)]
    if scope == "vpn-noise":
        return [row for row in filtered if _is_vpn_noise_alert(row)]
    return [row for row in filtered if not _is_internal_maintenance_alert(row)]


def _fast_list_metrics(rows: list[dict]) -> dict:
    open_statuses = {"closed", "false_positive"}
    return {
        "agg_total": len(rows),
        "agg_open": sum(1 for row in rows if str(row.get("status") or "new").lower() not in open_statuses),
        "raw_total": sum(int(row.get("raw_alerts_total") or row.get("count_alerts") or 1) for row in rows),
        "critical_raw": sum(1 for row in rows if str(row.get("severity_agg") or row.get("severity") or "").lower() == "critical"),
        "new_raw": sum(1 for row in rows if str(row.get("status") or "").lower() == "new"),
    }


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
    user=Depends(get_current_user),
) -> JSONResponse:
    safe_view = 'raw' if view == 'raw' else 'agg'
    safe_scope = 'vpn-noise' if scope == 'vpn-noise' else 'main'
    safe_limit = max(10, min(int(limit or 200), 1000))
    fetch_limit = min(1200, max(safe_limit * 2, 200))
    cache_key = json.dumps(
        [safe_view, safe_scope, q, window, from_ts, to_ts, safe_limit],
        ensure_ascii=False,
        sort_keys=True,
    )
    now_ts = time()
    cached = _INCIDENT_LIST_CACHE.get(cache_key)
    if cached and now_ts - cached[0] < INCIDENT_LIST_CACHE_TTL_SECONDS:
        return JSONResponse(cached[1])
    try:
        rows = (
            fetch_alerts_raw(limit=fetch_limit, window=window, from_ts=from_ts, to_ts=to_ts)
            if safe_view == 'raw'
            else fetch_alerts_agg(limit=fetch_limit, window=window, from_ts=from_ts, to_ts=to_ts)
        )
        filtered_rows = _filter_rows(rows, safe_scope, q)
        items = filtered_rows[:safe_limit]
        payload = {
            'view': safe_view,
            'scope': safe_scope,
            'query': q,
            'window': window,
            'from_ts': from_ts,
            'to_ts': to_ts,
            'limit': safe_limit,
            'requested_limit': safe_limit,
            'available_count': len(filtered_rows),
            'returned_count': len(items),
            'items': items,
            'metrics': _fast_list_metrics(rows),
            'status_transitions': {key: sorted(values) for key, values in INCIDENT_STATUS_TRANSITIONS.items()},
        }
        _INCIDENT_LIST_CACHE[cache_key] = (now_ts, payload)
        if len(_INCIDENT_LIST_CACHE) > 64:
            oldest_key = min(_INCIDENT_LIST_CACHE, key=lambda key: _INCIDENT_LIST_CACHE[key][0])
            _INCIDENT_LIST_CACHE.pop(oldest_key, None)
        return JSONResponse(payload)
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({'error': str(exc)}, status_code=400)


@router.get('/api/incidents/{view}/{record_id:path}', response_class=JSONResponse)
async def incident_detail_api(
    view: str,
    record_id: str,
    window: str = Query('24h'),
    from_ts: str = Query(''),
    to_ts: str = Query(''),
    event_limit: int = Query(200, ge=1, le=500),
    alert_limit: int = Query(500, ge=1, le=1000),
    user=Depends(get_current_user),
) -> JSONResponse:
    safe_view = 'raw' if view == 'raw' else 'agg'
    try:
        return JSONResponse(
            await run_in_threadpool(
                fetch_incident_detail_bundle,
                safe_view,
                record_id,
                window=window,
                from_ts=from_ts,
                to_ts=to_ts,
                event_limit=event_limit,
                alert_limit=alert_limit,
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
    user=Depends(get_current_user),
) -> JSONResponse:
    try:
        return JSONResponse(
            await run_in_threadpool(
                fetch_incident_detail_bundle,
                'agg',
                record_id,
                window=window,
                from_ts=from_ts,
                to_ts=to_ts,
                event_limit=event_limit,
                alert_limit=alert_limit,
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
        result = update_alert_assignment(
            view,
            record_id,
            status=str(payload.get('status', 'new') or 'new'),
            assignee=str(payload.get('assignee', '') or ''),
            changed_by=str(getattr(user, 'username', 'web') or 'web'),
            note=str(payload.get('note', '') or ''),
        )
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
