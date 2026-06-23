from __future__ import annotations

from urllib.parse import parse_qsl, quote, urlencode, urlsplit

from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.responses import RedirectResponse

from ..config import CONFIG
from ..oidc_runtime import build_authorize_redirect, finalize_callback, oidc_enabled, provider_status, providers_inventory
from ..control_plane_access_ops import record_break_glass_session, resolve_keycloak_principal_access
from ..security import (
    CurrentUser,
    authenticate_user,
    check_auth_rate_limit,
    create_access_token,
    decode_access_token,
    get_token_from_request,
    issue_csrf_token,
    record_auth_failure,
    record_auth_success,
)
from ..templates import templates
from ..ui_text import UI_TEXT, resolve_ui_lang

router = APIRouter()

LEGACY_UI_ROUTE_MAP = {
    "/": "/app/dashboards",
    "/dashboards": "/app/dashboards",
    "/alerts": "/app/incidents",
    "/alerts_raw": "/app/incidents?view=raw",
    "/alerts_agg": "/app/incidents?view=agg",
    "/events": "/app/events",
    "/assets": "/app/assets",
    "/sources": "/app/sources",
    "/collectors": "/app/collectors",
    "/resources": "/app/dashboards",
    "/reports": "/app/vuln/reports",
    "/documentation": "/app/docs",
}


def canonical_ui_redirect_path(value: str | None, *, fallback: str = "/app/dashboards") -> str:
    candidate = str(value or "").strip()
    if not candidate:
        return fallback
    if not candidate.startswith("/") or candidate.startswith("//"):
        return fallback
    parsed = urlsplit(candidate)
    path = (parsed.path or "/").strip() or "/"
    if path != "/" and path.endswith("/"):
        path = path.rstrip("/")
    target = ""
    drop_incoming_query = path.startswith("/api/") or path == "/api"
    if drop_incoming_query:
        target = fallback
    elif path.startswith("/app"):
        target = path
    elif path.startswith("/reports/"):
        target = f"/app/vuln/reports/{path.removeprefix('/reports/')}"
    elif path.startswith("/documentation/files/"):
        target = f"/app/docs/page/{path.removeprefix('/documentation/files/')}"
    elif path.startswith("/documentation/playbooks/"):
        target = f"/app/docs/playbooks/{path.removeprefix('/documentation/playbooks/')}"
    else:
        target = LEGACY_UI_ROUTE_MAP.get(path, path)
    target_parts = urlsplit(target)
    target_query_pairs = parse_qsl(target_parts.query, keep_blank_values=True)
    incoming_query_pairs = [
        (key, value)
        for key, value in parse_qsl(parsed.query, keep_blank_values=True)
        if not drop_incoming_query
        if key not in {existing_key for existing_key, _ in target_query_pairs}
    ]
    merged_query = target_query_pairs + incoming_query_pairs
    encoded_query = urlencode(merged_query, doseq=True)
    return f"{target_parts.path}{f'?{encoded_query}' if encoded_query else ''}"


def _safe_next_path(value: str | None, *, fallback: str = "/app/dashboards") -> str:
    candidate = str(value or "").strip()
    if not candidate:
        return fallback
    if not candidate.startswith("/") or candidate.startswith("//"):
        return fallback
    return canonical_ui_redirect_path(candidate, fallback=fallback)


def _requested_next_path(request: Request, submitted_value: str | None = None) -> str:
    return _safe_next_path(submitted_value or request.query_params.get("next") or "")


def _login_redirect_location(request: Request) -> str:
    target = request.url.path
    if request.url.query:
        target = f"{target}?{request.url.query}"
    next_path = _safe_next_path(target)
    return f"/auth/login?next={quote(next_path, safe='')}"


def _oidc_redirect_uri() -> str:
    return f"{CONFIG.base_url.rstrip('/')}/auth/oidc/callback"


def _template_payload(request: Request, *, error: str | None, next_path: str) -> dict[str, object]:
    status = provider_status()
    ui_lang = resolve_ui_lang(request)
    return {
        "request": request,
        "base_url": CONFIG.base_url,
        "error": error,
        "next_path": next_path,
        "ui_lang": ui_lang,
        "t": UI_TEXT[ui_lang],
        "providers": providers_inventory(status),
        "oidc_primary": bool(status.get("healthy")),
        "break_glass_supported": True,
        "enterprise_issuer": str(status.get("issuer") or ""),
    }


def get_current_user(request: Request) -> CurrentUser:
    token = get_token_from_request(request)
    if token is None:
        raise HTTPException(
            status_code=status.HTTP_307_TEMPORARY_REDIRECT,
            headers={"Location": _login_redirect_location(request)},
        )
    try:
        return decode_access_token(token)
    except HTTPException as exc:
        raise HTTPException(
            status_code=status.HTTP_307_TEMPORARY_REDIRECT,
            headers={"Location": _login_redirect_location(request)},
        ) from exc


@router.get("/auth/login", include_in_schema=False)
async def login_page(request: Request):
    token = get_token_from_request(request)
    if token:
        try:
            decode_access_token(token)
            return RedirectResponse(url=_requested_next_path(request), status_code=status.HTTP_302_FOUND)
        except HTTPException:
            pass
    return templates.TemplateResponse(
        "login.html",
        _template_payload(request, error=None, next_path=_requested_next_path(request)),
    )


@router.get("/login", include_in_schema=False)
async def login_alias(request: Request) -> RedirectResponse:
    query = f"?{request.url.query}" if request.url.query else ""
    return RedirectResponse(url=f"/auth/login{query}", status_code=status.HTTP_302_FOUND)


@router.post("/auth/login", include_in_schema=False)
async def login_submit(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    next_path: str = Form(""),
    auth_flow: str = Form(""),
    break_glass_reason: str = Form(""),
    break_glass_minutes: str = Form("60"),
):
    limiter = check_auth_rate_limit(request)
    if limiter.get("blocked"):
        retry_after_seconds = int(limiter.get("retry_after_seconds") or 0)
        response = templates.TemplateResponse(
            "login.html",
            _template_payload(
                request,
                error=f"Too many login attempts. Try again in {retry_after_seconds} seconds.",
                next_path=_requested_next_path(request, next_path),
            ),
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        )
        response.headers["Retry-After"] = str(retry_after_seconds)
        return response

    user = authenticate_user(username, password)
    if user is None:
        outcome = record_auth_failure(request)
        retry_after_seconds = int(outcome.get("retry_after_seconds") or 0)
        response = templates.TemplateResponse(
            "login.html",
            _template_payload(
                request,
                error=(
                    f"Too many login attempts. Try again in {retry_after_seconds} seconds."
                    if outcome.get("blocked")
                    else "Invalid username or password"
                ),
                next_path=_requested_next_path(request, next_path),
            ),
            status_code=status.HTTP_429_TOO_MANY_REQUESTS if outcome.get("blocked") else status.HTTP_401_UNAUTHORIZED,
        )
        if outcome.get("blocked"):
            response.headers["Retry-After"] = str(retry_after_seconds)
        return response

    record_auth_success(request)
    requested_flow = str(auth_flow or "").strip().lower() or "break_glass"
    break_glass_active = requested_flow == "break_glass" or oidc_enabled()
    reason = str(break_glass_reason or "").strip() or "Emergency local access"
    session_minutes = max(5, min(240, int(str(break_glass_minutes or "60") or "60")))
    break_glass_session = None
    if break_glass_active:
        break_glass_session = record_break_glass_session(
            user.username,
            role=user.role,
            reason=reason,
            actor=user.username,
            client_ip=str(limiter.get("client_ip") or ""),
            expires_minutes=session_minutes,
        )
    token = create_access_token(
        subject=user.username,
        role=user.role,
        auth_mechanism="break_glass" if break_glass_active else "password",
        break_glass=break_glass_active,
        session_expires_ts=str((break_glass_session or {}).get("expires_ts") or ""),
        break_glass_session_id=str((break_glass_session or {}).get("id") or ""),
        permissions=list(getattr(user, "permissions", []) or []),
    )
    csrf_token = issue_csrf_token()
    secure_cookie = CONFIG.base_url.startswith("https://")
    response = RedirectResponse(url=_requested_next_path(request, next_path), status_code=status.HTTP_303_SEE_OTHER)
    response.set_cookie(
        key="access_token",
        value=token,
        httponly=True,
        secure=secure_cookie,
        samesite="lax",
        max_age=CONFIG.jwt_expires_minutes * 60,
    )
    response.set_cookie(
        key="csrf_token",
        value=csrf_token,
        httponly=False,
        secure=secure_cookie,
        samesite="lax",
        max_age=CONFIG.jwt_expires_minutes * 60,
    )
    return response


@router.get("/auth/oidc/start", include_in_schema=False)
async def oidc_start(request: Request):
    if not bool(provider_status().get("healthy")):
        return templates.TemplateResponse(
            "login.html",
            _template_payload(request, error="Enterprise SSO is not available right now.", next_path=_requested_next_path(request)),
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        )
    redirect_url, state = build_authorize_redirect(
        redirect_uri=_oidc_redirect_uri(),
        next_path=_requested_next_path(request),
    )
    response = RedirectResponse(url=redirect_url, status_code=status.HTTP_302_FOUND)
    response.set_cookie(
        key="oidc_state",
        value=state,
        httponly=True,
        secure=CONFIG.base_url.startswith("https://"),
        samesite="lax",
        max_age=600,
    )
    return response


@router.get("/auth/oidc/callback", include_in_schema=False)
async def oidc_callback(request: Request, code: str = "", state: str = "", error: str = ""):
    if error:
        return templates.TemplateResponse(
            "login.html",
            _template_payload(request, error=f"Enterprise SSO failed: {error}", next_path=_requested_next_path(request)),
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    cookie_state = str(request.cookies.get("oidc_state") or "").strip()
    try:
        principal = finalize_callback(code=code, state=state, cookie_state=cookie_state, redirect_uri=_oidc_redirect_uri())
    except Exception as exc:  # noqa: BLE001
        return templates.TemplateResponse(
            "login.html",
            _template_payload(request, error=f"Enterprise SSO failed: {exc}", next_path=_requested_next_path(request)),
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    access = resolve_keycloak_principal_access(
        str(principal.get("username") or ""),
        claimed_groups=list(principal.get("groups") or []),
        fallback_role=str(principal.get("role") or "viewer"),
    )
    if not bool(access.get("allowed")):
        return templates.TemplateResponse(
            "login.html",
            _template_payload(
                request,
                error=str(access.get("message") or "No explicit SIEM access grant is assigned to this SSO user."),
                next_path=_requested_next_path(request),
            ),
            status_code=status.HTTP_403_FORBIDDEN,
        )
    token = create_access_token(
        subject=str(principal.get("username") or "oidc-user"),
        role=str(access.get("role") or principal.get("role") or "viewer"),  # type: ignore[arg-type]
        auth_mechanism="oidc",
        issuer=str(principal.get("issuer") or ""),
        groups=list(principal.get("groups") or []),
        session_expires_ts=str(principal.get("session_expires_ts") or ""),
        permissions=list(access.get("permissions") or []),
        section_access=list(access.get("section_access") or []),
        system_grants=list(access.get("system_grants") or []),
    )
    csrf_token = issue_csrf_token()
    secure_cookie = CONFIG.base_url.startswith("https://")
    response = RedirectResponse(
        url=canonical_ui_redirect_path(str(principal.get("next_path") or ""), fallback="/app/dashboards"),
        status_code=status.HTTP_303_SEE_OTHER,
    )
    response.set_cookie("access_token", token, httponly=True, secure=secure_cookie, samesite="lax", max_age=CONFIG.jwt_expires_minutes * 60)
    response.set_cookie("csrf_token", csrf_token, httponly=False, secure=secure_cookie, samesite="lax", max_age=CONFIG.jwt_expires_minutes * 60)
    response.delete_cookie("oidc_state")
    return response


@router.get("/auth/logout", include_in_schema=False)
async def logout(request: Request, user=Depends(get_current_user)):
    response = RedirectResponse(url="/auth/login", status_code=status.HTTP_303_SEE_OTHER)
    response.delete_cookie("access_token")
    response.delete_cookie("csrf_token")
    return response
