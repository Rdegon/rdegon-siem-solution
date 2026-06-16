"""
main.py
-------
Entry point for the Rdegon SIEM web UI (FastAPI).
"""

from __future__ import annotations

import logging
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles

from app.config import CONFIG
from app.routes import alerts, auth, console, events, health
from app.security import decode_access_token, get_token_from_request, validate_csrf_request

logger = logging.getLogger('siem_web')


def _resolve_frontend_dist_dir() -> Path:
    root = Path(__file__).resolve()
    candidates = [
        root.parent / "frontend-react" / "dist",
        root.parent.parent / "frontend-react" / "dist",
        root.parent.parent.parent / "frontend-react" / "dist",
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return candidates[0]


FRONTEND_DIST_DIR = _resolve_frontend_dist_dir()


def _react_index_response() -> HTMLResponse:
    index_path = FRONTEND_DIST_DIR / "index.html"
    html = index_path.read_text(encoding="utf-8")
    return HTMLResponse(
        content=html,
        headers={
            "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
            "Pragma": "no-cache",
            "Expires": "0",
        },
    )


def _frontend_static_file_response(asset_name: str, *, media_type: str | None = None) -> Response:
    asset_path = FRONTEND_DIST_DIR / asset_name
    if not asset_path.exists():
        raise HTTPException(status_code=404, detail="Asset not found")
    return FileResponse(asset_path, media_type=media_type)


def _react_shell_response(request: Request) -> Response:
    token = get_token_from_request(request)
    if token is None:
        return RedirectResponse(url="/auth/login", status_code=302)
    try:
        decode_access_token(token)
    except Exception:  # noqa: BLE001
        return RedirectResponse(url="/auth/login", status_code=302)
    return _react_index_response()


def create_app() -> FastAPI:
    app = FastAPI(
        title='SIEM Web UI',
        version='0.2.0',
        docs_url=None,
        redoc_url=None,
        openapi_url="/api/openapi.json",
    )
    app.state.instance_name = CONFIG.instance_name
    app.state.env = CONFIG.env
    app.state.base_url = CONFIG.base_url
    app.state.hot_retention_hours = CONFIG.hot_retention_hours
    app.state.cold_retention_days = CONFIG.cold_retention_days
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[CONFIG.base_url],
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Accept", "Authorization", "Content-Type", "X-API-Token", "X-CSRF-Token"],
    )
    app.add_middleware(GZipMiddleware, minimum_size=1024)

    @app.middleware("http")
    async def csrf_guard(request: Request, call_next):
        try:
            validate_csrf_request(request)
        except HTTPException as exc:
            return JSONResponse({"error": str(exc.detail or "Forbidden")}, status_code=exc.status_code)
        return await call_next(request)

    app.include_router(health.router)
    app.include_router(auth.router)
    app.include_router(console.router)
    app.include_router(alerts.router)
    app.include_router(events.router)
    if FRONTEND_DIST_DIR.exists():
        assets_dir = FRONTEND_DIST_DIR / "assets"
        if assets_dir.exists():
            app.mount("/app/assets", StaticFiles(directory=str(assets_dir)), name="react_assets")

        @app.api_route("/favicon.svg", methods=["GET", "HEAD"], include_in_schema=False)
        async def frontend_root_favicon():
            return _frontend_static_file_response("favicon.svg", media_type="image/svg+xml")

        @app.api_route("/mark.svg", methods=["GET", "HEAD"], include_in_schema=False)
        async def frontend_root_mark():
            return _frontend_static_file_response("mark.svg", media_type="image/svg+xml")

        @app.api_route("/favicon.ico", methods=["GET", "HEAD"], include_in_schema=False)
        async def frontend_root_favicon_ico():
            return _frontend_static_file_response("favicon.ico", media_type="image/x-icon")

        @app.api_route("/app/favicon.svg", methods=["GET", "HEAD"], include_in_schema=False)
        async def frontend_app_favicon():
            return _frontend_static_file_response("favicon.svg", media_type="image/svg+xml")

        @app.api_route("/app/favicon.ico", methods=["GET", "HEAD"], include_in_schema=False)
        async def frontend_app_favicon_ico():
            return _frontend_static_file_response("favicon.ico", media_type="image/x-icon")

        @app.api_route("/app/mark.svg", methods=["GET", "HEAD"], include_in_schema=False)
        async def frontend_app_mark():
            return _frontend_static_file_response("mark.svg", media_type="image/svg+xml")

        @app.get("/app", include_in_schema=False)
        async def react_shell(request: Request):
            return _react_shell_response(request)

        @app.get("/app/", include_in_schema=False)
        async def react_shell_trailing(request: Request):
            return _react_shell_response(request)

        @app.get("/app/{react_path:path}", include_in_schema=False)
        async def react_shell_catchall(request: Request, react_path: str):
            return _react_shell_response(request)
    return app


app = create_app()
