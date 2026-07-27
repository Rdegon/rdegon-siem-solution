from __future__ import annotations

from fastapi import APIRouter

from .console_assets_routes import router as assets_router
from .console_auth_routes import router as auth_router
from .console_dashboard_routes import router as dashboard_router
from .console_docs_routes import router as docs_router
from .console_health_routes import router as health_router
from .console_operations_routes import router as operations_router
from .console_response_routes import router as response_router
from .console_security_services_routes import router as security_services_router


ROUTERS = (
    auth_router,
    health_router,
    operations_router,
    response_router,
    dashboard_router,
    docs_router,
    assets_router,
    security_services_router,
)


def build_console_router() -> APIRouter:
    router = APIRouter()
    for child in ROUTERS:
        router.include_router(child)
    return router
