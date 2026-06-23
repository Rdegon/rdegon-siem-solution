from __future__ import annotations

from fastapi import APIRouter
from fastapi.responses import JSONResponse


router = APIRouter()


@router.get("/healthz", response_class=JSONResponse, include_in_schema=False)
async def healthz() -> JSONResponse:
    return JSONResponse({"status": "ok"})


@router.get("/api/healthz", response_class=JSONResponse, include_in_schema=False)
async def api_healthz() -> JSONResponse:
    return JSONResponse({"status": "ok"})
