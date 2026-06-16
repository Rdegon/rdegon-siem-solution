from __future__ import annotations

import os
import re
from typing import Any
from urllib.parse import quote

from fastapi import APIRouter, Body, Depends, File, Form, Query, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse, Response

from .auth import canonical_ui_redirect_path, get_current_user
from ..control_plane_connector_ops import list_integration_templates
from ..deps_runtime_docs_ops import (
    delete_runtime_doc,
    list_runtime_docs,
    load_runtime_doc,
    save_runtime_doc_file,
    save_runtime_doc,
)
from ..security import require_permissions
from ..templates import templates
from ..ui_text import investigation_playbooks, ui_context
from ..vuln_runtime import build_vulnerability_runtime_status
from ..vulnerability_query_runtime import (
    fetch_vulnerability_cves,
    fetch_vulnerability_findings,
    fetch_vulnerability_hosts,
    fetch_vulnerability_inventory,
    fetch_vulnerability_report_details,
    fetch_vulnerability_reports,
    fetch_vulnerability_software,
    get_report_artifact_path,
    import_greenbone_reports,
    sync_vulnerability_targets,
)
from ..vuln_maturity_runtime import apply_vulnerability_incident_policies, build_vulnerability_maturity_status

router = APIRouter()


def _slugify(value: str) -> str:
    candidate = re.sub(r"[^a-z0-9]+", "-", str(value or "").strip().lower()).strip("-")
    return candidate or "item"


def _playbook_items(lang: str) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for item in investigation_playbooks(lang):
        enriched = dict(item)
        enriched["slug"] = _slugify(str(item.get("title") or "playbook"))
        items.append(enriched)
    return items


def _document_sections(docs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    sections: list[dict[str, Any]] = [
        {"id": "access", "title": "Access and credentials", "matchers": ("access", "remote", "credential", "vpn", "nextcloud"), "items": []},
        {"id": "operations", "title": "Operations and maintenance", "matchers": ("operations", "maintenance", "retention", "deployment", "runbook"), "items": []},
        {"id": "investigations", "title": "Investigation scenarios", "matchers": ("investigation", "hunt", "playbook", "scenario"), "items": []},
        {"id": "misc", "title": "Miscellaneous", "matchers": (), "items": []},
    ]
    for item in docs:
        name = str(item.get("name") or "").lower()
        placed = False
        for section in sections[:-1]:
            if any(token in name for token in section["matchers"]):
                section["items"].append(item)
                placed = True
                break
        if not placed:
            sections[-1]["items"].append(item)
    return [section for section in sections if section["items"]]


@router.get("/api/docs", response_class=JSONResponse)
async def docs_index_api(request: Request, user=Depends(get_current_user)) -> JSONResponse:
    context = ui_context(request, user, "documentation")
    docs = list_runtime_docs()
    return JSONResponse(
        {
            "docs": docs,
            "doc_sections": _document_sections(docs),
            "playbooks": _playbook_items(context["ui_lang"]),
            "ui_lang": context["ui_lang"],
        }
    )


@router.get("/api/docs/{doc_name:path}", response_class=JSONResponse)
async def docs_detail_api(doc_name: str, user=Depends(get_current_user)) -> JSONResponse:
    try:
        return JSONResponse(load_runtime_doc(doc_name))
    except FileNotFoundError:
        return JSONResponse({"error": f"Document not found: {doc_name}"}, status_code=404)
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.get("/api/playbooks", response_class=JSONResponse)
async def playbooks_api(request: Request, user=Depends(get_current_user)) -> JSONResponse:
    context = ui_context(request, user, "documentation")
    return JSONResponse({"items": _playbook_items(context["ui_lang"])})


@router.get("/api/playbooks/{slug}", response_class=JSONResponse)
async def playbook_detail_api(request: Request, slug: str, user=Depends(get_current_user)) -> JSONResponse:
    context = ui_context(request, user, "documentation")
    selected = next((item for item in _playbook_items(context["ui_lang"]) if item["slug"] == slug), None)
    if selected is None:
        return JSONResponse({"error": f"Playbook not found: {slug}"}, status_code=404)
    return JSONResponse(selected)


@router.get("/api/integrations/catalog", response_class=JSONResponse)
async def integrations_catalog_api(user=Depends(get_current_user)) -> JSONResponse:
    return JSONResponse({"items": list_integration_templates()})


@router.get("/api/vuln/integration-contract", response_class=JSONResponse)
async def vuln_integration_contract_api(user=Depends(get_current_user)) -> JSONResponse:
    integration_templates = list_integration_templates()
    templates_payload = [
        item
        for item in integration_templates
        if str(item.get("group", "")).lower() == "vulnerability"
        or "vulnerability" in str(item.get("title", "")).lower()
        or "openvas" in str(item.get("title", "")).lower()
        or "greenbone" in str(item.get("title", "")).lower()
    ]
    return JSONResponse(
        {
            "version": "vuln-import-v1",
            "title": "External Vulnerability Manager import contract",
            "entities": [
                {"id": "report", "required": ["report_id", "scanner_source", "ts"], "optional": ["summary_message", "targets", "target_count", "finding_count", "ports"]},
                {"id": "host", "required": ["target"], "optional": ["host_name", "dst_ip", "environment", "asset_id", "aliases"]},
                {"id": "software", "required": ["service"], "optional": ["ports", "product", "vendor", "version", "host_samples"]},
                {"id": "cve", "required": ["cve"], "optional": ["cvss", "severity", "references", "products"]},
                {"id": "finding", "required": ["report_id", "ts"], "optional": ["host_name", "dst_ip", "service", "dst_port", "severity", "message", "cves"]},
            ],
            "transport_modes": ["REST pull", "Webhook source", "SQL database source", "NoSQL database source"],
            "templates": templates_payload,
        }
    )


@router.get("/api/reports", response_class=JSONResponse)
async def reports_api(user=Depends(require_permissions("resources:view"))) -> JSONResponse:
    try:
        return JSONResponse({"items": fetch_vulnerability_reports(limit=120, days=14)})
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.get("/api/reports/{report_id}", response_class=JSONResponse)
async def report_detail_api(report_id: str, user=Depends(require_permissions("resources:view"))) -> JSONResponse:
    try:
        return JSONResponse(fetch_vulnerability_report_details(report_id, limit=250))
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.get("/api/reports/{report_id}/artifact", response_class=FileResponse, response_model=None)
async def report_artifact_api(report_id: str, user=Depends(require_permissions("resources:view"))) -> Response:
    artifact_path = get_report_artifact_path(report_id)
    if not artifact_path:
        return JSONResponse({"error": "artifact not found"}, status_code=404)
    if not os.path.exists(artifact_path):
        return JSONResponse({"error": f"artifact path missing on disk: {artifact_path}"}, status_code=404)
    filename = os.path.basename(artifact_path) or f"{quote(report_id)}.xml"
    return FileResponse(artifact_path, filename=filename, media_type="application/xml")


@router.post("/api/vuln/sync", response_class=JSONResponse)
async def vuln_sync_api(payload: dict[str, Any] = Body(default={}), user=Depends(require_permissions("vuln:operate"))) -> JSONResponse:
    try:
        return JSONResponse(sync_vulnerability_targets(limit=int(payload.get("limit") or 500)))
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.post("/api/vuln/import", response_class=JSONResponse)
async def vuln_import_api(payload: dict[str, Any] = Body(default={}), user=Depends(require_permissions("vuln:operate"))) -> JSONResponse:
    try:
        return JSONResponse(import_greenbone_reports(limit=int(payload.get("limit") or 20)))
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.get("/api/vuln/overview", response_class=JSONResponse)
async def vuln_overview_api(
    days: int = Query(30, ge=1, le=90),
    limit: int = Query(25, ge=1, le=100),
    user=Depends(require_permissions("resources:view")),
) -> JSONResponse:
    try:
        return JSONResponse(fetch_vulnerability_inventory(days=days, limit=limit))
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.get("/api/vuln/runtime", response_class=JSONResponse)
async def vuln_runtime_api(days: int = Query(14, ge=1, le=90), user=Depends(require_permissions("resources:view"))) -> JSONResponse:
    try:
        return JSONResponse(build_vulnerability_runtime_status(days=days))
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.get("/api/vuln/maturity", response_class=JSONResponse)
async def vuln_maturity_api(
    days: int = Query(30, ge=1, le=180),
    limit: int = Query(100, ge=1, le=500),
    user=Depends(require_permissions("resources:view")),
) -> JSONResponse:
    try:
        return JSONResponse(build_vulnerability_maturity_status(days=days, limit=limit))
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.post("/api/vuln/policies/apply", response_class=JSONResponse)
async def vuln_policy_apply_api(
    payload: dict[str, Any] = Body(default={}),
    user=Depends(require_permissions("vuln:operate")),
) -> JSONResponse:
    try:
        actor = str(getattr(user, "username", "web") or "web")
        return JSONResponse(
            apply_vulnerability_incident_policies(
                actor=actor,
                days=int(payload.get("days") or 30),
                limit=int(payload.get("limit") or 50),
            )
        )
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.get("/api/vuln/findings", response_class=JSONResponse)
async def vuln_findings_api(
    q: str = Query(""),
    days: int = Query(30, ge=1, le=90),
    limit: int = Query(120, ge=1, le=500),
    user=Depends(require_permissions("resources:view")),
) -> JSONResponse:
    try:
        return JSONResponse(fetch_vulnerability_findings(query_text=q, days=days, limit=limit))
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.get("/api/vuln/hosts", response_class=JSONResponse)
async def vuln_hosts_api(
    q: str = Query(""),
    days: int = Query(30, ge=1, le=90),
    limit: int = Query(120, ge=1, le=500),
    user=Depends(require_permissions("resources:view")),
) -> JSONResponse:
    try:
        return JSONResponse(fetch_vulnerability_hosts(query_text=q, days=days, limit=limit))
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.get("/api/vuln/software", response_class=JSONResponse)
async def vuln_software_api(
    q: str = Query(""),
    days: int = Query(30, ge=1, le=90),
    limit: int = Query(120, ge=1, le=500),
    user=Depends(require_permissions("resources:view")),
) -> JSONResponse:
    try:
        return JSONResponse(fetch_vulnerability_software(query_text=q, days=days, limit=limit))
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.get("/api/vuln/cves", response_class=JSONResponse)
async def vuln_cves_api(
    q: str = Query(""),
    days: int = Query(30, ge=1, le=90),
    limit: int = Query(120, ge=1, le=500),
    user=Depends(require_permissions("resources:view")),
) -> JSONResponse:
    try:
        return JSONResponse(fetch_vulnerability_cves(query_text=q, days=days, limit=limit))
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": str(exc)}, status_code=400)


@router.get("/reports", response_class=HTMLResponse)
async def reports_page(request: Request, user=Depends(get_current_user)) -> RedirectResponse:
    target = canonical_ui_redirect_path(f"{request.url.path}{f'?{request.url.query}' if request.url.query else ''}")
    return RedirectResponse(url=target, status_code=307)


@router.get("/reports/{report_id}", response_class=HTMLResponse)
async def report_detail_page(report_id: str, request: Request, user=Depends(get_current_user)) -> RedirectResponse:
    target = canonical_ui_redirect_path(f"{request.url.path}{f'?{request.url.query}' if request.url.query else ''}")
    return RedirectResponse(url=target, status_code=307)


@router.get("/documentation", response_class=HTMLResponse)
async def documentation_page(request: Request, user=Depends(get_current_user)) -> RedirectResponse:
    target = canonical_ui_redirect_path(f"{request.url.path}{f'?{request.url.query}' if request.url.query else ''}")
    return RedirectResponse(url=target, status_code=307)


@router.get("/documentation/files/{doc_name:path}", response_class=HTMLResponse)
async def documentation_file_page(doc_name: str, request: Request, user=Depends(get_current_user)) -> RedirectResponse:
    target = canonical_ui_redirect_path(f"{request.url.path}{f'?{request.url.query}' if request.url.query else ''}")
    return RedirectResponse(url=target, status_code=307)


@router.get("/documentation/playbooks/{slug}", response_class=HTMLResponse)
async def documentation_playbook_page(slug: str, request: Request, user=Depends(get_current_user)) -> RedirectResponse:
    target = canonical_ui_redirect_path(f"{request.url.path}{f'?{request.url.query}' if request.url.query else ''}")
    return RedirectResponse(url=target, status_code=307)


@router.post("/documentation/save", response_class=HTMLResponse)
async def documentation_save(
    doc_name: str = Form(...),
    doc_content: str = Form(""),
    user=Depends(require_permissions("docs:write")),
) -> RedirectResponse:
    item = save_runtime_doc(doc_name, doc_content)
    return RedirectResponse(url=f"/documentation/files/{quote(item['name'])}", status_code=303)


@router.post("/documentation/upload", response_class=HTMLResponse)
async def documentation_upload(
    doc_file: UploadFile = File(...),
    user=Depends(require_permissions("docs:write")),
) -> RedirectResponse:
    payload = await doc_file.read()
    item = save_runtime_doc_file(doc_file.filename or "upload.txt", payload)
    return RedirectResponse(url=f"/documentation/files/{quote(item['name'])}", status_code=303)


@router.post("/documentation/delete", response_class=HTMLResponse)
async def documentation_delete(doc_name: str = Form(...), user=Depends(require_permissions("docs:write"))) -> RedirectResponse:
    delete_runtime_doc(doc_name)
    return RedirectResponse(url="/documentation", status_code=303)
