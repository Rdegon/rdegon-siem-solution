from __future__ import annotations

import json
import os
import ssl
from datetime import datetime, timezone
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from .secret_runtime import resolve_secret_value

DEFAULT_KUMA_API_URL = "https://kuma-ref.lab.home.arpa:7223"
DEFAULT_KUMA_TENANT_ID = "d7a1db02-9fa8-45bb-9589-49419394d055"
ALLOWED_RESOURCE_KINDS = {
    "collector",
    "correlator",
    "storage",
    "activeList",
    "aggregationRule",
    "connector",
    "correlationRule",
    "dictionary",
    "enrichmentRule",
    "destination",
    "filter",
    "normalizer",
    "responseRule",
    "search",
    "agent",
    "proxy",
    "secret",
    "segmentationRule",
    "emailTemplate",
    "contextTable",
    "eventRouter",
}


class KumaIntegrationError(RuntimeError):
    pass


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _api_url() -> str:
    return str(os.getenv("SIEM_KUMA_API_URL", DEFAULT_KUMA_API_URL) or DEFAULT_KUMA_API_URL).strip().rstrip("/")


def _tenant_id() -> str:
    return str(os.getenv("SIEM_KUMA_TENANT_ID", DEFAULT_KUMA_TENANT_ID) or DEFAULT_KUMA_TENANT_ID).strip()


def _token() -> tuple[str, str, dict[str, Any]]:
    return resolve_secret_value("SIEM_KUMA_API_TOKEN", explicit_value=str(os.getenv("SIEM_KUMA_API_TOKEN", "") or ""))


def _ssl_context() -> ssl.SSLContext:
    verify_tls = str(os.getenv("SIEM_KUMA_VERIFY_TLS", "1") or "1").strip().lower() not in {"0", "false", "no", "off"}
    if not verify_tls:
        return ssl._create_unverified_context()  # noqa: SLF001
    ca_file = str(os.getenv("SIEM_KUMA_CA_FILE", "") or "").strip()
    return ssl.create_default_context(cafile=ca_file or None)


def _request(
    method: str,
    path: str,
    *,
    query: list[tuple[str, str]] | None = None,
    json_body: dict[str, Any] | None = None,
    binary_body: bytes | None = None,
    expect_binary: bool = False,
) -> Any:
    token, _, _ = _token()
    if not token:
        raise KumaIntegrationError("KUMA API token is not configured")
    suffix = f"?{urlencode(query or [])}" if query else ""
    url = f"{_api_url()}{path}{suffix}"
    body: bytes | None = None
    headers = {
        "Accept": "application/octet-stream" if expect_binary else "application/json",
        "Authorization": f"Bearer {token}",
    }
    if json_body is not None:
        body = json.dumps(json_body, ensure_ascii=False).encode("utf-8")
        headers["Content-Type"] = "application/json"
    elif binary_body is not None:
        body = binary_body
        headers["Content-Type"] = "application/octet-stream"
    request = Request(url, data=body, headers=headers, method=method.upper())
    try:
        with urlopen(request, timeout=15, context=_ssl_context()) as response:  # noqa: S310
            payload = response.read()
            if expect_binary:
                return payload
            if not payload:
                return {}
            return json.loads(payload.decode("utf-8"))
    except HTTPError as exc:
        details = exc.read().decode("utf-8", errors="replace")
        raise KumaIntegrationError(f"KUMA API {exc.code}: {details[:500]}") from exc
    except (URLError, TimeoutError, ssl.SSLError) as exc:
        raise KumaIntegrationError(f"KUMA API connection failed: {exc}") from exc


def kuma_status() -> dict[str, Any]:
    token, token_source, token_details = _token()
    result: dict[str, Any] = {
        "configured": bool(token),
        "healthy": False,
        "api_url": _api_url(),
        "tenant_id": _tenant_id(),
        "token_source": token_source if token_source != "inline" else "inline",
        "token_status": str(token_details.get("status") or ("configured" if token else "missing")),
        "generated_ts": _now_iso(),
        "resource_count": 0,
        "issues": [],
    }
    if not token:
        result["issues"].append("SIEM_KUMA_API_TOKEN is not configured")
        return result
    try:
        resources = list_kuma_resources(page=1)
        result["healthy"] = True
        result["resource_count"] = len(resources)
    except Exception as exc:  # noqa: BLE001
        result["issues"].append(str(exc))
    return result


def list_kuma_resources(
    *,
    page: int = 1,
    kinds: list[str] | None = None,
    tenant_id: str = "",
    name: str = "",
) -> list[dict[str, Any]]:
    safe_kinds = [item for item in (kinds or []) if item in ALLOWED_RESOURCE_KINDS]
    invalid = sorted(set(kinds or []) - ALLOWED_RESOURCE_KINDS)
    if invalid:
        raise ValueError(f"Unsupported KUMA resource kinds: {', '.join(invalid)}")
    query: list[tuple[str, str]] = [("page", str(max(1, int(page or 1))))]
    for kind in safe_kinds:
        query.append(("kind", kind))
    if tenant_id:
        query.append(("TenantID", tenant_id))
    if name:
        query.append(("name", name))
    payload = _request("GET", "/api/v2/resources", query=query)
    return [dict(item) for item in payload] if isinstance(payload, list) else []


def export_kuma_resources(resource_ids: list[str], *, password: str, tenant_id: str = "") -> dict[str, Any]:
    ids = [str(item).strip() for item in resource_ids if str(item).strip()]
    if not ids:
        raise ValueError("At least one KUMA resource ID is required")
    if not password:
        raise ValueError("Export password is required")
    payload = _request(
        "POST",
        "/api/v1/resources/export",
        json_body={"ids": ids, "password": password, "TenantID": tenant_id or _tenant_id()},
    )
    file_id = str((payload or {}).get("fileID") or (payload or {}).get("id") or "").strip()
    if not file_id:
        raise KumaIntegrationError("KUMA export did not return a file ID")
    return {
        "file_id": file_id,
        "content": _request("GET", f"/api/v1/resources/download/{file_id}", expect_binary=True),
        "resource_ids": ids,
    }


def import_kuma_package(
    content: bytes,
    *,
    password: str,
    tenant_id: str = "",
    actions: dict[str, int] | None = None,
) -> dict[str, Any]:
    if not content:
        raise ValueError("KUMA resource package is empty")
    if len(content) > 64 * 1024 * 1024:
        raise ValueError("KUMA resource package exceeds 64 MB")
    if not password:
        raise ValueError("Import password is required")
    upload = _request("POST", "/api/v1/resources/upload", binary_body=content)
    file_id = str((upload or {}).get("id") or (upload or {}).get("fileID") or "").strip()
    if not file_id:
        raise KumaIntegrationError("KUMA upload did not return a file ID")
    response = _request(
        "POST",
        "/api/v1/resources/import",
        json_body={
            "fileID": file_id,
            "password": password,
            "TenantID": tenant_id or _tenant_id(),
            "actions": {str(key): int(value) for key, value in dict(actions or {}).items()},
        },
    )
    return {"status": "imported", "file_id": file_id, "response": response or {}, "imported_ts": _now_iso()}
