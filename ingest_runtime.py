from __future__ import annotations

import json
import os
import ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


def _base_url() -> str:
    return str(os.getenv("SIEM_INGEST_BASE_URL", "https://192.168.1.35") or "https://192.168.1.35").rstrip("/")


def _timeout_seconds() -> float:
    try:
        timeout = float(os.getenv("SIEM_INGEST_TIMEOUT_SECONDS", "8") or "8")
    except ValueError:
        timeout = 8.0
    return max(1.0, min(30.0, timeout))


def _shared_secret() -> str:
    return str(
        os.getenv("SIEM_INGEST_API_SHARED_SECRET", "").strip()
        or os.getenv("SIEM_WEBHOOK_SHARED_SECRET", "").strip()
    )


def _tls_verify_mode() -> str:
    raw = str(os.getenv("SIEM_INGEST_TLS_VERIFY", "system") or "system").strip().lower()
    if raw in {"disabled", "off", "none"}:
        return "disabled"
    if raw in {"ca", "cafile", "ca_file"}:
        return "ca_file"
    return "system"


def _tls_ca_file() -> str:
    return str(os.getenv("SIEM_INGEST_TLS_CA_FILE", "") or "").strip()


def _ssl_context(base_url: str):
    if base_url.startswith("https://"):
        verify_mode = _tls_verify_mode()
        if verify_mode == "disabled":
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            return context
        ca_file = _tls_ca_file()
        context = ssl.create_default_context(cafile=ca_file or None)
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        return context
    return None


def _request_json(path: str, *, method: str = "GET", payload: dict[str, Any] | None = None) -> dict[str, Any]:
    base_url = _base_url()
    url = f"{base_url}{path}"
    body = None
    headers = {"Accept": "application/json"}
    if payload is not None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        headers["Content-Type"] = "application/json"
    secret = _shared_secret()
    if secret:
        headers["X-Rdegon-Ingest-Secret"] = secret
    request = urllib.request.Request(url, data=body, headers=headers, method=method)
    context = _ssl_context(base_url)
    try:
        with urllib.request.urlopen(request, timeout=_timeout_seconds(), context=context) as response:
            raw = response.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        try:
            payload = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            payload = {"error": raw or f"HTTP {exc.code}"}
        message = str(payload.get("error") or payload.get("detail") or f"HTTP {exc.code}")
        raise RuntimeError(message) from exc
    except ssl.SSLError as exc:
        raise RuntimeError(f"Unable to verify ingest runtime TLS: {exc}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Unable to reach ingest runtime: {exc.reason}") from exc

    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Ingest runtime returned invalid JSON for {path}") from exc
    if not isinstance(parsed, dict):
        raise RuntimeError(f"Ingest runtime returned non-object payload for {path}")
    return parsed


def get_ingest_overview() -> dict[str, Any]:
    return _request_json("/health/overview")


def get_ingest_transport_health() -> dict[str, Any]:
    return _request_json("/health/transport")


def list_ingest_sources(*, limit: int = 200) -> dict[str, Any]:
    query = urllib.parse.urlencode({"limit": max(1, min(500, int(limit)))})
    return _request_json(f"/health/sources?{query}")


def list_ingest_collectors(*, limit: int = 200) -> dict[str, Any]:
    query = urllib.parse.urlencode({"limit": max(1, min(500, int(limit)))})
    return _request_json(f"/health/collectors?{query}")


def list_ingest_dlq(*, limit: int = 200) -> dict[str, Any]:
    query = urllib.parse.urlencode({"limit": max(1, min(500, int(limit)))})
    return _request_json(f"/dlq/events?{query}")


def replay_ingest_dlq(*, ids: list[str] | None = None, limit: int = 20, actor: str = "web") -> dict[str, Any]:
    return _request_json(
        "/dlq/replay",
        method="POST",
        payload={
            "ids": [str(item) for item in (ids or []) if str(item).strip()],
            "limit": max(1, min(2_000, int(limit))),
            "actor": str(actor or "web"),
        },
    )


def suppress_ingest_dlq(*, ids: list[str] | None = None, limit: int = 20, actor: str = "web") -> dict[str, Any]:
    return _request_json(
        "/dlq/suppress",
        method="POST",
        payload={
            "ids": [str(item) for item in (ids or []) if str(item).strip()],
            "limit": max(1, min(500_000, int(limit))),
            "actor": str(actor or "web"),
        },
    )


def remediate_ingest_dlq(*, actor: str = "web", replay_limit: int = 50, suppress_limit: int = 50) -> dict[str, Any]:
    replay = replay_ingest_dlq(limit=max(1, min(2_000, int(replay_limit))), actor=actor)
    suppress = suppress_ingest_dlq(limit=max(1, min(500_000, int(suppress_limit))), actor=actor)
    return {
        "status": "completed",
        "actor": str(actor or "web"),
        "replay": replay,
        "suppress": suppress,
        "replayed": int(replay.get("replayed") or 0),
        "suppressed": int(suppress.get("suppressed") or 0),
    }
