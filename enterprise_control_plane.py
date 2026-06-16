from __future__ import annotations

import hashlib
import importlib
import json
import logging
import os
import secrets as pysecrets
import smtplib
import sqlite3
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from pathlib import Path
from typing import Any

try:
    from .enterprise_control_plane_defaults import build_default_connector_definitions, build_default_response_actions
except ImportError:  # pragma: no cover - local test fallback
    from enterprise_control_plane_defaults import build_default_connector_definitions, build_default_response_actions  # type: ignore[no-redef]

try:
    from .secret_runtime import describe_secret_env as _describe_secret_env
    from .secret_runtime import resolve_runtime_object as _shared_resolve_runtime_object
    from .secret_runtime import resolve_secret_value as _shared_resolve_secret_value
except ImportError:  # pragma: no cover - local test fallback
    from secret_runtime import describe_secret_env as _describe_secret_env  # type: ignore[no-redef]
    from secret_runtime import resolve_runtime_object as _shared_resolve_runtime_object  # type: ignore[no-redef]
    from secret_runtime import resolve_secret_value as _shared_resolve_secret_value  # type: ignore[no-redef]


CONTROL_PLANE_SCHEMA_VERSION = "v1"
CONTROL_PLANE_META_COLLECTION = "__control_plane_meta"
_LOCK = threading.RLock()
logger = logging.getLogger("siem_web.enterprise_control_plane")
_FILESYSTEM_COLLECTION_ERRORS: dict[str, dict[str, str]] = {}


def _now() -> datetime:
    return datetime.now(tz=timezone.utc)


def _now_iso() -> str:
    return _now().replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _safe_slug(value: str, *, default: str = "item") -> str:
    raw = "".join(ch.lower() if ch.isalnum() else "-" for ch in str(value or "").strip())
    while "--" in raw:
        raw = raw.replace("--", "-")
    raw = raw.strip("-")
    return raw or default


def _new_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:10]}"


def _json_clone(value: Any) -> Any:
    return json.loads(json.dumps(value, ensure_ascii=False))


def _parse_ts(value: str | None) -> datetime:
    text = str(value or "").strip()
    if not text:
        return datetime.min.replace(tzinfo=timezone.utc)
    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return datetime.min.replace(tzinfo=timezone.utc)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _control_plane_dir() -> Path:
    root = os.getenv("SIEM_CONTROL_PLANE_DIR", "").strip()
    if root:
        base = Path(root)
    else:
        base = Path(__file__).resolve().parent / "runtime-control-plane"
    base.mkdir(parents=True, exist_ok=True)
    return base


def _collection_path(name: str) -> Path:
    return _control_plane_dir() / f"{name}.json"


def control_plane_collection_path(name: str) -> Path:
    return _collection_path(name)


def _env_first(*names: str) -> str:
    for name in names:
        value = os.getenv(name, "").strip()
        if value:
            return value
    return ""


def _control_plane_backend_setting() -> str:
    requested = str(os.getenv("SIEM_CONTROL_PLANE_BACKEND", "auto") or "auto").strip().lower()
    if requested in {"auto", "filesystem", "postgres"}:
        return requested
    return "auto"


def _control_plane_pg_table() -> str:
    return str(os.getenv("SIEM_CONTROL_PLANE_PG_TABLE", "siem_control_plane_collections") or "siem_control_plane_collections").strip()


def _quote_pg_identifier(value: str) -> str:
    safe = str(value or "").strip()
    if not safe:
        raise ValueError("Postgres identifier is empty")
    parts = safe.split(".")
    quoted_parts: list[str] = []
    for part in parts:
        chunk = part.strip()
        if not chunk or any(not (char.isalnum() or char == "_") for char in chunk):
            raise ValueError(f"Unsafe Postgres identifier: {value}")
        quoted_parts.append(f'"{chunk}"')
    return ".".join(quoted_parts)


def _build_control_plane_pg_dsn() -> tuple[str, str, dict[str, str]]:
    direct_dsn = _env_first("SIEM_CONTROL_PLANE_PG_DSN")
    if direct_dsn:
        return direct_dsn, "SIEM_CONTROL_PLANE_PG_DSN", {"mode": "dsn"}
    host = _env_first("SIEM_CONTROL_PLANE_PG_HOST", "SIEM_PG_HOST")
    database = _env_first("SIEM_CONTROL_PLANE_PG_DB", "SIEM_PG_DB")
    user = _env_first("SIEM_CONTROL_PLANE_PG_USER", "SIEM_PG_USER")
    password = _env_first("SIEM_CONTROL_PLANE_PG_PASSWORD", "SIEM_PG_PASSWORD")
    if not all((host, database, user, password)):
        return "", "", {"mode": "incomplete"}
    port = _env_first("SIEM_CONTROL_PLANE_PG_PORT", "SIEM_PG_PORT") or "5432"
    dsn = f"host={host} port={port} dbname={database} user={user} password={password} connect_timeout=2"
    return dsn, "assembled", {"mode": "env_parts", "host": host, "port": port, "database": database, "user": user}


def _atomic_write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    temp_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    temp_path.replace(path)


class ControlPlaneCollectionCorruptionError(RuntimeError):
    def __init__(self, *, name: str, path: Path, reason: str) -> None:
        self.name = str(name or "").strip()
        self.path = Path(path)
        self.reason = str(reason or "unknown_error").strip() or "unknown_error"
        super().__init__(f"Control-plane collection {self.name} is corrupted: {self.reason}")

    def as_dict(self) -> dict[str, str]:
        return {"collection": self.name, "path": str(self.path), "reason": self.reason}


def _default_control_plane_meta() -> list[dict[str, Any]]:
    return []


def _visible_collection_name(name: str) -> bool:
    return bool(str(name or "").strip()) and not str(name).startswith("__")


def _load_control_plane_meta() -> dict[str, Any]:
    rows = _load_rows(CONTROL_PLANE_META_COLLECTION, _default_control_plane_meta)
    if rows and isinstance(rows[0], dict):
        return dict(rows[0])
    return {}


def _save_control_plane_meta(payload: dict[str, Any]) -> None:
    _save_rows(CONTROL_PLANE_META_COLLECTION, [_json_clone(payload)])


class _FilesystemControlPlaneStore:
    def __init__(self, *, requested_backend: str, fallback_reason: str = "") -> None:
        self.backend = "filesystem"
        self.requested_backend = requested_backend
        self.fallback_reason = str(fallback_reason or "")

    def _read_rows(self, name: str, default_factory, *, create_if_missing: bool) -> list[dict[str, Any]]:
        path = _collection_path(name)
        if not path.exists():
            rows = default_factory()
            if create_if_missing:
                _atomic_write_json(path, rows)
            _FILESYSTEM_COLLECTION_ERRORS.pop(name, None)
            return rows
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:  # noqa: BLE001
            error = ControlPlaneCollectionCorruptionError(name=name, path=path, reason=f"json_decode_error:{exc.__class__.__name__}")
            _FILESYSTEM_COLLECTION_ERRORS[name] = error.as_dict()
            raise error from exc
        if not isinstance(payload, list):
            error = ControlPlaneCollectionCorruptionError(name=name, path=path, reason="payload_not_list")
            _FILESYSTEM_COLLECTION_ERRORS[name] = error.as_dict()
            raise error
        _FILESYSTEM_COLLECTION_ERRORS.pop(name, None)
        return payload

    def load_rows(self, name: str, default_factory) -> list[dict[str, Any]]:
        with _LOCK:
            try:
                return self._read_rows(name, default_factory, create_if_missing=True)
            except ControlPlaneCollectionCorruptionError:
                return default_factory()

    def save_rows(self, name: str, rows: list[dict[str, Any]]) -> None:
        path = _collection_path(name)
        with _LOCK:
            _atomic_write_json(path, rows)
            _FILESYSTEM_COLLECTION_ERRORS.pop(name, None)

    def read_snapshot(self, name: str, default_factory) -> list[dict[str, Any]]:
        with _LOCK:
            return self._read_rows(name, default_factory, create_if_missing=False)

    def list_collection_names(self) -> list[str]:
        with _LOCK:
            return sorted(path.stem for path in _control_plane_dir().glob("*.json") if path.is_file())

    def status(self) -> dict[str, Any]:
        return {
            "backend": self.backend,
            "requested_backend": self.requested_backend,
            "path": str(_control_plane_dir()),
            "supports_transactions": False,
            "fallback_reason": self.fallback_reason,
            "corrupt_collections": list(_FILESYSTEM_COLLECTION_ERRORS.values()),
        }


class _PostgresControlPlaneStore:
    def __init__(self, *, requested_backend: str, dsn: str, dsn_source: str, connection_meta: dict[str, str]) -> None:
        self.backend = "postgres"
        self.requested_backend = requested_backend
        self.dsn = str(dsn or "").strip()
        self.dsn_source = str(dsn_source or "")
        self.connection_meta = dict(connection_meta or {})
        self.table_name = _control_plane_pg_table()
        self.table_sql = _quote_pg_identifier(self.table_name)
        self._driver_name = "psycopg"
        self._import_driver()

    def _import_driver(self):
        return importlib.import_module(self._driver_name)

    def _connect(self):
        driver = self._import_driver()
        return driver.connect(self.dsn, autocommit=True)

    def _ensure_schema(self, cursor) -> None:
        cursor.execute(
            f"""
            CREATE TABLE IF NOT EXISTS {self.table_sql} (
                collection_name TEXT PRIMARY KEY,
                payload JSONB NOT NULL,
                updated_ts TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
            """
        )

    def load_rows(self, name: str, default_factory) -> list[dict[str, Any]]:
        with _LOCK:
            with self._connect() as connection:
                with connection.cursor() as cursor:
                    self._ensure_schema(cursor)
                    cursor.execute(f"SELECT payload::text FROM {self.table_sql} WHERE collection_name = %s", (name,))
                    record = cursor.fetchone()
                    if record and record[0]:
                        try:
                            payload = json.loads(str(record[0]))
                        except Exception:  # noqa: BLE001
                            payload = None
                        if isinstance(payload, list):
                            return payload
                    rows = default_factory()
                    cursor.execute(
                        f"""
                        INSERT INTO {self.table_sql} (collection_name, payload, updated_ts)
                        VALUES (%s, %s::jsonb, NOW())
                        ON CONFLICT (collection_name)
                        DO UPDATE SET payload = EXCLUDED.payload, updated_ts = EXCLUDED.updated_ts
                        """,
                        (name, json.dumps(rows, ensure_ascii=False)),
                    )
                    return rows

    def save_rows(self, name: str, rows: list[dict[str, Any]]) -> None:
        with _LOCK:
            with self._connect() as connection:
                with connection.cursor() as cursor:
                    self._ensure_schema(cursor)
                    cursor.execute(
                        f"""
                        INSERT INTO {self.table_sql} (collection_name, payload, updated_ts)
                        VALUES (%s, %s::jsonb, NOW())
                        ON CONFLICT (collection_name)
                        DO UPDATE SET payload = EXCLUDED.payload, updated_ts = EXCLUDED.updated_ts
                        """,
                        (name, json.dumps(rows, ensure_ascii=False)),
                    )

    def list_collection_names(self) -> list[str]:
        with _LOCK:
            with self._connect() as connection:
                with connection.cursor() as cursor:
                    self._ensure_schema(cursor)
                    cursor.execute(f"SELECT collection_name FROM {self.table_sql} ORDER BY collection_name")
                    rows = getattr(cursor, "fetchall", None)
                    if callable(rows):
                        raw_rows = rows()
                    else:
                        first = cursor.fetchone()
                        raw_rows = [first] if first else []
                    names: list[str] = []
                    for row in raw_rows:
                        if not row:
                            continue
                        names.append(str(row[0] or "").strip())
                    return [name for name in names if name]

    def status(self) -> dict[str, Any]:
        return {
            "backend": self.backend,
            "requested_backend": self.requested_backend,
            "table": self.table_name,
            "dsn_source": self.dsn_source,
            "connection": _json_clone(self.connection_meta),
            "supports_transactions": True,
            "driver": self._driver_name,
        }


def _create_control_plane_store():
    requested = _control_plane_backend_setting()
    if requested == "filesystem":
        return _FilesystemControlPlaneStore(requested_backend=requested)

    dsn, dsn_source, connection_meta = _build_control_plane_pg_dsn()
    if not dsn:
        if requested == "postgres":
            raise RuntimeError("SIEM_CONTROL_PLANE_BACKEND=postgres requires SIEM_CONTROL_PLANE_PG_DSN or SIEM_PG_* variables")
        return _FilesystemControlPlaneStore(requested_backend=requested, fallback_reason="postgres_not_configured")

    try:
        return _PostgresControlPlaneStore(
            requested_backend=requested,
            dsn=dsn,
            dsn_source=dsn_source,
            connection_meta=connection_meta,
        )
    except Exception as exc:  # noqa: BLE001
        if requested == "postgres":
            raise
        logger.warning("Postgres control-plane store unavailable, falling back to filesystem: %s", exc)
        return _FilesystemControlPlaneStore(requested_backend=requested, fallback_reason=str(exc))


_STORE = _create_control_plane_store()


def control_plane_storage_status() -> dict[str, Any]:
    status = _STORE.status()
    status["schema_version"] = CONTROL_PLANE_SCHEMA_VERSION
    collection_names = [name for name in _STORE.list_collection_names() if _visible_collection_name(name)]
    collection_counts: dict[str, int] = {}
    for name in collection_names:
        try:
            collection_counts[name] = len(_STORE.load_rows(name, list))
        except Exception:  # noqa: BLE001
            collection_counts[name] = 0
    meta = _load_control_plane_meta()
    requested_backend = str(status.get("requested_backend") or "")
    backend = str(status.get("backend") or "")
    if meta:
        migration_status = str(meta.get("migration_status") or "").strip() or "unknown"
        last_migration_at = str(meta.get("last_migration_at") or "").strip()
    elif backend == "postgres":
        migration_status = "pending" if requested_backend == "postgres" else "ready_without_migration"
        last_migration_at = ""
    elif requested_backend == "postgres":
        migration_status = "blocked"
        last_migration_at = ""
    else:
        migration_status = "not_applicable"
        last_migration_at = ""
    status["collection_counts"] = collection_counts
    status["migration_status"] = migration_status
    status["last_migration_at"] = last_migration_at
    if meta:
        status["migration_details"] = _json_clone(meta)
    return status


def _load_rows(name: str, default_factory) -> list[dict[str, Any]]:
    return _STORE.load_rows(name, default_factory)


def _save_rows(name: str, rows: list[dict[str, Any]]) -> None:
    _STORE.save_rows(name, rows)


def load_control_plane_rows(name: str, default_factory=None) -> list[dict[str, Any]]:
    factory = default_factory if callable(default_factory) else list
    return _load_rows(name, factory)


def save_control_plane_rows(name: str, rows: list[dict[str, Any]]) -> None:
    _save_rows(name, rows)


def migrate_filesystem_snapshot_to_active_store(*, actor: str = "system", force: bool = False) -> dict[str, Any]:
    started_at = _now_iso()
    target_status = _STORE.status()
    requested_backend = str(target_status.get("requested_backend") or "")
    if str(target_status.get("backend") or "") != "postgres":
        report = {
            "migration_status": "not_applicable",
            "source_backend": "filesystem",
            "target_backend": str(target_status.get("backend") or "filesystem"),
            "started_at": started_at,
            "last_migration_at": started_at,
            "actor": str(actor or "system"),
            "force": bool(force),
            "errors": [],
            "imported_collections": [],
            "skipped_collections": [],
            "source_collection_counts": {},
        }
        _save_control_plane_meta(report)
        return report

    existing_meta = _load_control_plane_meta()
    existing_status = str(existing_meta.get("migration_status") or "").strip()
    if existing_status in {"completed", "completed_with_errors"} and not force:
        return existing_meta

    snapshot_store = _FilesystemControlPlaneStore(requested_backend="filesystem")
    source_collection_counts: dict[str, int] = {}
    imported_collections: list[str] = []
    skipped_collections: list[str] = []
    errors: list[dict[str, str]] = []

    snapshot_names = [name for name in snapshot_store.list_collection_names() if _visible_collection_name(name)]
    for name in snapshot_names:
        try:
            rows = snapshot_store.read_snapshot(name, list)
        except ControlPlaneCollectionCorruptionError as exc:
            errors.append(exc.as_dict())
            continue
        source_collection_counts[name] = len(rows)
        existing_rows = _STORE.load_rows(name, list)
        if existing_rows and not force:
            skipped_collections.append(name)
            continue
        _STORE.save_rows(name, rows)
        imported_collections.append(name)

    finished_at = _now_iso()
    migration_status = "completed_with_errors" if errors else "completed"
    report = {
        "migration_status": migration_status,
        "source_backend": "filesystem",
        "target_backend": "postgres",
        "requested_backend": requested_backend,
        "started_at": started_at,
        "last_migration_at": finished_at,
        "actor": str(actor or "system"),
        "force": bool(force),
        "errors": errors,
        "imported_collections": imported_collections,
        "skipped_collections": skipped_collections,
        "source_collection_counts": source_collection_counts,
    }
    _save_control_plane_meta(report)
    return report


def _normalize_connector_secret_requirements(items: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    normalized: list[dict[str, Any]] = []
    for item in items or []:
        if not isinstance(item, dict):
            continue
        env = str(item.get("env") or "").strip()
        if not env:
            continue
        normalized.append(
            {
                "env": env,
                "label": str(item.get("label") or env).strip(),
                "required": bool(item.get("required", True)),
                "secret_ref_env": str(item.get("secret_ref_env") or f"{env}_REF").strip(),
            }
        )
    return normalized


def _extract_env_reference_name(value: str) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    if text.startswith("${") and text.endswith("}"):
        return text[2:-1].strip()
    if text.startswith("env://"):
        return text[6:].strip()
    if text.startswith("ref://"):
        return text[6:].strip()
    return ""


def _resolve_string_value(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    ref_name = _extract_env_reference_name(value)
    if ref_name:
        return os.getenv(ref_name, "")
    return value


def _resolve_runtime_object(value: Any) -> Any:
    return _shared_resolve_runtime_object(value)


def _resolve_secret_value(env_name: str, *, explicit_value: str = "") -> tuple[str, str]:
    value, source, _ = _shared_resolve_secret_value(env_name, explicit_value=explicit_value)
    return value, source


def _resolve_required_secrets(items: list[dict[str, Any]] | None) -> tuple[dict[str, str], list[dict[str, str]]]:
    resolved: dict[str, str] = {}
    missing: list[dict[str, str]] = []
    for item in items or []:
        env_name = str(item.get("env") or "").strip()
        if not env_name:
            continue
        value, source = _resolve_secret_value(env_name)
        if value:
            resolved[env_name] = value
            continue
        if bool(item.get("required", True)):
            missing.append({"env": env_name, "label": str(item.get("label") or env_name), "source": source or env_name})
    return resolved, missing


def _resolve_config_value(config: dict[str, Any], key: str, default: Any = "") -> Any:
    if key in config and config.get(key) is not None:
        return _resolve_runtime_object(config.get(key))
    env_key = str(config.get(f"{key}_env") or "").strip()
    if env_key:
        return os.getenv(env_key, default)
    return default


def _safe_timeout_seconds(value: Any, default_ms: int = 10000) -> float:
    try:
        raw = int(value if value is not None and value != "" else default_ms)
    except (TypeError, ValueError):
        raw = default_ms
    return max(1, raw) / 1000.0


def _extract_records(payload: Any, path: str = "") -> list[Any]:
    if path:
        current = payload
        for part in [chunk for chunk in str(path).split(".") if chunk]:
            if isinstance(current, dict):
                current = current.get(part)
            else:
                current = None
            if current is None:
                return []
        if isinstance(current, list):
            return current
        return [] if current is None or current == "" else [current]
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        for candidate in ("items", "records", "events", "results", "findings", "data"):
            value = payload.get(candidate)
            if isinstance(value, list):
                return value
        return [payload]
    return [] if payload is None or payload == "" else [payload]


def _sample_records(payload: Any, *, limit: int = 3) -> Any:
    if isinstance(payload, list):
        return _json_clone(payload[:limit])
    if isinstance(payload, dict):
        return _json_clone(payload)
    return payload


def _http_request(
    *,
    url: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: Any = None,
    timeout_seconds: float = 10.0,
    verify_tls: bool = True,
) -> dict[str, Any]:
    request_headers = {str(key): str(value) for key, value in (headers or {}).items()}
    data: bytes | None = None
    if body is not None:
        if isinstance(body, (dict, list)):
            data = json.dumps(body, ensure_ascii=False).encode("utf-8")
            request_headers.setdefault("Content-Type", "application/json")
        else:
            data = str(body).encode("utf-8")
    request = urllib.request.Request(url, data=data, headers=request_headers, method=str(method or "GET").upper())
    context: ssl.SSLContext | None = None
    if url.lower().startswith("https://"):
        context = ssl.create_default_context()
        if not verify_tls:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
    started = time.perf_counter()
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds, context=context) as response:
            raw = response.read()
            latency_ms = round((time.perf_counter() - started) * 1000.0, 1)
            return {
                "http_status": int(getattr(response, "status", response.getcode())),
                "content_type": str(response.headers.get("content-type") or ""),
                "body": raw,
                "latency_ms": latency_ms,
            }
    except urllib.error.HTTPError as exc:
        latency_ms = round((time.perf_counter() - started) * 1000.0, 1)
        return {
            "http_status": int(exc.code),
            "content_type": str(exc.headers.get("content-type") or ""),
            "body": exc.read(),
            "latency_ms": latency_ms,
            "error": str(exc),
        }


def _decode_http_payload(raw: bytes, content_type: str) -> Any:
    if not raw:
        return {}
    text = raw.decode("utf-8", errors="replace")
    if "json" in str(content_type or "").lower():
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return {"raw_text": text}
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {"raw_text": text}


def _coerce_message_text(action: dict[str, Any], payload: dict[str, Any]) -> str:
    direct_message = str(payload.get("message") or "").strip()
    if direct_message:
        return direct_message
    template = str(action.get("message_template") or "").strip()
    if template:
        return template.format_map(defaultdict(str, {str(key): value for key, value in payload.items()}))
    if payload:
        return json.dumps(payload, ensure_ascii=False, indent=2)
    return f"{action.get('title') or action.get('id') or 'Action'} executed"


def _default_connector_definitions() -> list[dict[str, Any]]:
    return build_default_connector_definitions(
        schema_version=CONTROL_PLANE_SCHEMA_VERSION,
        now_iso=_now_iso(),
        normalize_secret_requirements=_normalize_connector_secret_requirements,
    )


def _default_cases() -> list[dict[str, Any]]:
    return []


def _default_entities() -> list[dict[str, Any]]:
    return []


def _default_risk_signals() -> list[dict[str, Any]]:
    return []


def _default_response_actions() -> list[dict[str, Any]]:
    return build_default_response_actions(
        schema_version=CONTROL_PLANE_SCHEMA_VERSION,
        now_iso=_now_iso(),
        normalize_secret_requirements=_normalize_connector_secret_requirements,
    )


def _default_response_executions() -> list[dict[str, Any]]:
    return []


def _default_response_dlq() -> list[dict[str, Any]]:
    return []


def _default_response_idempotency() -> list[dict[str, Any]]:
    return []


def _default_response_ledger() -> list[dict[str, Any]]:
    return []


def _default_service_accounts() -> list[dict[str, Any]]:
    return []


def _default_service_account_tokens() -> list[dict[str, Any]]:
    return []


def _default_local_users() -> list[dict[str, Any]]:
    return []


def _default_content_bundles() -> list[dict[str, Any]]:
    now = _now_iso()
    return [
        {
            "id": "parsers-core-v1",
            "type": "content_bundle",
            "schema_version": CONTROL_PLANE_SCHEMA_VERSION,
            "bundle_type": "parser_pack",
            "version": "1.0.0",
            "title": "Core parser pack",
            "description": "Linux, Windows, VPN, network and vulnerability parser set.",
            "objects": 24,
            "signed": True,
            "status": "active",
            "stage": "active",
            "release_ring": "soc-core",
            "owner": "content-engineering",
            "linked_pack_id": "core-parsers",
            "coverage_domains": ["linux", "windows", "vpn", "network", "vulnerability"],
            "personas": ["content_engineer", "soc_analyst"],
            "quality_gates": {
                "ci_status": "passed",
                "validation_status": "validated",
                "approval_status": "approved",
                "signed": True,
                "test_coverage_pct": 92,
                "regression_status": "passed",
                "qa_status": "ready",
            },
            "integrity": {
                "signed": True,
                "signing_profile": "platform-release",
                "signed_by": "content-release",
                "artifact_uri": "cp://content-bundles/parsers-core-v1/1.0.0",
            },
            "qa_datasets": ["linux-auth-regression", "windows-auth-regression", "vpn-session-regression"],
            "rollback_targets": ["parsers-core-v0", "parsers-core-stable"],
            "updated_ts": now,
        },
        {
            "id": "detections-core-v1",
            "type": "content_bundle",
            "schema_version": CONTROL_PLANE_SCHEMA_VERSION,
            "bundle_type": "detection_pack",
            "version": "1.0.0",
            "title": "Core detection pack",
            "description": "Threshold, match and sequence content seed for the current deployment.",
            "objects": 34,
            "signed": True,
            "status": "active",
            "stage": "active",
            "release_ring": "soc-core",
            "owner": "content-engineering",
            "linked_pack_id": "detections-core",
            "coverage_domains": ["authentication", "endpoint", "network", "system"],
            "personas": ["content_engineer", "soc_analyst"],
            "quality_gates": {
                "ci_status": "passed",
                "validation_status": "validated",
                "approval_status": "approved",
                "signed": True,
                "test_coverage_pct": 89,
                "regression_status": "passed",
                "qa_status": "ready",
            },
            "integrity": {
                "signed": True,
                "signing_profile": "platform-release",
                "signed_by": "content-release",
                "artifact_uri": "cp://content-bundles/detections-core-v1/1.0.0",
            },
            "qa_datasets": ["auth-bruteforce-pack", "linux-root-pack", "windows-sysmon-pack"],
            "rollback_targets": ["detections-core-v0", "detections-core-stable"],
            "updated_ts": now,
        },
        {
            "id": "dashboards-soc-v1",
            "type": "content_bundle",
            "schema_version": CONTROL_PLANE_SCHEMA_VERSION,
            "bundle_type": "dashboard_pack",
            "version": "1.0.0",
            "title": "SOC dashboard pack",
            "description": "Overview, incident, collector and threat-intel dashboard templates.",
            "objects": 7,
            "signed": True,
            "status": "active",
            "stage": "active",
            "release_ring": "soc-core",
            "owner": "ux-admin",
            "linked_pack_id": "dashboard-presets",
            "coverage_domains": ["overview", "incidents", "collectors", "threat_intel"],
            "personas": ["soc_analyst", "admin"],
            "quality_gates": {
                "ci_status": "passed",
                "validation_status": "validated",
                "approval_status": "approved",
                "signed": True,
                "test_coverage_pct": 86,
                "regression_status": "passed",
                "qa_status": "ready",
            },
            "integrity": {
                "signed": True,
                "signing_profile": "platform-release",
                "signed_by": "content-release",
                "artifact_uri": "cp://content-bundles/dashboards-soc-v1/1.0.0",
            },
            "qa_datasets": ["overview-dashboard-smoke", "incident-dashboard-smoke"],
            "rollback_targets": ["dashboards-soc-v0", "dashboards-soc-stable"],
            "updated_ts": now,
        },
        {
            "id": "lookups-geo-ti-v1",
            "type": "content_bundle",
            "schema_version": CONTROL_PLANE_SCHEMA_VERSION,
            "bundle_type": "lookup_pack",
            "version": "1.0.0",
            "title": "Geo and TI lookup pack",
            "description": "GeoIP, ASN, TI and active-list enrichment references.",
            "objects": 9,
            "signed": True,
            "status": "active",
            "stage": "active",
            "release_ring": "soc-core",
            "owner": "threat-intel",
            "linked_pack_id": "geo-ti-lookups",
            "coverage_domains": ["geoip", "asn", "ti", "active_lists"],
            "personas": ["threat_hunter", "soc_analyst"],
            "quality_gates": {
                "ci_status": "passed",
                "validation_status": "validated",
                "approval_status": "approved",
                "signed": True,
                "test_coverage_pct": 90,
                "regression_status": "passed",
                "qa_status": "ready",
            },
            "integrity": {
                "signed": True,
                "signing_profile": "platform-release",
                "signed_by": "content-release",
                "artifact_uri": "cp://content-bundles/lookups-geo-ti-v1/1.0.0",
            },
            "qa_datasets": ["geo-enrichment-regression", "ti-match-regression"],
            "rollback_targets": ["lookups-geo-ti-v0", "lookups-geo-ti-stable"],
            "updated_ts": now,
        },
        {
            "id": "integrations-foundation-v1",
            "type": "content_bundle",
            "schema_version": CONTROL_PLANE_SCHEMA_VERSION,
            "bundle_type": "integration_pack",
            "version": "1.0.0",
            "title": "Integration foundation pack",
            "description": "Connector and response templates for webhook, REST, SQL, vuln and outbound hooks.",
            "objects": 9,
            "signed": True,
            "status": "active",
            "stage": "active",
            "release_ring": "soc-core",
            "owner": "integration-engineering",
            "linked_pack_id": "integration-foundation",
            "coverage_domains": ["connectors", "response", "outbound_hooks"],
            "personas": ["integration_engineer", "admin"],
            "quality_gates": {
                "ci_status": "passed",
                "validation_status": "validated",
                "approval_status": "approved",
                "signed": True,
                "test_coverage_pct": 87,
                "regression_status": "passed",
                "qa_status": "ready",
            },
            "integrity": {
                "signed": True,
                "signing_profile": "platform-release",
                "signed_by": "content-release",
                "artifact_uri": "cp://content-bundles/integrations-foundation-v1/1.0.0",
            },
            "qa_datasets": ["connector-contract-regression", "response-governance-regression"],
            "rollback_targets": ["integrations-foundation-v0", "integrations-foundation-stable"],
            "updated_ts": now,
        },
        {
            "id": "host-runtime-observability-v1",
            "type": "content_bundle",
            "schema_version": CONTROL_PLANE_SCHEMA_VERSION,
            "bundle_type": "detection_pack",
            "version": "1.0.0",
            "title": "Host runtime observability pack",
            "description": "Planned CPU, memory, disk, load, swap, inode, and stale-telemetry correlation content for the host-health wave.",
            "objects": 10,
            "signed": False,
            "status": "planned",
            "stage": "draft",
            "release_ring": "observability-wave",
            "owner": "platform-engineering",
            "linked_pack_id": "host-runtime-health",
            "coverage_domains": ["host_runtime", "capacity", "collector_freshness"],
            "personas": ["soc_analyst", "platform_engineer"],
            "quality_gates": {"ci_status": "planned", "validation_status": "pending", "approval_status": "pending", "signed": False, "test_coverage_pct": 0},
            "updated_ts": now,
        },
    ]


def _default_saved_searches() -> list[dict[str, Any]]:
    now = _now_iso()
    return [
        {
            "id": "hot-auth-failures",
            "type": "saved_search",
            "schema_version": CONTROL_PLANE_SCHEMA_VERSION,
            "title": "Hot auth failures",
            "description": "Quick hunt across hot storage for auth bursts and brute-force style behavior.",
            "storage": "hot",
            "window": "24h",
            "query": "category = 'authentication' AND severity IN ('high','critical')",
            "schedule": "",
            "tags": ["hot", "authentication", "triage"],
            "owner": "soc-ops",
            "persona": "analyst",
            "lifecycle_stage": "published",
            "bundle_ids": ["detections-core-v1"],
            "updated_ts": now,
        },
        {
            "id": "cold-vuln-follow-up",
            "type": "saved_search",
            "schema_version": CONTROL_PLANE_SCHEMA_VERSION,
            "title": "Cold vuln follow-up",
            "description": "Cold-search lookup for systems that reappear in vulnerability reports.",
            "storage": "all",
            "window": "30d",
            "query": "message ILIKE '%CVE-%' OR category = 'vulnerability'",
            "schedule": "0 3 * * *",
            "tags": ["cold", "vulnerability", "hunting"],
            "owner": "exposure-management",
            "persona": "threat_hunter",
            "lifecycle_stage": "published",
            "bundle_ids": ["integrations-foundation-v1"],
            "updated_ts": now,
        },
        {
            "id": "host-runtime-pressure",
            "type": "saved_search",
            "schema_version": CONTROL_PLANE_SCHEMA_VERSION,
            "title": "Host runtime pressure",
            "description": "Forward-ready hunt for CPU, memory, disk, swap, load, and inode pressure once host telemetry events are published.",
            "storage": "hot",
            "window": "24h",
            "query": "subcategory IN ('host_cpu_pressure','host_memory_pressure','host_disk_pressure','host_load_pressure','host_swap_pressure','host_inode_pressure')",
            "schedule": "",
            "tags": ["host-health", "capacity", "triage"],
            "owner": "platform-engineering",
            "persona": "analyst",
            "lifecycle_stage": "draft",
            "bundle_ids": ["host-runtime-observability-v1"],
            "updated_ts": now,
        },
        {
            "id": "host-telemetry-gaps",
            "type": "saved_search",
            "schema_version": CONTROL_PLANE_SCHEMA_VERSION,
            "title": "Host telemetry gaps",
            "description": "Forward-ready hunt for missing host metrics and stale runtime heartbeat events.",
            "storage": "hot",
            "window": "24h",
            "query": "subcategory IN ('host_telemetry_missing','collector_heartbeat_missing')",
            "schedule": "",
            "tags": ["host-health", "freshness", "triage"],
            "owner": "platform-engineering",
            "persona": "admin",
            "lifecycle_stage": "draft",
            "bundle_ids": ["host-runtime-observability-v1"],
            "updated_ts": now,
        },
    ]


def _merge_seed_rows(rows: list[dict[str, Any]], seed_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    current_by_id = {str(item.get("id") or ""): item for item in rows}
    merged: list[dict[str, Any]] = []
    seed_ids: set[str] = set()
    for seed in seed_rows:
        seed_id = str(seed.get("id") or "")
        if not seed_id:
            continue
        seed_ids.add(seed_id)
        merged.append(_json_clone(current_by_id.get(seed_id, seed)))
    for row in rows:
        row_id = str(row.get("id") or "")
        if row_id and row_id in seed_ids:
            continue
        merged.append(_json_clone(row))
    return merged


def _default_connector_runs() -> list[dict[str, Any]]:
    return []


def _default_audit_events() -> list[dict[str, Any]]:
    return []


def _collection(name: str, default_factory) -> list[dict[str, Any]]:
    return _load_rows(name, default_factory)


def _save_collection(name: str, rows: list[dict[str, Any]]) -> None:
    _save_rows(name, rows)


def _find_by_id(rows: list[dict[str, Any]], item_id: str) -> dict[str, Any] | None:
    safe_id = str(item_id or "").strip()
    return next((item for item in rows if str(item.get("id") or "") == safe_id), None)


def _audit_event_hash_payload(event: dict[str, Any]) -> str:
    payload = {
        "id": event.get("id"),
        "seq": event.get("seq"),
        "ts": event.get("ts"),
        "actor": event.get("actor"),
        "action": event.get("action"),
        "object_type": event.get("object_type"),
        "object_id": event.get("object_id"),
        "summary": event.get("summary"),
        "details": event.get("details"),
        "prev_hash": event.get("prev_hash"),
    }
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def append_audit_event(
    *,
    actor: str,
    action: str,
    object_type: str,
    object_id: str,
    summary: str,
    details: dict[str, Any] | None = None,
) -> dict[str, Any]:
    rows = _collection("audit_events", _default_audit_events)
    previous = rows[-1] if rows else None
    event = {
        "id": _new_id("audit"),
        "type": "audit_event",
        "schema_version": CONTROL_PLANE_SCHEMA_VERSION,
        "seq": int(previous.get("seq") or 0) + 1 if previous else 1,
        "ts": _now_iso(),
        "actor": str(actor or "system"),
        "action": str(action or "updated"),
        "object_type": str(object_type or "object"),
        "object_id": str(object_id or ""),
        "summary": str(summary or ""),
        "details": _json_clone(details or {}),
        "prev_hash": str(previous.get("hash") or "") if previous else "",
    }
    event["hash"] = hashlib.sha256(_audit_event_hash_payload(event).encode("utf-8")).hexdigest()
    rows.append(event)
    rows = rows[-5000:]
    _save_collection("audit_events", rows)
    return _json_clone(event)


def verify_audit_chain() -> dict[str, Any]:
    rows = _collection("audit_events", _default_audit_events)
    previous_hash = ""
    for index, item in enumerate(rows, start=1):
        expected_hash = hashlib.sha256(_audit_event_hash_payload(item).encode("utf-8")).hexdigest()
        if str(item.get("prev_hash") or "") != previous_hash:
            return {
                "valid": False,
                "index": index,
                "event_id": str(item.get("id") or ""),
                "reason": "prev_hash_mismatch",
            }
        if str(item.get("hash") or "") != expected_hash:
            return {
                "valid": False,
                "index": index,
                "event_id": str(item.get("id") or ""),
                "reason": "hash_mismatch",
            }
        previous_hash = expected_hash
    return {"valid": True, "count": len(rows), "last_hash": previous_hash}


def list_audit_events(*, object_type: str = "", actor: str = "", limit: int = 200) -> dict[str, Any]:
    rows = _collection("audit_events", _default_audit_events)
    safe_object_type = str(object_type or "").strip().lower()
    safe_actor = str(actor or "").strip().lower()
    filtered = rows
    if safe_object_type:
        filtered = [item for item in filtered if str(item.get("object_type") or "").lower() == safe_object_type]
    if safe_actor:
        filtered = [item for item in filtered if str(item.get("actor") or "").lower() == safe_actor]
    filtered = list(reversed(filtered[-max(1, min(500, limit)) :]))
    return {"items": _json_clone(filtered), "chain": verify_audit_chain()}


























def _risk_level(score: float) -> str:
    if score >= 90:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    if score > 0:
        return "low"
    return "none"


def _normalize_case_status(value: str) -> str:
    safe = _safe_slug(value or "new", default="new").replace("-", "_")
    if safe in {"new", "open", "triaged", "assigned", "in_progress", "closed", "false_positive", "reopened"}:
        return safe
    return "new"


def _normalize_severity(value: str) -> str:
    safe = str(value or "medium").strip().lower()
    if safe in {"critical", "high", "medium", "low", "info"}:
        return safe
    return "medium"


def _normalize_priority(value: str | int | None) -> int:
    try:
        priority = int(value if value is not None else 3)
    except (TypeError, ValueError):
        priority = 3
    return max(0, min(4, priority))












CONNECTOR_SUCCESS_STATUSES = {"success", "dry_run", "accepted", "executed"}


def _resolve_connector_runtime(connector: dict[str, Any]) -> dict[str, Any]:
    return dict(_resolve_runtime_object(connector.get("runtime") or {}))


def _execute_rest_connector(connector: dict[str, Any], payload: dict[str, Any], *, dry_run: bool) -> dict[str, Any]:
    runtime = _resolve_connector_runtime(connector)
    request_cfg = dict(runtime.get("request") or {})
    response_cfg = dict(runtime.get("response") or {})
    url = str(_resolve_config_value(request_cfg, "url", "") or "").strip()
    if not url:
        raise ValueError("REST connector requires runtime.request.url or runtime.request.url_env")
    method = str(_resolve_config_value(request_cfg, "method", "GET") or "GET").upper()
    headers = {str(key): str(value) for key, value in dict(_resolve_config_value(request_cfg, "headers", {}) or {}).items()}
    auth_cfg = dict(request_cfg.get("auth") or {})
    if str(auth_cfg.get("type") or "").lower() == "bearer":
        token_env = str(auth_cfg.get("token_env") or "").strip()
        token, _ = _resolve_secret_value(token_env or "SIEM_VENDOR_API_TOKEN")
        if token:
            headers.setdefault("Authorization", f"Bearer {token}")
    query_params = dict(_resolve_config_value(request_cfg, "params", {}) or {})
    if query_params:
        parsed = urllib.parse.urlparse(url)
        merged = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
        merged.update({str(key): str(value) for key, value in query_params.items()})
        url = urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(merged)))
    body = _resolve_config_value(request_cfg, "body", payload.get("body"))
    timeout_seconds = _safe_timeout_seconds(_resolve_config_value(request_cfg, "timeout_ms", 10000))
    verify_tls = bool(request_cfg.get("verify_tls", True))
    if dry_run:
        return {
            "status": "dry_run",
            "message": f"Validated REST connector target {url}",
            "stats": {"executor": "rest_pull", "method": method, "url": url, "accepted_events": 0},
            "payload_sample": None,
        }
    response = _http_request(url=url, method=method, headers=headers, body=body, timeout_seconds=timeout_seconds, verify_tls=verify_tls)
    decoded = _decode_http_payload(response.get("body", b""), str(response.get("content_type") or ""))
    records = _extract_records(decoded, str(response_cfg.get("records_path") or ""))
    status = "success" if 200 <= int(response.get("http_status") or 0) < 300 else "error"
    return {
        "status": status,
        "message": f"Fetched {len(records)} record(s) from {url}",
        "stats": {
            "executor": "rest_pull",
            "method": method,
            "url": url,
            "http_status": int(response.get("http_status") or 0),
            "latency_ms": float(response.get("latency_ms") or 0),
            "accepted_events": len(records),
            "bytes_received": len(response.get("body") or b""),
        },
        "payload_sample": _sample_records(records or decoded),
        "result": {"response": _sample_records(decoded), "records_path": str(response_cfg.get("records_path") or "")},
    }


def _execute_sql_connector(connector: dict[str, Any], payload: dict[str, Any], *, dry_run: bool) -> dict[str, Any]:
    runtime = _resolve_connector_runtime(connector)
    connection_cfg = dict(runtime.get("connection") or {})
    driver = str(connection_cfg.get("driver") or "").strip().lower()
    dsn = str(_resolve_config_value(connection_cfg, "dsn", "") or "").strip()
    db_path = str(_resolve_config_value(connection_cfg, "path", "") or "").strip()
    if dsn.startswith("sqlite:///") and not db_path:
        db_path = dsn[len("sqlite:///") :]
    if not driver and (dsn.startswith("sqlite:///") or db_path):
        driver = "sqlite"
    if driver not in {"sqlite", "sqlite3"}:
        raise ValueError("SQL connector currently supports only sqlite runtime.connection.driver=sqlite")
    query = str(runtime.get("query") or payload.get("query") or "").strip()
    if not query:
        raise ValueError("SQL connector requires runtime.query")
    if not db_path:
        raise ValueError("SQL connector requires runtime.connection.path or sqlite:/// DSN")
    if dry_run:
        return {
            "status": "dry_run",
            "message": f"Validated sqlite query against {db_path}",
            "stats": {"executor": "sql_source", "driver": driver, "db_path": db_path, "accepted_events": 0},
            "payload_sample": None,
        }
    started = time.perf_counter()
    conn = sqlite3.connect(db_path)
    try:
        cursor = conn.execute(query)
        columns = [str(item[0]) for item in (cursor.description or [])]
        rows = [dict(zip(columns, row)) for row in cursor.fetchall()]
    finally:
        conn.close()
    latency_ms = round((time.perf_counter() - started) * 1000.0, 1)
    return {
        "status": "success",
        "message": f"Fetched {len(rows)} row(s) from sqlite source",
        "stats": {"executor": "sql_source", "driver": driver, "db_path": db_path, "latency_ms": latency_ms, "accepted_events": len(rows)},
        "payload_sample": _sample_records(rows),
        "result": {"columns": columns, "row_count": len(rows)},
    }


def _execute_webhook_source(connector: dict[str, Any], payload: dict[str, Any], *, dry_run: bool) -> dict[str, Any]:
    events = payload.get("events")
    if events is None:
        events = payload.get("payload_sample")
    if events is None:
        events = payload.get("body")
    if events is None:
        events = payload
    records = events if isinstance(events, list) else [events] if events else []
    return {
        "status": "dry_run" if dry_run else "accepted",
        "message": f"Validated webhook source {connector.get('id')}",
        "stats": {"executor": "webhook_source", "accepted_events": len(records)},
        "payload_sample": _sample_records(records),
    }


def _execute_connector_runtime(connector: dict[str, Any], payload: dict[str, Any], *, dry_run: bool) -> dict[str, Any]:
    block_type = str(connector.get("block_type") or "").strip().lower()
    if block_type in {"rest_pull"}:
        return _execute_rest_connector(connector, payload, dry_run=dry_run)
    if block_type in {"sql_source"}:
        return _execute_sql_connector(connector, payload, dry_run=dry_run)
    if block_type in {"webhook_source", "custom_connector"} or str(connector.get("mode") or "").lower() == "push":
        return _execute_webhook_source(connector, payload, dry_run=dry_run)
    raise ValueError(f"Connector executor is not implemented for block_type={block_type or 'unknown'}")












































RESPONSE_SUCCESS_STATUSES = {"dry_run", "accepted", "approved", "executed"}


def _save_response_action_rows(rows: list[dict[str, Any]], updated: dict[str, Any]) -> None:
    _save_collection("response_actions", [updated if str(item.get("id") or "") == str(updated.get("id") or "") else item for item in rows])


def _save_response_execution_rows(rows: list[dict[str, Any]], updated: dict[str, Any]) -> None:
    _save_collection("response_executions", [updated if str(item.get("id") or "") == str(updated.get("id") or "") else item for item in rows])


def _update_action_health(action: dict[str, Any], *, status: str, details: dict[str, Any] | None = None, increment_total: bool = True) -> dict[str, Any]:
    health = dict(action.get("health") or {})
    health["last_execution_ts"] = _now_iso()
    health["last_status"] = str(status or "unknown")
    if increment_total:
        health["total_executions"] = int(health.get("total_executions") or 0) + 1
    if details and details.get("latency_ms") is not None:
        health["last_latency_ms"] = float(details.get("latency_ms") or 0)
    if details and details.get("error"):
        health["last_error"] = str(details.get("error"))
    elif status in RESPONSE_SUCCESS_STATUSES:
        health.pop("last_error", None)
    action["health"] = health
    action["updated_ts"] = _now_iso()
    return action


def _clean_runtime_payload(payload: dict[str, Any]) -> dict[str, Any]:
    return {str(key): value for key, value in payload.items() if not str(key).startswith("_")}


def _execute_webhook_action(action: dict[str, Any], payload: dict[str, Any], *, dry_run: bool) -> dict[str, Any]:
    target = dict(_resolve_runtime_object(action.get("target") or {}))
    url = str(_resolve_config_value(target, "url", "") or "").strip()
    if not url:
        raise ValueError("Webhook action requires target.url or target.url_env")
    method = str(_resolve_config_value(target, "method", "POST") or "POST").upper()
    headers = {str(key): str(value) for key, value in dict(_resolve_config_value(target, "headers", {}) or {}).items()}
    message = _coerce_message_text(action, _clean_runtime_payload(payload))
    secret_value = str(payload.get("_resolved_secrets", {}).get("SIEM_WEBHOOK_SHARED_SECRET") or _resolve_secret_value("SIEM_WEBHOOK_SHARED_SECRET")[0] or "").strip()
    if secret_value:
        headers.setdefault("x-rdegon-webhook-secret", secret_value)
    body = payload.get("body")
    if body is None:
        body = {
            "action_id": action.get("id"),
            "title": action.get("title"),
            "kind": action.get("kind"),
            "message": message,
            "payload": _clean_runtime_payload(payload),
        }
    if dry_run:
        return {
            "status": "dry_run",
            "message": f"Validated webhook target {url}",
            "details": {"executor": "webhook", "url": url, "method": method},
        }
    response = _http_request(
        url=url,
        method=method,
        headers=headers,
        body=body,
        timeout_seconds=_safe_timeout_seconds(_resolve_config_value(target, "timeout_ms", 10000)),
        verify_tls=bool(target.get("verify_tls", True)),
    )
    http_status = int(response.get("http_status") or 0)
    status = "executed" if 200 <= http_status < 300 else "error"
    return {
        "status": status,
        "message": f"Webhook action delivered to {url}",
        "details": {
            "executor": "webhook",
            "url": url,
            "method": method,
            "http_status": http_status,
            "latency_ms": float(response.get("latency_ms") or 0),
            "response": _sample_records(_decode_http_payload(response.get("body", b""), str(response.get("content_type") or ""))),
            "error": str(response.get("error") or ""),
        },
    }


def _execute_telegram_action(action: dict[str, Any], payload: dict[str, Any], *, dry_run: bool) -> dict[str, Any]:
    target = dict(_resolve_runtime_object(action.get("target") or {}))
    api_base_url = str(_resolve_config_value(target, "api_base_url", "https://api.telegram.org") or "https://api.telegram.org").rstrip("/")
    bot_token = str(payload.get("_resolved_secrets", {}).get("SIEM_TELEGRAM_BOT_TOKEN") or _resolve_secret_value("SIEM_TELEGRAM_BOT_TOKEN")[0] or _resolve_config_value(target, "token", "") or "").strip()
    chat_id = str(_resolve_config_value(target, "chat_id", "") or "").strip()
    if not bot_token:
        raise ValueError("Telegram action requires a bot token")
    if not chat_id:
        raise ValueError("Telegram action requires target.chat_id or target.chat_id_env")
    message = _coerce_message_text(action, _clean_runtime_payload(payload))
    if dry_run:
        return {
            "status": "dry_run",
            "message": f"Validated Telegram action for chat {chat_id}",
            "details": {"executor": "telegram", "chat_id": chat_id},
        }
    response = _http_request(
        url=f"{api_base_url}/bot{bot_token}/sendMessage",
        method="POST",
        headers={"Accept": "application/json"},
        body={"chat_id": chat_id, "text": message},
        timeout_seconds=_safe_timeout_seconds(_resolve_config_value(target, "timeout_ms", 10000)),
        verify_tls=bool(target.get("verify_tls", True)),
    )
    http_status = int(response.get("http_status") or 0)
    status = "executed" if 200 <= http_status < 300 else "error"
    return {
        "status": status,
        "message": f"Telegram message sent to chat {chat_id}",
        "details": {
            "executor": "telegram",
            "chat_id": chat_id,
            "http_status": http_status,
            "latency_ms": float(response.get("latency_ms") or 0),
            "response": _sample_records(_decode_http_payload(response.get("body", b""), str(response.get("content_type") or ""))),
            "error": str(response.get("error") or ""),
        },
    }


def _execute_email_action(action: dict[str, Any], payload: dict[str, Any], *, dry_run: bool) -> dict[str, Any]:
    target = dict(_resolve_runtime_object(action.get("target") or {}))
    host = str(_resolve_config_value(target, "smtp_host", "") or "").strip()
    if not host:
        raise ValueError("Email action requires target.smtp_host")
    sender = str(_resolve_config_value(target, "from", "") or "").strip()
    recipients_value = _resolve_config_value(target, "recipients", target.get("to") or [])
    if isinstance(recipients_value, str):
        recipients = [item.strip() for item in recipients_value.split(",") if item.strip()]
    else:
        recipients = [str(item).strip() for item in (recipients_value or []) if str(item).strip()]
    if not sender or not recipients:
        raise ValueError("Email action requires sender and recipients")
    subject = str(payload.get("subject") or action.get("title") or "Rdegon SIEM notification")
    message_text = _coerce_message_text(action, _clean_runtime_payload(payload))
    if dry_run:
        return {
            "status": "dry_run",
            "message": f"Validated email action for {len(recipients)} recipient(s)",
            "details": {"executor": "email", "smtp_host": host, "recipients": recipients},
        }
    started = time.perf_counter()
    email_message = EmailMessage()
    email_message["Subject"] = subject
    email_message["From"] = sender
    email_message["To"] = ", ".join(recipients)
    email_message.set_content(message_text)
    port = int(_resolve_config_value(target, "smtp_port", 587) or 587)
    username = str(_resolve_config_value(target, "smtp_user", "") or "").strip()
    password = str(_resolve_config_value(target, "smtp_password", "") or _resolve_secret_value("SIEM_SMTP_PASSWORD")[0] or "").strip()
    use_ssl = bool(target.get("use_ssl", False))
    use_tls = bool(target.get("use_tls", not use_ssl))
    if use_ssl:
        with smtplib.SMTP_SSL(host, port, timeout=_safe_timeout_seconds(_resolve_config_value(target, "timeout_ms", 10000))) as server:
            if username and password:
                server.login(username, password)
            server.send_message(email_message)
    else:
        with smtplib.SMTP(host, port, timeout=_safe_timeout_seconds(_resolve_config_value(target, "timeout_ms", 10000))) as server:
            if use_tls:
                server.starttls()
            if username and password:
                server.login(username, password)
            server.send_message(email_message)
    latency_ms = round((time.perf_counter() - started) * 1000.0, 1)
    return {
        "status": "executed",
        "message": f"Email sent to {len(recipients)} recipient(s)",
        "details": {"executor": "email", "smtp_host": host, "recipients": recipients, "latency_ms": latency_ms},
    }


def _run_response_executor(action: dict[str, Any], payload: dict[str, Any], *, dry_run: bool) -> dict[str, Any]:
    kind = str(action.get("kind") or "webhook").strip().lower()
    if kind == "webhook":
        return _execute_webhook_action(action, payload, dry_run=dry_run)
    if kind == "telegram":
        return _execute_telegram_action(action, payload, dry_run=dry_run)
    if kind == "email":
        return _execute_email_action(action, payload, dry_run=dry_run)
    if kind == "approval_gate":
        return {
            "status": "dry_run" if dry_run else "approved",
            "message": "Approval gate satisfied",
            "details": {"executor": "approval_gate"},
        }
    raise ValueError(f"Response executor is not implemented for kind={kind}")














SECRET_SPECS: list[dict[str, Any]] = [
    {"id": "clickhouse-password", "group": "platform", "label": "ClickHouse password", "env": "SIEM_CH_PASSWORD", "required": True},
    {"id": "kafka-password", "group": "platform", "label": "Kafka password", "env": "SIEM_KAFKA_PASSWORD", "required": False},
    {"id": "postgres-password", "group": "platform", "label": "Postgres password", "env": "SIEM_PG_PASSWORD", "required": False},
    {"id": "mongo-uri", "group": "platform", "label": "Mongo URI", "env": "SIEM_MONGO_URI", "required": False},
    {"id": "jwt-signing", "group": "platform", "label": "JWT signing secret", "env": "SIEM_JWT_SECRET", "required": True},
    {"id": "sso-client-secret", "group": "platform", "label": "SSO client secret", "env": "SIEM_SSO_CLIENT_SECRET", "required": False},
    {"id": "tls-key", "group": "platform", "label": "TLS private key path", "env": "SIEM_TLS_KEY_PATH", "required": False},
    {"id": "smtp-password", "group": "platform", "label": "SMTP password", "env": "SIEM_SMTP_PASSWORD", "required": False},
    {"id": "greenbone-password", "group": "integration", "label": "Greenbone password", "env": "SIEM_GREENBONE_PASSWORD", "required": False},
    {"id": "ti-feed-key", "group": "integration", "label": "TI feed API key", "env": "SIEM_TI_FEED_API_KEY", "required": False},
    {"id": "geoip-license", "group": "integration", "label": "GeoIP / offline feed license", "env": "SIEM_GEOIP_LICENSE_KEY", "required": False},
    {"id": "telegram-token", "group": "integration", "label": "Telegram bot token", "env": "SIEM_TELEGRAM_BOT_TOKEN", "required": False},
    {"id": "webhook-secret", "group": "integration", "label": "Webhook shared secret", "env": "SIEM_WEBHOOK_SHARED_SECRET", "required": False},
    {"id": "db-poll-password", "group": "integration", "label": "DB polling password", "env": "SIEM_DB_POLL_PASSWORD", "required": False},
    {"id": "vendor-token", "group": "integration", "label": "Vendor API token", "env": "SIEM_VENDOR_API_TOKEN", "required": False},
    {"id": "windows-bootstrap", "group": "integration", "label": "Windows bootstrap credential", "env": "SIEM_WINDOWS_BOOTSTRAP_TOKEN", "required": False},
]


def _secret_status_for_env(env_name: str) -> tuple[str, str]:
    payload = _describe_secret_env(env_name)
    return str(payload.get("status") or "missing"), str(payload.get("source") or env_name)


def get_secret_inventory() -> dict[str, Any]:
    try:
        from .control_plane_health import get_secret_inventory as get_secret_inventory_impl
    except ImportError:  # pragma: no cover - local test fallback
        from control_plane_health import get_secret_inventory as get_secret_inventory_impl  # type: ignore[no-redef]

    return get_secret_inventory_impl()


def build_health_overview(
    *,
    platform_status: dict[str, Any],
    source_inventory: list[dict[str, Any]],
    collector_inventory: list[dict[str, Any]],
    ingest_runtime: dict[str, Any] | None = None,
) -> dict[str, Any]:
    try:
        from .control_plane_health import build_health_overview as build_health_overview_impl
    except ImportError:  # pragma: no cover - local test fallback
        from control_plane_health import build_health_overview as build_health_overview_impl  # type: ignore[no-redef]

    return build_health_overview_impl(
        platform_status=platform_status,
        source_inventory=source_inventory,
        collector_inventory=collector_inventory,
        ingest_runtime=ingest_runtime,
    )


try:
    from .control_plane_access_ops import (  # type: ignore[attr-defined]
        authenticate_service_account_token,
        delete_service_account,
        delete_local_user,
        get_auth_overview,
        get_local_user,
        get_permission_inventory,
        get_service_account,
        issue_service_account_token,
        list_local_users,
        list_service_account_tokens,
        list_service_accounts,
        load_local_user_auth_records,
        revoke_service_account_token,
        save_local_user,
        save_service_account,
        set_local_user_password,
    )
except ImportError:  # pragma: no cover - local test fallback
    from control_plane_access_ops import (  # type: ignore[no-redef]
        authenticate_service_account_token,
        delete_service_account,
        delete_local_user,
        get_auth_overview,
        get_local_user,
        get_permission_inventory,
        get_service_account,
        issue_service_account_token,
        list_local_users,
        list_service_account_tokens,
        list_service_accounts,
        load_local_user_auth_records,
        revoke_service_account_token,
        save_local_user,
        save_service_account,
        set_local_user_password,
    )

try:
    from .control_plane_connector_ops import (  # type: ignore[attr-defined]
        delete_connector_definition,
        get_connector_definition,
        get_connectors_overview,
        list_connector_definitions,
        list_connector_runs,
        list_integration_templates,
        record_connector_run,
        run_connector_definition,
        save_connector_definition,
    )
except ImportError:  # pragma: no cover - local test fallback
    from control_plane_connector_ops import (  # type: ignore[no-redef]
        delete_connector_definition,
        get_connector_definition,
        get_connectors_overview,
        list_connector_definitions,
        list_connector_runs,
        list_integration_templates,
        record_connector_run,
        run_connector_definition,
        save_connector_definition,
    )

try:
    from .control_plane_case_ops import (  # type: ignore[attr-defined]
        append_case_comment,
        append_case_task,
        attach_case_evidence,
        get_case,
        get_entities_overview,
        get_entity,
        list_cases,
        list_entities,
        list_risk_signals,
        promote_entity_to_case,
        record_risk_signal,
        save_case,
        save_entity,
    )
except ImportError:  # pragma: no cover - local test fallback
    from control_plane_case_ops import (  # type: ignore[no-redef]
        append_case_comment,
        append_case_task,
        attach_case_evidence,
        get_case,
        get_entities_overview,
        get_entity,
        list_cases,
        list_entities,
        list_risk_signals,
        promote_entity_to_case,
        record_risk_signal,
        save_case,
        save_entity,
    )

def _response_ops_module():
    try:
        from . import control_plane_response_ops as module
    except ImportError:  # pragma: no cover - local test fallback
        import control_plane_response_ops as module  # type: ignore[no-redef]
    return module


def approve_response_execution(*args: Any, **kwargs: Any) -> Any:
    return _response_ops_module().approve_response_execution(*args, **kwargs)


def execute_response_action(*args: Any, **kwargs: Any) -> Any:
    return _response_ops_module().execute_response_action(*args, **kwargs)


def delete_response_action(*args: Any, **kwargs: Any) -> Any:
    return _response_ops_module().delete_response_action(*args, **kwargs)


def get_response_overview(*args: Any, **kwargs: Any) -> Any:
    return _response_ops_module().get_response_overview(*args, **kwargs)


def list_response_actions(*args: Any, **kwargs: Any) -> Any:
    return _response_ops_module().list_response_actions(*args, **kwargs)


def list_response_dlq(*args: Any, **kwargs: Any) -> Any:
    return _response_ops_module().list_response_dlq(*args, **kwargs)


def list_response_executions(*args: Any, **kwargs: Any) -> Any:
    return _response_ops_module().list_response_executions(*args, **kwargs)


def replay_response_dlq(*args: Any, **kwargs: Any) -> Any:
    return _response_ops_module().replay_response_dlq(*args, **kwargs)


def retry_response_execution(*args: Any, **kwargs: Any) -> Any:
    return _response_ops_module().retry_response_execution(*args, **kwargs)


def save_response_action(*args: Any, **kwargs: Any) -> Any:
    return _response_ops_module().save_response_action(*args, **kwargs)

try:
    from .control_plane_content_ops import (  # type: ignore[attr-defined]
        list_content_bundles,
        list_saved_searches,
        save_saved_search,
    )
except ImportError:  # pragma: no cover - local test fallback
    from control_plane_content_ops import (  # type: ignore[no-redef]
        list_content_bundles,
        list_saved_searches,
        save_saved_search,
    )
