from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any
from datetime import datetime, timezone

try:
    from .config import CONFIG
except ImportError:  # pragma: no cover - local test/runtime fallback
    from config import CONFIG  # type: ignore[no-redef]

try:
    from pymongo import MongoClient
    from pymongo.errors import PyMongoError
except Exception:  # noqa: BLE001
    MongoClient = None
    PyMongoError = Exception

logger = logging.getLogger("siem_web.content_store")


class ContentStore:
    def __init__(self) -> None:
        self._requested_backend = str(CONFIG.content_store_backend or "auto").strip().lower() or "auto"
        self._backend = "filesystem"
        self._client = None
        self._db = None
        self._fallback_reason = ""
        self._init_backend()

    def _init_backend(self) -> None:
        desired = self._requested_backend
        if desired == "filesystem":
            self._backend = "filesystem"
            return
        if MongoClient is None:
            self._backend = "filesystem"
            self._fallback_reason = "pymongo_unavailable"
            return
        try:
            client = MongoClient(
                CONFIG.mongo_uri,
                serverSelectionTimeoutMS=1500,
                connectTimeoutMS=1500,
                socketTimeoutMS=1500,
            )
            client.admin.command("ping")
            self._client = client
            self._db = client[CONFIG.mongo_db]
            self._backend = "mongo"
        except Exception as exc:  # noqa: BLE001
            self._fallback_reason = f"{type(exc).__name__}:{exc}"
            if desired == "mongo":
                logger.warning("MongoDB content store unavailable, falling back to filesystem: %s", exc)
            self._backend = "filesystem"

    @property
    def backend(self) -> str:
        return self._backend

    @property
    def requested_backend(self) -> str:
        return self._requested_backend

    @property
    def fallback_reason(self) -> str:
        return self._fallback_reason

    def _storage_status_key(self) -> str:
        return "__storage_status__"

    def _meta_collection(self):
        if self._backend != "mongo" or self._db is None:
            return None
        return self._db["_content_store_meta"]

    def _collection(self, name: str):
        if self._backend != "mongo" or self._db is None:
            return None
        return self._db[name]

    def _collection_initialized(self, collection_name: str) -> bool:
        meta = self._meta_collection()
        if meta is None:
            return False
        try:
            return meta.find_one({"_id": collection_name}, projection={"_id": True}) is not None
        except PyMongoError:
            return False

    def _mark_collection_initialized(self, collection_name: str, *, document_count: int | None = None) -> None:
        meta = self._meta_collection()
        if meta is None:
            return
        payload: dict[str, Any] = {
            "_id": collection_name,
            "updated_ts": datetime.now(tz=timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        }
        if document_count is not None:
            payload["document_count"] = int(document_count)
        try:
            meta.replace_one({"_id": collection_name}, payload, upsert=True)
        except PyMongoError as exc:
            logger.warning("Failed to mark content collection initialized %s: %s", collection_name, exc)
        self._update_storage_status(
            collection_name=collection_name,
            document_count=document_count if document_count is not None else None,
        )

    def _load_storage_status(self) -> dict[str, Any]:
        meta = self._meta_collection()
        if meta is None:
            return {}
        try:
            item = meta.find_one({"_id": self._storage_status_key()}, projection={"_id": False})
            return dict(item) if isinstance(item, dict) else {}
        except PyMongoError as exc:
            logger.warning("Failed to read content-store storage status: %s", exc)
            return {}

    def _update_storage_status(
        self,
        *,
        collection_name: str | None = None,
        document_count: int | None = None,
        migration_status: str | None = None,
        fallback_reason: str | None = None,
        last_migration_at: str | None = None,
    ) -> None:
        meta = self._meta_collection()
        if meta is None:
            return
        payload = self._load_storage_status()
        counts = dict(payload.get("collection_counts") or {})
        if collection_name is not None and document_count is not None:
            counts[str(collection_name)] = int(document_count)
        payload.update(
            {
                "_id": self._storage_status_key(),
                "backend": self._backend,
                "requested_backend": self._requested_backend,
                "updated_ts": datetime.now(tz=timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
                "collection_counts": counts,
            }
        )
        if migration_status is not None:
            payload["migration_status"] = str(migration_status)
        if fallback_reason is not None:
            payload["fallback_reason"] = str(fallback_reason)
        if last_migration_at is not None:
            payload["last_migration_at"] = str(last_migration_at)
        try:
            meta.replace_one({"_id": self._storage_status_key()}, payload, upsert=True)
        except PyMongoError as exc:
            logger.warning("Failed to update content-store storage status: %s", exc)

    def collection_counts(self, collection_names: list[str] | None = None) -> dict[str, int]:
        if self._backend != "mongo" or self._db is None:
            return {}
        names = [str(name).strip() for name in (collection_names or []) if str(name).strip()]
        status = self._load_storage_status()
        counts_from_status = {
            str(key): int(value or 0)
            for key, value in dict(status.get("collection_counts") or {}).items()
            if str(key).strip()
        }
        if not names:
            return counts_from_status
        counts: dict[str, int] = {}
        for name in names:
            collection = self._collection(name)
            if collection is None:
                counts[name] = int(counts_from_status.get(name) or 0)
                continue
            try:
                count = int(collection.count_documents({}))
            except Exception:  # noqa: BLE001
                count = int(counts_from_status.get(name) or 0)
            counts[name] = count
        return counts

    def record_migration(self, *, collection_counts: dict[str, int], migration_status: str, fallback_reason: str = "") -> dict[str, Any]:
        if self._backend != "mongo":
            return self.backend_status(list(collection_counts.keys()))
        now_iso = datetime.now(tz=timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        for collection_name, document_count in collection_counts.items():
            self._mark_collection_initialized(str(collection_name), document_count=int(document_count))
        self._update_storage_status(
            migration_status=str(migration_status),
            fallback_reason=str(fallback_reason),
            last_migration_at=now_iso,
        )
        return self.backend_status(list(collection_counts.keys()))

    def list_collection(self, collection_name: str) -> list[dict[str, Any]] | None:
        collection = self._collection(collection_name)
        if collection is None:
            return None
        try:
            rows: list[dict[str, Any]] = []
            for item in collection.find({}, projection={"_id": False}):
                if isinstance(item, dict):
                    rows.append(item)
            if rows or self._collection_initialized(collection_name):
                return rows
            return None
        except PyMongoError as exc:
            logger.warning("Failed to read %s from MongoDB: %s", collection_name, exc)
            return None

    def upsert_document(self, collection_name: str, key: str, payload: dict[str, Any]) -> bool:
        collection = self._collection(collection_name)
        if collection is None:
            return False
        try:
            safe_payload = dict(payload)
            safe_payload["_id"] = key
            collection.replace_one({"_id": key}, safe_payload, upsert=True)
            self._mark_collection_initialized(collection_name)
            return True
        except PyMongoError as exc:
            logger.warning("Failed to upsert %s/%s in MongoDB: %s", collection_name, key, exc)
            return False

    def delete_document(self, collection_name: str, key: str) -> bool:
        collection = self._collection(collection_name)
        if collection is None:
            return False
        try:
            collection.delete_one({"_id": key})
            return True
        except PyMongoError as exc:
            logger.warning("Failed to delete %s/%s in MongoDB: %s", collection_name, key, exc)
            return False

    def save_text_document(self, collection_name: str, key: str, payload: dict[str, Any]) -> bool:
        return self.upsert_document(collection_name, key, payload)

    def get_text_document(self, collection_name: str, key: str) -> dict[str, Any] | None:
        collection = self._collection(collection_name)
        if collection is None:
            return None
        try:
            item = collection.find_one({"_id": key}, projection={"_id": False})
            if isinstance(item, dict):
                return item
            if self._collection_initialized(collection_name):
                return None
            return None
        except PyMongoError as exc:
            logger.warning("Failed to read %s/%s from MongoDB: %s", collection_name, key, exc)
            return None

    def import_list(self, collection_name: str, rows: list[dict[str, Any]], *, key_field: str = "id") -> dict[str, Any]:
        if self._backend != "mongo":
            return {"backend": self._backend, "imported": 0}
        imported = 0
        existing = self.list_collection(collection_name) or []
        existing_ids = {str(item.get(key_field) or "") for item in rows}
        for row in existing:
            row_id = str(row.get(key_field) or "")
            if row_id and row_id not in existing_ids:
                self.delete_document(collection_name, row_id)
        for row in rows:
            row_id = str(row.get(key_field) or "")
            if not row_id:
                continue
            if self.upsert_document(collection_name, row_id, row):
                imported += 1
        self._mark_collection_initialized(collection_name, document_count=len(rows))
        return {"backend": self._backend, "imported": imported}

    def import_text_documents(self, collection_name: str, rows: list[dict[str, Any]]) -> dict[str, Any]:
        if self._backend != "mongo":
            return {"backend": self._backend, "imported": 0}
        imported = 0
        desired_keys = {
            str(row.get("name") or row.get("id") or "").strip()
            for row in rows
            if str(row.get("name") or row.get("id") or "").strip()
        }
        existing = self.list_collection(collection_name) or []
        for row in existing:
            key = str(row.get("name") or row.get("id") or "").strip()
            if key and key not in desired_keys:
                self.delete_document(collection_name, key)
        for row in rows:
            key = str(row.get("name") or row.get("id") or "").strip()
            if not key:
                continue
            if self.save_text_document(collection_name, key, row):
                imported += 1
        self._mark_collection_initialized(collection_name, document_count=len(rows))
        return {"backend": self._backend, "imported": imported}

    def backend_status(self, collection_names: list[str] | None = None) -> dict[str, Any]:
        mongo_healthy = self._backend == "mongo"
        storage_status = self._load_storage_status()
        collection_counts = self.collection_counts(collection_names)
        if not collection_counts and isinstance(storage_status.get("collection_counts"), dict):
            collection_counts = {
                str(key): int(value or 0)
                for key, value in dict(storage_status.get("collection_counts") or {}).items()
                if str(key).strip()
            }
        if self._backend == "mongo":
            migration_status = str(storage_status.get("migration_status") or ("completed" if collection_counts else "pending"))
            last_migration_at = str(storage_status.get("last_migration_at") or "")
            fallback_reason = str(storage_status.get("fallback_reason") or "")
        else:
            migration_status = "fallback" if self._requested_backend == "mongo" else "filesystem"
            last_migration_at = ""
            fallback_reason = self._fallback_reason
        return {
            "backend": self._backend,
            "requested_backend": self._requested_backend,
            "mongo_healthy": mongo_healthy,
            "healthy": bool(mongo_healthy or self._requested_backend in {"filesystem", "auto"}),
            "fallback_reason": fallback_reason,
            "mongo_db": CONFIG.mongo_db,
            "migration_status": migration_status,
            "collection_counts": collection_counts,
            "last_migration_at": last_migration_at,
        }


_STORE = ContentStore()


def content_store_backend() -> str:
    return _STORE.backend


def content_store_status(collection_names: list[str] | None = None) -> dict[str, Any]:
    return _STORE.backend_status(collection_names)


def record_content_store_migration(*, collection_counts: dict[str, int], migration_status: str, fallback_reason: str = "") -> dict[str, Any]:
    return _STORE.record_migration(
        collection_counts=collection_counts,
        migration_status=migration_status,
        fallback_reason=fallback_reason,
    )


def import_content_list(collection_name: str, rows: list[dict[str, Any]], *, key_field: str = "id") -> dict[str, Any]:
    return _STORE.import_list(collection_name, rows, key_field=key_field)


def import_content_text_documents(collection_name: str, rows: list[dict[str, Any]]) -> dict[str, Any]:
    return _STORE.import_text_documents(collection_name, rows)


def list_content_collection(collection_name: str) -> list[dict[str, Any]] | None:
    return _STORE.list_collection(collection_name)


def get_content_document(collection_name: str, key: str) -> dict[str, Any] | None:
    return _STORE.get_text_document(collection_name, key)


def upsert_content_document(
    collection_name: str,
    key: str,
    payload: dict[str, Any],
) -> bool:
    return _STORE.upsert_document(collection_name, key, payload)


def load_list(collection_name: str, file_path: Path, default: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if _STORE.backend == "mongo":
        rows = _STORE.list_collection(collection_name)
        if rows is not None:
            return rows
    if not file_path.exists():
        file_path.write_text(json.dumps(default, ensure_ascii=False, indent=2), encoding="utf-8")
        return json.loads(json.dumps(default))
    try:
        payload = json.loads(file_path.read_text(encoding="utf-8"))
        if isinstance(payload, list):
            return payload
    except Exception:  # noqa: BLE001
        pass
    file_path.write_text(json.dumps(default, ensure_ascii=False, indent=2), encoding="utf-8")
    return json.loads(json.dumps(default))


def save_list(collection_name: str, file_path: Path, payload: list[dict[str, Any]], key_field: str = "id") -> None:
    if _STORE.backend == "mongo":
        _STORE.import_list(collection_name, payload, key_field=key_field)
    file_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def load_text_document(collection_name: str, key: str, file_path: Path) -> dict[str, Any] | None:
    if _STORE.backend == "mongo":
        item = _STORE.get_text_document(collection_name, key)
        if item:
            return item
    if not file_path.exists() or not file_path.is_file():
        return None
    return {
        "name": key,
        "content": file_path.read_text(encoding="utf-8", errors="ignore"),
    }


def save_text_document(collection_name: str, key: str, file_path: Path, payload: dict[str, Any]) -> None:
    if _STORE.backend == "mongo":
        _STORE.save_text_document(collection_name, key, payload)
    file_path.write_text(str(payload.get("content") or ""), encoding="utf-8")


def delete_text_document(collection_name: str, key: str, file_path: Path) -> None:
    if _STORE.backend == "mongo":
        _STORE.delete_document(collection_name, key)
    if file_path.exists() and file_path.is_file():
        file_path.unlink()
