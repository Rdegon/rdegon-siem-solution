from __future__ import annotations

from datetime import datetime
from typing import Any

try:
    from .content_store import content_store_status, import_content_list, import_content_text_documents, record_content_store_migration
except ImportError:  # pragma: no cover - local test/runtime fallback
    from content_store import content_store_status, import_content_list, import_content_text_documents, record_content_store_migration  # type: ignore[no-redef]


def _deps():
    try:
        from . import deps as deps_module
    except ImportError:  # pragma: no cover - local test/runtime fallback
        import deps as deps_module  # type: ignore[no-redef]

    return deps_module


def content_store_collection_counts() -> dict[str, int]:
    deps = _deps()
    docs_total = len(deps.list_runtime_docs())
    dashboards_total = len(deps._load_dashboard_registry())
    drafts_total = len(deps.list_builder_drafts())
    return {
        "docs_pages": int(docs_total),
        "dashboard_instances": int(dashboards_total),
        "builder_drafts": int(drafts_total),
    }


def content_store_collection_names() -> list[str]:
    return list(content_store_collection_counts().keys())


def migrate_content_store() -> dict[str, Any]:
    deps = _deps()
    status = content_store_status(content_store_collection_names())
    counts_before = content_store_collection_counts()
    if status.get("backend") != "mongo":
        return {
            **status,
            "migration_status": "skipped",
            "collection_counts": counts_before,
            "last_migration_at": "",
            "fallback_reason": status.get("fallback_reason") or "mongo_not_active",
        }

    doc_dir = deps._ensure_runtime_docs_dir()
    docs_payload: list[dict[str, Any]] = []
    for item in sorted(doc_dir.iterdir(), key=lambda path: path.name.lower()):
        if not item.is_file():
            continue
        docs_payload.append(
            {
                "name": item.name,
                "content": item.read_text(encoding="utf-8", errors="ignore"),
                "updated_ts": deps._fmt(datetime.fromtimestamp(item.stat().st_mtime)),
            }
        )

    dashboards = deps._load_dashboard_registry()
    drafts = deps.list_builder_drafts()
    import_content_text_documents("docs_pages", docs_payload)
    import_content_list("dashboard_instances", dashboards)
    import_content_list("builder_drafts", drafts)
    counts_after = content_store_collection_counts()
    recorded_status = record_content_store_migration(
        collection_counts=counts_after,
        migration_status="completed",
    )
    return {
        **recorded_status,
        "migration_status": "completed",
        "collection_counts": counts_after,
        "last_migration_at": str(recorded_status.get("last_migration_at") or deps._now_iso()),
        "fallback_reason": "",
    }


def content_storage_status() -> dict[str, Any]:
    status = content_store_status(content_store_collection_names())
    counts = content_store_collection_counts()
    return {
        **status,
        "healthy": bool(status.get("healthy", False)),
        "migration_status": str(
            status.get("migration_status")
            or ("completed" if status.get("backend") == "mongo" else ("fallback" if status.get("requested_backend") == "mongo" else "filesystem"))
        ),
        "collection_counts": counts,
        "last_migration_at": str(status.get("last_migration_at") or ""),
        "fallback_reason": status.get("fallback_reason") or "",
    }
