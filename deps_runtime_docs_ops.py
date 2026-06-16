from __future__ import annotations

from typing import Any


def _deps():
    try:
        from . import deps as deps_module
    except ImportError:  # pragma: no cover - local test fallback
        import deps as deps_module  # type: ignore[no-redef]

    return deps_module


def list_runtime_docs() -> list[dict[str, Any]]:
    return list(_deps()._list_runtime_docs_raw())


def load_runtime_doc(name: str) -> dict[str, Any]:
    return dict(_deps()._load_runtime_doc_raw(name))


def save_runtime_doc(name: str, content: str) -> dict[str, Any]:
    return dict(_deps()._save_runtime_doc_raw(name, content))


def save_runtime_doc_file(filename: str, payload: bytes) -> dict[str, Any]:
    return dict(_deps()._save_runtime_doc_file_raw(filename, payload))


def delete_runtime_doc(name: str) -> None:
    _deps()._delete_runtime_doc_raw(name)


def list_dashboards() -> list[dict[str, Any]]:
    return list(_deps()._list_dashboards_raw())


def describe_dashboard_widgets() -> list[dict[str, Any]]:
    return list(_deps()._describe_dashboard_widgets_raw())


def save_dashboard_definition(
    title: str,
    description: str,
    widgets: list[str],
    layout: list[dict[str, Any]] | None = None,
    dashboard_id: str = "",
) -> dict[str, Any]:
    return dict(
        _deps()._save_dashboard_definition_raw(
            title=title,
            description=description,
            widgets=widgets,
            layout=layout,
            dashboard_id=dashboard_id,
        )
    )


def delete_dashboard_definition(dashboard_id: str) -> None:
    _deps()._delete_dashboard_definition_raw(dashboard_id)


def list_builder_drafts() -> list[dict[str, Any]]:
    return list(_deps()._list_builder_drafts_raw())


def save_builder_draft(
    title: str,
    description: str,
    kind: str,
    blocks: list[dict[str, Any]],
    draft_id: str = "",
    status: str = "draft",
) -> dict[str, Any]:
    return dict(
        _deps()._save_builder_draft_raw(
            title=title,
            description=description,
            kind=kind,
            blocks=blocks,
            draft_id=draft_id,
            status=status,
        )
    )


def delete_builder_draft(draft_id: str) -> None:
    _deps()._delete_builder_draft_raw(draft_id)


def validate_builder_draft_payload(title: str, description: str, kind: str, blocks: list[dict[str, Any]]) -> dict[str, Any]:
    return dict(_deps()._validate_builder_draft_payload_raw(title, description, kind, blocks))


def test_builder_draft_payload(title: str, description: str, kind: str, blocks: list[dict[str, Any]]) -> dict[str, Any]:
    return dict(_deps()._test_builder_draft_payload_raw(title, description, kind, blocks))


def publish_builder_draft(draft_id: str) -> dict[str, Any]:
    return dict(_deps()._publish_builder_draft_raw(draft_id))
