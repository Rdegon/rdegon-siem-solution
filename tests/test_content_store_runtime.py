import importlib.util
import sys
import types
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PACKAGE_NAME = "fake_content_app"
MODULE_NAME = f"{PACKAGE_NAME}.content_store"


def _content_store_path() -> Path:
    for candidate in (ROOT / "content_store.py", ROOT / "services" / "web" / "app" / "content_store.py"):
        if candidate.exists():
            return candidate
    return ROOT / "content_store.py"


def _load_content_store_module():
    for name in [MODULE_NAME, PACKAGE_NAME, f"{PACKAGE_NAME}.config"]:
        sys.modules.pop(name, None)

    package = types.ModuleType(PACKAGE_NAME)
    package.__path__ = []  # type: ignore[attr-defined]
    sys.modules[PACKAGE_NAME] = package

    config_module = types.ModuleType(f"{PACKAGE_NAME}.config")

    class _Config:
        content_store_backend = "filesystem"
        mongo_uri = "mongodb://127.0.0.1:27017"
        mongo_db = "siem_content"

    config_module.CONFIG = _Config()
    sys.modules[f"{PACKAGE_NAME}.config"] = config_module

    spec = importlib.util.spec_from_file_location(MODULE_NAME, _content_store_path())
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    module.__package__ = PACKAGE_NAME
    sys.modules[MODULE_NAME] = module
    spec.loader.exec_module(module)
    return module


class _FakeCollection:
    def __init__(self) -> None:
        self.docs: dict[str, dict] = {}

    def find(self, query=None, projection=None):  # noqa: ARG002
        items = list(self.docs.values())
        if projection and projection.get("_id") is False:
            return [{key: value for key, value in item.items() if key != "_id"} for item in items]
        return [dict(item) for item in items]

    def find_one(self, query, projection=None):
        item = self.docs.get(str((query or {}).get("_id") or ""))
        if item is None:
            return None
        if projection and projection.get("_id") is False:
            return {key: value for key, value in item.items() if key != "_id"}
        return dict(item)

    def replace_one(self, query, payload, upsert=False):  # noqa: ARG002
        self.docs[str((query or {}).get("_id") or payload.get("_id") or "")] = dict(payload)

    def delete_one(self, query):
        self.docs.pop(str((query or {}).get("_id") or ""), None)

    def count_documents(self, query=None):  # noqa: ARG002
        return len(self.docs)


class _FakeDb(dict):
    def __getitem__(self, item):
        if item not in self:
            self[item] = _FakeCollection()
        return dict.__getitem__(self, item)


class ContentStoreRuntimeTests(unittest.TestCase):
    def _mongo_store(self):
        module = _load_content_store_module()
        store = object.__new__(module.ContentStore)
        store._requested_backend = "mongo"
        store._backend = "mongo"
        store._client = object()
        store._db = _FakeDb()
        store._fallback_reason = ""
        return store

    def test_import_text_documents_removes_stale_rows_and_marks_collection(self) -> None:
        store = self._mongo_store()
        store.import_text_documents(
            "docs_pages",
            [
                {"name": "alpha.md", "content": "A", "updated_ts": "2026-03-22T00:00:00Z"},
                {"name": "beta.md", "content": "B", "updated_ts": "2026-03-22T00:05:00Z"},
            ],
        )
        store.import_text_documents(
            "docs_pages",
            [
                {"name": "beta.md", "content": "B2", "updated_ts": "2026-03-22T00:10:00Z"},
            ],
        )

        rows = store.list_collection("docs_pages")

        self.assertEqual(rows, [{"name": "beta.md", "content": "B2", "updated_ts": "2026-03-22T00:10:00Z"}])
        self.assertTrue(store._collection_initialized("docs_pages"))

    def test_import_list_keeps_empty_collection_authoritative(self) -> None:
        store = self._mongo_store()
        store.import_list("builder_drafts", [])

        rows = store.list_collection("builder_drafts")

        self.assertEqual(rows, [])
        self.assertTrue(store._collection_initialized("builder_drafts"))

    def test_backend_status_reports_migration_counts(self) -> None:
        store = self._mongo_store()
        store.import_list("dashboard_instances", [{"id": "soc-overview", "title": "SOC"}])
        store.import_text_documents("docs_pages", [{"name": "alpha.md", "content": "A"}])
        status = store.record_migration(
            collection_counts={
                "dashboard_instances": 1,
                "docs_pages": 1,
            },
            migration_status="completed",
        )

        self.assertEqual(status["backend"], "mongo")
        self.assertEqual(status["migration_status"], "completed")
        self.assertEqual(status["collection_counts"]["dashboard_instances"], 1)
        self.assertEqual(status["collection_counts"]["docs_pages"], 1)
        self.assertTrue(status["last_migration_at"])


if __name__ == "__main__":
    unittest.main()
