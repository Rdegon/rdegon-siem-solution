import tempfile
import unittest
from pathlib import Path

from services.backup_runtime import backup_runtime_status


class BackupRuntimeTests(unittest.TestCase):
    def test_backup_runtime_marks_local_paths_prepared(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            pg_dir = root / "pg"
            mongo_dir = root / "mongo"
            sqlite_dir = root / "sqlite"
            sqlite_source = root / "runtime-state.db"
            pg_dir.mkdir()
            mongo_dir.mkdir()
            sqlite_dir.mkdir()
            sqlite_source.write_text("ok", encoding="utf-8")

            payload = backup_runtime_status(
                control_plane_status={"backend": "postgres", "requested_backend": "postgres"},
                content_status={"backend": "mongo", "requested_backend": "mongo"},
                stream_state_status={"backend": "sqlite", "sqlite_path": str(sqlite_source)},
                platform_status={"clickhouse_ok": True},
                env={
                    "SIEM_CONTROL_PLANE_PG_BACKUP_DIR": str(pg_dir),
                    "SIEM_MONGO_BACKUP_DIR": str(mongo_dir),
                    "SIEM_STREAM_STATE_BACKUP_DIR": str(sqlite_dir),
                    "SIEM_STREAM_STATE_SQLITE_SOURCE_CHECK_LOCAL": "1",
                    "SIEM_STREAM_STATE_BACKUP_CHECK_LOCAL": "1",
                    "SIEM_CLICKHOUSE_BACKUP_DIR": str(root / "clickhouse"),
                    "SIEM_CLICKHOUSE_BACKUP_CHECK_LOCAL": "0",
                },
            )

            self.assertTrue(payload["healthy"])
            self.assertTrue(payload["targets"]["control_plane_postgres"]["prepared"])
            self.assertTrue(payload["targets"]["content_store_mongo"]["prepared"])
            self.assertTrue(payload["targets"]["stream_state_sqlite"]["prepared"])
            self.assertTrue(payload["targets"]["clickhouse_storage"]["prepared"])

    def test_backup_runtime_accepts_remote_sqlite_source_when_runtime_reports_it_healthy(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            pg_dir = root / "pg"
            mongo_dir = root / "mongo"
            pg_dir.mkdir()
            mongo_dir.mkdir()

            payload = backup_runtime_status(
                control_plane_status={"backend": "postgres", "requested_backend": "postgres"},
                content_status={"backend": "mongo", "requested_backend": "mongo"},
                stream_state_status={
                    "backend": "sqlite",
                    "sqlite_path": "/var/lib/siem-stream-corr/runtime-state.db",
                    "sqlite_exists": True,
                    "sqlite_node": "vm3",
                    "last_offset_ts": "2026-03-26T10:00:00Z",
                },
                platform_status={"clickhouse_ok": True},
                env={
                    "SIEM_CONTROL_PLANE_PG_BACKUP_DIR": str(pg_dir),
                    "SIEM_MONGO_BACKUP_DIR": str(mongo_dir),
                    "SIEM_STREAM_STATE_BACKUP_DIR": "/var/backups/siem-stream-state",
                    "SIEM_STREAM_STATE_BACKUP_NODE": "vm3",
                    "SIEM_BACKUP_LOCAL_NODE": "vm4",
                    "SIEM_CLICKHOUSE_BACKUP_DIR": str(root / "clickhouse"),
                    "SIEM_CLICKHOUSE_BACKUP_CHECK_LOCAL": "0",
                },
            )

            self.assertTrue(payload["healthy"])
            self.assertTrue(payload["targets"]["stream_state_sqlite"]["sqlite_source_exists"])
            self.assertFalse(payload["targets"]["stream_state_sqlite"]["check_local"])
            self.assertTrue(payload["targets"]["stream_state_sqlite"]["prepared"])

    def test_backup_runtime_reports_missing_required_paths(self) -> None:
        payload = backup_runtime_status(
            control_plane_status={"backend": "postgres", "requested_backend": "postgres"},
            content_status={"backend": "mongo", "requested_backend": "mongo"},
            stream_state_status={"backend": "sqlite", "sqlite_path": "/nonexistent/runtime-state.db"},
            platform_status={"clickhouse_ok": True},
            env={
                "SIEM_CONTROL_PLANE_PG_BACKUP_DIR": "/nonexistent/pg",
                "SIEM_MONGO_BACKUP_DIR": "/nonexistent/mongo",
                "SIEM_STREAM_STATE_BACKUP_DIR": "/nonexistent/sqlite",
                "SIEM_CLICKHOUSE_BACKUP_DIR": "/nonexistent/clickhouse",
                "SIEM_CLICKHOUSE_BACKUP_CHECK_LOCAL": "1",
            },
        )

        self.assertFalse(payload["healthy"])
        self.assertGreaterEqual(len(payload["issues"]), 3)
        self.assertFalse(payload["targets"]["control_plane_postgres"]["prepared"])
        self.assertFalse(payload["targets"]["content_store_mongo"]["prepared"])
        self.assertFalse(payload["targets"]["stream_state_sqlite"]["prepared"])
        self.assertFalse(payload["targets"]["clickhouse_storage"]["prepared"])


if __name__ == "__main__":
    unittest.main()
