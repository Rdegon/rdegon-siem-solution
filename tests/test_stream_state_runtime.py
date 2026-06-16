import sqlite3
import tempfile
import unittest
from pathlib import Path

from stream_state_runtime import stream_state_runtime_status


class StreamStateRuntimeTests(unittest.TestCase):
    def test_reports_sqlite_runtime_status(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            db_path = Path(temp_dir) / "runtime-state.db"
            conn = sqlite3.connect(str(db_path))
            try:
                conn.executescript(
                    """
                    CREATE TABLE runtime_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                    CREATE TABLE consumer_offsets (
                        transport_backend TEXT NOT NULL,
                        group_name TEXT NOT NULL,
                        topic_name TEXT NOT NULL,
                        partition_id INTEGER NOT NULL,
                        offset_value INTEGER NOT NULL,
                        updated_ts TEXT NOT NULL,
                        PRIMARY KEY (transport_backend, group_name, topic_name, partition_id)
                    );
                    INSERT INTO runtime_meta(key, value) VALUES ('watermark_epoch', '123.5');
                    INSERT INTO consumer_offsets(transport_backend, group_name, topic_name, partition_id, offset_value, updated_ts)
                    VALUES ('kafka', 'siem-normalizer', 'siem.raw', 0, 42, '2026-03-23T10:00:00Z');
                    """
                )
                conn.commit()
            finally:
                conn.close()

            payload = stream_state_runtime_status(
                {
                    "SIEM_STREAM_STATE_BACKEND": "sqlite",
                    "SIEM_STREAM_STATE_SQLITE_PATH": str(db_path),
                }
            )

            self.assertTrue(payload["healthy"])
            self.assertEqual("sqlite", payload["backend"])
            self.assertEqual(1, payload["stored_offsets_total"])
            self.assertEqual(["siem-normalizer"], payload["groups"])
            self.assertEqual(["siem.raw"], payload["topics"])
            self.assertIn("watermark_epoch", payload["runtime_meta_keys"])

    def test_redis_backend_skips_sqlite_probe(self) -> None:
        payload = stream_state_runtime_status({"SIEM_STREAM_STATE_BACKEND": "redis"})
        self.assertEqual("redis", payload["backend"])
        self.assertTrue(payload["healthy"])
        self.assertEqual([], payload["offsets"])


if __name__ == "__main__":
    unittest.main()
