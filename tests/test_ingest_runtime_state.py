import asyncio
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


from services.ingest.config import IngestSettings
from services.ingest import redis_client as redis_client_module
from services.ingest.redis_client import (
    DLQ_LIST_SCAN_MAX_ROWS,
    DLQ_LIST_SCAN_MULTIPLIER,
    DLQ_REPLAY_SCAN_MAX_ROWS,
    DLQ_REPLAY_SCAN_MULTIPLIER,
    create_redis_client,
    list_dlq_events,
    replay_dlq_events,
    push_dead_letter_event,
)
from services.ingest.runtime_state import SQLiteIngestStateStore


class IngestRuntimeStateTests(unittest.IsolatedAsyncioTestCase):
    async def test_sqlite_store_supports_hashes_and_streams(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SQLiteIngestStateStore(str(Path(tmp) / "ingest-state.db"))
            await store.hset("metrics", mapping={"accepted_total": "2"})
            self.assertEqual(await store.hget("metrics", "accepted_total"), "2")
            await store.hincrby("metrics", "accepted_total", 3)
            self.assertEqual(await store.hget("metrics", "accepted_total"), "5")
            dlq_id = await store.xadd("siem:raw:dlq", {"reason": "broken", "raw_payload": "{}"}, maxlen=100)
            self.assertTrue(str(dlq_id))
            rows = await store.xrevrange("siem:raw:dlq", count=5)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0][1]["reason"], "broken")

    async def test_create_redis_client_uses_sqlite_runtime_state_when_configured(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            settings = IngestSettings(
                env="prod",
                log_level="INFO",
                instance_name="test",
                redis_host="127.0.0.1",
                redis_port=6379,
                redis_db=0,
                redis_password=None,
                runtime_state_backend="sqlite",
                runtime_state_sqlite_path=str(Path(tmp) / "ingest-state.db"),
                ingest_syslog_host="0.0.0.0",
                ingest_syslog_port=1514,
                ingest_syslog_audit_port=1515,
                ingest_syslog_network_port=1516,
                ingest_syslog_vpn_port=1517,
                ingest_syslog_app_port=1518,
                ingest_http_host="0.0.0.0",
                ingest_http_port=8443,
                raw_stream_max_len=1000,
                raw_stream_soft_limit=900,
                raw_stream_hard_limit=980,
            )
            client = create_redis_client(settings)
            self.assertIsInstance(client, SQLiteIngestStateStore)
            await client.close()

    async def test_dlq_listing_and_replay_metadata_work_with_sqlite_runtime_state(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = SQLiteIngestStateStore(str(Path(tmp) / "ingest-state.db"))
            dlq_id = await push_dead_letter_event(
                store,
                {"message": "broken"},
                reason="payload_item_not_object",
                source_ip="127.0.0.1",
                collector="vm1-smoke",
                collector_profile="generic-http",
                ingest_path="/ingest/json",
                metadata={"source_type": "synthetic", "event.dataset": "smoke"},
            )
            self.assertTrue(str(dlq_id))
            payload = await list_dlq_events(store, count=10)
            self.assertEqual(payload["metrics"]["visible"], 1)
            self.assertEqual(payload["items"][0]["reason"], "payload_item_not_object")

    async def test_dlq_listing_caps_reverse_scan_budget_for_large_backlog(self) -> None:
        class FakeRedis:
            async def hget(self, _key: str, _field: str) -> str:
                return "451706"

            async def hgetall(self, _key: str) -> dict[str, str]:
                return {}

        fake_redis = FakeRedis()

        async def fake_scan(_redis, _stream_key: str, *, max_scan: int):
            self.assertEqual(max_scan, min(DLQ_LIST_SCAN_MAX_ROWS, 200 * DLQ_LIST_SCAN_MULTIPLIER))
            return []

        with mock.patch.object(redis_client_module, "_load_replay_records", new=mock.AsyncMock(return_value={})):
            with mock.patch.object(redis_client_module, "_scan_stream_reverse", new=fake_scan):
                payload = await list_dlq_events(fake_redis, count=200)

        self.assertEqual(payload["metrics"]["visible"], 0)
        self.assertEqual(payload["metrics"]["total"], 451706)
        self.assertEqual(payload["metrics"]["outstanding"], 451706)

    async def test_dlq_replay_auto_select_caps_reverse_scan_budget_for_large_backlog(self) -> None:
        class FakeRedis:
            async def hget(self, _key: str, _field: str) -> str:
                return "451706"

            async def hgetall(self, _key: str) -> dict[str, str]:
                return {}

        fake_redis = FakeRedis()

        async def fake_scan(_redis, _stream_key: str, *, max_scan: int):
            self.assertEqual(max_scan, min(DLQ_REPLAY_SCAN_MAX_ROWS, 1 * DLQ_REPLAY_SCAN_MULTIPLIER))
            return []

        with mock.patch.object(redis_client_module, "_load_replay_records", new=mock.AsyncMock(return_value={})):
            with mock.patch.object(redis_client_module, "_scan_stream_reverse", new=fake_scan):
                payload = await replay_dlq_events(fake_redis, limit=1, actor="tester")

        self.assertEqual(payload["requested"], 0)
        self.assertEqual(payload["replayed"], 0)

    async def test_dlq_replay_auto_select_returns_fast_when_nothing_is_outstanding(self) -> None:
        class FakeRedis:
            async def hget(self, _key: str, _field: str) -> str:
                return "12"

            async def hgetall(self, _key: str) -> dict[str, str]:
                return {}

        fake_redis = FakeRedis()
        replay_rows = {f"dlq-{index}": {"status": "success"} for index in range(12)}

        with mock.patch.object(redis_client_module, "_load_replay_records", new=mock.AsyncMock(return_value=replay_rows)):
            with mock.patch.object(redis_client_module, "_scan_stream_reverse", new=mock.AsyncMock(side_effect=AssertionError("scan_not_expected"))):
                payload = await replay_dlq_events(fake_redis, limit=20, actor="tester")

        self.assertEqual(payload["requested"], 0)
        self.assertEqual(payload["replayed"], 0)
        self.assertEqual(payload["failed"], 0)


if __name__ == "__main__":
    unittest.main()
