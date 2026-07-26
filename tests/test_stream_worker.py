import importlib.util
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PACKAGE_NAME = "fake_stream_corr"
MODULE_NAME = f"{PACKAGE_NAME}.worker"

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _resolve_worker_path() -> Path:
    candidates = (
        ROOT / "stream_worker.py",
        ROOT / "services" / "stream_corr" / "worker.py",
    )
    for candidate in candidates:
        if candidate.exists():
            return candidate
    raise FileNotFoundError("Unable to resolve stream worker module path")


WORKER_PATH = _resolve_worker_path()


class _FakeRedis:
    def __init__(self) -> None:
        self.zsets: dict[str, dict[str, float]] = {}
        self.values: dict[str, str] = {}

    async def zadd(self, key: str, mapping: dict[str, float]) -> None:
        bucket = self.zsets.setdefault(key, {})
        bucket.update({str(member): float(score) for member, score in mapping.items()})

    async def zremrangebyscore(self, key: str, minimum, maximum) -> None:
        minimum_value = float("-inf") if str(minimum) == "-inf" else float(minimum)
        maximum_value = float(maximum)
        bucket = self.zsets.setdefault(key, {})
        for member, score in list(bucket.items()):
            if minimum_value <= score <= maximum_value:
                bucket.pop(member, None)

    async def zcount(self, key: str, minimum: float, maximum: float) -> int:
        bucket = self.zsets.get(key, {})
        return sum(1 for score in bucket.values() if float(minimum) <= score <= float(maximum))

    async def get(self, key: str):
        return self.values.get(key)

    async def set(self, key: str, value: str) -> None:
        self.values[key] = str(value)


class _FakeClickHouseClient:
    def __init__(self) -> None:
        self.calls: list[tuple[str, object]] = []

    def execute(self, query: str, rows=None):
        self.calls.append((str(query), rows))
        return []


class _FakeSQLiteOffsetState:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    def save_offsets(self, offsets) -> None:
        self.calls.extend(dict(item) for item in offsets)


def _load_worker_module():
    for name in [MODULE_NAME, PACKAGE_NAME, f"{PACKAGE_NAME}.config", f"{PACKAGE_NAME}.logging_conf", f"{PACKAGE_NAME}.rules", "clickhouse_driver", "redis", "redis.asyncio"]:
        sys.modules.pop(name, None)

    package = types.ModuleType(PACKAGE_NAME)
    package.__path__ = []  # type: ignore[attr-defined]
    sys.modules[PACKAGE_NAME] = package

    config_module = types.ModuleType(f"{PACKAGE_NAME}.config")

    class StreamCorrSettings:
        def __init__(self) -> None:
            self.redis_host = "127.0.0.1"
            self.redis_port = 6379
            self.redis_db = 0
            self.redis_password = None
            self.ch_host = "127.0.0.1"
            self.ch_port = 9000
            self.ch_db = "siem"
            self.ch_user = "siem"
            self.ch_password = ""
            self.ch_timeout_secs = 10
            self.filtered_stream_key = "siem:filtered"
            self.group_name = "siem_stream_corr"
            self.consumer_name = "siem_stream_corr_1"
            self.batch_size = 200
            self.instance_name = "unit-stream-corr"

    config_module.StreamCorrSettings = StreamCorrSettings
    sys.modules[f"{PACKAGE_NAME}.config"] = config_module

    logging_conf_module = types.ModuleType(f"{PACKAGE_NAME}.logging_conf")
    logging_conf_module.configure_logging = lambda: None
    sys.modules[f"{PACKAGE_NAME}.logging_conf"] = logging_conf_module

    rules_module = types.ModuleType(f"{PACKAGE_NAME}.rules")

    class StreamCorrRule:
        def __init__(self, *, id: int, window_s: int, threshold: int, entity_field: str = "source.ip", name: str = "rule", severity: str = "medium", description: str = "test", pattern: str = "threshold") -> None:
            self.id = id
            self.window_s = window_s
            self.threshold = threshold
            self.entity_field = entity_field
            self.name = name
            self.severity = severity
            self.description = description
            self.pattern = pattern

    rules_module.StreamCorrRule = StreamCorrRule
    rules_module.load_stream_rules = lambda settings: []
    rules_module.matches_rule = lambda rule, event: True
    sys.modules[f"{PACKAGE_NAME}.rules"] = rules_module

    clickhouse_module = types.ModuleType("clickhouse_driver")
    clickhouse_module.Client = _FakeClickHouseClient
    sys.modules["clickhouse_driver"] = clickhouse_module

    redis_module = types.ModuleType("redis")
    redis_asyncio_module = types.ModuleType("redis.asyncio")
    redis_module.Redis = _FakeRedis
    redis_asyncio_module.Redis = _FakeRedis
    redis_module.asyncio = redis_asyncio_module
    sys.modules["redis"] = redis_module
    sys.modules["redis.asyncio"] = redis_asyncio_module

    spec = importlib.util.spec_from_file_location(MODULE_NAME, WORKER_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    module.__package__ = PACKAGE_NAME
    sys.modules[MODULE_NAME] = module
    spec.loader.exec_module(module)
    return module, StreamCorrSettings, StreamCorrRule


class StreamWorkerTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        for key in (
            "SIEM_STREAM_CORR_TIME_MODE",
            "SIEM_STREAM_CORR_ALLOWED_LATENESS_SEC",
            "SIEM_STREAM_CORR_WATERMARK_LAG_SEC",
            "SIEM_STREAM_CORR_SHADOW_COMPARE",
            "SIEM_STREAM_STATE_BACKEND",
            "SIEM_STREAM_STATE_SQLITE_PATH",
        ):
            os.environ.pop(key, None)

    async def test_event_mode_counts_only_events_inside_event_window(self) -> None:
        os.environ["SIEM_STREAM_CORR_TIME_MODE"] = "event"
        module, Settings, Rule = _load_worker_module()
        worker = module.StreamCorrWorker(Settings())
        worker._state_redis = _FakeRedis()

        future = await worker._evaluate_threshold(Rule(id=1, window_s=20, threshold=2), "127.0.0.1", "future", 130.0, mode="event", watermark_epoch=130.0)
        older = await worker._evaluate_threshold(Rule(id=1, window_s=20, threshold=2), "127.0.0.1", "older", 100.0, mode="event", watermark_epoch=130.0)

        self.assertFalse(future["should_alert"])
        self.assertEqual(future["hits"], 1)
        self.assertFalse(older["should_alert"])
        self.assertEqual(older["hits"], 1)

    async def test_event_epoch_marks_processing_time_fallback(self) -> None:
        module, Settings, _ = _load_worker_module()
        worker = module.StreamCorrWorker(Settings())

        epoch, fallback_used = worker._event_epoch({}, 1700000000.0)

        self.assertEqual(epoch, 1700000000.0)
        self.assertTrue(fallback_used)

    async def test_event_epoch_accepts_decimal_unix_timestamp_string(self) -> None:
        module, Settings, _ = _load_worker_module()
        worker = module.StreamCorrWorker(Settings())

        epoch, fallback_used = worker._event_epoch(
            {"@timestamp": "1785057668.347427"},
            1700000000.0,
        )

        self.assertAlmostEqual(epoch, 1785057668.347427)
        self.assertFalse(fallback_used)

    async def test_runtime_status_snapshot_persists_mode_and_counters(self) -> None:
        os.environ["SIEM_STREAM_CORR_TIME_MODE"] = "event"
        os.environ["SIEM_STREAM_CORR_SHADOW_COMPARE"] = "true"
        module, Settings, _ = _load_worker_module()
        worker = module.StreamCorrWorker(Settings())
        worker._ch_client = _FakeClickHouseClient()
        worker._max_event_epoch_seen = 200.0
        worker._last_event_epoch = 190.0
        worker._late_events_total = 3
        worker._timestamp_fallback_total = 2
        worker._shadow_compare_mismatches_total = 1

        worker._write_runtime_status(events_processed=12, alerts_created=4)

        self.assertTrue(worker._ch_client.calls)
        query, rows = worker._ch_client.calls[-1]
        self.assertIn("INSERT INTO siem.stream_corr_runtime_status", query)
        self.assertEqual(rows[0][2], "kafka")
        self.assertEqual(rows[0][3], "sqlite")
        self.assertEqual(rows[0][4], "event")
        self.assertEqual(rows[0][5], 1)
        self.assertEqual(rows[0][11], 3)
        self.assertEqual(rows[0][12], 2)
        self.assertEqual(rows[0][13], 1)

    async def test_rule_index_limits_candidates_without_dropping_fallback_rules(self) -> None:
        module, Settings, Rule = _load_worker_module()
        worker = module.StreamCorrWorker(Settings())
        linux_rule = Rule(id=1002, window_s=60, threshold=5)
        linux_rule.expr_text = "event.provider == 'linux.sshd' and event.type == 'ssh_login_failure'"
        windows_rule = Rule(id=2618, window_s=300, threshold=20)
        windows_rule.expr_text = "event.provider == 'windows.security' and event.type == 'wmi_activity'"
        fallback_rule = Rule(id=9000, window_s=60, threshold=2)
        fallback_rule.expr_text = "source.ip != ''"
        worker._rules = [linux_rule, windows_rule, fallback_rule]
        worker._rebuild_rule_index()

        candidates = worker._candidate_rules(
            {
                "event.provider": "windows.security",
                "event.type": "wmi_activity",
                "source.ip": "10.0.0.5",
            }
        )

        self.assertEqual({rule.id for rule in candidates}, {2618, 9000})

    async def test_rule_index_uses_host_and_outcome_selectors(self) -> None:
        module, Settings, Rule = _load_worker_module()
        worker = module.StreamCorrWorker(Settings())
        host_rule = Rule(id=2901, window_s=300, threshold=6)
        host_rule.expr_text = "host.name == 'nextcloud-siem' and event.original icontains 'login failed'"
        outcome_rule = Rule(id=2501, window_s=600, threshold=5)
        outcome_rule.expr_text = "event.outcome == 'failure' and log_source == 'pilot-web-01'"
        fallback_rule = Rule(id=9001, window_s=300, threshold=1)
        fallback_rule.expr_text = "ti_indicator != ''"
        worker._rules = [host_rule, outcome_rule, fallback_rule]
        worker._rebuild_rule_index()

        candidates = worker._candidate_rules(
            {
                "host.name": "nextcloud-siem",
                "event.outcome": "success",
                "log_source": "nextcloud-siem",
            }
        )

        self.assertEqual({rule.id for rule in candidates}, {2901, 9001})

    async def test_benchmark_events_are_skipped_before_rule_evaluation(self) -> None:
        module, Settings, _ = _load_worker_module()
        worker = module.StreamCorrWorker(Settings())

        self.assertTrue(worker._should_skip_correlation({"event.category": "benchmark"}))
        self.assertTrue(worker._should_skip_correlation({"event.dataset": "benchmark"}))
        self.assertTrue(worker._should_skip_correlation({"tags": '["distributed", "allowlist:benchmark"]'}))
        self.assertTrue(worker._should_skip_correlation({"event.tags": ["benchmark", "allowlist:benchmark"]}))
        self.assertFalse(
            worker._should_skip_correlation(
                {
                    "event.provider": "linux.sshd",
                    "event.type": "ssh_login_failure",
                    "source.ip": "10.0.0.5",
                }
            )
        )

    async def test_processed_offsets_are_checkpointed_once_per_partition(self) -> None:
        module, Settings, _ = _load_worker_module()
        worker = module.StreamCorrWorker(Settings())
        fake_state = _FakeSQLiteOffsetState()
        worker._sqlite_state = fake_state

        worker._save_processed_offsets(
            [
                types.SimpleNamespace(topic="siem.filtered", partition=0, offset=10),
                types.SimpleNamespace(topic="siem.filtered", partition=0, offset=11),
                types.SimpleNamespace(topic="siem.filtered", partition=1, offset=3),
                types.SimpleNamespace(topic="siem.filtered", partition=1, offset=4),
                types.SimpleNamespace(topic="siem.filtered", partition=1, offset=2),
            ]
        )

        self.assertEqual(len(fake_state.calls), 2)
        offsets = {(call["topic_name"], call["partition_id"]): call["offset_value"] for call in fake_state.calls}
        self.assertEqual(offsets[("siem.filtered", 0)], 12)
        self.assertEqual(offsets[("siem.filtered", 1)], 5)

    async def test_sqlite_state_backend_tracks_threshold_hits(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            os.environ["SIEM_STREAM_STATE_BACKEND"] = "sqlite"
            os.environ["SIEM_STREAM_STATE_SQLITE_PATH"] = str(Path(temp_dir) / "runtime-state.db")
            module, Settings, Rule = _load_worker_module()
            worker = module.StreamCorrWorker(Settings())
            worker._sqlite_state = module.SQLiteStreamState(os.environ["SIEM_STREAM_STATE_SQLITE_PATH"])

            try:
                first = await worker._evaluate_threshold(Rule(id=7, window_s=30, threshold=2), "host-a", "msg-1", 100.0, mode="event", watermark_epoch=100.0)
                second = await worker._evaluate_threshold(Rule(id=7, window_s=30, threshold=2), "host-a", "msg-2", 110.0, mode="event", watermark_epoch=110.0)
                third = await worker._evaluate_threshold(Rule(id=7, window_s=30, threshold=2), "host-a", "msg-3", 130.0, mode="event", watermark_epoch=130.0)
                fourth = await worker._evaluate_threshold(Rule(id=7, window_s=30, threshold=2), "host-a", "msg-4", 145.0, mode="event", watermark_epoch=145.0)

                self.assertFalse(first["should_alert"])
                self.assertEqual(first["hits"], 1)
                self.assertTrue(second["should_alert"])
                self.assertEqual(second["hits"], 2)
                self.assertFalse(third["should_alert"])
                self.assertFalse(fourth["should_alert"])
                self.assertEqual(fourth["suppression_window_s"], 3600)
                meta = worker._sqlite_state.read_runtime_meta()
                self.assertEqual(meta, {})
            finally:
                worker._sqlite_state.close()


if __name__ == "__main__":
    unittest.main()
