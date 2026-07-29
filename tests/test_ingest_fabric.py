import importlib
import importlib.util
import json
import os
import sys
import threading
import unittest
from unittest import mock
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import SimpleNamespace
import types
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
IMPORT_ROOTS = (ROOT, ROOT / "services" / "web" / "app")
for candidate in IMPORT_ROOTS:
    candidate_text = str(candidate)
    if candidate.exists() and candidate_text not in sys.path:
        sys.path.insert(0, candidate_text)


def _load_module_by_path(module_name: str, *relative_candidates: str):
    for candidate in relative_candidates:
        path = ROOT / candidate
        if not path.exists():
            continue
        parent_text = str(path.parent)
        if parent_text not in sys.path:
            sys.path.insert(0, parent_text)
        spec = importlib.util.spec_from_file_location(module_name, path)
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        spec.loader.exec_module(module)
        return module
    raise ModuleNotFoundError(module_name)


class _FakeRedis:
    def __init__(self) -> None:
        self.hashes: dict[str, dict[str, str]] = {}
        self.streams: dict[str, list[tuple[str, dict[str, str]]]] = {}
        self.groups: dict[str, list[dict[str, object]]] = {}
        self.counter = 0

    async def ping(self):
        return True

    async def close(self):
        return None

    async def hget(self, key: str, field: str):
        return self.hashes.get(key, {}).get(field)

    async def hgetall(self, key: str):
        return dict(self.hashes.get(key, {}))

    async def hvals(self, key: str):
        return list(self.hashes.get(key, {}).values())

    async def hset(self, key: str, *args, mapping=None):
        bucket = self.hashes.setdefault(key, {})
        if mapping is not None:
            for item_key, item_value in mapping.items():
                bucket[str(item_key)] = "" if item_value is None else str(item_value)
            return len(mapping)
        if len(args) == 2:
            bucket[str(args[0])] = "" if args[1] is None else str(args[1])
            return 1
        raise AssertionError("Unsupported hset call")

    async def hincrby(self, key: str, field: str, amount: int = 1):
        bucket = self.hashes.setdefault(key, {})
        current = int(bucket.get(field) or 0)
        current += int(amount)
        bucket[field] = str(current)
        return current

    async def xadd(self, key: str, fields: dict[str, str], maxlen=None, approximate=True):  # noqa: ARG002
        self.counter += 1
        stream_id = f"{self.counter}-0"
        self.streams.setdefault(key, []).append((stream_id, dict(fields)))
        return stream_id

    async def xlen(self, key: str):
        return len(self.streams.get(key, []))

    async def xinfo_groups(self, key: str):
        return list(self.groups.get(key, []))

    @staticmethod
    def _stream_id_key(stream_id: str) -> tuple[int, int]:
        text = str(stream_id or "").strip()
        if text == "+":
            return (2**63 - 1, 2**63 - 1)
        if text == "-":
            return (-1, -1)
        parts = text.split("-", 1)
        if len(parts) != 2:
            return (0, 0)
        try:
            return (int(parts[0]), int(parts[1]))
        except ValueError:
            return (0, 0)

    async def xrange(self, key: str, min: str = "-", max: str = "+", count: int | None = None):  # noqa: A002
        rows = list(self.streams.get(key, []))
        if min != "-":
            rows = [item for item in rows if self._stream_id_key(item[0]) >= self._stream_id_key(min)]
        if max != "+":
            rows = [item for item in rows if self._stream_id_key(item[0]) <= self._stream_id_key(max)]
        if count is not None:
            rows = rows[:count]
        return rows

    async def xrevrange(self, key: str, max: str = "+", min: str = "-", count: int | None = None):  # noqa: A002
        rows = list(reversed(self.streams.get(key, [])))
        if max != "+":
            rows = [item for item in rows if self._stream_id_key(item[0]) <= self._stream_id_key(max)]
        if min != "-":
            rows = [item for item in rows if self._stream_id_key(item[0]) >= self._stream_id_key(min)]
        if count is not None:
            rows = rows[:count]
        return rows


class _FakeTransportProducer:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []

    async def publish(self, alias: str, payload: dict[str, object], *, maxlen: int = 0, approximate: bool = False):
        self.calls.append(
            {
                "alias": alias,
                "payload": dict(payload),
                "maxlen": maxlen,
                "approximate": approximate,
            }
        )
        return f"{alias}:0:{len(self.calls)}"

    async def publish_many(self, alias: str, payloads: list[dict[str, object]], *, maxlen: int = 0, approximate: bool = False):
        ids: list[str] = []
        for payload in payloads:
            self.calls.append(
                {
                    "alias": alias,
                    "payload": dict(payload),
                    "maxlen": maxlen,
                    "approximate": approximate,
                    "batch": True,
                }
            )
            ids.append(f"{alias}:0:{len(self.calls)}")
        return ids

    async def close(self):
        return None


def _request(path: str, *, host: str = "127.0.0.1", port: int = 8443, headers: dict[str, str] | None = None):
    return SimpleNamespace(
        client=SimpleNamespace(host=host),
        url=SimpleNamespace(path=path, port=port),
        headers=headers or {},
    )


class IngestFabricTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.fastapi_stubbed = False
        for module_name in (
            "fastapi.responses",
            "fastapi.templating",
            "services.ingest.redis_client",
            "services.ingest.app",
            "services.ingest.syslog_server",
            "ingest_runtime",
        ):
            sys.modules.pop(module_name, None)
        if "fastapi" in sys.modules and getattr(sys.modules["fastapi"], "__spec__", None) is None:
            sys.modules.pop("fastapi", None)
        if "fastapi.responses" in sys.modules and getattr(sys.modules["fastapi.responses"], "__spec__", None) is None:
            sys.modules.pop("fastapi.responses", None)
        if "fastapi.templating" in sys.modules and getattr(sys.modules["fastapi.templating"], "__spec__", None) is None:
            sys.modules.pop("fastapi.templating", None)
        if importlib.util.find_spec("fastapi") is None:
            fastapi_stub = types.ModuleType("fastapi")

            class HTTPException(Exception):
                def __init__(self, status_code: int, detail: str) -> None:
                    super().__init__(detail)
                    self.status_code = status_code
                    self.detail = detail

            class FastAPI:
                def __init__(self, *args, **kwargs) -> None:  # noqa: D401, ARG002
                    return None

                def on_event(self, event_name: str):  # noqa: ARG002
                    def decorator(func):
                        return func

                    return decorator

                def get(self, path: str, **kwargs):  # noqa: ARG002
                    def decorator(func):
                        return func

                    return decorator

                def post(self, path: str, **kwargs):  # noqa: ARG002
                    def decorator(func):
                        return func

                    return decorator

            def Body(default=None, **kwargs):  # noqa: ARG001, N802
                return default

            def Query(default=None, **kwargs):  # noqa: ARG001, N802
                return default

            fastapi_stub.Body = Body
            fastapi_stub.FastAPI = FastAPI
            fastapi_stub.HTTPException = HTTPException
            fastapi_stub.Query = Query
            fastapi_stub.Request = object
            sys.modules["fastapi"] = fastapi_stub
            self.fastapi_stubbed = True
        syslog_stub = types.ModuleType("services.ingest.syslog_server")

        async def create_syslog_servers(*args, **kwargs):  # noqa: ARG001
            return []

        syslog_stub.create_syslog_servers = create_syslog_servers
        sys.modules["services.ingest.syslog_server"] = syslog_stub
        self.redis_client = importlib.import_module("services.ingest.redis_client")
        self.app = importlib.import_module("services.ingest.app")
        self.app._settings = SimpleNamespace(env="test", instance_name="ingest-test", syslog_profiles=lambda: {"linux-auth": 1514})
        self.app._syslog_servers = []
        self.fake_redis = _FakeRedis()
        self.fake_transport = _FakeTransportProducer()
        self.app._redis = self.fake_redis
        self.app._transport_producer = self.fake_transport
        self.original_env = {
            key: os.environ.get(key)
            for key in (
                "SIEM_INGEST_API_SHARED_SECRET",
                "SIEM_INGEST_BASE_URL",
                "SIEM_WEBHOOK_SHARED_SECRET",
                "SIEM_INGEST_RAW_STREAM_MAX_LEN",
                "SIEM_INGEST_RAW_STREAM_SOFT_LIMIT",
                "SIEM_INGEST_RAW_STREAM_HARD_LIMIT",
                "SIEM_TRANSPORT_BACKEND",
                "SIEM_TRANSPORT_CONSUMER_BACKEND",
                "SIEM_KAFKA_BOOTSTRAP_SERVERS",
            )
        }
        for key in self.original_env:
            os.environ.pop(key, None)

    def tearDown(self) -> None:
        self.app._settings = None
        self.app._redis = None
        self.app._transport_producer = None
        self.app._syslog_servers = []
        if self.fastapi_stubbed:
            sys.modules.pop("fastapi", None)
        for key, value in self.original_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value

    async def test_push_raw_event_updates_metrics_and_health(self) -> None:
        stream_id = await self.redis_client.push_raw_event(
            self.fake_redis,
            {
                "source": "192.168.1.42",
                "source_type": "windows_event_json",
                "collector": "windows_http",
                "collector_profile": "windows-security-http",
                "event.dataset": "windows-security-http",
                "ts": "2026-03-13T00:00:00Z",
            },
        )

        overview = await self.redis_client.build_ingest_overview(self.fake_redis, self.app._settings)

        self.assertEqual(stream_id, "1-0")
        self.assertEqual(overview["metrics"]["accepted_total"], 1)
        self.assertEqual(overview["metrics"]["received_total"], 1)
        self.assertEqual(overview["sources"]["metrics"]["total"], 1)
        self.assertEqual(overview["collectors"]["metrics"]["total"], 1)

    async def test_ingest_overview_uses_cached_resolved_dlq_total(self) -> None:
        await self.fake_redis.hset(
            self.redis_client.INGEST_METRICS_HASH_KEY,
            mapping={
                "dlq_total": "456914",
                "resolved_dlq_total": "456900",
            },
        )

        with mock.patch.object(
            self.redis_client,
            "_load_replay_records",
            new=mock.AsyncMock(side_effect=AssertionError("full replay scan not expected")),
        ):
            overview = await self.redis_client.build_ingest_overview(self.fake_redis, self.app._settings)

        self.assertEqual(overview["dlq"]["replayed"], 456900)
        self.assertEqual(overview["dlq"]["outstanding"], 14)

    async def test_relocated_source_aliases_use_current_network_identities(self) -> None:
        expected = {
            "192.168.3.81": "DESKTOP-5JMJVBH",
            "192.168.3.101": "pve",
            "192.168.3.102": "lab-edge-01",
            "10.20.10.104": "siem-ingest",
            "10.20.10.108": "siem-transport",
            "10.20.20.100": "minecraft-01",
            "10.20.20.130": "gamepanel-01",
        }
        for source_id, alias in expected.items():
            with self.subTest(source_id=source_id):
                self.assertEqual(alias, self.redis_client._source_alias(source_id))

    async def test_source_health_hides_legacy_core_address(self) -> None:
        await self.redis_client.push_raw_event(
            self.fake_redis,
            {
                "source": "192.168.1.35",
                "source_type": "Platform",
                "collector": "host-runtime",
                "collector_profile": "host-runtime",
                "event.dataset": "host-runtime",
            },
        )

        sources = await self.redis_client.list_source_health(self.fake_redis)

        self.assertEqual(sources["items"][0]["id"], "siem-ingest")
        self.assertEqual(sources["items"][0]["source_alias"], "siem-ingest")

    async def test_source_health_merges_legacy_and_segmented_alias_records(self) -> None:
        for source in ("192.168.1.35", "10.20.10.104"):
            await self.redis_client.push_raw_event(
                self.fake_redis,
                {
                    "source": source,
                    "source_type": "Platform",
                    "collector": "syslog_tcp",
                    "collector_profile": "linux-audit",
                    "event.dataset": "linux-audit",
                },
            )

        sources = await self.redis_client.list_source_health(self.fake_redis)

        self.assertEqual(1, sources["metrics"]["total"])
        self.assertEqual(2, sources["metrics"]["events_total"])
        self.assertEqual("siem-ingest", sources["items"][0]["id"])
        self.assertEqual(2, sources["items"][0]["accepted_total"])

    async def test_record_ingest_acceptance_batch_defers_runtime_bookkeeping(self) -> None:
        accepted_events: list[dict[str, object]] = []
        for suffix in ("42", "43"):
            event = {
                "source": f"192.168.1.{suffix}",
                "source_type": "windows_event_json",
                "collector": "windows_http",
                "collector_profile": "windows-security-http",
                "event.dataset": "windows-security-http",
                "ts": "2026-03-13T00:00:00Z",
            }
            stream_id = await self.redis_client.push_raw_event(
                self.fake_redis,
                event,
                record_runtime_bookkeeping=False,
            )
            accepted_events.append({"event": event, "stream_id": stream_id, "replayed": False})

        overview_before = await self.redis_client.build_ingest_overview(self.fake_redis, self.app._settings)
        await self.redis_client.record_ingest_acceptance_batch(self.fake_redis, accepted_events, settings=self.app._settings)
        overview_after = await self.redis_client.build_ingest_overview(self.fake_redis, self.app._settings)

        self.assertEqual(overview_before["metrics"]["accepted_total"], 0)
        self.assertEqual(overview_before["sources"]["metrics"]["total"], 0)
        self.assertEqual(overview_after["metrics"]["accepted_total"], 2)
        self.assertEqual(overview_after["metrics"]["received_total"], 2)
        self.assertEqual(overview_after["sources"]["metrics"]["total"], 2)
        self.assertEqual(overview_after["collectors"]["metrics"]["total"], 1)

    async def test_synthetic_smoke_source_is_excluded_from_operational_metrics(self) -> None:
        await self.redis_client.push_raw_event(
            self.fake_redis,
            {
                "source": "vm1-smoke",
                "source_type": "synthetic",
                "collector": "http_json",
                "collector_profile": "generic-http",
                "event.dataset": "smoke",
                "tags": ["synthetic", "smoke"],
                "ts": "2026-03-13T00:00:00Z",
            },
        )

        sources = await self.redis_client.list_source_health(self.fake_redis)
        collectors = await self.redis_client.list_collector_health(self.fake_redis)

        self.assertEqual(sources["metrics"]["total"], 0)
        self.assertEqual(sources["metrics"]["synthetic"], 1)
        self.assertEqual(collectors["metrics"]["total"], 0)
        self.assertEqual(collectors["metrics"]["synthetic"], 1)
        self.assertEqual(sources["items"], [])
        sources_with_excluded = await self.redis_client.list_source_health(self.fake_redis, include_excluded=True)
        self.assertEqual(sources_with_excluded["items"][0]["status"], "synthetic")

    async def test_dead_letter_and_replay_flow(self) -> None:
        dlq_id = await self.redis_client.push_dead_letter_event(
            self.fake_redis,
            {"message": "broken", "source": "192.168.1.60"},
            reason="parser_failure",
            source_ip="192.168.1.60",
            collector="app_http",
            collector_profile="app-json-http",
            ingest_path="/ingest/app/json",
            metadata={"source_type": "http_json", "event.dataset": "app-json-http"},
        )

        dlq_state = await self.redis_client.list_dlq_events(self.fake_redis)
        replay_state = await self.redis_client.replay_dlq_events(self.fake_redis, ids=[dlq_id], actor="tester")
        overview = await self.redis_client.build_ingest_overview(self.fake_redis, self.app._settings)

        self.assertEqual(dlq_state["metrics"]["total"], 1)
        self.assertEqual(replay_state["replayed"], 1)
        self.assertEqual(overview["metrics"]["accepted_total"], 1)
        self.assertEqual(overview["metrics"]["replayed_total"], 1)
        self.assertEqual(overview["dlq"]["outstanding"], 0)

    async def test_historical_parser_errors_do_not_keep_overview_red_after_replay(self) -> None:
        dlq_id = await self.redis_client.push_dead_letter_event(
            self.fake_redis,
            {"message": "broken", "source": "192.168.1.60"},
            reason="parser_failure",
            source_ip="192.168.1.60",
            collector="app_http",
            collector_profile="app-json-http",
            ingest_path="/ingest/app/json",
            metadata={"source_type": "http_json", "event.dataset": "app-json-http"},
        )

        await self.redis_client.replay_dlq_events(self.fake_redis, ids=[dlq_id], actor="tester")
        stale_dlq_ts = (datetime.now(tz=timezone.utc) - timedelta(seconds=self.redis_client.HEALTH_STALE_SECONDS + 60)).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        await self.fake_redis.hset(self.redis_client.INGEST_METRICS_HASH_KEY, "last_dlq_ts", stale_dlq_ts)

        overview = await self.redis_client.build_ingest_overview(self.fake_redis, self.app._settings)

        self.assertEqual(overview["dlq"]["outstanding"], 0)
        self.assertNotIn("Parser errors recorded: 1", overview["issues"])

    async def test_replay_marks_scalar_dlq_payload_as_failed(self) -> None:
        dlq_id = await self.redis_client.push_dead_letter_event(
            self.fake_redis,
            "invalid",
            reason="payload_item_not_object",
            source_ip="192.168.1.70",
            collector="http_json",
            collector_profile="generic-http",
            ingest_path="/ingest/json",
        )

        replay_state = await self.redis_client.replay_dlq_events(self.fake_redis, ids=[dlq_id], actor="tester")
        overview = await self.redis_client.build_ingest_overview(self.fake_redis, self.app._settings)

        self.assertEqual(replay_state["failed"], 1)
        self.assertEqual(replay_state["items"][0]["reason"], "payload_not_object")
        self.assertEqual(overview["dlq"]["outstanding"], 0)

    async def test_replay_auto_select_skips_terminal_failed_items(self) -> None:
        failed_id = await self.redis_client.push_dead_letter_event(
            self.fake_redis,
            "invalid",
            reason="payload_item_not_object",
            source_ip="192.168.1.70",
            collector="http_json",
            collector_profile="generic-http",
            ingest_path="/ingest/json",
        )
        valid_id = await self.redis_client.push_dead_letter_event(
            self.fake_redis,
            {"message": "ok", "source": "192.168.1.71"},
            reason="parser_failure",
            source_ip="192.168.1.71",
            collector="http_json",
            collector_profile="generic-http",
            ingest_path="/ingest/json",
            metadata={"source_type": "http_json", "event.dataset": "generic-http"},
        )

        failed_replay = await self.redis_client.replay_dlq_events(self.fake_redis, ids=[failed_id], actor="tester")
        next_replay = await self.redis_client.replay_dlq_events(self.fake_redis, limit=1, actor="tester")

        self.assertEqual(failed_replay["failed"], 1)
        self.assertEqual(next_replay["replayed"], 1)
        self.assertEqual(next_replay["items"][0]["id"], valid_id)

    async def test_replay_auto_select_skips_scalar_payload_candidates(self) -> None:
        await self.redis_client.push_dead_letter_event(
            self.fake_redis,
            "invalid",
            reason="payload_item_not_object",
            source_ip="192.168.1.70",
            collector="http_json",
            collector_profile="generic-http",
            ingest_path="/ingest/json",
        )
        valid_id = await self.redis_client.push_dead_letter_event(
            self.fake_redis,
            {"message": "ok", "source": "192.168.1.71"},
            reason="parser_failure",
            source_ip="192.168.1.71",
            collector="http_json",
            collector_profile="generic-http",
            ingest_path="/ingest/json",
            metadata={"source_type": "http_json", "event.dataset": "generic-http"},
        )

        next_replay = await self.redis_client.replay_dlq_events(self.fake_redis, limit=1, actor="tester")

        self.assertEqual(next_replay["replayed"], 1)
        self.assertEqual(next_replay["failed"], 0)
        self.assertEqual(next_replay["items"][0]["id"], valid_id)

    async def test_replay_auto_select_scans_beyond_recently_resolved_window(self) -> None:
        ids: list[str] = []
        for index in range(205):
            ids.append(
                await self.redis_client.push_dead_letter_event(
                    self.fake_redis,
                    {"message": f"broken-{index}", "source": f"192.168.1.{100 + index}"},
                    reason="parser_failure",
                    source_ip=f"192.168.1.{100 + index}",
                    collector="http_json",
                    collector_profile="generic-http",
                    ingest_path="/ingest/json",
                    metadata={"source_type": "http_json", "event.dataset": "generic-http"},
                )
            )

        newest_first = list(reversed(ids))
        initial = await self.redis_client.replay_dlq_events(self.fake_redis, ids=newest_first[:200], actor="tester")
        next_replay = await self.redis_client.replay_dlq_events(self.fake_redis, limit=1, actor="tester")

        self.assertEqual(initial["replayed"], 200)
        self.assertEqual(next_replay["replayed"], 1)
        self.assertEqual(next_replay["items"][0]["id"], newest_first[200])

    async def test_replay_uses_transport_producer_for_kafka_backend(self) -> None:
        os.environ["SIEM_TRANSPORT_BACKEND"] = "kafka"
        dlq_id = await self.redis_client.push_dead_letter_event(
            self.fake_redis,
            {"message": "needs-replay", "source": "192.168.1.90"},
            reason="parser_failure",
            source_ip="192.168.1.90",
            collector="http_json",
            collector_profile="generic-http",
            ingest_path="/ingest/json",
            metadata={"source_type": "http_json", "event.dataset": "generic-http"},
        )

        replay_state = await self.redis_client.replay_dlq_events(
            self.fake_redis,
            ids=[dlq_id],
            actor="tester",
            settings=self.app._settings,
            producer=self.fake_transport,
        )

        self.assertEqual(replay_state["replayed"], 1)
        self.assertEqual(len(self.fake_transport.calls), 1)
        self.assertEqual(self.fake_transport.calls[0]["alias"], "raw")

    async def test_suppress_non_operational_dlq_marks_rsyslog_noise_resolved(self) -> None:
        dlq_id = await self.redis_client.push_dead_letter_event(
            self.fake_redis,
            {
                "message": "<43>Mar 29 16:34:57 vpn-host-khanov rsyslogd: omfwd: remote server at 127.0.0.1:5517 seems to have closed connection.",
                "source": "127.0.0.1",
            },
            reason="syslog_push_failed",
            source_ip="127.0.0.1",
            collector="syslog_tcp",
            collector_profile="linux-auth",
            ingest_path="tcp://0.0.0.0:1514",
            metadata={"error": "ProducerClosed"},
        )

        cleanup = await self.redis_client.suppress_non_operational_dlq_events(self.fake_redis, actor="tester", limit=100)
        overview = await self.redis_client.build_ingest_overview(self.fake_redis, self.app._settings)
        dlq_state = await self.redis_client.list_dlq_events(self.fake_redis, count=20)

        self.assertEqual(cleanup["suppressed"], 1)
        self.assertEqual(overview["dlq"]["outstanding"], 0)
        self.assertEqual(dlq_state["metrics"]["replayed"], 1)
        self.assertEqual(dlq_state["metrics"]["visible"], 0)
        replay_row = json.loads(self.fake_redis.hashes[self.redis_client.DLQ_REPLAY_HASH_KEY][dlq_id])
        self.assertEqual(replay_row["status"], "ignored")

    async def test_ingest_json_partially_accepts_invalid_list_items(self) -> None:
        result = await self.app._ingest_json(
            _request("/ingest/json"),
            [{"message": "ok"}, "broken"],
            default_source_type="http_json",
            collector="http_json",
            collector_profile="generic-http",
            ingest_profile="generic-http",
        )

        dlq_state = await self.redis_client.list_dlq_events(self.fake_redis)

        self.assertEqual(result["status"], "partial_ok")
        self.assertEqual(result["ingested"], 1)
        self.assertEqual(result["rejected"], 1)
        self.assertEqual(dlq_state["metrics"]["total"], 1)

    async def test_ingest_json_batches_runtime_bookkeeping_for_valid_items(self) -> None:
        result = await self.app._ingest_json(
            _request("/ingest/json"),
            [{"message": "first"}, {"message": "second"}],
            default_source_type="http_json",
            collector="app_http",
            collector_profile="app-json-http",
            ingest_profile="app-json-http",
        )

        overview = await self.redis_client.build_ingest_overview(self.fake_redis, self.app._settings)

        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["ingested"], 2)
        self.assertEqual(result["rejected"], 0)
        self.assertEqual(overview["metrics"]["accepted_total"], 2)
        self.assertEqual(overview["sources"]["metrics"]["total"], 0)
        self.assertEqual(overview["sources"]["metrics"]["excluded"], 1)
        self.assertEqual(overview["collectors"]["metrics"]["total"], 1)

    async def test_ingest_json_uses_kafka_batch_publish_for_valid_items(self) -> None:
        os.environ["SIEM_TRANSPORT_BACKEND"] = "kafka"

        result = await self.app._ingest_json(
            _request("/ingest/json"),
            [{"message": "first"}, {"message": "second"}],
            default_source_type="http_json",
            collector="app_http",
            collector_profile="app-json-http",
            ingest_profile="app-json-http",
        )

        overview = await self.redis_client.build_ingest_overview(self.fake_redis, self.app._settings)

        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["ingested"], 2)
        self.assertEqual(len(self.fake_transport.calls), 2)
        self.assertTrue(all(call.get("batch") for call in self.fake_transport.calls))
        self.assertEqual(overview["metrics"]["accepted_total"], 2)
        self.assertEqual(overview["streams"]["raw"]["length"], 0)

    async def test_generic_http_source_is_excluded_from_health_gating(self) -> None:
        await self.app._ingest_json(
            _request("/ingest/json"),
            [{"message": "first", "source": "generic-http"}],
            default_source_type="http_json",
            collector="http_json",
            collector_profile="generic-http",
            ingest_profile="generic-http",
        )

        stale_ts = (
            datetime.now(tz=timezone.utc) - timedelta(seconds=self.redis_client.HEALTH_STALE_SECONDS + 60)
        ).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        raw = await self.fake_redis.hget(self.redis_client.SOURCE_HEALTH_HASH_KEY, "generic-http")
        row = json.loads(raw)
        row["last_seen_ts"] = stale_ts
        row["last_event_ts"] = stale_ts
        await self.fake_redis.hset(self.redis_client.SOURCE_HEALTH_HASH_KEY, "generic-http", json.dumps(row))
        collector_raw = await self.fake_redis.hget(self.redis_client.COLLECTOR_HEALTH_HASH_KEY, "generic-http")
        collector_row = json.loads(collector_raw)
        collector_row["last_seen_ts"] = stale_ts
        collector_row["last_event_ts"] = stale_ts
        await self.fake_redis.hset(self.redis_client.COLLECTOR_HEALTH_HASH_KEY, "generic-http", json.dumps(collector_row))

        overview = await self.redis_client.build_ingest_overview(self.fake_redis, self.app._settings)
        sources = await self.redis_client.list_source_health(self.fake_redis)
        collectors = await self.redis_client.list_collector_health(self.fake_redis)
        sources_with_excluded = await self.redis_client.list_source_health(self.fake_redis, include_excluded=True)
        collectors_with_excluded = await self.redis_client.list_collector_health(self.fake_redis, include_excluded=True)

        self.assertEqual(overview["sources"]["metrics"]["stale"], 0)
        self.assertEqual(overview["collectors"]["metrics"]["stale"], 0)
        self.assertEqual(sources["items"], [])
        self.assertEqual(collectors["items"], [])
        self.assertTrue(sources_with_excluded["items"][0]["health_gating_excluded"])
        self.assertTrue(collectors_with_excluded["items"][0]["health_gating_excluded"])
        self.assertNotIn("Stale sources detected: 1", overview["issues"])
        self.assertNotIn("Stale collectors detected: 1", overview["issues"])

    async def test_network_collector_uses_relaxed_freshness_thresholds(self) -> None:
        await self.redis_client.push_raw_event(
            self.fake_redis,
            {
                "source": "192.168.1.254",
                "collector": "syslog_tcp",
                "collector_profile": "network",
                "ingest_profile": "network",
                "event.dataset": "network-syslog",
                "message": "link up",
            },
        )

        aged_ts = (
            datetime.now(tz=timezone.utc) - timedelta(seconds=4_500)
        ).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        collector_raw = await self.fake_redis.hget(self.redis_client.COLLECTOR_HEALTH_HASH_KEY, "network")
        collector_row = json.loads(collector_raw)
        collector_row["last_seen_ts"] = aged_ts
        collector_row["last_event_ts"] = aged_ts
        await self.fake_redis.hset(self.redis_client.COLLECTOR_HEALTH_HASH_KEY, "network", json.dumps(collector_row))

        collectors = await self.redis_client.list_collector_health(self.fake_redis, include_excluded=True)
        overview = await self.redis_client.build_ingest_overview(self.fake_redis, self.app._settings)

        self.assertEqual(collectors["items"][0]["source_type"], "Network")
        self.assertEqual(collectors["items"][0]["status"], "delayed")
        self.assertEqual(collectors["metrics"]["stale"], 0)
        self.assertNotIn("Stale collectors detected: 1", overview["issues"])

    async def test_event_driven_sensor_does_not_go_stale_between_findings(self) -> None:
        await self.redis_client.push_raw_event(
            self.fake_redis,
            {
                "source": "soc-ti-01",
                "source_type": "misp",
                "collector": "misp-forwarder",
                "collector_profile": "misp-json",
                "event.dataset": "misp.attribute",
            },
        )
        aged_ts = (
            datetime.now(tz=timezone.utc) - timedelta(days=1)
        ).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        source_row = await self.redis_client._load_hash_record(
            self.fake_redis,
            self.redis_client.SOURCE_HEALTH_HASH_KEY,
            "soc-ti-01",
        )
        collector_row = await self.redis_client._load_hash_record(
            self.fake_redis,
            self.redis_client.COLLECTOR_HEALTH_HASH_KEY,
            "misp-json",
        )
        for row in (source_row, collector_row):
            row["last_seen_ts"] = aged_ts
            row["last_event_ts"] = aged_ts
        await self.redis_client._save_hash_record(
            self.fake_redis,
            self.redis_client.SOURCE_HEALTH_HASH_KEY,
            "soc-ti-01",
            source_row,
        )
        await self.redis_client._save_hash_record(
            self.fake_redis,
            self.redis_client.COLLECTOR_HEALTH_HASH_KEY,
            "misp-json",
            collector_row,
        )

        sources = await self.redis_client.list_source_health(self.fake_redis)
        collectors = await self.redis_client.list_collector_health(self.fake_redis)

        self.assertEqual("healthy", sources["items"][0]["status"])
        self.assertEqual("healthy", collectors["items"][0]["status"])

    async def test_low_volume_control_plane_sensors_are_event_driven(self) -> None:
        for provider in ("step-ca", "minio", "velociraptor"):
            await self.redis_client.push_raw_event(
                self.fake_redis,
                {
                    "source": f"soc-{provider}",
                    "source_type": "unknown",
                    "collector": f"{provider}-forwarder",
                    "collector_profile": f"{provider}-json",
                    "ingest_profile": f"{provider}-json",
                    "event.dataset": f"{provider}.audit",
                },
            )

        aged_ts = (
            datetime.now(tz=timezone.utc) - timedelta(days=1)
        ).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        for provider in ("step-ca", "minio", "velociraptor"):
            source_key = f"soc-{provider}"
            source_row = await self.redis_client._load_hash_record(
                self.fake_redis,
                self.redis_client.SOURCE_HEALTH_HASH_KEY,
                source_key,
            )
            collector_row = await self.redis_client._load_hash_record(
                self.fake_redis,
                self.redis_client.COLLECTOR_HEALTH_HASH_KEY,
                f"{provider}-json",
            )
            for row in (source_row, collector_row):
                row["last_seen_ts"] = aged_ts
                row["last_event_ts"] = aged_ts
            await self.redis_client._save_hash_record(
                self.fake_redis,
                self.redis_client.SOURCE_HEALTH_HASH_KEY,
                source_key,
                source_row,
            )
            await self.redis_client._save_hash_record(
                self.fake_redis,
                self.redis_client.COLLECTOR_HEALTH_HASH_KEY,
                f"{provider}-json",
                collector_row,
            )

        sources = await self.redis_client.list_source_health(self.fake_redis)
        collectors = await self.redis_client.list_collector_health(self.fake_redis)

        self.assertEqual({"healthy"}, {item["status"] for item in sources["items"]})
        self.assertEqual({"healthy"}, {item["status"] for item in collectors["items"]})
        self.assertEqual(
            {"Event-driven"},
            {item["source_type"] for item in sources["items"] + collectors["items"]},
        )

    async def test_retired_and_malformed_sensor_sources_are_not_health_gates(self) -> None:
        for event in (
            {
                "source": "openclaw-gateway",
                "source_type": "platform_host_runtime",
                "collector_profile": "openclaw-gateway",
            },
            {
                "source": "HTTP",
                "source_type": "zeek",
                "collector_profile": "zeek-json",
            },
        ):
            await self.redis_client.push_raw_event(
                self.fake_redis,
                {
                    **event,
                    "collector": "sensor-forwarder",
                    "event.dataset": "sensor.event",
                },
            )

        sources = await self.redis_client.list_source_health(self.fake_redis)
        sources_with_excluded = await self.redis_client.list_source_health(
            self.fake_redis,
            include_excluded=True,
        )

        self.assertEqual([], sources["items"])
        self.assertEqual(2, sources_with_excluded["metrics"]["excluded"])

    async def test_orphaned_legacy_collectors_are_excluded_from_health_gating(self) -> None:
        aged_ts = (
            datetime.now(tz=timezone.utc) - timedelta(seconds=22_000)
        ).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        orphaned_collector = {
            "id": "vpn",
            "collector": "syslog_tcp",
            "collector_profile": "vpn",
            "ingest_profile": "vpn",
            "first_seen_ts": aged_ts,
            "last_seen_ts": aged_ts,
            "last_event_ts": aged_ts,
            "last_stream_id": "1-0",
            "events_total": 42,
            "accepted_total": 42,
            "rejected_total": 0,
            "replayed_total": 0,
            "synthetic_total": 0,
            "last_error": "",
        }
        await self.redis_client._save_hash_record(
            self.fake_redis,
            self.redis_client.COLLECTOR_HEALTH_HASH_KEY,
            "vpn",
            orphaned_collector,
        )

        collectors = await self.redis_client.list_collector_health(self.fake_redis, include_excluded=True)
        overview = await self.redis_client.build_ingest_overview(self.fake_redis, self.app._settings)

        self.assertEqual(collectors["metrics"]["stale"], 0)
        self.assertEqual(collectors["metrics"]["excluded"], 1)
        self.assertTrue(collectors["items"][0]["health_gating_excluded"])
        self.assertEqual(collectors["items"][0]["health_gating_reason"], "orphaned_legacy_collector")
        self.assertNotIn("Stale collectors detected: 1", overview["issues"])

    async def test_superseded_collector_aliases_do_not_mask_live_canonical_profiles(self) -> None:
        now_ts = datetime.now(tz=timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        aged_ts = (
            datetime.now(tz=timezone.utc) - timedelta(seconds=22_000)
        ).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        pairs = (
            ("minecraft", "game-server", "minecraft-01", "linux-auth"),
            ("threat-intelligence", "threat-intel", "soc-ti-01", "threat-intel"),
        )
        for legacy_profile, canonical_profile, source_name, source_profile in pairs:
            source_row = {
                "id": source_name,
                "source": source_name,
                "source_alias": source_name,
                "source_type": "Platform",
                "collector": "host_runtime_agent",
                "collector_profile": source_profile,
                "ingest_profile": "host-runtime",
                "first_seen_ts": now_ts,
                "last_seen_ts": now_ts,
                "last_event_ts": now_ts,
                "last_stream_id": "2-0",
                "events_total": 10,
                "accepted_total": 10,
                "rejected_total": 0,
                "replayed_total": 0,
                "synthetic_total": 0,
                "last_error": "",
            }
            legacy_collector = {
                "id": legacy_profile,
                "collector": "host_runtime_agent",
                "collector_profile": legacy_profile,
                "ingest_profile": "host-runtime",
                "first_seen_ts": aged_ts,
                "last_seen_ts": aged_ts,
                "last_event_ts": aged_ts,
                "last_stream_id": "1-0",
                "events_total": 2,
                "accepted_total": 2,
                "rejected_total": 0,
                "replayed_total": 0,
                "synthetic_total": 0,
                "last_error": "",
            }
            canonical_collector = {
                **legacy_collector,
                "id": canonical_profile,
                "collector_profile": canonical_profile,
                "first_seen_ts": now_ts,
                "last_seen_ts": now_ts,
                "last_event_ts": now_ts,
                "last_stream_id": "3-0",
                "events_total": 20,
                "accepted_total": 20,
            }
            await self.redis_client._save_hash_record(
                self.fake_redis,
                self.redis_client.SOURCE_HEALTH_HASH_KEY,
                source_name,
                source_row,
            )
            await self.redis_client._save_hash_record(
                self.fake_redis,
                self.redis_client.COLLECTOR_HEALTH_HASH_KEY,
                legacy_profile,
                legacy_collector,
            )
            await self.redis_client._save_hash_record(
                self.fake_redis,
                self.redis_client.COLLECTOR_HEALTH_HASH_KEY,
                canonical_profile,
                canonical_collector,
            )

        collectors = await self.redis_client.list_collector_health(
            self.fake_redis,
            include_excluded=True,
        )
        overview = await self.redis_client.build_ingest_overview(self.fake_redis, self.app._settings)
        aliases = {
            item["id"]: item
            for item in collectors["items"]
            if item["id"] in {"minecraft", "threat-intelligence"}
        }

        self.assertEqual(2, collectors["metrics"]["excluded"])
        self.assertEqual(2, collectors["metrics"]["healthy"])
        self.assertEqual(0, collectors["metrics"]["stale"])
        self.assertEqual(
            {"superseded_collector_alias"},
            {item["health_gating_reason"] for item in aliases.values()},
        )
        self.assertNotIn("Stale collectors detected: 2", overview["issues"])

    async def test_replay_scans_past_latest_resolved_tail_to_find_older_unresolved_items(self) -> None:
        unresolved_ids: list[str] = []
        for index in range(2200):
            dlq_id = await self.redis_client.push_dead_letter_event(
                self.fake_redis,
                {"message": f"broken-{index}", "source": f"192.168.1.{index % 200}"},
                reason="parser_failure",
                source_ip=f"192.168.1.{index % 200}",
                collector="syslog_tcp",
                collector_profile="linux-auth",
                ingest_path="/ingest/json",
            )
            if index < 50:
                unresolved_ids.append(dlq_id)
            else:
                await self.redis_client._save_hash_record(
                    self.fake_redis,
                    self.redis_client.DLQ_REPLAY_HASH_KEY,
                    dlq_id,
                    {"id": dlq_id, "status": "success", "actor": "tester", "ts": "2026-04-09T00:00:00Z"},
                )

        replay_state = await self.redis_client.replay_dlq_events(self.fake_redis, limit=20, actor="tester")

        self.assertEqual(replay_state["replayed"], 20)
        self.assertTrue(all(item["id"] in unresolved_ids for item in replay_state["items"]))

    async def test_admin_secret_is_enforced_for_runtime_routes(self) -> None:
        os.environ["SIEM_INGEST_API_SHARED_SECRET"] = "test-secret"

        with self.assertRaisesRegex(Exception, "invalid_ingest_runtime_secret"):
            await self.app.health_overview(_request("/health/overview", headers={}))

        payload = await self.app.health_overview(_request("/health/overview", headers={"x-rdegon-ingest-secret": "test-secret"}))
        self.assertIn("metrics", payload)

    async def test_backpressure_diverts_events_to_dlq_before_stream_trim(self) -> None:
        os.environ["SIEM_TRANSPORT_BACKEND"] = "redis"
        os.environ["SIEM_INGEST_RAW_STREAM_MAX_LEN"] = "3"
        os.environ["SIEM_INGEST_RAW_STREAM_SOFT_LIMIT"] = "1"
        os.environ["SIEM_INGEST_RAW_STREAM_HARD_LIMIT"] = "1"

        first_id = await self.redis_client.push_raw_event(
            self.fake_redis,
            {
                "source": "192.168.1.90",
                "source_type": "http_json",
                "collector": "app_http",
                "collector_profile": "app-json-http",
                "event.dataset": "app-json-http",
            },
        )
        self.assertEqual(first_id, "1-0")

        with self.assertRaises(self.redis_client.IngestBackpressureError):
            await self.redis_client.push_raw_event(
                self.fake_redis,
                {
                    "source": "192.168.1.90",
                    "source_type": "http_json",
                    "collector": "app_http",
                    "collector_profile": "app-json-http",
                    "event.dataset": "app-json-http",
                },
            )

        overview = await self.redis_client.build_ingest_overview(self.fake_redis, self.app._settings)
        self.assertEqual(overview["metrics"]["backpressure_total"], 1)
        self.assertEqual(overview["streams"]["raw"]["length"], 1)
        self.assertEqual(overview["dlq"]["total"], 1)

    async def test_hard_limit_allows_push_when_normalizer_group_is_draining(self) -> None:
        os.environ["SIEM_TRANSPORT_BACKEND"] = "redis"
        os.environ["SIEM_INGEST_RAW_STREAM_MAX_LEN"] = "3"
        os.environ["SIEM_INGEST_RAW_STREAM_SOFT_LIMIT"] = "1"
        os.environ["SIEM_INGEST_RAW_STREAM_HARD_LIMIT"] = "1"
        self.fake_redis.groups[self.redis_client.RAW_STREAM_KEY] = [
            {
                "name": "normalizer",
                "pending": 0,
            }
        ]

        first_id = await self.redis_client.push_raw_event(
            self.fake_redis,
            {
                "source": "192.168.1.90",
                "source_type": "http_json",
                "collector": "app_http",
                "collector_profile": "app-json-http",
                "event.dataset": "app-json-http",
            },
        )
        second_id = await self.redis_client.push_raw_event(
            self.fake_redis,
            {
                "source": "192.168.1.91",
                "source_type": "http_json",
                "collector": "app_http",
                "collector_profile": "app-json-http",
                "event.dataset": "app-json-http",
            },
        )

        overview = await self.redis_client.build_ingest_overview(self.fake_redis, self.app._settings)
        self.assertEqual(first_id, "1-0")
        self.assertEqual(second_id, "2-0")
        self.assertEqual(overview["metrics"]["backpressure_total"], 0)
        self.assertEqual(overview["streams"]["raw"]["length"], 2)

    async def test_vulnerability_scanner_sources_use_relaxed_staleness_thresholds(self) -> None:
        await self.redis_client.push_raw_event(
            self.fake_redis,
            {
                "source": "192.168.1.121",
                "collector": "vulnscanner-http",
                "collector_profile": "vulnscanner-http",
                "event.dataset": "vuln-report",
            },
        )
        aged_ts = (datetime.now(tz=timezone.utc) - timedelta(seconds=4_000)).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        source_row = await self.redis_client._load_hash_record(self.fake_redis, self.redis_client.SOURCE_HEALTH_HASH_KEY, "192.168.1.121")
        collector_row = await self.redis_client._load_hash_record(self.fake_redis, self.redis_client.COLLECTOR_HEALTH_HASH_KEY, "vulnscanner-http")
        source_row["last_seen_ts"] = aged_ts
        source_row["last_event_ts"] = aged_ts
        collector_row["last_seen_ts"] = aged_ts
        collector_row["last_event_ts"] = aged_ts
        await self.redis_client._save_hash_record(self.fake_redis, self.redis_client.SOURCE_HEALTH_HASH_KEY, "192.168.1.121", source_row)
        await self.redis_client._save_hash_record(self.fake_redis, self.redis_client.COLLECTOR_HEALTH_HASH_KEY, "vulnscanner-http", collector_row)

        sources = await self.redis_client.list_source_health(self.fake_redis)
        collectors = await self.redis_client.list_collector_health(self.fake_redis)

        self.assertEqual(sources["items"][0]["source_type"], "Vulnerability scanner")
        self.assertEqual(sources["items"][0]["status"], "delayed")
        self.assertEqual(collectors["items"][0]["source_type"], "Vulnerability scanner")
        self.assertEqual(collectors["items"][0]["status"], "delayed")
        self.assertEqual(sources["metrics"]["stale"], 0)
        self.assertEqual(collectors["metrics"]["stale"], 0)

    async def test_kafka_transport_uses_producer_and_reports_cutover_state(self) -> None:
        os.environ["SIEM_TRANSPORT_BACKEND"] = "kafka"
        os.environ["SIEM_KAFKA_BOOTSTRAP_SERVERS"] = "192.168.1.35:9092,192.168.1.37:9092,192.168.1.40:9092"

        stream_id = await self.redis_client.push_raw_event(
            self.fake_redis,
            {
                "source": "192.168.1.95",
                "source_type": "http_json",
                "collector": "app_http",
                "collector_profile": "app-json-http",
                "event.dataset": "app-json-http",
            },
            settings=self.app._settings,
            producer=self.fake_transport,
        )

        transport = await self.app.health_transport(_request("/health/transport"))

        self.assertEqual(stream_id, "raw:0:1")
        self.assertEqual(len(self.fake_transport.calls), 1)
        self.assertEqual(transport["backend"], "kafka")
        self.assertEqual(transport["cutover_stage"], "kafka_only")
        self.assertEqual(transport["raw_target"], "siem.raw")
        self.assertEqual(transport["streams"]["raw"]["length"], 0)


class IngestRuntimeProxyTests(unittest.TestCase):
    def setUp(self) -> None:
        self.original_env = {key: os.environ.get(key) for key in ("SIEM_INGEST_BASE_URL", "SIEM_INGEST_API_SHARED_SECRET", "SIEM_WEBHOOK_SHARED_SECRET")}
        for key in self.original_env:
            os.environ.pop(key, None)
        sys.modules.pop("ingest_runtime", None)

    def tearDown(self) -> None:
        for key, value in self.original_env.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        sys.modules.pop("ingest_runtime", None)

    def _start_server(self, response_payload: dict[str, object]):
        captured: list[dict[str, str]] = []
        body = json.dumps(response_payload).encode("utf-8")

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                self._respond()

            def do_POST(self):  # noqa: N802
                self._respond()

            def log_message(self, format: str, *args) -> None:  # noqa: A003
                return

            def _respond(self) -> None:
                raw_length = int(self.headers.get("Content-Length") or 0)
                raw_body = self.rfile.read(raw_length) if raw_length else b""
                captured.append(
                    {
                        "method": self.command,
                        "path": self.path,
                        "secret": str(self.headers.get("X-Rdegon-Ingest-Secret") or ""),
                        "body": raw_body.decode("utf-8", errors="replace"),
                    }
                )
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(body)

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        return server, thread, captured, f"http://127.0.0.1:{server.server_address[1]}"

    def test_proxy_uses_expected_paths_and_headers(self) -> None:
        server, thread, captured, base_url = self._start_server({"items": [], "metrics": {}})
        try:
            os.environ["SIEM_INGEST_BASE_URL"] = base_url
            os.environ["SIEM_INGEST_API_SHARED_SECRET"] = "proxy-secret"
            try:
                module = importlib.import_module("ingest_runtime")
            except ModuleNotFoundError:
                module = _load_module_by_path(
                    "ingest_runtime",
                    "ingest_runtime.py",
                    "services/web/app/ingest_runtime.py",
                )

            module.get_ingest_overview()
            module.get_ingest_transport_health()
            module.list_ingest_sources(limit=33)
            module.replay_ingest_dlq(ids=["1-0"], actor="tester")

            self.assertEqual(captured[0]["path"], "/health/overview")
            self.assertEqual(captured[1]["path"], "/health/transport")
            self.assertEqual(captured[2]["path"], "/health/sources?limit=33")
            self.assertEqual(captured[3]["path"], "/dlq/replay")
            self.assertEqual(captured[3]["secret"], "proxy-secret")
            self.assertIn("\"ids\": [\"1-0\"]", captured[3]["body"])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
