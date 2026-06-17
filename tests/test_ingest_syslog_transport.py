import unittest
from types import SimpleNamespace

from services.ingest import syslog_server


class _FakeReader:
    def __init__(self, lines: list[bytes]) -> None:
        self._lines = list(lines)

    async def readline(self) -> bytes:
        if self._lines:
            return self._lines.pop(0)
        return b""


class _FakeWriter:
    def __init__(self, peername: tuple[str, int]) -> None:
        self._peername = peername
        self.closed = False

    def get_extra_info(self, key: str):
        if key == "peername":
            return self._peername
        return None

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        return None


class SyslogTransportTests(unittest.IsolatedAsyncioTestCase):
    async def test_syslog_server_enables_reuse_port_for_multi_worker_ingest(self) -> None:
        settings = SimpleNamespace(
            ingest_syslog_host="0.0.0.0",
            syslog_profiles=lambda: {"linux-auth": 1514},
        )
        redis = object()
        producer = object()
        server = syslog_server.SyslogTcpServer(settings, redis, producer, "linux-auth", 1514)
        captured: dict[str, object] = {}

        class _FakeAsyncServer:
            sockets = [SimpleNamespace(getsockname=lambda: ("0.0.0.0", 1514))]

            def close(self) -> None:
                return None

            async def wait_closed(self) -> None:
                return None

        async def fake_start_server(handler, *, host, port, reuse_port):  # noqa: ARG001
            captured["host"] = host
            captured["port"] = port
            captured["reuse_port"] = reuse_port
            return _FakeAsyncServer()

        original = syslog_server.asyncio.start_server
        syslog_server.asyncio.start_server = fake_start_server
        try:
            await server.start()
            await server.stop()
        finally:
            syslog_server.asyncio.start_server = original

        self.assertEqual(captured["host"], "0.0.0.0")
        self.assertEqual(captured["port"], 1514)
        self.assertTrue(captured["reuse_port"])

    async def test_syslog_handler_uses_transport_producer_batch(self) -> None:
        settings = SimpleNamespace(
            ingest_syslog_host="0.0.0.0",
            syslog_profiles=lambda: {"linux-auth": 1514},
        )
        redis = object()
        producer = object()
        server = syslog_server.SyslogTcpServer(settings, redis, producer, "linux-auth", 1514)
        reader = _FakeReader([b"<14>test message 1\n", b"<14>test message 2\n", b""])
        writer = _FakeWriter(("192.168.1.50", 5514))
        captured: dict[str, object] = {}

        async def fake_push_raw_events_batch(redis_arg, events_arg, *, settings=None, producer=None):
            captured["redis"] = redis_arg
            captured["events"] = [dict(item) for item in events_arg]
            captured["settings"] = settings
            captured["producer"] = producer
            return [{"event": dict(item), "stream_id": f"raw:0:{index}", "replayed": False} for index, item in enumerate(events_arg)]

        async def fake_record_ingest_acceptance_batch(redis_arg, accepted_events, *, settings=None):
            captured["accepted_redis"] = redis_arg
            captured["accepted"] = [dict(item) for item in accepted_events]
            captured["accepted_settings"] = settings

        original_push = syslog_server.push_raw_events_batch
        original_record = syslog_server.record_ingest_acceptance_batch
        syslog_server.push_raw_events_batch = fake_push_raw_events_batch
        syslog_server.record_ingest_acceptance_batch = fake_record_ingest_acceptance_batch
        try:
            await server._handle_client(reader, writer)
        finally:
            syslog_server.push_raw_events_batch = original_push
            syslog_server.record_ingest_acceptance_batch = original_record

        self.assertTrue(writer.closed)
        self.assertIs(captured["redis"], redis)
        self.assertIs(captured["accepted_redis"], redis)
        self.assertIs(captured["settings"], settings)
        self.assertIs(captured["accepted_settings"], settings)
        self.assertIs(captured["producer"], producer)
        self.assertEqual(len(captured["events"]), 2)
        self.assertEqual(len(captured["accepted"]), 2)
        self.assertEqual(captured["events"][0]["message"], "<14>test message 1")
        self.assertEqual(captured["events"][1]["message"], "<14>test message 2")
        self.assertEqual(captured["events"][0]["source"], "192.168.1.50")
        self.assertEqual(captured["events"][0]["collector"], "syslog_tcp")
        self.assertEqual(captured["events"][0]["collector_profile"], "linux-auth")

    async def test_syslog_stop_closes_active_client_writers(self) -> None:
        settings = SimpleNamespace(
            ingest_syslog_host="0.0.0.0",
            syslog_profiles=lambda: {"linux-auth": 1514},
        )
        server = syslog_server.SyslogTcpServer(settings, object(), object(), "linux-auth", 1514)
        writer = _FakeWriter(("192.168.1.51", 5515))
        server._active_writers.add(writer)

        await server.stop()

        self.assertTrue(writer.closed)


if __name__ == "__main__":
    unittest.main()
