import importlib
import asyncio
import os
import sys
import unittest
from datetime import datetime
from types import SimpleNamespace


class WriterWorkerSettingsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.original_port = os.environ.get("SIEM_CH_PORT")
        os.environ.pop("SIEM_CH_PORT", None)
        sys.modules.pop("services.writer.worker", None)

    def tearDown(self) -> None:
        if self.original_port is None:
            os.environ.pop("SIEM_CH_PORT", None)
        else:
            os.environ["SIEM_CH_PORT"] = self.original_port
        sys.modules.pop("services.writer.worker", None)

    def test_writer_defaults_to_clickhouse_native_port(self) -> None:
        writer_worker = importlib.import_module("services.writer.worker")

        self.assertEqual(writer_worker.WriterSettings().ch_port, 9000)
        self.assertEqual(writer_worker.WriterSettings().batch_wait_ms, 500)

    def test_writer_parses_decimal_unix_timestamp(self) -> None:
        writer_worker = importlib.import_module("services.writer.worker")
        worker = writer_worker.WriterWorker(writer_worker.WriterSettings())

        parsed = worker._parse_event_ts({"@timestamp": "1785057668.347427"})

        self.assertEqual(datetime.utcfromtimestamp(1785057668.347427), parsed)

    def test_writer_uses_stable_ingest_timestamp_before_clock_fallback(self) -> None:
        writer_worker = importlib.import_module("services.writer.worker")
        worker = writer_worker.WriterWorker(writer_worker.WriterSettings())

        parsed = worker._parse_event_ts(
            {"ingest_ts": "2026-07-28T09:47:17Z"}
        )

        self.assertEqual(datetime(2026, 7, 28, 9, 47, 17), parsed)

    def test_writer_insert_deduplication_token_is_stable_for_same_offsets(self) -> None:
        writer_worker = importlib.import_module("services.writer.worker")
        worker = writer_worker.WriterWorker(
            writer_worker.WriterSettings(group_name="writer-standby")
        )

        first = worker._insert_deduplication_token(
            [
                SimpleNamespace(id="siem.filtered:1:42"),
                SimpleNamespace(id="siem.filtered:0:10"),
            ]
        )
        reordered = worker._insert_deduplication_token(
            [
                SimpleNamespace(id="siem.filtered:0:10"),
                SimpleNamespace(id="siem.filtered:1:42"),
            ]
        )
        different = worker._insert_deduplication_token(
            [SimpleNamespace(id="siem.filtered:0:11")]
        )

        self.assertEqual(first, reordered)
        self.assertNotEqual(first, different)

    def test_writer_coalesces_messages_during_micro_batch_window(self) -> None:
        writer_worker = importlib.import_module("services.writer.worker")
        settings = writer_worker.WriterSettings(
            batch_size=4,
            block_ms=100,
            batch_wait_ms=50,
        )
        worker = writer_worker.WriterWorker(settings)

        class Consumer:
            def __init__(self):
                self.responses = [["one"], ["two", "three", "four"]]
                self.calls = []

            async def poll(self, *, batch_size, block_ms):
                self.calls.append((batch_size, block_ms))
                return self.responses.pop(0)

        consumer = Consumer()
        worker._consumer = consumer

        messages = asyncio.run(worker._poll_batch())

        self.assertEqual(["one", "two", "three", "four"], messages)
        self.assertEqual(2, len(consumer.calls))
        self.assertEqual(3, consumer.calls[1][0])


if __name__ == "__main__":
    unittest.main()
