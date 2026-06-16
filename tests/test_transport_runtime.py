import asyncio
import unittest
from unittest.mock import AsyncMock

from services import transport_runtime as transport_module
from services.transport_runtime import (
    KafkaTopicConsumer,
    RedisStreamConsumer,
    RedisStreamProducer,
    create_transport_consumer,
    create_transport_producer,
    transport_health_snapshot,
    transport_cutover_stage,
    transport_settings_from_object,
)


class TransportRuntimeTests(unittest.TestCase):
    def test_kafka_producer_runtime_retries_recoverable_publish_failure(self) -> None:
        class ProducerClosed(Exception):
            pass

        class FakeMetadata:
            topic = "siem.raw"
            partition = 3
            offset = 42

        class FakeProducer:
            def __init__(self, *, fail: bool) -> None:
                self.start = AsyncMock()
                self.stop = AsyncMock()
                if fail:
                    self.send_and_wait = AsyncMock(side_effect=ProducerClosed("ProducerClosed"))
                else:
                    self.send_and_wait = AsyncMock(return_value=FakeMetadata())

        created: list[FakeProducer] = []

        def factory(**kwargs):
            producer = FakeProducer(fail=not created)
            created.append(producer)
            return producer

        original_available = transport_module.KAFKA_CLIENTS_AVAILABLE
        original_producer = transport_module.AIOKafkaProducer
        transport_module.KAFKA_CLIENTS_AVAILABLE = True
        transport_module.AIOKafkaProducer = factory
        try:
            settings = transport_settings_from_object(
                None,
                env={
                    "SIEM_TRANSPORT_BACKEND": "kafka",
                    "SIEM_KAFKA_BOOTSTRAP_SERVERS": "192.168.1.35:9092",
                },
            )
            runtime = transport_module.KafkaProducerRuntime(settings)

            result = asyncio.run(runtime.publish("raw", {"event": "x"}))

            self.assertEqual(result, "siem.raw:3:42")
            self.assertEqual(len(created), 2)
            created[0].start.assert_awaited_once()
            created[0].stop.assert_awaited_once()
            created[0].send_and_wait.assert_awaited_once()
            created[1].start.assert_awaited_once()
            created[1].send_and_wait.assert_awaited_once()
        finally:
            transport_module.KAFKA_CLIENTS_AVAILABLE = original_available
            transport_module.AIOKafkaProducer = original_producer

    def test_kafka_producer_runtime_batch_publish_preserves_metadata_order(self) -> None:
        class FakeMetadata:
            def __init__(self, offset: int) -> None:
                self.topic = "siem.raw"
                self.partition = 1
                self.offset = offset

        class FakeProducer:
            def __init__(self) -> None:
                self.start = AsyncMock()
                self.stop = AsyncMock()
                self.send = AsyncMock(side_effect=[FakeMetadata(10), FakeMetadata(11), FakeMetadata(12)])
                self.send_and_wait = AsyncMock()

        created: list[FakeProducer] = []

        def factory(**kwargs):
            producer = FakeProducer()
            created.append(producer)
            return producer

        original_available = transport_module.KAFKA_CLIENTS_AVAILABLE
        original_producer = transport_module.AIOKafkaProducer
        transport_module.KAFKA_CLIENTS_AVAILABLE = True
        transport_module.AIOKafkaProducer = factory
        try:
            settings = transport_settings_from_object(
                None,
                env={
                    "SIEM_TRANSPORT_BACKEND": "kafka",
                    "SIEM_KAFKA_BOOTSTRAP_SERVERS": "192.168.1.35:9092",
                },
            )
            runtime = transport_module.KafkaProducerRuntime(settings)

            result = asyncio.run(runtime.publish_many("raw", [{"event": "a"}, {"event": "b"}, {"event": "c"}]))

            self.assertEqual(result, ["siem.raw:1:10", "siem.raw:1:11", "siem.raw:1:12"])
            self.assertEqual(len(created), 1)
            created[0].start.assert_awaited_once()
            self.assertEqual(created[0].send.await_count, 3)
            created[0].send_and_wait.assert_not_awaited()
        finally:
            transport_module.KAFKA_CLIENTS_AVAILABLE = original_available
            transport_module.AIOKafkaProducer = original_producer

    def test_kafka_producer_runtime_uses_env_tuning_knobs(self) -> None:
        class FakeMetadata:
            topic = "siem.raw"
            partition = 0
            offset = 1

        class FakeProducer:
            def __init__(self) -> None:
                self.start = AsyncMock()
                self.stop = AsyncMock()
                self.send_and_wait = AsyncMock(return_value=FakeMetadata())

        captured: dict[str, object] = {}

        def factory(**kwargs):
            captured.update(kwargs)
            return FakeProducer()

        original_available = transport_module.KAFKA_CLIENTS_AVAILABLE
        original_producer = transport_module.AIOKafkaProducer
        transport_module.KAFKA_CLIENTS_AVAILABLE = True
        transport_module.AIOKafkaProducer = factory
        try:
            settings = transport_settings_from_object(
                None,
                env={
                    "SIEM_TRANSPORT_BACKEND": "kafka",
                    "SIEM_KAFKA_BOOTSTRAP_SERVERS": "192.168.1.35:9092",
                    "SIEM_KAFKA_PRODUCER_LINGER_MS": "15",
                    "SIEM_KAFKA_PRODUCER_COMPRESSION_TYPE": "lz4",
                    "SIEM_KAFKA_PRODUCER_MAX_BATCH_SIZE": "65536",
                    "SIEM_KAFKA_PRODUCER_MAX_REQUEST_SIZE": "4194304",
                },
            )
            runtime = transport_module.KafkaProducerRuntime(settings)

            result = asyncio.run(runtime.publish("raw", {"event": "x"}))

            self.assertEqual(result, "siem.raw:0:1")
            self.assertEqual(captured["linger_ms"], 15)
            self.assertEqual(captured["compression_type"], "lz4")
            self.assertEqual(captured["max_batch_size"], 65536)
            self.assertEqual(captured["max_request_size"], 4194304)
        finally:
            transport_module.KAFKA_CLIENTS_AVAILABLE = original_available
            transport_module.AIOKafkaProducer = original_producer

    def test_dual_backend_uses_kafka_topics_and_kafka_consumer_by_default(self) -> None:
        settings = transport_settings_from_object(
            None,
            env={
                "SIEM_TRANSPORT_BACKEND": "dual",
                "SIEM_KAFKA_TOPIC_RAW": "custom.raw",
                "SIEM_KAFKA_TOPIC_FILTERED": "custom.filtered",
            },
        )

        self.assertEqual(settings.backend, "dual")
        self.assertEqual(settings.consumer_backend, "kafka")
        self.assertEqual(settings.alias_target("raw"), "custom.raw")
        self.assertEqual(settings.alias_target("filtered"), "custom.filtered")
        self.assertEqual(settings.alias_stream("raw"), "siem:raw")
        self.assertEqual(settings.alias_stream("filtered"), "siem:filtered")

    def test_redis_stream_producer_uses_stream_key_in_dual_mode(self) -> None:
        settings = transport_settings_from_object(
            None,
            env={
                "SIEM_TRANSPORT_BACKEND": "dual",
                "SIEM_KAFKA_TOPIC_RAW": "custom.raw",
            },
        )
        producer = RedisStreamProducer(settings)
        producer._redis = type("FakeRedis", (), {"xadd": AsyncMock(return_value="1-0")})()

        result = asyncio.run(producer.publish("raw", {"event": "x"}))

        self.assertEqual(result, "1-0")
        producer._redis.xadd.assert_awaited_once()
        args, kwargs = producer._redis.xadd.await_args
        self.assertEqual(args[0], "siem:raw")
        self.assertEqual(args[1], {"event": "x"})

    def test_redis_stream_producer_serializes_nested_transport_fields_as_json(self) -> None:
        settings = transport_settings_from_object(
            None,
            env={
                "SIEM_TRANSPORT_BACKEND": "dual",
            },
        )
        producer = RedisStreamProducer(settings)
        producer._redis = type("FakeRedis", (), {"xadd": AsyncMock(return_value="1-1")})()

        asyncio.run(
            producer.publish(
                "raw",
                {
                    "event.provider": "host.metrics",
                    "metrics": {"memory_used_pct": 19.3, "cpu_pct": 12.4},
                    "services": [{"name": "siem-web", "status": "active"}],
                },
            )
        )

        args, kwargs = producer._redis.xadd.await_args
        self.assertEqual(args[1]["metrics"], '{"memory_used_pct":19.3,"cpu_pct":12.4}')
        self.assertEqual(args[1]["services"], '[{"name":"siem-web","status":"active"}]')

    def test_create_transport_consumer_uses_redis_when_requested(self) -> None:
        class Settings:
            transport_backend = "dual"
            transport_consumer_backend = "redis"

        consumer = create_transport_consumer(
            Settings(),
            alias="raw",
            group="g1",
            consumer="c1",
        )

        self.assertIsInstance(consumer, RedisStreamConsumer)

    def test_create_transport_consumer_uses_kafka_when_requested(self) -> None:
        class Settings:
            transport_backend = "dual"
            transport_consumer_backend = "kafka"
        if transport_module.KAFKA_CLIENTS_AVAILABLE:
            consumer = create_transport_consumer(
                Settings(),
                alias="filtered",
                group="g2",
                consumer="c2",
            )
            self.assertIsInstance(consumer, KafkaTopicConsumer)
        else:
            with self.assertRaisesRegex(RuntimeError, "aiokafka is not installed"):
                create_transport_consumer(
                    Settings(),
                    alias="filtered",
                    group="g2",
                    consumer="c2",
                )

    def test_create_transport_producer_uses_redis_when_requested(self) -> None:
        class Settings:
            transport_backend = "redis"

        producer = create_transport_producer(Settings())

        self.assertIsInstance(producer, RedisStreamProducer)

    def test_transport_cutover_stage_labels_dual_mode(self) -> None:
        class Settings:
            transport_backend = "dual"

        self.assertEqual(transport_cutover_stage(Settings()), "dual_write")

    def test_transport_health_snapshot_reports_kafka_wave_defaults(self) -> None:
        snapshot = transport_health_snapshot(
            None,
        )

        self.assertEqual(snapshot["backend"], "kafka")
        self.assertEqual(snapshot["cutover_stage"], "kafka_only")
        self.assertIn("raw", snapshot["configured_topics"])
        self.assertEqual(snapshot["kafka_expected_brokers"], 3)
        self.assertEqual(snapshot["kafka_producer_linger_ms"], 5)

    def test_transport_health_snapshot_reports_dual_kafka_targets(self) -> None:
        class Settings:
            transport_backend = "dual"
            kafka_bootstrap_servers = "192.168.1.35:9092,192.168.1.37:9092,192.168.1.40:9092"
            kafka_security_protocol = "SASL_SSL"
            kafka_sasl_username = "siem"
            kafka_sasl_password = "secret"

        snapshot = transport_health_snapshot(Settings())

        self.assertEqual(snapshot["backend"], "dual")
        self.assertEqual(snapshot["cutover_stage"], "dual_write")
        self.assertEqual(snapshot["kafka_auth_mode"], "scram_tls")
        self.assertEqual(snapshot["kafka_bootstrap_servers"][2], "192.168.1.40:9092")
        self.assertTrue(snapshot["kafka_shadow_ready"])


if __name__ == "__main__":
    unittest.main()
