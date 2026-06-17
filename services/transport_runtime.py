from __future__ import annotations

import json
import os
import asyncio
import inspect
import importlib.util
import logging
from dataclasses import dataclass
from typing import Any, Mapping

from services.redis_runtime import RedisConnectionSettings, connection_settings_from_object, create_resilient_async_redis_client

logger = logging.getLogger(__name__)

try:
    from aiokafka import AIOKafkaConsumer, AIOKafkaProducer
    from aiokafka.structs import OffsetAndMetadata, TopicPartition
    KAFKA_CLIENTS_AVAILABLE = True
except ModuleNotFoundError:  # pragma: no cover - local test fallback
    KAFKA_CLIENTS_AVAILABLE = False
    AIOKafkaConsumer = Any  # type: ignore[assignment,misc]
    AIOKafkaProducer = Any  # type: ignore[assignment,misc]
    OffsetAndMetadata = Any  # type: ignore[assignment,misc]
    TopicPartition = Any  # type: ignore[assignment,misc]

__all__ = [
    "KAFKA_CLIENTS_AVAILABLE",
    "KafkaConnectionSettings",
    "TransportMessage",
    "TransportSettings",
    "create_transport_consumer",
    "create_transport_producer",
    "effective_kafka_compression_type",
    "transport_cutover_stage",
    "transport_health_snapshot",
    "transport_settings_from_object",
]


def _parse_bool(value: object) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _transport_field_value(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    return str(value)


def _compression_codec_available(codec: str | None) -> bool:
    selected = str(codec or "").strip().lower()
    if not selected:
        return False
    if selected == "gzip":
        return True
    required_modules = {
        "lz4": ("lz4", "lz4.frame"),
        "snappy": ("snappy",),
        "zstd": ("zstandard",),
    }.get(selected)
    if not required_modules:
        return False
    return any(importlib.util.find_spec(module_name) is not None for module_name in required_modules)


def effective_kafka_compression_type(codec: str | None) -> str | None:
    selected = str(codec or "").strip().lower()
    return selected if _compression_codec_available(selected) else None


@dataclass(frozen=True)
class KafkaConnectionSettings:
    bootstrap_servers: tuple[str, ...]
    client_id: str
    security_protocol: str
    sasl_mechanism: str
    sasl_username: str | None
    sasl_password: str | None
    ssl_cafile: str | None
    ssl_certfile: str | None
    ssl_keyfile: str | None
    auto_offset_reset: str = "latest"
    expected_brokers: int = 3
    expected_controllers: int = 3
    default_replication_factor: int = 3
    min_insync_replicas: int = 2
    producer_linger_ms: int = 5
    producer_compression_type: str | None = None
    producer_max_batch_size: int = 0
    producer_max_request_size: int = 0


@dataclass(frozen=True)
class TransportSettings:
    backend: str
    consumer_backend: str
    redis: RedisConnectionSettings
    kafka: KafkaConnectionSettings
    raw_stream: str
    normalized_stream: str
    filtered_stream: str
    dlq_stream: str
    replay_stream: str
    transport_audit_stream: str
    raw_topic: str
    normalized_topic: str
    filtered_topic: str
    dlq_topic: str
    replay_topic: str
    transport_audit_topic: str

    def alias_stream(self, alias: str) -> str:
        key = str(alias or "").strip().lower()
        if key == "raw":
            return self.raw_stream
        if key == "normalized":
            return self.normalized_stream
        if key == "filtered":
            return self.filtered_stream
        if key == "dlq":
            return self.dlq_stream
        if key == "replay":
            return self.replay_stream
        if key == "transport_audit":
            return self.transport_audit_stream
        raise ValueError(f"Unknown transport alias: {alias!r}")

    def alias_topic(self, alias: str) -> str:
        key = str(alias or "").strip().lower()
        if key == "raw":
            return self.raw_topic
        if key == "normalized":
            return self.normalized_topic
        if key == "filtered":
            return self.filtered_topic
        if key == "dlq":
            return self.dlq_topic
        if key == "replay":
            return self.replay_topic
        if key == "transport_audit":
            return self.transport_audit_topic
        raise ValueError(f"Unknown transport alias: {alias!r}")

    def alias_target(self, alias: str) -> str:
        return self.alias_topic(alias) if self.backend in {"kafka", "dual"} else self.alias_stream(alias)


def _attr(settings: object | None, name: str, default: object) -> object:
    if settings is not None and hasattr(settings, name):
        value = getattr(settings, name)
        if value is not None and value != "":
            return value
    return default


def transport_settings_from_object(
    settings: object | None = None,
    *,
    env: Mapping[str, str] | None = None,
) -> TransportSettings:
    env_map = env or os.environ
    backend = str(_attr(settings, "transport_backend", env_map.get("SIEM_TRANSPORT_BACKEND", "kafka")) or "kafka").strip().lower()
    if backend not in {"redis", "dual", "kafka"}:
        backend = "kafka"
    consumer_backend = str(
        _attr(
            settings,
            "transport_consumer_backend",
            env_map.get("SIEM_TRANSPORT_CONSUMER_BACKEND", "kafka" if backend == "dual" else backend),
        )
        or ("kafka" if backend == "dual" else backend)
    ).strip().lower()
    if consumer_backend not in {"redis", "kafka"}:
        consumer_backend = "kafka" if backend == "dual" else backend

    bootstrap = str(_attr(settings, "kafka_bootstrap_servers", env_map.get("SIEM_KAFKA_BOOTSTRAP_SERVERS", "127.0.0.1:9092")) or "127.0.0.1:9092")
    bootstrap_servers = tuple(part.strip() for part in bootstrap.split(",") if part.strip()) or ("127.0.0.1:9092",)
    security_protocol = str(_attr(settings, "kafka_security_protocol", env_map.get("SIEM_KAFKA_SECURITY_PROTOCOL", "PLAINTEXT")) or "PLAINTEXT").strip().upper()
    sasl_mechanism = str(_attr(settings, "kafka_sasl_mechanism", env_map.get("SIEM_KAFKA_SASL_MECHANISM", "SCRAM-SHA-256")) or "SCRAM-SHA-256").strip().upper()
    sasl_username = str(_attr(settings, "kafka_sasl_username", env_map.get("SIEM_KAFKA_SASL_USERNAME", "")) or "").strip() or None
    sasl_password = str(_attr(settings, "kafka_sasl_password", env_map.get("SIEM_KAFKA_SASL_PASSWORD", "")) or "").strip() or None
    ssl_cafile = str(_attr(settings, "kafka_ssl_cafile", env_map.get("SIEM_KAFKA_SSL_CAFILE", "")) or "").strip() or None
    ssl_certfile = str(_attr(settings, "kafka_ssl_certfile", env_map.get("SIEM_KAFKA_SSL_CERTFILE", "")) or "").strip() or None
    ssl_keyfile = str(_attr(settings, "kafka_ssl_keyfile", env_map.get("SIEM_KAFKA_SSL_KEYFILE", "")) or "").strip() or None
    auto_offset_reset = str(_attr(settings, "kafka_auto_offset_reset", env_map.get("SIEM_KAFKA_AUTO_OFFSET_RESET", "latest")) or "latest").strip().lower()
    if auto_offset_reset not in {"latest", "earliest"}:
        auto_offset_reset = "latest"
    expected_brokers = max(1, int(_attr(settings, "kafka_expected_brokers", env_map.get("SIEM_KAFKA_EXPECTED_BROKERS", "3")) or "3"))
    expected_controllers = max(
        1,
        int(_attr(settings, "kafka_expected_controllers", env_map.get("SIEM_KAFKA_EXPECTED_CONTROLLERS", "3")) or "3"),
    )
    default_replication_factor = max(
        1,
        int(_attr(settings, "kafka_default_replication_factor", env_map.get("SIEM_KAFKA_DEFAULT_REPLICATION_FACTOR", "3")) or "3"),
    )
    min_insync_replicas = max(
        1,
        int(_attr(settings, "kafka_min_insync_replicas", env_map.get("SIEM_KAFKA_MIN_INSYNC_REPLICAS", "2")) or "2"),
    )
    producer_linger_ms = max(
        0,
        int(_attr(settings, "kafka_producer_linger_ms", env_map.get("SIEM_KAFKA_PRODUCER_LINGER_MS", "5")) or "5"),
    )
    compression_raw = str(
        _attr(settings, "kafka_producer_compression_type", env_map.get("SIEM_KAFKA_PRODUCER_COMPRESSION_TYPE", ""))
        or ""
    ).strip().lower()
    producer_compression_type = compression_raw if compression_raw in {"gzip", "snappy", "lz4", "zstd"} else None
    producer_max_batch_size = max(
        0,
        int(_attr(settings, "kafka_producer_max_batch_size", env_map.get("SIEM_KAFKA_PRODUCER_MAX_BATCH_SIZE", "0")) or "0"),
    )
    producer_max_request_size = max(
        0,
        int(_attr(settings, "kafka_producer_max_request_size", env_map.get("SIEM_KAFKA_PRODUCER_MAX_REQUEST_SIZE", "0")) or "0"),
    )

    redis = connection_settings_from_object(settings, env=env_map)
    return TransportSettings(
        backend=backend,
        consumer_backend=consumer_backend,
        redis=redis,
        kafka=KafkaConnectionSettings(
            bootstrap_servers=bootstrap_servers,
            client_id=str(_attr(settings, "kafka_client_id", env_map.get("SIEM_KAFKA_CLIENT_ID", env_map.get("SIEM_INSTANCE_NAME", "siem-runtime"))) or "siem-runtime").strip(),
            security_protocol=security_protocol,
            sasl_mechanism=sasl_mechanism,
            sasl_username=sasl_username,
            sasl_password=sasl_password,
            ssl_cafile=ssl_cafile,
            ssl_certfile=ssl_certfile,
            ssl_keyfile=ssl_keyfile,
            auto_offset_reset=auto_offset_reset,
            expected_brokers=expected_brokers,
            expected_controllers=expected_controllers,
            default_replication_factor=default_replication_factor,
            min_insync_replicas=min_insync_replicas,
            producer_linger_ms=producer_linger_ms,
            producer_compression_type=producer_compression_type,
            producer_max_batch_size=producer_max_batch_size,
            producer_max_request_size=producer_max_request_size,
        ),
        raw_stream=str(_attr(settings, "raw_stream_key", env_map.get("SIEM_REDIS_STREAM_RAW", "siem:raw")) or "siem:raw").strip(),
        normalized_stream=str(_attr(settings, "normalized_stream_key", env_map.get("SIEM_REDIS_STREAM_NORMALIZED", "siem:normalized")) or "siem:normalized").strip(),
        filtered_stream=str(_attr(settings, "filtered_stream_key", env_map.get("SIEM_REDIS_STREAM_FILTERED", "siem:filtered")) or "siem:filtered").strip(),
        dlq_stream=str(_attr(settings, "dlq_stream_key", env_map.get("SIEM_REDIS_STREAM_DLQ", "siem:raw:dlq")) or "siem:raw:dlq").strip(),
        replay_stream=str(_attr(settings, "replay_stream_key", env_map.get("SIEM_REDIS_STREAM_REPLAY", "siem:replay")) or "siem:replay").strip(),
        transport_audit_stream=str(_attr(settings, "transport_audit_stream_key", env_map.get("SIEM_REDIS_STREAM_TRANSPORT_AUDIT", "siem:transport:audit")) or "siem:transport:audit").strip(),
        raw_topic=str(_attr(settings, "kafka_topic_raw", env_map.get("SIEM_KAFKA_TOPIC_RAW", "siem.raw")) or "siem.raw").strip(),
        normalized_topic=str(_attr(settings, "kafka_topic_normalized", env_map.get("SIEM_KAFKA_TOPIC_NORMALIZED", "siem.normalized")) or "siem.normalized").strip(),
        filtered_topic=str(_attr(settings, "kafka_topic_filtered", env_map.get("SIEM_KAFKA_TOPIC_FILTERED", "siem.filtered")) or "siem.filtered").strip(),
        dlq_topic=str(_attr(settings, "kafka_topic_dlq", env_map.get("SIEM_KAFKA_TOPIC_DLQ", "siem.dlq")) or "siem.dlq").strip(),
        replay_topic=str(_attr(settings, "kafka_topic_replay", env_map.get("SIEM_KAFKA_TOPIC_REPLAY", "siem.replay")) or "siem.replay").strip(),
        transport_audit_topic=str(_attr(settings, "kafka_topic_transport_audit", env_map.get("SIEM_KAFKA_TOPIC_TRANSPORT_AUDIT", "siem.transport.audit")) or "siem.transport.audit").strip(),
    )


@dataclass(frozen=True)
class TransportMessage:
    id: str
    fields: dict[str, Any]
    partition: int = -1
    offset: int = -1
    topic: str = ""
    stream: str = ""


def _kafka_auth_mode(settings: KafkaConnectionSettings) -> str:
    security_protocol = str(settings.security_protocol or "PLAINTEXT").upper()
    has_sasl = bool(settings.sasl_username and settings.sasl_password)
    if "SSL" in security_protocol and has_sasl:
        return "scram_tls"
    if "SSL" in security_protocol:
        return "tls"
    if has_sasl:
        return "scram_plaintext"
    return "plaintext"


def transport_health_snapshot(settings: object | None = None) -> dict[str, Any]:
    resolved = transport_settings_from_object(settings)
    kafka_enabled = resolved.backend in {"dual", "kafka"} or resolved.consumer_backend == "kafka"
    configured_topics = {
        "raw": resolved.raw_topic,
        "normalized": resolved.normalized_topic,
        "filtered": resolved.filtered_topic,
        "dlq": resolved.dlq_topic,
        "replay": resolved.replay_topic,
        "transport_audit": resolved.transport_audit_topic,
    }
    stream_targets = {
        "raw": resolved.raw_stream,
        "normalized": resolved.normalized_stream,
        "filtered": resolved.filtered_stream,
        "dlq": resolved.dlq_stream,
        "replay": resolved.replay_stream,
        "transport_audit": resolved.transport_audit_stream,
    }
    return {
        "backend": resolved.backend,
        "consumer_backend": resolved.consumer_backend,
        "cutover_stage": transport_cutover_stage(resolved),
        "kafka_enabled": kafka_enabled,
        "kafka_clients_available": bool(KAFKA_CLIENTS_AVAILABLE),
        "kafka_configured": bool(resolved.kafka.bootstrap_servers),
        "kafka_bootstrap_servers": list(resolved.kafka.bootstrap_servers),
        "kafka_auth_mode": _kafka_auth_mode(resolved.kafka),
        "kafka_security_protocol": resolved.kafka.security_protocol,
        "kafka_expected_brokers": int(resolved.kafka.expected_brokers),
        "kafka_expected_controllers": int(resolved.kafka.expected_controllers),
        "kafka_default_replication_factor": int(resolved.kafka.default_replication_factor),
        "kafka_min_insync_replicas": int(resolved.kafka.min_insync_replicas),
        "kafka_producer_linger_ms": int(resolved.kafka.producer_linger_ms),
        "kafka_producer_compression_type": resolved.kafka.producer_compression_type or "",
        "kafka_producer_compression_effective": effective_kafka_compression_type(
            resolved.kafka.producer_compression_type
        )
        or "",
        "kafka_producer_max_batch_size": int(resolved.kafka.producer_max_batch_size),
        "kafka_producer_max_request_size": int(resolved.kafka.producer_max_request_size),
        "configured_topics": configured_topics,
        "configured_streams": stream_targets,
        "raw_target": resolved.alias_target("raw"),
        "normalized_target": resolved.alias_target("normalized"),
        "filtered_target": resolved.alias_target("filtered"),
        "dlq_target": resolved.alias_target("dlq"),
        "replay_target": resolved.alias_target("replay"),
        "transport_audit_target": resolved.alias_target("transport_audit"),
        "redis_streams_active": resolved.backend in {"redis", "dual"},
        "kafka_shadow_ready": bool(kafka_enabled and resolved.kafka.bootstrap_servers),
    }


class RedisStreamProducer:
    def __init__(self, settings: TransportSettings) -> None:
        self._settings = settings
        self._redis = create_resilient_async_redis_client(settings.redis)

    async def close(self) -> None:
        await self._redis.close()

    async def publish(self, alias: str, payload: Mapping[str, Any], *, maxlen: int = 1_000_000, approximate: bool = True) -> str:
        target = self._settings.alias_stream(alias)
        return str(
            await self._redis.xadd(
                target,
                {str(key): _transport_field_value(value) for key, value in payload.items()},
                maxlen=maxlen,
                approximate=approximate,
            )
        )

    async def publish_many(
        self,
        alias: str,
        payloads: list[Mapping[str, Any]],
        *,
        maxlen: int = 1_000_000,
        approximate: bool = True,
    ) -> list[str]:
        ids: list[str] = []
        for payload in payloads:
            ids.append(await self.publish(alias, payload, maxlen=maxlen, approximate=approximate))
        return ids


class KafkaProducerRuntime:
    def __init__(self, settings: TransportSettings) -> None:
        if not KAFKA_CLIENTS_AVAILABLE:
            raise RuntimeError("Kafka transport requested but aiokafka is not installed")
        self._settings = settings
        self._producer: AIOKafkaProducer | None = None
        self._producer_lock = asyncio.Lock()

    async def _ensure(self) -> AIOKafkaProducer:
        async with self._producer_lock:
            if self._producer is None:
                kwargs: dict[str, Any] = {
                    "bootstrap_servers": list(self._settings.kafka.bootstrap_servers),
                    "client_id": self._settings.kafka.client_id,
                    "acks": "all",
                    "linger_ms": self._settings.kafka.producer_linger_ms,
                    "request_timeout_ms": 120_000,
                    "retry_backoff_ms": 500,
                }
                requested_compression = self._settings.kafka.producer_compression_type
                effective_compression = effective_kafka_compression_type(requested_compression)
                if requested_compression and not effective_compression:
                    logger.warning(
                        "Kafka producer compression codec is not available; publishing without compression",
                        extra={"extra": {"requested_compression_type": requested_compression}},
                    )
                if effective_compression:
                    kwargs["compression_type"] = effective_compression
                if self._settings.kafka.producer_max_batch_size > 0:
                    kwargs["max_batch_size"] = self._settings.kafka.producer_max_batch_size
                if self._settings.kafka.producer_max_request_size > 0:
                    kwargs["max_request_size"] = self._settings.kafka.producer_max_request_size
                if self._settings.kafka.security_protocol != "PLAINTEXT":
                    kwargs["security_protocol"] = self._settings.kafka.security_protocol
                if self._settings.kafka.sasl_username:
                    kwargs["sasl_plain_username"] = self._settings.kafka.sasl_username
                if self._settings.kafka.sasl_password:
                    kwargs["sasl_plain_password"] = self._settings.kafka.sasl_password
                if self._settings.kafka.sasl_mechanism:
                    kwargs["sasl_mechanism"] = self._settings.kafka.sasl_mechanism
                if self._settings.kafka.ssl_cafile:
                    kwargs["ssl_cafile"] = self._settings.kafka.ssl_cafile
                if self._settings.kafka.ssl_certfile:
                    kwargs["ssl_certfile"] = self._settings.kafka.ssl_certfile
                if self._settings.kafka.ssl_keyfile:
                    kwargs["ssl_keyfile"] = self._settings.kafka.ssl_keyfile
                self._producer = AIOKafkaProducer(**kwargs)
                await self._producer.start()
        return self._producer

    async def close(self) -> None:
        await self._reset_producer()

    async def _reset_producer(self) -> None:
        async with self._producer_lock:
            producer = self._producer
            self._producer = None
        if producer is not None:
            try:
                await producer.stop()
            except Exception:
                pass

    @staticmethod
    def _is_recoverable_publish_error(exc: Exception) -> bool:
        name = exc.__class__.__name__
        if name in {"ProducerClosed", "RequestTimedOutError", "NodeNotReadyError", "KafkaConnectionError"}:
            return True
        message = str(exc or "").strip().lower()
        return bool(message) and any(
            marker in message
            for marker in (
                "producerclosed",
                "requesttimedouterror",
                "nodenotreadyerror",
                "kafkaconnectionerror",
                "producer closed",
                "request timed out",
            )
        )

    async def publish(self, alias: str, payload: Mapping[str, Any], *, maxlen: int = 0, approximate: bool = False) -> str:
        target = self._settings.alias_target(alias)
        data = json.dumps(dict(payload), ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        attempts = 2
        last_error: Exception | None = None
        for attempt in range(1, attempts + 1):
            producer = await self._ensure()
            try:
                metadata = await producer.send_and_wait(target, data)
                return f"{metadata.topic}:{metadata.partition}:{metadata.offset}"
            except Exception as exc:
                last_error = exc
                if attempt >= attempts or not self._is_recoverable_publish_error(exc):
                    raise
                await self._reset_producer()
        raise RuntimeError(f"Kafka publish failed without exception context for target {target!r}") from last_error

    async def publish_many(
        self,
        alias: str,
        payloads: list[Mapping[str, Any]],
        *,
        maxlen: int = 0,
        approximate: bool = False,
    ) -> list[str]:
        if not payloads:
            return []
        target = self._settings.alias_target(alias)
        encoded = [
            json.dumps(dict(payload), ensure_ascii=False, separators=(",", ":")).encode("utf-8")
            for payload in payloads
        ]
        attempts = 2
        last_error: Exception | None = None
        for attempt in range(1, attempts + 1):
            producer = await self._ensure()
            try:
                futures: list[Any] = []
                for data in encoded:
                    if hasattr(producer, "send"):
                        sent = producer.send(target, data)
                        if inspect.isawaitable(sent):
                            sent = await sent
                        futures.append(sent)
                    else:  # pragma: no cover - compatibility with simple test doubles
                        futures.append(producer.send_and_wait(target, data))

                ids: list[str] = []
                for future in futures:
                    metadata = await future if inspect.isawaitable(future) else future
                    ids.append(f"{metadata.topic}:{metadata.partition}:{metadata.offset}")
                return ids
            except Exception as exc:
                last_error = exc
                if attempt >= attempts or not self._is_recoverable_publish_error(exc):
                    raise
                await self._reset_producer()
        raise RuntimeError(f"Kafka batch publish failed without exception context for target {target!r}") from last_error


class DualTransportProducer:
    def __init__(self, settings: TransportSettings) -> None:
        self._redis = RedisStreamProducer(settings)
        self._kafka = KafkaProducerRuntime(settings)

    async def close(self) -> None:
        await self._redis.close()
        await self._kafka.close()

    async def publish(self, alias: str, payload: Mapping[str, Any], *, maxlen: int = 1_000_000, approximate: bool = True) -> str:
        redis_id = await self._redis.publish(alias, payload, maxlen=maxlen, approximate=approximate)
        await self._kafka.publish(alias, payload)
        return redis_id

    async def publish_many(
        self,
        alias: str,
        payloads: list[Mapping[str, Any]],
        *,
        maxlen: int = 1_000_000,
        approximate: bool = True,
    ) -> list[str]:
        redis_ids = await self._redis.publish_many(alias, payloads, maxlen=maxlen, approximate=approximate)
        await self._kafka.publish_many(alias, payloads)
        return redis_ids


class RedisStreamConsumer:
    def __init__(self, settings: TransportSettings, *, stream: str, group: str, consumer: str) -> None:
        self._settings = settings
        self._stream = stream
        self._group = group
        self._consumer = consumer
        self._redis = create_resilient_async_redis_client(settings.redis)

    async def init(self) -> None:
        try:
            await self._redis.xgroup_create(name=self._stream, groupname=self._group, id="0-0", mkstream=True)
        except Exception as exc:  # noqa: BLE001
            if "BUSYGROUP" not in str(exc):
                raise

    async def close(self) -> None:
        await self._redis.close()

    async def poll(self, *, batch_size: int, block_ms: int) -> list[TransportMessage]:
        resp = await self._redis.xreadgroup(
            groupname=self._group,
            consumername=self._consumer,
            streams={self._stream: ">"},
            count=batch_size,
            block=block_ms,
        )
        messages: list[TransportMessage] = []
        for stream_name, rows in resp or []:
            for msg_id, fields in rows:
                messages.append(
                    TransportMessage(
                        id=str(msg_id),
                        fields={str(key): str(value) for key, value in dict(fields).items()},
                        stream=str(stream_name or self._stream),
                    )
                )
        return messages

    async def ack(self, messages: list[TransportMessage]) -> None:
        ids = [message.id for message in messages if message.id]
        if ids:
            await self._redis.xack(self._stream, self._group, *ids)


class KafkaTopicConsumer:
    def __init__(self, settings: TransportSettings, *, topic: str, group: str, consumer: str) -> None:
        if not KAFKA_CLIENTS_AVAILABLE:
            raise RuntimeError("Kafka transport requested but aiokafka is not installed")
        self._settings = settings
        self._topic = topic
        self._group = group
        self._consumer_name = consumer
        self._consumer: AIOKafkaConsumer | None = None

    async def init(self) -> None:
        session_timeout_ms = max(10_000, int(os.getenv("SIEM_KAFKA_SESSION_TIMEOUT_MS", "120000") or "120000"))
        heartbeat_interval_ms = max(1_000, int(os.getenv("SIEM_KAFKA_HEARTBEAT_INTERVAL_MS", "10000") or "10000"))
        heartbeat_interval_ms = min(heartbeat_interval_ms, max(1_000, session_timeout_ms // 3))
        kwargs: dict[str, Any] = {
            "bootstrap_servers": list(self._settings.kafka.bootstrap_servers),
            "group_id": self._group,
            "client_id": self._settings.kafka.client_id,
            "enable_auto_commit": False,
            "auto_offset_reset": self._settings.kafka.auto_offset_reset,
            "request_timeout_ms": max(
                40_000,
                int(os.getenv("SIEM_KAFKA_REQUEST_TIMEOUT_MS", "120000") or "120000"),
            ),
            "metadata_max_age_ms": 15000,
            "session_timeout_ms": session_timeout_ms,
            "heartbeat_interval_ms": heartbeat_interval_ms,
            "max_poll_interval_ms": max(
                300_000,
                int(os.getenv("SIEM_KAFKA_MAX_POLL_INTERVAL_MS", "900000") or "900000"),
            ),
        }
        if self._settings.kafka.security_protocol != "PLAINTEXT":
            kwargs["security_protocol"] = self._settings.kafka.security_protocol
        if self._settings.kafka.sasl_username:
            kwargs["sasl_plain_username"] = self._settings.kafka.sasl_username
        if self._settings.kafka.sasl_password:
            kwargs["sasl_plain_password"] = self._settings.kafka.sasl_password
        if self._settings.kafka.sasl_mechanism:
            kwargs["sasl_mechanism"] = self._settings.kafka.sasl_mechanism
        if self._settings.kafka.ssl_cafile:
            kwargs["ssl_cafile"] = self._settings.kafka.ssl_cafile
        if self._settings.kafka.ssl_certfile:
            kwargs["ssl_certfile"] = self._settings.kafka.ssl_certfile
        if self._settings.kafka.ssl_keyfile:
            kwargs["ssl_keyfile"] = self._settings.kafka.ssl_keyfile
        self._consumer = AIOKafkaConsumer(self._topic, **kwargs)
        await self._consumer.start()

    async def close(self) -> None:
        if self._consumer is not None:
            await self._consumer.stop()
            self._consumer = None

    async def poll(self, *, batch_size: int, block_ms: int) -> list[TransportMessage]:
        if self._consumer is None:
            raise RuntimeError("Kafka consumer not initialized")
        results = await self._consumer.getmany(timeout_ms=block_ms, max_records=batch_size)
        messages: list[TransportMessage] = []
        for topic_partition, rows in results.items():
            for row in rows:
                payload = json.loads((row.value or b"{}").decode("utf-8", errors="replace"))
                fields = payload if isinstance(payload, dict) else {"payload": payload}
                messages.append(
                    TransportMessage(
                        id=f"{row.topic}:{row.partition}:{row.offset}",
                        fields={str(key): _transport_field_value(value) for key, value in fields.items()},
                        partition=int(row.partition),
                        offset=int(row.offset),
                        topic=str(row.topic),
                    )
                )
        return messages

    async def ack(self, messages: list[TransportMessage]) -> None:
        if self._consumer is None or not messages:
            return
        offsets: dict[TopicPartition, OffsetAndMetadata] = {}
        for message in messages:
            if message.topic == "" or message.partition < 0 or message.offset < 0:
                continue
            topic_partition = TopicPartition(message.topic, message.partition)
            current = offsets.get(topic_partition)
            next_offset = message.offset + 1
            if current is None or next_offset > current.offset:
                offsets[topic_partition] = OffsetAndMetadata(next_offset, "")
        if offsets:
            await self._consumer.commit(offsets=offsets)


def create_transport_producer(settings: object | None = None) -> Any:
    resolved = transport_settings_from_object(settings)
    if resolved.backend == "kafka":
        return KafkaProducerRuntime(resolved)
    if resolved.backend == "dual":
        return DualTransportProducer(resolved)
    return RedisStreamProducer(resolved)


def create_transport_consumer(
    settings: object | None,
    *,
    alias: str,
    group: str,
    consumer: str,
) -> Any:
    resolved = transport_settings_from_object(settings)
    backend = resolved.consumer_backend
    if backend == "kafka":
        return KafkaTopicConsumer(resolved, topic=resolved.alias_target(alias), group=group, consumer=consumer)
    stream_map = {
        "raw": resolved.raw_stream,
        "normalized": resolved.normalized_stream,
        "filtered": resolved.filtered_stream,
        "dlq": resolved.dlq_stream,
        "replay": resolved.replay_stream,
        "transport_audit": resolved.transport_audit_stream,
    }
    if alias not in stream_map:
        raise ValueError(f"Unknown transport alias: {alias!r}")
    return RedisStreamConsumer(resolved, stream=stream_map[alias], group=group, consumer=consumer)


def transport_backend(settings: object | None = None) -> str:
    return transport_settings_from_object(settings).backend


def transport_cutover_stage(settings: object | None = None) -> str:
    if isinstance(settings, TransportSettings):
        backend = settings.backend
    else:
        backend = transport_settings_from_object(settings).backend
    if backend == "kafka":
        return "kafka_only"
    if backend == "dual":
        return "dual_write"
    return "redis_only"
