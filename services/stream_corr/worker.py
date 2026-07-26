"""
/home/siem/siem-solution/services/stream_corr/worker.py

Stream correlation worker for threshold rules.

Current runtime features:
  - Redis Stream consumer for `siem:filtered`
  - threshold correlation state in Redis ZSETs
  - event-time or processing-time primary mode
  - optional shadow comparison against the alternate mode
  - runtime status snapshots written to ClickHouse for VM4 health visibility
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import re
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from clickhouse_driver import Client
from services.redis_runtime import connection_settings_from_object, create_resilient_async_redis_client
from services.stream_state import SQLiteStreamState, stream_state_settings_from_env
from services.transport_runtime import create_transport_consumer, transport_backend

from .config import StreamCorrSettings
from .logging_conf import configure_logging
from .rules import StreamCorrRule, load_stream_rules, matches_rule

logger = logging.getLogger(__name__)


_RULE_INDEX_FIELDS = {
    "event.provider",
    "event.dataset",
    "event.category",
    "event.type",
    "event.action",
    "event.outcome",
    "event.code",
    "host.name",
    "log_source",
    "source_type",
    "collector_profile",
    "ingest_profile",
}
_EXACT_FIELD_RE = re.compile(r"(?P<field>[A-Za-z0-9_.-]+)\s*==\s*'(?P<value>[^']+)'")


def _event_field_lower(event: dict[str, Any], *fields: str) -> str:
    for field in fields:
        value = event.get(field)
        if value not in (None, ""):
            return str(value).strip().lower()
    return ""


def _event_tags(event: dict[str, Any]) -> set[str]:
    raw_tags = event.get("tags", event.get("event.tags", ""))
    if isinstance(raw_tags, (list, tuple, set)):
        return {str(item).strip().lower() for item in raw_tags if str(item).strip()}
    text = str(raw_tags or "").strip()
    if not text:
        return set()
    if text.startswith("["):
        try:
            parsed = json.loads(text)
            if isinstance(parsed, list):
                return {str(item).strip().lower() for item in parsed if str(item).strip()}
        except json.JSONDecodeError:
            pass
    return {part.strip().lower() for part in re.split(r"[,;\s]+", text) if part.strip()}


def _is_benchmark_event(event: dict[str, Any]) -> bool:
    if _event_field_lower(event, "event.category", "category") == "benchmark":
        return True
    if _event_field_lower(event, "event.dataset", "dataset") == "benchmark":
        return True
    return "allowlist:benchmark" in _event_tags(event)


def _iso_from_epoch(value: float) -> str:
    if value <= 0:
        return ""
    return datetime.fromtimestamp(value, tz=timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


class StreamCorrWorker:
    def __init__(self, settings: StreamCorrSettings) -> None:
        self._settings = settings
        self._consumer = None
        self._state_redis = None
        self._sqlite_state: SQLiteStreamState | None = None
        self._ch_client: Optional[Client] = None
        self._rules: List[StreamCorrRule] = []
        self._rule_index: dict[str, list[StreamCorrRule]] = {}
        self._rule_index_fallback: list[StreamCorrRule] = []
        self._transport_backend = transport_backend(settings)
        state_settings = stream_state_settings_from_env()
        self._state_backend = state_settings.backend
        self._sqlite_state_path = state_settings.sqlite_path
        self._time_mode = str(os.getenv("SIEM_STREAM_CORR_TIME_MODE", "processing") or "processing").strip().lower()
        if self._time_mode not in {"processing", "event"}:
            self._time_mode = "processing"
        self._shadow_compare = str(os.getenv("SIEM_STREAM_CORR_SHADOW_COMPARE", "false") or "false").strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }
        self._allowed_lateness_sec = max(0, int(os.getenv("SIEM_STREAM_CORR_ALLOWED_LATENESS_SEC", "600") or "600"))
        self._watermark_lag_sec = max(1, int(os.getenv("SIEM_STREAM_CORR_WATERMARK_LAG_SEC", "300") or "300"))
        self._runtime_table = "siem.stream_corr_runtime_status"
        self._runtime_status_interval_sec = max(5, int(os.getenv("SIEM_STREAM_CORR_RUNTIME_STATUS_INTERVAL_SEC", "30") or "30"))
        self._min_alert_cooldown_sec = max(0, int(os.getenv("SIEM_STREAM_CORR_MIN_ALERT_COOLDOWN_SEC", "3600") or "3600"))
        self._heartbeat_yield_every = max(
            1,
            int(os.getenv("SIEM_STREAM_CORR_HEARTBEAT_YIELD_EVERY", "100") or "100"),
        )
        self._max_event_epoch_seen = 0.0
        self._last_event_epoch = 0.0
        self._late_events_total = 0
        self._timestamp_fallback_total = 0
        self._shadow_compare_mismatches_total = 0
        self._last_mismatch_ts = ""
        self._last_runtime_status_flush = 0.0
        self._runtime_events_since_flush = 0
        self._runtime_alerts_since_flush = 0

    async def init(self) -> None:
        self._consumer = create_transport_consumer(
            self._settings,
            alias="filtered",
            group=self._settings.group_name,
            consumer=self._settings.consumer_name,
        )
        await self._consumer.init()
        if self._state_backend == "sqlite":
            self._sqlite_state = SQLiteStreamState(self._sqlite_state_path)
            state_meta = self._sqlite_state.read_runtime_meta()
            self._max_event_epoch_seen = float(state_meta.get("max_event_epoch_seen") or 0.0)
            self._last_event_epoch = float(state_meta.get("last_event_epoch") or 0.0)
            self._late_events_total = int(state_meta.get("late_events_total") or 0)
            self._timestamp_fallback_total = int(state_meta.get("timestamp_fallback_total") or 0)
            self._shadow_compare_mismatches_total = int(state_meta.get("shadow_compare_mismatches_total") or 0)
            self._last_mismatch_ts = str(state_meta.get("last_mismatch_ts") or "")
        else:
            self._state_redis = create_resilient_async_redis_client(connection_settings_from_object(self._settings))
        self._ch_client = Client(
            host=self._settings.ch_host,
            port=self._settings.ch_port,
            user=self._settings.ch_user,
            password=self._settings.ch_password,
            database=self._settings.ch_db,
            send_receive_timeout=self._settings.ch_timeout_secs,
        )

        self._ensure_runtime_tables()
        self._rules = load_stream_rules(self._settings)
        self._rebuild_rule_index()
        self._write_runtime_status(events_processed=0, alerts_created=0)

        logger.info(
            "StreamCorrWorker initialized",
            extra={
                "extra": {
                    "stream": self._settings.filtered_stream_key,
                    "group": self._settings.group_name,
                    "consumer": self._settings.consumer_name,
                    "rules_count": len(self._rules),
                    "batch_size": self._settings.batch_size,
                    "time_mode": self._time_mode,
                    "shadow_compare": self._shadow_compare,
                    "allowed_lateness_sec": self._allowed_lateness_sec,
                    "watermark_lag_sec": self._watermark_lag_sec,
                    "transport_backend": self._transport_backend,
                    "state_backend": self._state_backend,
                    "rule_index_buckets": len(self._rule_index),
                    "rule_index_fallback": len(self._rule_index_fallback),
                }
            },
        )

    @staticmethod
    def _index_key(field: str, value: Any) -> str:
        return f"{field}\x00{str(value or '').strip().lower()}"

    @classmethod
    def _rule_index_keys(cls, rule: StreamCorrRule) -> set[str]:
        expr = str(getattr(rule, "expr_text", "") or "")
        keys: set[str] = set()
        for match in _EXACT_FIELD_RE.finditer(expr):
            field = str(match.group("field") or "").strip()
            if field not in _RULE_INDEX_FIELDS:
                continue
            value = str(match.group("value") or "").strip()
            if value:
                keys.add(cls._index_key(field, value))
        return keys

    def _rebuild_rule_index(self) -> None:
        index: dict[str, list[StreamCorrRule]] = {}
        fallback: list[StreamCorrRule] = []
        for rule in self._rules:
            keys = self._rule_index_keys(rule)
            if not keys:
                fallback.append(rule)
                continue
            for key in keys:
                index.setdefault(key, []).append(rule)
        self._rule_index = index
        self._rule_index_fallback = fallback

    def _candidate_rules(self, event: dict[str, Any]) -> list[StreamCorrRule]:
        candidates: list[StreamCorrRule] = []
        seen: set[int] = set()
        for rule in self._rule_index_fallback:
            rule_id = int(getattr(rule, "id", 0) or 0)
            if rule_id in seen:
                continue
            seen.add(rule_id)
            candidates.append(rule)
        for field in _RULE_INDEX_FIELDS:
            value = str(event.get(field) or "").strip()
            if not value:
                continue
            for rule in self._rule_index.get(self._index_key(field, value), []):
                rule_id = int(getattr(rule, "id", 0) or 0)
                if rule_id in seen:
                    continue
                seen.add(rule_id)
                candidates.append(rule)
        return candidates

    def _should_skip_correlation(self, event: dict[str, Any]) -> bool:
        return _is_benchmark_event(event)

    def _ensure_runtime_tables(self) -> None:
        assert self._ch_client is not None
        try:
            self._ch_client.execute(
                f"""
                CREATE TABLE IF NOT EXISTS {self._runtime_table} (
                    observed_ts DateTime,
                    instance_name String,
                    transport_backend LowCardinality(String),
                    state_backend LowCardinality(String),
                    mode LowCardinality(String),
                    shadow_compare UInt8,
                    watermark_epoch Float64,
                    watermark_lag_sec UInt32,
                    allowed_lateness_sec UInt32,
                    max_event_epoch_seen Float64,
                    last_event_epoch Float64,
                    late_events_total UInt64,
                    timestamp_fallback_total UInt64,
                    shadow_compare_mismatches_total UInt64,
                    last_mismatch_ts Nullable(DateTime),
                    last_batch_events UInt32,
                    last_batch_alerts UInt32
                )
                ENGINE = MergeTree
                ORDER BY (instance_name, observed_ts)
                """
            )
            self._ch_client.execute(
                f"ALTER TABLE {self._runtime_table} ADD COLUMN IF NOT EXISTS transport_backend LowCardinality(String)"
            )
            self._ch_client.execute(
                f"ALTER TABLE {self._runtime_table} ADD COLUMN IF NOT EXISTS state_backend LowCardinality(String)"
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("Unable to ensure stream correlation runtime table: %s", exc)

    async def _reload_rules_periodically(self) -> None:
        while True:
            try:
                self._rules = await asyncio.to_thread(load_stream_rules, self._settings)
                self._rebuild_rule_index()
            except Exception as exc:  # noqa: BLE001
                logger.error("Failed to reload stream correlation rules", extra={"extra": {"error": str(exc)}})
            await asyncio.sleep(60)

    async def run(self) -> None:
        assert self._consumer is not None
        assert self._ch_client is not None
        ch = self._ch_client

        asyncio.create_task(self._reload_rules_periodically())

        while True:
            try:
                resp = await self._consumer.poll(batch_size=self._settings.batch_size, block_ms=5000)
            except Exception as exc:  # noqa: BLE001
                logger.error(
                    "Transport poll failed in stream_corr",
                    extra={"extra": {"error_type": type(exc).__name__, "error": repr(exc)}},
                )
                await asyncio.sleep(1)
                continue

            if not resp:
                now = time.time()
                if now - self._last_runtime_status_flush >= self._runtime_status_interval_sec:
                    status_written = await asyncio.to_thread(
                        self._write_runtime_status,
                        events_processed=self._runtime_events_since_flush,
                        alerts_created=self._runtime_alerts_since_flush,
                    )
                    if status_written:
                        self._runtime_events_since_flush = 0
                        self._runtime_alerts_since_flush = 0
                continue

            wall_clock_now = time.time()
            alerts_to_insert: List[tuple[Any, ...]] = []
            processed_messages: List[Any] = []
            events_processed = 0
            alerts_created = 0

            for message in resp:
                events_processed += 1
                processed_messages.append(message)

                event: Dict[str, Any] = dict(message.fields)
                msg_id = str(event.get("event.id") or event.get("event_id") or message.id)
                if self._should_skip_correlation(event):
                    continue

                event_epoch, fallback_used = self._event_epoch(event, wall_clock_now)
                if fallback_used:
                    self._timestamp_fallback_total += 1
                self._max_event_epoch_seen = max(self._max_event_epoch_seen, event_epoch)
                self._last_event_epoch = max(self._last_event_epoch, event_epoch)
                watermark_epoch = self._watermark_epoch()
                if event_epoch < watermark_epoch:
                    self._late_events_total += 1

                event["_correlation_event_epoch"] = str(event_epoch)
                event["_correlation_watermark_epoch"] = str(watermark_epoch)
                event["_correlation_timestamp_fallback"] = bool(fallback_used)

                for rule in self._candidate_rules(event):
                    if rule.pattern != "threshold":
                        continue
                    if not matches_rule(rule, event):
                        continue

                    entity_key = str(event.get(rule.entity_field) or "")
                    if not entity_key:
                        continue

                    primary_mode = self._time_mode
                    primary_epoch = event_epoch if primary_mode == "event" else wall_clock_now
                    primary_result = await self._evaluate_threshold(
                        rule,
                        entity_key,
                        msg_id,
                        primary_epoch,
                        mode=primary_mode,
                        watermark_epoch=watermark_epoch,
                    )

                    shadow_result = None
                    if self._shadow_compare:
                        shadow_mode = "processing" if primary_mode == "event" else "event"
                        shadow_epoch = event_epoch if shadow_mode == "event" else wall_clock_now
                        shadow_result = await self._evaluate_threshold(
                            rule,
                            entity_key,
                            msg_id,
                            shadow_epoch,
                            mode=shadow_mode,
                            watermark_epoch=watermark_epoch,
                        )
                        if (
                            bool(primary_result["should_alert"]) != bool(shadow_result["should_alert"])
                            or int(primary_result["hits"]) != int(shadow_result["hits"])
                        ):
                            self._shadow_compare_mismatches_total += 1
                            self._last_mismatch_ts = _iso_from_epoch(max(primary_epoch, shadow_epoch))

                    if bool(primary_result["should_alert"]):
                        alerts_to_insert.append(
                            self._build_alert_row(
                                rule,
                                event,
                                entity_key,
                                float(primary_result["event_epoch"]),
                                int(primary_result["hits"]),
                                mode=primary_mode,
                                fallback_used=fallback_used,
                                shadow_result=shadow_result,
                            )
                        )
                        alerts_created += 1

                if events_processed % self._heartbeat_yield_every == 0:
                    await asyncio.sleep(0)

            if self._sqlite_state is not None:
                self._sqlite_state.flush()

            if alerts_to_insert:
                try:
                    await asyncio.to_thread(
                        ch.execute,
                        """
                            INSERT INTO siem.alerts_raw
                            (ts, alert_id, rule_id, rule_name, severity,
                             ts_first, ts_last, window_s, entity_key,
                             hits, context_json, source, status)
                            VALUES
                        """,
                        alerts_to_insert,
                    )
                    logger.info(
                        "Inserted alerts batch into ClickHouse",
                        extra={"extra": {"alerts_inserted": len(alerts_to_insert)}},
                    )
                except Exception as exc:  # noqa: BLE001
                    logger.error(
                        "Failed to insert alerts into ClickHouse in stream_corr",
                        extra={"extra": {"error": str(exc), "rows": len(alerts_to_insert)}},
                    )

            if processed_messages:
                try:
                    await self._consumer.ack(processed_messages)
                    if self._sqlite_state is not None:
                        self._save_processed_offsets(processed_messages)
                except Exception as exc:  # noqa: BLE001
                    logger.error("Failed to ack messages in stream_corr", extra={"extra": {"error": str(exc)}})

            if events_processed > 0:
                self._runtime_events_since_flush += events_processed
                self._runtime_alerts_since_flush += alerts_created
                now = time.time()
                if now - self._last_runtime_status_flush >= self._runtime_status_interval_sec:
                    status_written = await asyncio.to_thread(
                        self._write_runtime_status,
                        events_processed=self._runtime_events_since_flush,
                        alerts_created=self._runtime_alerts_since_flush,
                    )
                    if status_written:
                        logger.info(
                            "StreamCorr interval processed",
                            extra={
                                "extra": {
                                    "events_processed": self._runtime_events_since_flush,
                                    "alerts_created": self._runtime_alerts_since_flush,
                                }
                            },
                        )
                        self._runtime_events_since_flush = 0
                        self._runtime_alerts_since_flush = 0

    def _save_processed_offsets(self, messages: list[Any]) -> None:
        if self._sqlite_state is None:
            return
        offsets: dict[tuple[str, int], int] = {}
        for message in messages:
            topic = str(getattr(message, "topic", "") or "")
            partition = int(getattr(message, "partition", -1))
            offset = int(getattr(message, "offset", -1))
            if not topic or partition < 0 or offset < 0:
                continue
            key = (topic, partition)
            offsets[key] = max(offsets.get(key, 0), offset + 1)
        if not offsets:
            return
        updated_ts = _iso_from_epoch(time.time())
        self._sqlite_state.save_offsets(
            [
                {
                    "transport_backend": self._transport_backend,
                    "group_name": self._settings.group_name,
                    "topic_name": topic,
                    "partition_id": partition,
                    "offset_value": offset_value,
                    "updated_ts": updated_ts,
                }
                for (topic, partition), offset_value in offsets.items()
            ]
        )

    def _redis_key_zset(self, rule_id: int, entity_key: str, *, mode: str) -> str:
        return f"siem:stream_corr:rule:{rule_id}:ent:{entity_key}:mode:{mode}"

    def _redis_key_last_alert(self, rule_id: int, entity_key: str, *, mode: str) -> str:
        return f"siem:stream_corr:last_alert:{rule_id}:{entity_key}:mode:{mode}"

    def _watermark_epoch(self) -> float:
        if self._max_event_epoch_seen <= 0:
            return 0.0
        return max(0.0, self._max_event_epoch_seen - float(self._watermark_lag_sec))

    def _event_epoch(self, event: Dict[str, Any], fallback: float) -> tuple[float, bool]:
        candidates = (
            event.get("ts"),
            event.get("@timestamp"),
            event.get("event.created"),
            event.get("event.ingested"),
            event.get("event.time"),
        )
        for raw_value in candidates:
            if raw_value in (None, ""):
                continue
            if isinstance(raw_value, (int, float)):
                value = float(raw_value)
                if value > 0:
                    return value, False
                continue
            text = str(raw_value).strip()
            if not text:
                continue
            if text.replace(".", "", 1).isdigit():
                try:
                    return float(text), False
                except ValueError:
                    pass
            normalized = text.replace("Z", "+00:00")
            for candidate in (normalized, normalized.replace(" ", "T")):
                try:
                    parsed = datetime.fromisoformat(candidate)
                    if parsed.tzinfo is None:
                        parsed = parsed.replace(tzinfo=timezone.utc)
                    return parsed.timestamp(), False
                except ValueError:
                    continue
            for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M"):
                try:
                    parsed = datetime.strptime(text, fmt).replace(tzinfo=timezone.utc)
                    return parsed.timestamp(), False
                except ValueError:
                    continue
        return fallback, True

    async def _evaluate_threshold(
        self,
        rule: StreamCorrRule,
        entity_key: str,
        msg_id: str,
        event_epoch: float,
        *,
        mode: str,
        watermark_epoch: float,
    ) -> dict[str, Any]:
        window_start = event_epoch - rule.window_s
        retention_floor = window_start
        if watermark_epoch:
            retention_floor = min(retention_floor, watermark_epoch - self._allowed_lateness_sec - rule.window_s)

        if self._sqlite_state is not None:
            self._sqlite_state.append_event(rule.id, entity_key, mode, msg_id, event_epoch, commit=False)
            self._sqlite_state.trim_events(rule.id, entity_key, mode, retention_floor, commit=False)
            current_count = int(self._sqlite_state.count_events(rule.id, entity_key, mode, window_start, event_epoch))
            last_alert_ts = float(self._sqlite_state.get_last_alert(rule.id, entity_key, mode))
        else:
            assert self._state_redis is not None
            redis = self._state_redis
            zkey = self._redis_key_zset(rule.id, entity_key, mode=mode)
            last_alert_key = self._redis_key_last_alert(rule.id, entity_key, mode=mode)
            await redis.zadd(zkey, {msg_id: event_epoch})
            await redis.zremrangebyscore(zkey, "-inf", retention_floor)
            current_count = int(await redis.zcount(zkey, window_start, event_epoch))
            last_alert_raw = await redis.get(last_alert_key)
            last_alert_ts = float(last_alert_raw) if last_alert_raw is not None else 0.0

        if current_count < rule.threshold:
            return {
                "should_alert": False,
                "hits": current_count,
                "event_epoch": event_epoch,
                "window_start": window_start,
                "mode": mode,
                "late_event": bool(watermark_epoch and event_epoch < watermark_epoch),
            }

        alert_cooldown_s = max(int(rule.window_s), int(self._min_alert_cooldown_sec))
        if last_alert_ts and abs(event_epoch - last_alert_ts) < alert_cooldown_s:
            return {
                "should_alert": False,
                "hits": current_count,
                "event_epoch": event_epoch,
                "window_start": window_start,
                "mode": mode,
                "late_event": bool(watermark_epoch and event_epoch < watermark_epoch),
                "suppression_window_s": alert_cooldown_s,
            }

        if self._sqlite_state is not None:
            self._sqlite_state.set_last_alert(rule.id, entity_key, mode, event_epoch, commit=False)
        else:
            assert self._state_redis is not None
            await self._state_redis.set(self._redis_key_last_alert(rule.id, entity_key, mode=mode), str(event_epoch))
        return {
            "should_alert": True,
            "hits": current_count,
            "event_epoch": event_epoch,
            "window_start": window_start,
            "mode": mode,
            "late_event": bool(watermark_epoch and event_epoch < watermark_epoch),
            "suppression_window_s": alert_cooldown_s,
        }

    def _build_alert_row(
        self,
        rule: StreamCorrRule,
        event: Dict[str, Any],
        entity_key: str,
        event_epoch: float,
        hits: int,
        *,
        mode: str,
        fallback_used: bool,
        shadow_result: dict[str, Any] | None,
    ) -> tuple[Any, ...]:
        ts_dt = datetime.fromtimestamp(event_epoch, tz=timezone.utc)
        ts_first_dt = datetime.fromtimestamp(event_epoch - rule.window_s, tz=timezone.utc)
        ts_last_dt = ts_dt

        alert_id = str(uuid.uuid4())
        source = str(event.get("log_source") or event.get("host.name") or event.get("source.ip") or "stream")
        context = {
            "rule_id": rule.id,
            "entity_key": entity_key,
            "description": rule.description,
            "source": source,
            "host_name": str(event.get("host.name") or ""),
            "category": str(event.get("event.category") or ""),
            "event_type": str(event.get("event.type") or ""),
            "event_action": str(event.get("event.action") or ""),
            "user_name": str(event.get("user.name") or ""),
            "target_user": str(event.get("user.target.name") or ""),
            "process_name": str(event.get("process.name") or ""),
            "process_command": str(event.get("process.command_line") or ""),
            "correlation_mode": mode,
            "timestamp_fallback": bool(fallback_used),
            "watermark_epoch": str(event.get("_correlation_watermark_epoch") or ""),
            "event_epoch": str(event.get("_correlation_event_epoch") or ""),
            "shadow_compare": shadow_result or {},
        }

        return (
            ts_dt,
            alert_id,
            rule.id,
            rule.name,
            rule.severity,
            ts_first_dt,
            ts_last_dt,
            rule.window_s,
            entity_key,
            hits,
            json.dumps(context, ensure_ascii=False),
            source,
            "open",
        )

    def _write_runtime_status(self, *, events_processed: int, alerts_created: int) -> bool:
        assert self._ch_client is not None
        observed_ts = datetime.now(timezone.utc).replace(tzinfo=None)
        last_mismatch_dt = None
        if self._last_mismatch_ts:
            try:
                last_mismatch_dt = datetime.fromisoformat(self._last_mismatch_ts.replace("Z", "+00:00")).astimezone(timezone.utc).replace(tzinfo=None)
            except ValueError:
                last_mismatch_dt = None
        try:
            self._ch_client.execute(
                f"""
                INSERT INTO {self._runtime_table}
                (observed_ts, instance_name, transport_backend, state_backend, mode, shadow_compare, watermark_epoch, watermark_lag_sec,
                 allowed_lateness_sec, max_event_epoch_seen, last_event_epoch, late_events_total,
                 timestamp_fallback_total, shadow_compare_mismatches_total, last_mismatch_ts,
                 last_batch_events, last_batch_alerts)
                VALUES
                """,
                [
                    (
                        observed_ts,
                        str(getattr(self._settings, "instance_name", "siem-stream-corr") or "siem-stream-corr"),
                        self._transport_backend,
                        self._state_backend,
                        self._time_mode,
                        1 if self._shadow_compare else 0,
                        float(self._watermark_epoch()),
                        int(self._watermark_lag_sec),
                        int(self._allowed_lateness_sec),
                        float(self._max_event_epoch_seen),
                        float(self._last_event_epoch),
                        int(self._late_events_total),
                        int(self._timestamp_fallback_total),
                        int(self._shadow_compare_mismatches_total),
                        last_mismatch_dt,
                        int(events_processed),
                        int(alerts_created),
                    )
                ],
            )
            self._last_runtime_status_flush = time.time()
            if self._sqlite_state is not None:
                self._sqlite_state.write_runtime_meta(
                    {
                        "max_event_epoch_seen": float(self._max_event_epoch_seen),
                        "last_event_epoch": float(self._last_event_epoch),
                        "late_events_total": int(self._late_events_total),
                        "timestamp_fallback_total": int(self._timestamp_fallback_total),
                        "shadow_compare_mismatches_total": int(self._shadow_compare_mismatches_total),
                        "last_mismatch_ts": self._last_mismatch_ts,
                    }
                )
            return True
        except Exception as exc:  # noqa: BLE001
            logger.warning("Unable to write stream correlation runtime status: %s", exc)
            return False


async def main() -> None:
    configure_logging()
    settings = StreamCorrSettings.load()
    worker = StreamCorrWorker(settings)
    await worker.init()
    await worker.run()


if __name__ == "__main__":
    asyncio.run(main())
