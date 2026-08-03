from __future__ import annotations

import hashlib
import json
import logging
import os
import signal
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
from zoneinfo import ZoneInfo

import psycopg
import requests

try:
    from runtime_humanization import humanize_source_name, humanize_technical_value
except ImportError:  # pragma: no cover - service-local fallback
    try:
        from app.runtime_humanization import humanize_source_name, humanize_technical_value  # type: ignore[no-redef]
    except ImportError:  # pragma: no cover - test fallback

        def humanize_source_name(value: Any, *, lang: str = "en", technical_suffix: bool = False) -> str:  # type: ignore[no-redef]
            return str(value or "").strip()

        def humanize_technical_value(value: Any, *, lang: str = "en") -> str:  # type: ignore[no-redef]
            return str(value or "").strip()


LOG = logging.getLogger("incident_telegram_bot")
TERMINAL_STATUSES = {
    "closed",
    "false_positive",
    "expired",
    "merged",
    "suppressed",
    "suppressed_by_tuning",
}


def _env(name: str, default: str = "") -> str:
    return str(os.getenv(name, default) or default).strip()


def _env_int(name: str, default: int) -> int:
    try:
        return int(_env(name, str(default)) or default)
    except Exception:
        return default


def _env_bool(name: str, default: bool = False) -> bool:
    value = _env(name)
    return default if not value else value.lower() in {"1", "true", "yes", "on"}


def _utc_now() -> datetime:
    return datetime.now(tz=timezone.utc)


def _incident_count(incident: dict[str, Any]) -> int:
    for key in ("raw_hits_total", "raw_alerts_total", "count_alerts", "hits", "count", "events_count"):
        try:
            value = incident.get(key)
            if value not in {None, ""}:
                return int(value)
        except Exception:
            continue
    return 0


def _incident_should_skip_delivery(incident: dict[str, Any]) -> bool:
    return str(incident.get("status") or "").strip().lower() in TERMINAL_STATUSES


def _safe_chat_title(user: dict[str, Any]) -> str:
    return str(user.get("username") or user.get("first_name") or user.get("last_name") or "operator").strip()


def _redact_secret(value: Any, secret: str) -> str:
    text = str(value or "")
    return text.replace(secret, "<redacted>") if secret else text


def _incident_hosts(incident: dict[str, Any]) -> list[str]:
    values: list[Any] = []
    for container in (incident, incident.get("cluster") or {}):
        if not isinstance(container, dict):
            continue
        for key in ("host_labels", "hosts", "sources", "assets"):
            if isinstance(container.get(key), list):
                values.extend(container[key])
    result: list[str] = []
    seen: set[str] = set()
    for value in values:
        raw = str(value or "").strip()
        label = humanize_source_name(raw, lang="ru", technical_suffix=True) or humanize_technical_value(raw, lang="ru")
        normalized = str(label or raw).strip()
        if normalized and normalized.lower() not in seen:
            seen.add(normalized.lower())
            result.append(normalized)
    return result


@dataclass(frozen=True)
class BotConfig:
    siem_base_url: str
    siem_api_token: str
    incident_view: str
    incident_window: str
    incident_limit: int
    poll_seconds: int
    verify_tls: bool
    telegram_bot_token: str
    telegram_chat_id: str
    postgres_dsn: str
    open_base_url: str
    callback_note: str
    enable_callbacks: bool
    telegram_proxy_url: str
    default_timezone: str
    stale_grace_seconds: int = 180

    @property
    def telegram_enabled(self) -> bool:
        return bool(self.telegram_bot_token and self.telegram_chat_id)


def load_config() -> BotConfig:
    siem_base_url = _env("SIEM_BOT_BASE_URL", _env("SIEM_WEB_BASE_URL", "https://192.168.3.102")).rstrip("/")
    return BotConfig(
        siem_base_url=siem_base_url,
        siem_api_token=_env("SIEM_BOT_API_TOKEN"),
        # Notifications intentionally follow the same aggregated queue as Web.
        # Raw-alert delivery is not supported because it bypasses incident grouping.
        incident_view="agg",
        incident_window=_env("SIEM_BOT_INCIDENT_WINDOW", "24h"),
        incident_limit=max(10, min(_env_int("SIEM_BOT_INCIDENT_LIMIT", 1000), 1000)),
        poll_seconds=max(15, _env_int("SIEM_BOT_POLL_SECONDS", 45)),
        verify_tls=_env_bool("SIEM_BOT_VERIFY_TLS", False),
        telegram_bot_token=_env("SIEM_TELEGRAM_BOT_TOKEN"),
        telegram_chat_id=_env("SIEM_TELEGRAM_CHAT_ID"),
        postgres_dsn=_env(
            "SIEM_BOT_POSTGRES_DSN",
            "postgresql://siem_incident_bot:siem_incident_bot@127.0.0.1:5432/siem_incident_bot",
        ),
        open_base_url=_env("SIEM_BOT_OPEN_BASE_URL", siem_base_url).rstrip("/"),
        callback_note=_env("SIEM_BOT_CALLBACK_NOTE", "Готово."),
        enable_callbacks=_env_bool("SIEM_BOT_ENABLE_CALLBACKS", True),
        telegram_proxy_url=_env("SIEM_TELEGRAM_PROXY_URL"),
        default_timezone=_env("SIEM_BOT_DEFAULT_TIMEZONE", "Europe/Moscow"),
        stale_grace_seconds=max(60, _env_int("SIEM_BOT_STALE_GRACE_SECONDS", 180)),
    )


class IncidentTelegramBot:
    def __init__(self, config: BotConfig) -> None:
        self.config = config
        self._stop = False
        self._ssl_context = ssl.create_default_context()
        if not config.verify_tls:
            self._ssl_context.check_hostname = False
            self._ssl_context.verify_mode = ssl.CERT_NONE

    def stop(self, *_args: object) -> None:
        self._stop = True

    def run(self) -> None:
        signal.signal(signal.SIGINT, self.stop)
        signal.signal(signal.SIGTERM, self.stop)
        with psycopg.connect(self.config.postgres_dsn, autocommit=True) as conn:
            self._ensure_schema(conn)
            with conn.cursor() as cur:
                cur.execute("select pg_try_advisory_lock(hashtext('siem_incident_telegram_bot'))")
                lock_row = cur.fetchone()
            if not lock_row or not bool(lock_row[0]):
                raise RuntimeError("another incident Telegram worker owns the delivery lock")
            LOG.info("incident bot started; telegram=%s callbacks=%s", self.config.telegram_enabled, self.config.enable_callbacks)
            while not self._stop:
                try:
                    self._poll_incidents(conn)
                    if self.config.enable_callbacks:
                        self._poll_callbacks(conn)
                except Exception as exc:  # noqa: BLE001
                    LOG.exception("incident bot iteration failed: %s", exc)
                deadline = time.time() + self.config.poll_seconds
                while not self._stop and time.time() < deadline:
                    time.sleep(1)

    def _ensure_schema(self, conn: psycopg.Connection[Any]) -> None:
        with conn.cursor() as cur:
            cur.execute(
                """
                create table if not exists incident_delivery_state (
                    incident_key text primary key,
                    incident_view text not null,
                    fingerprint text not null,
                    incident_status text not null default '',
                    incident_title text not null default '',
                    delivered_at timestamptz not null default now(),
                    updated_at timestamptz not null default now(),
                    payload jsonb not null default '{}'::jsonb
                )
                """
            )
            cur.execute("alter table incident_delivery_state add column if not exists telegram_message_id bigint")
            cur.execute("alter table incident_delivery_state add column if not exists telegram_chat_id text not null default ''")
            cur.execute("alter table incident_delivery_state add column if not exists delivery_count integer not null default 0")
            cur.execute("alter table incident_delivery_state add column if not exists last_seen_at timestamptz not null default now()")
            cur.execute("alter table incident_delivery_state add column if not exists current_incident_key text not null default ''")
            cur.execute("alter table incident_delivery_state add column if not exists aggregation_fingerprint text not null default ''")
            cur.execute("alter table incident_delivery_state add column if not exists operation_key text not null default ''")
            cur.execute("alter table incident_delivery_state add column if not exists operation_kind text not null default ''")
            cur.execute("alter table incident_delivery_state add column if not exists operation_state text not null default 'committed'")
            cur.execute("alter table incident_delivery_state add column if not exists operation_fingerprint text not null default ''")
            cur.execute("alter table incident_delivery_state add column if not exists retry_count integer not null default 0")
            cur.execute("alter table incident_delivery_state add column if not exists last_error text not null default ''")
            cur.execute(
                "update incident_delivery_state set current_incident_key = incident_key "
                "where current_incident_key = ''"
            )
            cur.execute(
                """
                create table if not exists telegram_bot_state (
                    state_key text primary key,
                    state_value text not null,
                    updated_at timestamptz not null default now()
                )
                """
            )

    def _poll_incidents(self, conn: psycopg.Connection[Any]) -> None:
        if not self.config.siem_api_token:
            LOG.warning("SIEM API token is missing; incident polling is disabled")
            return
        payload = self._siem_request_json(
            f"/api/incidents?view={urllib.parse.quote(self.config.incident_view)}"
            f"&scope=main&window={urllib.parse.quote(self.config.incident_window)}"
            f"&limit={self.config.incident_limit}"
        )
        items = [dict(item or {}) for item in list(payload.get("items") or [])]
        current_keys = {self._delivery_key(item) for item in items if self._delivery_key(item)}
        for item in reversed(items):
            self._process_incident(conn, item)
        available_count = int(payload.get("available_count") or len(items))
        if available_count <= len(items):
            self._reconcile_absent_incidents(conn, current_keys)
        else:
            LOG.info(
                "incident snapshot truncated (%s/%s); stale-card reconciliation deferred",
                len(items),
                available_count,
            )

    def _process_incident(self, conn: psycopg.Connection[Any], incident: dict[str, Any]) -> None:
        current_incident_key = self._incident_key(incident)
        delivery_key = self._delivery_key(incident)
        if not current_incident_key or not delivery_key:
            return
        fingerprint = self._incident_fingerprint(incident)
        aggregation_fingerprint = self._aggregation_fingerprint(incident)
        state = self._get_incident_state(
            conn,
            delivery_key,
            current_incident_key=current_incident_key,
            aggregation_fingerprint=aggregation_fingerprint,
        )
        if state and str(state.get("stored_delivery_key") or delivery_key) != delivery_key:
            self._migrate_state_key(
                conn,
                old_key=str(state.get("stored_delivery_key") or ""),
                new_key=delivery_key,
            )
            state["stored_delivery_key"] = delivery_key
        interrupted_state = str((state or {}).get("operation_state") or "")
        interrupted_operation = str((state or {}).get("operation_kind") or "")
        if (
            state
            and interrupted_state in {"prepared", "uncertain"}
            and interrupted_operation == "send"
            and not state.get("telegram_message_id")
            and str(state.get("operation_fingerprint") or "") == fingerprint
        ):
            # A restart may happen after Telegram accepted sendMessage but before
            # the message id was committed. Re-sending would create a duplicate;
            # keep the attempt explicitly uncertain for operator reconciliation.
            self._touch_incident_state(
                conn,
                delivery_key=delivery_key,
                current_incident_key=current_incident_key,
                incident=incident,
                operation_state="uncertain",
            )
            self._publish_delivery_state(
                incident,
                incident_key=current_incident_key,
                delivery_key=delivery_key,
                aggregation_fingerprint=aggregation_fingerprint,
                telegram={
                    "status": "uncertain",
                    "message_id": state.get("telegram_message_id") or 0,
                    "reason": "unconfirmed_delivery_attempt_not_replayed",
                },
                delivery_count=0,
                operation=str(state.get("operation_kind") or "send"),
                attempt_key=str(state.get("operation_key") or ""),
                active=bool(state.get("telegram_message_id")),
            )
            return
        if state and interrupted_state == "prepared":
            # Edits and deletes target a known message id and are safe to resume.
            # The process-wide PostgreSQL advisory lock prevents a second worker
            # from racing the resumed operation.
            self._touch_incident_state(
                conn,
                delivery_key=delivery_key,
                current_incident_key=current_incident_key,
                incident=incident,
                operation_state="retryable",
            )
            state["operation_state"] = "retryable"
        if (
            state
            and str(state.get("fingerprint") or "") == fingerprint
            and str(state.get("operation_state") or "committed") == "committed"
        ):
            self._touch_incident_state(
                conn,
                delivery_key=delivery_key,
                current_incident_key=current_incident_key,
                incident=incident,
            )
            stored_payload = state.get("payload") if isinstance(state.get("payload"), dict) else {}
            stored_telegram = (
                stored_payload.get("telegram")
                if isinstance(stored_payload.get("telegram"), dict)
                else {}
            )
            self._publish_delivery_state(
                incident,
                incident_key=current_incident_key,
                delivery_key=delivery_key,
                aggregation_fingerprint=aggregation_fingerprint,
                telegram={
                    **stored_telegram,
                    "message_id": (
                        stored_telegram.get("message_id")
                        or state.get("telegram_message_id")
                    ),
                    "status": stored_telegram.get("status") or "unchanged",
                },
                delivery_count=0,
                operation="unchanged",
                attempt_key=str(state.get("operation_key") or ""),
                active=bool(state.get("telegram_message_id")),
            )
            return
        status = str(incident.get("status") or "new").strip().lower()
        terminal = status in TERMINAL_STATUSES
        chat_id = str((state or {}).get("telegram_chat_id") or self.config.telegram_chat_id)
        message_id = (state or {}).get("telegram_message_id")
        callback_ref = self._store_incident_callback_ref(conn, current_incident_key)
        timezone_name = self._get_chat_timezone(conn, chat_id)
        operation = "delete" if message_id and terminal else "edit" if message_id else "retract" if terminal else "send"
        attempt_key = hashlib.sha256(f"{delivery_key}|{operation}|{fingerprint}".encode("utf-8")).hexdigest()
        acquired = self._prepare_operation(
            conn,
            delivery_key=delivery_key,
            current_incident_key=current_incident_key,
            aggregation_fingerprint=aggregation_fingerprint,
            incident=incident,
            state=state,
            operation=operation,
            attempt_key=attempt_key,
            operation_fingerprint=fingerprint,
            chat_id=chat_id,
        )
        if not acquired:
            self._publish_delivery_state(
                incident,
                incident_key=current_incident_key,
                delivery_key=delivery_key,
                aggregation_fingerprint=aggregation_fingerprint,
                telegram={
                    "status": "pending",
                    "message_id": message_id or 0,
                    "reason": "delivery_operation_already_in_flight",
                },
                delivery_count=0,
                operation=operation,
                attempt_key=attempt_key,
                active=bool(message_id) and not terminal,
            )
            return
        try:
            if operation == "delete":
                telegram = self._delete_incident_card(
                    chat_id=chat_id,
                    message_id=int(message_id),
                    reason=f"terminal_{status}",
                )
            elif operation == "edit":
                telegram = self._edit_incident(
                    incident,
                    current_incident_key,
                    chat_id=chat_id,
                    message_id=int(message_id),
                    timezone_name=timezone_name,
                    callback_ref=callback_ref,
                )
            elif operation == "retract":
                telegram = {"status": "skipped", "reason": f"terminal_{status}"}
            else:
                telegram = self._send_incident(
                    incident,
                    current_incident_key,
                    chat_id=chat_id,
                    timezone_name=timezone_name,
                    callback_ref=callback_ref,
                )
        except Exception as exc:  # noqa: BLE001
            telegram = {
                "status": "uncertain" if operation == "send" else f"{operation}_failed",
                "message_id": message_id or 0,
                "reason": "telegram_operation_not_confirmed",
                "error": self._redact_error(exc),
            }
        next_message_id = (
            None
            if telegram.get("status") in {"deleted", "archived"}
            else telegram.get("message_id") or message_id
        )
        successful = str(telegram.get("status") or "") in {
            "sent",
            "edited",
            "unchanged",
            "deleted",
            "archived",
            "skipped",
        }
        delivered = int(telegram.get("status") == "sent")
        operation_state = (
            "committed"
            if successful
            else "retryable"
            if telegram.get("status") == "telegram_disabled"
            else "uncertain"
            if operation == "send"
            else "retryable"
        )
        committed_fingerprint = fingerprint if successful else str((state or {}).get("fingerprint") or "")
        with conn.cursor() as cur:
            cur.execute(
                """
                insert into incident_delivery_state (
                    incident_key, incident_view, fingerprint, incident_status,
                    incident_title, telegram_message_id, telegram_chat_id,
                    delivery_count, delivered_at, updated_at, last_seen_at, payload,
                    current_incident_key, aggregation_fingerprint, operation_key,
                    operation_kind, operation_state, operation_fingerprint,
                    retry_count, last_error
                )
                values (
                    %s, %s, %s, %s, %s, %s, %s, %s, now(), now(), now(), %s::jsonb,
                    %s, %s, %s, %s, %s, %s, %s, %s
                )
                on conflict (incident_key) do update set
                    fingerprint = excluded.fingerprint,
                    incident_status = excluded.incident_status,
                    incident_title = excluded.incident_title,
                    telegram_message_id = excluded.telegram_message_id,
                    telegram_chat_id = excluded.telegram_chat_id,
                    delivery_count = incident_delivery_state.delivery_count + excluded.delivery_count,
                    updated_at = now(),
                    last_seen_at = now(),
                    payload = excluded.payload,
                    current_incident_key = excluded.current_incident_key,
                    aggregation_fingerprint = excluded.aggregation_fingerprint,
                    operation_key = excluded.operation_key,
                    operation_kind = excluded.operation_kind,
                    operation_state = excluded.operation_state,
                    operation_fingerprint = excluded.operation_fingerprint,
                    retry_count = case when excluded.operation_state = 'committed' then 0 else incident_delivery_state.retry_count + 1 end,
                    last_error = excluded.last_error
                """,
                (
                    delivery_key,
                    self.config.incident_view,
                    committed_fingerprint,
                    status,
                    self._incident_title(incident),
                    next_message_id,
                    chat_id,
                    delivered,
                    json.dumps(
                        {"incident": incident, "telegram": telegram, "processed_at": _utc_now().isoformat()},
                        ensure_ascii=False,
                    ),
                    current_incident_key,
                    aggregation_fingerprint,
                    attempt_key,
                    operation,
                    operation_state,
                    fingerprint,
                    0 if successful else int((state or {}).get("retry_count") or 0) + 1,
                    self._redact_error(telegram.get("error") or telegram.get("reason") or "") if not successful else "",
                ),
            )
        self._publish_delivery_state(
            incident,
            incident_key=current_incident_key,
            delivery_key=delivery_key,
            aggregation_fingerprint=aggregation_fingerprint,
            telegram=telegram,
            delivery_count=delivered,
            operation=operation,
            attempt_key=attempt_key,
            active=bool(next_message_id) and not terminal,
        )

    def _aggregation_group(self, incident: dict[str, Any]) -> dict[str, Any]:
        group = incident.get("group_key")
        if isinstance(group, dict):
            return dict(group)
        raw = incident.get("group_key_json")
        if isinstance(raw, str) and raw.strip():
            try:
                parsed = json.loads(raw)
                if isinstance(parsed, dict):
                    return parsed
            except (TypeError, ValueError):
                pass
        return {}

    def _delivery_key(self, incident: dict[str, Any]) -> str:
        group = self._aggregation_group(incident)
        return str(
            group.get("incident_key")
            or group.get("agg_id")
            or incident.get("aggregation_key")
            or incident.get("agg_id")
            or incident.get("record_id")
            or incident.get("id")
            or ""
        ).strip()

    def _aggregation_fingerprint(self, incident: dict[str, Any]) -> str:
        return hashlib.sha256(f"agg|{self._delivery_key(incident)}".encode("utf-8")).hexdigest()

    def _redact_error(self, value: Any) -> str:
        text = _redact_secret(value, self.config.telegram_bot_token)
        text = _redact_secret(text, self.config.siem_api_token)
        return text[:300]

    def _telegram_message_missing(self, value: Any) -> bool:
        message = self._redact_error(value).lower()
        return "message to edit not found" in message or "message to delete not found" in message

    def _touch_incident_state(
        self,
        conn: psycopg.Connection[Any],
        *,
        delivery_key: str,
        current_incident_key: str,
        incident: dict[str, Any],
        operation_state: str | None = None,
    ) -> None:
        assignment = ", operation_state = %s" if operation_state else ""
        params: list[Any] = [
            current_incident_key,
            str(incident.get("status") or "new").strip().lower(),
            self._incident_title(incident),
        ]
        if operation_state:
            params.append(operation_state)
        params.append(delivery_key)
        with conn.cursor() as cur:
            cur.execute(
                f"""
                update incident_delivery_state
                set last_seen_at = now(), updated_at = now(),
                    current_incident_key = %s,
                    incident_status = %s, incident_title = %s
                    {assignment}
                where incident_key = %s
                """,
                tuple(params),
            )

    def _prepare_operation(
        self,
        conn: psycopg.Connection[Any],
        *,
        delivery_key: str,
        current_incident_key: str,
        aggregation_fingerprint: str,
        incident: dict[str, Any],
        state: dict[str, Any] | None,
        operation: str,
        attempt_key: str,
        operation_fingerprint: str,
        chat_id: str,
    ) -> bool:
        with conn.cursor() as cur:
            cur.execute(
                """
                insert into incident_delivery_state (
                    incident_key, incident_view, fingerprint, incident_status,
                    incident_title, telegram_message_id, telegram_chat_id,
                    delivery_count, delivered_at, updated_at, last_seen_at, payload,
                    current_incident_key, aggregation_fingerprint, operation_key,
                    operation_kind, operation_state, operation_fingerprint,
                    retry_count, last_error
                ) values (
                    %s, %s, %s, %s, %s, %s, %s, %s, now(), now(), now(), %s::jsonb,
                    %s, %s, %s, %s, 'prepared', %s, %s, ''
                )
                on conflict (incident_key) do update set
                    incident_view = excluded.incident_view,
                    incident_status = excluded.incident_status,
                    incident_title = excluded.incident_title,
                    current_incident_key = excluded.current_incident_key,
                    aggregation_fingerprint = excluded.aggregation_fingerprint,
                    operation_key = excluded.operation_key,
                    operation_kind = excluded.operation_kind,
                    operation_state = 'prepared',
                    operation_fingerprint = excluded.operation_fingerprint,
                    updated_at = now(), last_seen_at = now(), last_error = ''
                where incident_delivery_state.operation_state not in ('prepared', 'uncertain')
                returning incident_key
                """,
                (
                    delivery_key,
                    self.config.incident_view,
                    str((state or {}).get("fingerprint") or ""),
                    str(incident.get("status") or "new").strip().lower(),
                    self._incident_title(incident),
                    (state or {}).get("telegram_message_id"),
                    chat_id,
                    0,
                    json.dumps(
                        {"incident": incident, "operation": operation, "prepared_at": _utc_now().isoformat()},
                        ensure_ascii=False,
                    ),
                    current_incident_key,
                    aggregation_fingerprint,
                    attempt_key,
                    operation,
                    operation_fingerprint,
                    int((state or {}).get("retry_count") or 0),
                ),
            )
            return cur.fetchone() is not None

    def _reconcile_absent_incidents(
        self,
        conn: psycopg.Connection[Any],
        current_keys: set[str],
    ) -> None:
        with conn.cursor() as cur:
            cur.execute(
                """
                select incident_key, current_incident_key
                from incident_delivery_state
                where incident_view = %s
                  and incident_status not in (
                      'closed', 'false_positive', 'expired', 'merged',
                      'suppressed', 'suppressed_by_tuning'
                  )
                  and last_seen_at < now() - make_interval(secs => %s)
                order by last_seen_at asc
                limit 500
                """,
                (self.config.incident_view, self.config.stale_grace_seconds),
            )
            stale_rows = list(cur.fetchall())
        for delivery_key, current_incident_key in stale_rows:
            key = str(delivery_key or "").strip()
            if not key or key in current_keys:
                continue
            self._process_incident(
                conn,
                {
                    "record_id": str(current_incident_key or key),
                    "status": "expired",
                    "title": "Incident left the active Web queue",
                    "group_key": {"incident_key": key},
                },
            )

    def _delete_incident_card(
        self,
        *,
        chat_id: str,
        message_id: int,
        reason: str,
    ) -> dict[str, Any]:
        if not self.config.telegram_enabled:
            return {"status": "telegram_disabled", "reason": reason}
        try:
            self._telegram_request(
                "deleteMessage",
                {"chat_id": chat_id, "message_id": int(message_id)},
            )
            return {
                "status": "deleted",
                "message_id": int(message_id),
                "reason": reason,
            }
        except Exception as exc:  # noqa: BLE001
            if self._telegram_message_missing(exc):
                return {
                    "status": "deleted",
                    "message_id": int(message_id),
                    "reason": f"{reason}:already_absent",
                }
            LOG.warning(
                "unable to delete stale Telegram incident card %s: %s",
                message_id,
                self._redact_error(exc),
            )
            try:
                self._telegram_request(
                    "editMessageText",
                    {
                        "chat_id": chat_id,
                        "message_id": int(message_id),
                        "text": (
                            "[АРХИВ] Инцидент больше не находится "
                            "в активной очереди SIEM.\n"
                            f"Причина: {reason}"
                        ),
                        "disable_web_page_preview": True,
                        "reply_markup": {"inline_keyboard": []},
                    },
                )
                return {
                    "status": "archived",
                    "message_id": int(message_id),
                    "reason": reason,
                }
            except Exception as edit_exc:  # noqa: BLE001
                LOG.warning(
                    "unable to archive stale Telegram incident card %s: %s",
                    message_id,
                    self._redact_error(edit_exc),
                )
                return {
                    "status": "delete_failed",
                    "message_id": int(message_id),
                    "reason": reason,
                    "error": self._redact_error(edit_exc),
                }

    def _publish_delivery_state(
        self,
        incident: dict[str, Any],
        *,
        incident_key: str,
        delivery_key: str,
        aggregation_fingerprint: str,
        telegram: dict[str, Any],
        delivery_count: int,
        operation: str,
        attempt_key: str,
        active: bool,
    ) -> None:
        try:
            self._siem_request_json(
                "/api/notification-delivery/incidents",
                method="POST",
                payload={
                    "incident_key": incident_key,
                    "delivery_key": delivery_key,
                    "aggregation_fingerprint": aggregation_fingerprint,
                    "incident_view": self.config.incident_view,
                    "incident_status": str(incident.get("status") or ""),
                    "channel": "telegram",
                    "delivery_status": str(telegram.get("status") or "unknown"),
                    "message_id": int(telegram.get("message_id") or 0),
                    "delivery_count": int(delivery_count),
                    "active": bool(active),
                    "operation": operation,
                    "attempt_key": attempt_key,
                    "reason": str(telegram.get("reason") or telegram.get("error") or "")[:300],
                    "updated_at": _utc_now().isoformat(),
                },
            )
        except Exception as exc:  # noqa: BLE001
            LOG.warning(
                "unable to publish incident delivery state for %s: %s",
                incident_key,
                self._redact_error(exc),
            )

    def _migrate_state_key(
        self,
        conn: psycopg.Connection[Any],
        *,
        old_key: str,
        new_key: str,
    ) -> None:
        if not old_key or not new_key or old_key == new_key:
            return
        with conn.cursor() as cur:
            cur.execute(
                """
                update incident_delivery_state
                set incident_key = %s, aggregation_fingerprint = %s, updated_at = now()
                where incident_key = %s
                  and not exists (
                      select 1 from incident_delivery_state existing
                      where existing.incident_key = %s
                  )
                """,
                (new_key, hashlib.sha256(f"agg|{new_key}".encode("utf-8")).hexdigest(), old_key, new_key),
            )

    def _get_incident_state(
        self,
        conn: psycopg.Connection[Any],
        incident_key: str,
        *,
        current_incident_key: str = "",
        aggregation_fingerprint: str = "",
    ) -> dict[str, Any] | None:
        with conn.cursor() as cur:
            cur.execute(
                """
                select incident_key, fingerprint, payload, telegram_message_id, telegram_chat_id,
                       incident_status, current_incident_key, aggregation_fingerprint,
                       operation_key, operation_kind, operation_state,
                       operation_fingerprint, retry_count, last_error
                from incident_delivery_state
                where incident_key = %s
                   or (%s != '' and current_incident_key = %s)
                   or (%s != '' and aggregation_fingerprint = %s)
                order by (incident_key = %s) desc, updated_at desc
                limit 1
                """,
                (
                    incident_key,
                    current_incident_key,
                    current_incident_key,
                    aggregation_fingerprint,
                    aggregation_fingerprint,
                    incident_key,
                ),
            )
            row = cur.fetchone()
        if not row:
            return None
        payload = row[2] if isinstance(row[2], dict) else {}
        legacy_message_id = ((payload.get("telegram") or {}) if isinstance(payload, dict) else {}).get("message_id")
        return {
            "stored_delivery_key": row[0],
            "fingerprint": row[1],
            "payload": payload,
            "telegram_message_id": row[3] or legacy_message_id,
            "telegram_chat_id": row[4],
            "incident_status": row[5],
            "current_incident_key": row[6],
            "aggregation_fingerprint": row[7],
            "operation_key": row[8],
            "operation_kind": row[9],
            "operation_state": row[10],
            "operation_fingerprint": row[11],
            "retry_count": row[12],
            "last_error": row[13],
        }

    def _incident_key(self, incident: dict[str, Any]) -> str:
        return str(
            incident.get("record_id")
            or incident.get("agg_id")
            or incident.get("alert_id")
            or incident.get("id")
            or ""
        ).strip()

    def _incident_title(self, incident: dict[str, Any]) -> str:
        return str(
            incident.get("title")
            or incident.get("summary")
            or incident.get("rule_name")
            or incident.get("message")
            or self._incident_key(incident)
            or "Инцидент"
        ).strip()

    def _incident_fingerprint(self, incident: dict[str, Any]) -> str:
        relevant = {
            "id": self._incident_key(incident),
            "status": str(incident.get("status") or ""),
            "severity": str(incident.get("severity_agg") or incident.get("severity") or ""),
            "assignee": str(incident.get("assignee") or ""),
            "title": self._incident_title(incident),
            "count": _incident_count(incident),
            "hosts": _incident_hosts(incident),
        }
        return hashlib.sha256(json.dumps(relevant, ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest()

    def _status_label(self, value: str) -> str:
        return {
            "new": "новый",
            "open": "открыт",
            "assigned": "назначен",
            "in_progress": "в работе",
            "closed": "закрыт",
            "deferred": "отложен",
            "false_positive": "ложное срабатывание",
        }.get(str(value or "").strip().lower(), str(value or "new"))

    def _format_timestamp(self, value: str, timezone_name: str) -> str:
        text = str(value or "").strip()
        if not text:
            return ""
        try:
            parsed = datetime.fromisoformat(f"{text[:-1]}+00:00" if text.endswith("Z") else text)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(ZoneInfo(timezone_name)).strftime("%Y-%m-%d %H:%M:%S %Z")
        except Exception:
            return text

    def _format_incident_message(self, incident: dict[str, Any], *, timezone_name: str) -> str:
        severity = str(incident.get("severity_agg") or incident.get("severity") or "medium").upper()
        title = self._incident_title(incident)
        status = self._status_label(str(incident.get("status") or "new"))
        assignee = str(incident.get("assignee") or "").strip() or "не назначен"
        last_seen = str(incident.get("updated_ts") or incident.get("last_seen_ts") or incident.get("ts") or "")
        summary = str(incident.get("summary") or incident.get("message") or incident.get("rule_name") or "").strip()
        hosts = _incident_hosts(incident)
        parts = [
            f"[ИНЦИДЕНТ] {severity}",
            title,
            f"Статус: {status}",
            f"Ответственный: {assignee}",
            f"События: {_incident_count(incident)}",
        ]
        if hosts:
            parts.append(f"Хосты: {', '.join(hosts[:4])}")
        if last_seen:
            parts.append(f"Обновлено: {self._format_timestamp(last_seen, timezone_name)}")
        if summary and summary != title:
            parts.extend(["", summary[:900]])
        return "\n".join(parts)[:3900]

    def _build_incident_keyboard(
        self,
        incident_key: str,
        callback_ref: str,
        *,
        terminal: bool = False,
    ) -> list[list[dict[str, str]]]:
        incident_url = (
            f"{self.config.open_base_url}/app/incidents?view={urllib.parse.quote(self.config.incident_view)}"
            f"&focus={urllib.parse.quote(incident_key)}"
        )
        keyboard = [[{"text": "Открыть в SIEM", "url": incident_url}]]
        if self.config.enable_callbacks and not terminal:
            keyboard.extend(
                [
                    [{"text": "В работу", "callback_data": f"claim:{callback_ref}"}],
                    [
                        {"text": "Закрыть", "callback_data": f"close:{callback_ref}"},
                        {"text": "Снимок хоста", "callback_data": f"snap:{callback_ref}"},
                    ],
                    [{"text": "Обновить телеметрию", "callback_data": f"refresh:{callback_ref}"}],
                ]
            )
        return keyboard

    def _send_incident(
        self,
        incident: dict[str, Any],
        incident_key: str,
        *,
        chat_id: str,
        timezone_name: str,
        callback_ref: str,
    ) -> dict[str, Any]:
        if not self.config.telegram_enabled:
            return {"status": "telegram_disabled"}
        response = self._telegram_request(
            "sendMessage",
            {
                "chat_id": chat_id,
                "text": self._format_incident_message(incident, timezone_name=timezone_name),
                "disable_web_page_preview": True,
                "reply_markup": {"inline_keyboard": self._build_incident_keyboard(incident_key, callback_ref)},
            },
        )
        message_id = response.get("result", {}).get("message_id")
        if not message_id:
            raise RuntimeError("Telegram accepted sendMessage without a message id")
        return {"status": "sent", "message_id": message_id}

    def _edit_incident(
        self,
        incident: dict[str, Any],
        incident_key: str,
        *,
        chat_id: str,
        message_id: int,
        timezone_name: str,
        callback_ref: str,
    ) -> dict[str, Any]:
        terminal = str(incident.get("status") or "").strip().lower() in TERMINAL_STATUSES
        payload = {
            "chat_id": chat_id,
            "message_id": message_id,
            "text": self._format_incident_message(incident, timezone_name=timezone_name),
            "disable_web_page_preview": True,
            "reply_markup": {
                "inline_keyboard": self._build_incident_keyboard(incident_key, callback_ref, terminal=terminal)
            },
        }
        try:
            self._telegram_request("editMessageText", payload)
            return {"status": "edited", "message_id": message_id}
        except RuntimeError as exc:
            if "message is not modified" in str(exc).lower():
                return {"status": "unchanged", "message_id": message_id}
            if self._telegram_message_missing(exc):
                try:
                    replacement = self._send_incident(
                        incident,
                        incident_key,
                        chat_id=chat_id,
                        timezone_name=timezone_name,
                        callback_ref=callback_ref,
                    )
                    return {**replacement, "reason": "stale_message_replaced"}
                except Exception as replacement_exc:  # noqa: BLE001
                    LOG.warning(
                        "incident card replacement failed: %s",
                        self._redact_error(replacement_exc),
                    )
                    return {
                        "status": "edit_failed",
                        "message_id": message_id,
                        "error": self._redact_error(replacement_exc),
                    }
            LOG.warning("incident card edit failed; existing card retained: %s", self._redact_error(exc))
            return {"status": "edit_failed", "message_id": message_id, "error": self._redact_error(exc)}

    def _incident_callback_ref(self, incident_key: str) -> str:
        return hashlib.sha256(incident_key.encode("utf-8")).hexdigest()[:20]

    def _store_incident_callback_ref(self, conn: psycopg.Connection[Any], incident_key: str) -> str:
        callback_ref = self._incident_callback_ref(incident_key)
        self._set_state_value(conn, f"incident_ref:{callback_ref}", incident_key)
        return callback_ref

    def _poll_callbacks(self, conn: psycopg.Connection[Any]) -> None:
        if not self.config.telegram_enabled:
            return
        offset = int(self._get_state_value(conn, "telegram_offset", default="0") or "0")
        response = self._telegram_request(
            "getUpdates",
            {"offset": offset, "timeout": 0, "allowed_updates": ["callback_query"]},
        )
        next_offset = offset
        for update in list(response.get("result") or []):
            next_offset = max(next_offset, int(update.get("update_id") or 0) + 1)
            callback = dict(update.get("callback_query") or {})
            if callback:
                self._handle_callback(conn, callback)
        self._set_state_value(conn, "telegram_offset", str(next_offset))

    def _handle_callback(self, conn: psycopg.Connection[Any], callback: dict[str, Any]) -> None:
        callback_id = str(callback.get("id") or "")
        data = str(callback.get("data") or "")
        label = _safe_chat_title(dict(callback.get("from") or {}))
        response_text = self.config.callback_note
        try:
            action, callback_ref = (data.split(":", 1) + [""])[:2]
            incident_key = self._get_state_value(conn, f"incident_ref:{callback_ref}") if callback_ref else ""
            if action in {"claim", "close", "snap", "refresh"} and not incident_key:
                raise RuntimeError("Инцидент для этой кнопки не найден")
            if action == "claim":
                self._update_incident(
                    incident_key,
                    status="in_progress",
                    assignee=label,
                    note=f"Taken in work from Telegram by {label}",
                )
                response_text = "Инцидент взят в работу"
            elif action == "close":
                self._update_incident(
                    incident_key,
                    status="closed",
                    assignee=label,
                    note=f"Closed from Telegram by {label}",
                )
                response_text = "Инцидент закрыт"
            elif action in {"snap", "refresh"}:
                host_action = "snapshot" if action == "snap" else "refresh_telemetry"
                payload = self._siem_request_json(
                    f"/api/incident-ops/{urllib.parse.quote(self.config.incident_view, safe='')}/"
                    f"{urllib.parse.quote(incident_key, safe='')}/host-action",
                    method="POST",
                    payload={"action": host_action},
                )
                chat_id = str(((callback.get("message") or {}).get("chat") or {}).get("id") or self.config.telegram_chat_id)
                self._post_chat_message(chat_id, self._format_host_action_message(host_action, payload))
                response_text = "Действие выполнено"
        except Exception as exc:  # noqa: BLE001
            response_text = f"Ошибка: {exc}"
            LOG.exception("telegram callback failed: %s", exc)
        if callback_id:
            self._telegram_request(
                "answerCallbackQuery",
                {"callback_query_id": callback_id, "text": response_text[:180], "show_alert": False},
            )

    def _format_host_action_message(self, action: str, payload: dict[str, Any]) -> str:
        label = {"snapshot": "Снимок хоста", "refresh_telemetry": "Обновление телеметрии"}.get(action, action)
        parts = ["[ДЕЙСТВИЕ С ХОСТОМ]", label]
        for item in list(payload.get("results") or [])[:2]:
            parts.append(f"{item.get('label') or item.get('host') or 'host'}: {item.get('status') or 'unknown'}")
            message = str(item.get("message") or item.get("output") or "").strip()
            if message:
                parts.append(message[:1200])
        return "\n".join(parts)[:3900]

    def _update_incident(self, incident_key: str, *, status: str, assignee: str, note: str) -> dict[str, Any]:
        return self._siem_request_json(
            f"/api/alerts/{urllib.parse.quote(self.config.incident_view)}/{urllib.parse.quote(incident_key)}",
            method="POST",
            payload={"status": status, "assignee": assignee, "note": note},
        )

    def _get_state_value(self, conn: psycopg.Connection[Any], state_key: str, *, default: str = "") -> str:
        with conn.cursor() as cur:
            cur.execute("select state_value from telegram_bot_state where state_key = %s", (state_key,))
            row = cur.fetchone()
        return str(row[0] if row else default)

    def _set_state_value(self, conn: psycopg.Connection[Any], state_key: str, value: str) -> None:
        with conn.cursor() as cur:
            cur.execute(
                """
                insert into telegram_bot_state (state_key, state_value, updated_at)
                values (%s, %s, now())
                on conflict (state_key) do update set state_value = excluded.state_value, updated_at = now()
                """,
                (state_key, value),
            )

    def _get_chat_timezone(self, conn: psycopg.Connection[Any], chat_id: str) -> str:
        return self._get_state_value(
            conn,
            f"chat:{chat_id}:timezone",
            default=self.config.default_timezone,
        ) or self.config.default_timezone

    def _siem_request_json(self, path: str, *, method: str = "GET", payload: dict[str, Any] | None = None) -> dict[str, Any]:
        headers = {"Accept": "application/json", "Authorization": f"Bearer {self.config.siem_api_token}"}
        data = None
        if payload is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        request = urllib.request.Request(
            f"{self.config.siem_base_url}{path}",
            headers=headers,
            method=method.upper(),
            data=data,
        )
        try:
            with urllib.request.urlopen(request, timeout=60, context=self._ssl_context) as response:
                return json.loads(response.read().decode("utf-8", errors="replace"))
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(
                f"SIEM request failed: {path} -> HTTP {exc.code}; body={self._redact_error(body)}"
            ) from exc

    def _post_chat_message(self, chat_id: str, text: str) -> dict[str, Any]:
        return self._telegram_request(
            "sendMessage",
            {"chat_id": chat_id, "text": text[:3900], "disable_web_page_preview": True},
        )

    def _telegram_request(self, method: str, payload: dict[str, Any]) -> dict[str, Any]:
        proxy_url = self.config.telegram_proxy_url.strip()
        proxies = {"http": proxy_url, "https": proxy_url} if proxy_url else None
        try:
            response = requests.post(
                f"https://api.telegram.org/bot{self.config.telegram_bot_token}/{method}",
                json=payload,
                headers={"Accept": "application/json"},
                timeout=60,
                proxies=proxies,
            )
            response.raise_for_status()
            body = response.json()
        except requests.RequestException as exc:
            detail = getattr(getattr(exc, "response", None), "text", "")
            safe_detail = _redact_secret(detail or exc, self.config.telegram_bot_token)
            raise RuntimeError(f"Telegram request failed: {method}; {safe_detail[:400]}") from exc
        if not bool(body.get("ok")):
            raise RuntimeError(
                f"Telegram request failed: {method} -> {self._redact_error(json.dumps(body, ensure_ascii=False))}"
            )
        return body


def _configure_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        stream=sys.stdout,
    )


def main() -> int:
    _configure_logging()
    IncidentTelegramBot(load_config()).run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
