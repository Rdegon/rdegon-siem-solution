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
TERMINAL_STATUSES = {"closed", "false_positive", "expired"}


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
    return str(incident.get("status") or "").strip().lower() == "false_positive"


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
        incident_view=_env("SIEM_BOT_INCIDENT_VIEW", "agg"),
        incident_window=_env("SIEM_BOT_INCIDENT_WINDOW", "24h"),
        incident_limit=max(10, min(_env_int("SIEM_BOT_INCIDENT_LIMIT", 200), 500)),
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
        current_keys = {
            incident_key
            for incident_key in (self._incident_key(item) for item in items)
            if incident_key
        }
        for item in reversed(items):
            self._process_incident(conn, item)
        self._reconcile_absent_incidents(conn, current_keys)

    def _process_incident(self, conn: psycopg.Connection[Any], incident: dict[str, Any]) -> None:
        incident_key = self._incident_key(incident)
        if not incident_key:
            return
        fingerprint = self._incident_fingerprint(incident)
        state = self._get_incident_state(conn, incident_key)
        if (
            state
            and str(state.get("fingerprint") or "") == fingerprint
            and str(state.get("incident_status") or "").lower() != "expired"
        ):
            with conn.cursor() as cur:
                cur.execute(
                    """
                    update incident_delivery_state
                    set last_seen_at = now(), updated_at = now(),
                        incident_status = %s, incident_title = %s
                    where incident_key = %s
                    """,
                    (
                        str(incident.get("status") or "new").strip().lower(),
                        self._incident_title(incident),
                        incident_key,
                    ),
                )
            stored_payload = state.get("payload") if isinstance(state.get("payload"), dict) else {}
            stored_telegram = (
                stored_payload.get("telegram")
                if isinstance(stored_payload.get("telegram"), dict)
                else {}
            )
            self._publish_delivery_state(
                incident,
                incident_key=incident_key,
                telegram={
                    **stored_telegram,
                    "message_id": (
                        stored_telegram.get("message_id")
                        or state.get("telegram_message_id")
                    ),
                    "status": stored_telegram.get("status") or "unchanged",
                },
                delivery_count=0,
            )
            return
        status = str(incident.get("status") or "new").strip().lower()
        terminal = status in TERMINAL_STATUSES
        chat_id = str((state or {}).get("telegram_chat_id") or self.config.telegram_chat_id)
        message_id = (state or {}).get("telegram_message_id")
        callback_ref = self._store_incident_callback_ref(conn, incident_key)
        timezone_name = self._get_chat_timezone(conn, chat_id)
        if message_id and terminal:
            telegram = self._delete_incident_card(
                chat_id=chat_id,
                message_id=int(message_id),
                reason=f"terminal_{status}",
            )
        elif message_id:
            telegram = self._edit_incident(
                incident,
                incident_key,
                chat_id=chat_id,
                message_id=int(message_id),
                timezone_name=timezone_name,
                callback_ref=callback_ref,
            )
        elif terminal:
            telegram = {"status": "skipped", "reason": f"terminal_{status}"}
        else:
            telegram = self._send_incident(
                incident,
                incident_key,
                chat_id=chat_id,
                timezone_name=timezone_name,
                callback_ref=callback_ref,
            )
        next_message_id = (
            None
            if telegram.get("status") == "deleted"
            else telegram.get("message_id") or message_id
        )
        delivered = int(telegram.get("status") in {"sent", "edited"})
        with conn.cursor() as cur:
            cur.execute(
                """
                insert into incident_delivery_state (
                    incident_key, incident_view, fingerprint, incident_status,
                    incident_title, telegram_message_id, telegram_chat_id,
                    delivery_count, delivered_at, updated_at, last_seen_at, payload
                )
                values (%s, %s, %s, %s, %s, %s, %s, %s, now(), now(), now(), %s::jsonb)
                on conflict (incident_key) do update set
                    fingerprint = excluded.fingerprint,
                    incident_status = excluded.incident_status,
                    incident_title = excluded.incident_title,
                    telegram_message_id = excluded.telegram_message_id,
                    telegram_chat_id = excluded.telegram_chat_id,
                    delivery_count = incident_delivery_state.delivery_count + excluded.delivery_count,
                    updated_at = now(),
                    last_seen_at = now(),
                    payload = excluded.payload
                """,
                (
                    incident_key,
                    self.config.incident_view,
                    fingerprint,
                    status,
                    self._incident_title(incident),
                    next_message_id,
                    chat_id,
                    delivered,
                    json.dumps(
                        {"incident": incident, "telegram": telegram, "processed_at": _utc_now().isoformat()},
                        ensure_ascii=False,
                    ),
                ),
            )
        self._publish_delivery_state(
            incident,
            incident_key=incident_key,
            telegram=telegram,
            delivery_count=delivered,
        )

    def _reconcile_absent_incidents(
        self,
        conn: psycopg.Connection[Any],
        current_keys: set[str],
    ) -> None:
        with conn.cursor() as cur:
            cur.execute(
                """
                select incident_key, telegram_message_id, telegram_chat_id
                from incident_delivery_state
                where incident_view = %s
                  and incident_status not in ('closed', 'false_positive', 'expired')
                  and last_seen_at < now() - make_interval(secs => %s)
                order by last_seen_at asc
                limit 500
                """,
                (self.config.incident_view, self.config.stale_grace_seconds),
            )
            stale_rows = list(cur.fetchall())
        for incident_key, message_id, stored_chat_id in stale_rows:
            key = str(incident_key or "").strip()
            if not key or key in current_keys:
                continue
            chat_id = str(stored_chat_id or self.config.telegram_chat_id)
            telegram = (
                self._delete_incident_card(
                    chat_id=chat_id,
                    message_id=int(message_id),
                    reason="left_main_incident_queue",
                )
                if message_id
                else {"status": "expired", "reason": "left_main_incident_queue"}
            )
            with conn.cursor() as cur:
                cur.execute(
                    """
                    update incident_delivery_state
                    set incident_status = 'expired',
                        fingerprint = 'expired:' || fingerprint,
                        telegram_message_id = null,
                        updated_at = now()
                    where incident_key = %s
                    """,
                    (key,),
                )
            self._publish_delivery_state(
                {"record_id": key, "status": "expired"},
                incident_key=key,
                telegram=telegram,
                delivery_count=0,
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
            LOG.warning(
                "unable to delete stale Telegram incident card %s: %s",
                message_id,
                exc,
            )
            return {
                "status": "delete_failed",
                "message_id": int(message_id),
                "reason": reason,
                "error": str(exc)[:300],
            }

    def _publish_delivery_state(
        self,
        incident: dict[str, Any],
        *,
        incident_key: str,
        telegram: dict[str, Any],
        delivery_count: int,
    ) -> None:
        try:
            self._siem_request_json(
                "/api/notification-delivery/incidents",
                method="POST",
                payload={
                    "incident_key": incident_key,
                    "incident_view": self.config.incident_view,
                    "incident_status": str(incident.get("status") or ""),
                    "channel": "telegram",
                    "delivery_status": str(telegram.get("status") or "unknown"),
                    "message_id": int(telegram.get("message_id") or 0),
                    "delivery_count": int(delivery_count),
                    "reason": str(telegram.get("reason") or telegram.get("error") or "")[:300],
                    "updated_at": _utc_now().isoformat(),
                },
            )
        except Exception as exc:  # noqa: BLE001
            LOG.warning("unable to publish incident delivery state for %s: %s", incident_key, exc)

    def _get_incident_state(self, conn: psycopg.Connection[Any], incident_key: str) -> dict[str, Any] | None:
        with conn.cursor() as cur:
            cur.execute(
                """
                select fingerprint, payload, telegram_message_id, telegram_chat_id, incident_status
                from incident_delivery_state where incident_key = %s
                """,
                (incident_key,),
            )
            row = cur.fetchone()
        if not row:
            return None
        payload = row[1] if isinstance(row[1], dict) else {}
        legacy_message_id = ((payload.get("telegram") or {}) if isinstance(payload, dict) else {}).get("message_id")
        return {
            "fingerprint": row[0],
            "payload": payload,
            "telegram_message_id": row[2] or legacy_message_id,
            "telegram_chat_id": row[3],
            "incident_status": row[4],
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
        return {"status": "sent", "message_id": response.get("result", {}).get("message_id")}

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
            if terminal:
                LOG.warning("terminal incident card could not be edited: %s", exc)
                return {"status": "edit_failed", "message_id": message_id, "error": str(exc)[:300]}
            LOG.warning("incident card edit failed; replacing card: %s", exc)
            return self._send_incident(
                incident,
                incident_key,
                chat_id=chat_id,
                timezone_name=timezone_name,
                callback_ref=callback_ref,
            )

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
            raise RuntimeError(f"SIEM request failed: {path} -> HTTP {exc.code}; body={body[:400]}") from exc

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
            raise RuntimeError(f"Telegram request failed: {method} -> {body}")
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
