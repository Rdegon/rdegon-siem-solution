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


def _env(name: str, default: str = "") -> str:
    return str(os.getenv(name, default) or default).strip()


def _env_int(name: str, default: int) -> int:
    try:
        return int(_env(name, str(default)) or default)
    except Exception:
        return default


def _env_bool(name: str, default: bool = False) -> bool:
    value = _env(name, "")
    if not value:
        return default
    return value.lower() in {"1", "true", "yes", "on"}


def _utc_now() -> datetime:
    return datetime.now(tz=timezone.utc)


def _incident_count(incident: dict[str, Any]) -> int:
    for key in ("raw_hits_total", "raw_alerts_total", "count_alerts", "hits", "count", "events_count"):
        value = incident.get(key)
        try:
            if value in {None, ""}:
                continue
            return int(value)
        except Exception:
            continue
    return 0


def _safe_chat_title(user: dict[str, Any]) -> str:
    return str(user.get("username") or user.get("first_name") or user.get("last_name") or "operator").strip() or "operator"


def _incident_hosts(incident: dict[str, Any]) -> list[str]:
    values: list[Any] = []
    for key in ("host_labels", "hosts", "sources", "assets"):
        blob = incident.get(key)
        if isinstance(blob, list):
            values.extend(blob)
    cluster = incident.get("cluster")
    if isinstance(cluster, dict):
        for key in ("host_labels", "hosts", "sources", "assets"):
            blob = cluster.get(key)
            if isinstance(blob, list):
                values.extend(blob)
    resolved: list[str] = []
    seen: set[str] = set()
    for value in values:
        raw = str(value or "").strip()
        if not raw:
            continue
        label = humanize_source_name(raw, lang="ru", technical_suffix=True) or humanize_technical_value(raw, lang="ru") or raw
        safe_label = str(label or "").strip()
        dedupe_key = safe_label.lower()
        if not safe_label or dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        resolved.append(safe_label)
    return resolved


def _incident_should_skip_delivery(incident: dict[str, Any]) -> bool:
    status = str(incident.get("status") or "").strip().lower()
    return status in {"false_positive"}


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

    @property
    def telegram_enabled(self) -> bool:
        return bool(self.telegram_bot_token and self.telegram_chat_id)


def load_config() -> BotConfig:
    siem_base_url = _env("SIEM_BOT_BASE_URL", _env("SIEM_WEB_BASE_URL", "https://192.168.3.102")).rstrip("/")
    open_base_url = _env("SIEM_BOT_OPEN_BASE_URL", siem_base_url).rstrip("/")
    return BotConfig(
        siem_base_url=siem_base_url,
        siem_api_token=_env("SIEM_BOT_API_TOKEN"),
        incident_view=_env("SIEM_BOT_INCIDENT_VIEW", "agg"),
        incident_window=_env("SIEM_BOT_INCIDENT_WINDOW", "24h"),
        incident_limit=max(10, min(_env_int("SIEM_BOT_INCIDENT_LIMIT", 30), 200)),
        poll_seconds=max(15, _env_int("SIEM_BOT_POLL_SECONDS", 45)),
        verify_tls=_env_bool("SIEM_BOT_VERIFY_TLS", False),
        telegram_bot_token=_env("SIEM_TELEGRAM_BOT_TOKEN"),
        telegram_chat_id=_env("SIEM_TELEGRAM_CHAT_ID"),
        postgres_dsn=_env("SIEM_BOT_POSTGRES_DSN", "postgresql://siem_incident_bot:siem_incident_bot@127.0.0.1:5432/siem_incident_bot"),
        open_base_url=open_base_url,
        callback_note=_env("SIEM_BOT_CALLBACK_NOTE", "Готово."),
        enable_callbacks=_env_bool("SIEM_BOT_ENABLE_CALLBACKS", True),
        telegram_proxy_url=_env("SIEM_TELEGRAM_PROXY_URL"),
        default_timezone=_env("SIEM_BOT_DEFAULT_TIMEZONE", "Europe/Moscow"),
    )


class IncidentTelegramBot:
    def __init__(self, config: BotConfig) -> None:
        self.config = config
        self._stop = False
        self._ssl_context = ssl.create_default_context()
        if not self.config.verify_tls:
            self._ssl_context.check_hostname = False
            self._ssl_context.verify_mode = ssl.CERT_NONE

    def stop(self, *_args: object) -> None:
        self._stop = True

    def run(self) -> None:
        self._install_signal_handlers()
        with psycopg.connect(self.config.postgres_dsn, autocommit=True) as conn:
            self._ensure_schema(conn)
            LOG.info(
                "incident bot started",
                extra={
                    "telegram_enabled": self.config.telegram_enabled,
                    "callbacks_enabled": self.config.enable_callbacks,
                },
            )
            while not self._stop:
                try:
                    self._poll_incidents(conn)
                    if self.config.enable_callbacks:
                        self._poll_callbacks(conn)
                except Exception as exc:  # noqa: BLE001
                    LOG.exception("incident bot iteration failed: %s", exc)
                self._sleep(self.config.poll_seconds)

    def _install_signal_handlers(self) -> None:
        signal.signal(signal.SIGINT, self.stop)
        signal.signal(signal.SIGTERM, self.stop)

    def _sleep(self, seconds: int) -> None:
        deadline = time.time() + max(1, seconds)
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
                );
                """
            )
            cur.execute(
                """
                create table if not exists telegram_bot_state (
                    state_key text primary key,
                    state_value text not null,
                    updated_at timestamptz not null default now()
                );
                """
            )

    def _poll_incidents(self, conn: psycopg.Connection[Any]) -> None:
        if not self.config.siem_api_token:
            LOG.warning("SIEM API token is missing; incident polling is disabled")
            return
        payload = self._siem_request_json(
            f"/api/incidents?view={urllib.parse.quote(self.config.incident_view)}&window={urllib.parse.quote(self.config.incident_window)}&limit={self.config.incident_limit}"
        )
        items = list(payload.get("items") or [])
        for item in reversed(items):
            self._process_incident(conn, dict(item or {}))

    def _process_incident(self, conn: psycopg.Connection[Any], incident: dict[str, Any]) -> None:
        incident_key = self._incident_key(incident)
        if not incident_key:
            return
        fingerprint = self._incident_fingerprint(incident)
        state = self._get_incident_state(conn, incident_key)
        if state and str(state.get("fingerprint") or "") == fingerprint:
            return
        chat_id = self.config.telegram_chat_id
        timezone_name = self._get_chat_timezone(conn, chat_id)
        callback_ref = self._store_incident_callback_ref(conn, incident_key)
        skip_delivery = _incident_should_skip_delivery(incident)
        if skip_delivery:
            telegram_payload = {"status": "skipped", "reason": "status_false_positive"}
        else:
            telegram_payload = self._send_incident(
                incident,
                incident_key,
                chat_id=chat_id,
                timezone_name=timezone_name,
                callback_ref=callback_ref,
            )
        with conn.cursor() as cur:
            cur.execute(
                """
                insert into incident_delivery_state (
                    incident_key, incident_view, fingerprint, incident_status, incident_title, delivered_at, updated_at, payload
                )
                values (%s, %s, %s, %s, %s, now(), now(), %s::jsonb)
                on conflict (incident_key) do update set
                    fingerprint = excluded.fingerprint,
                    incident_status = excluded.incident_status,
                    incident_title = excluded.incident_title,
                    updated_at = now(),
                    payload = excluded.payload
                """,
                (
                    incident_key,
                    self.config.incident_view,
                    fingerprint,
                    str(incident.get("status") or ""),
                    self._incident_title(incident),
                    json.dumps(
                        {
                            "incident": incident,
                            "telegram": telegram_payload,
                            "telegram_enabled": self.config.telegram_enabled,
                            "callbacks_enabled": self.config.enable_callbacks,
                            "skip_delivery": skip_delivery,
                            "processed_at": _utc_now().isoformat(),
                        },
                        ensure_ascii=False,
                    ),
                ),
            )

    def _get_incident_state(self, conn: psycopg.Connection[Any], incident_key: str) -> dict[str, Any] | None:
        with conn.cursor() as cur:
            cur.execute("select fingerprint, payload from incident_delivery_state where incident_key = %s", (incident_key,))
            row = cur.fetchone()
        if not row:
            return None
        return {"fingerprint": row[0], "payload": row[1]}

    def _incident_key(self, incident: dict[str, Any]) -> str:
        return str(incident.get("agg_id") or incident.get("alert_id") or incident.get("id") or "").strip()

    def _incident_title(self, incident: dict[str, Any]) -> str:
        return str(
            incident.get("title")
            or incident.get("summary")
            or incident.get("rule_name")
            or incident.get("message")
            or incident.get("agg_id")
            or incident.get("alert_id")
            or "Incident"
        ).strip()

    def _incident_fingerprint(self, incident: dict[str, Any]) -> str:
        relevant = {
            "id": self._incident_key(incident),
            "status": str(incident.get("status") or ""),
            "severity": str(incident.get("severity") or ""),
            "assignee": str(incident.get("assignee") or ""),
            "updated_ts": str(incident.get("updated_ts") or incident.get("last_seen_ts") or incident.get("ts") or ""),
            "title": self._incident_title(incident),
            "count": _incident_count(incident),
        }
        return hashlib.sha256(json.dumps(relevant, sort_keys=True).encode("utf-8")).hexdigest()

    def _incident_callback_ref(self, incident_key: str) -> str:
        return hashlib.sha256(str(incident_key or "").encode("utf-8")).hexdigest()[:20]

    def _store_incident_callback_ref(self, conn: psycopg.Connection[Any], incident_key: str) -> str:
        callback_ref = self._incident_callback_ref(incident_key)
        self._set_state_value(conn, f"incident_ref:{callback_ref}", incident_key)
        return callback_ref

    def _resolve_incident_callback_ref(self, conn: psycopg.Connection[Any], callback_ref: str) -> str:
        return self._get_state_value(conn, f"incident_ref:{callback_ref}").strip()

    def _status_label(self, value: str) -> str:
        mapping = {
            "new": "новый",
            "open": "открыт",
            "assigned": "назначен",
            "in_progress": "в работе",
            "closed": "закрыт",
            "deferred": "отложен",
            "false_positive": "фолс",
        }
        safe = str(value or "").strip().lower()
        return mapping.get(safe, safe or "new")

    def _format_timestamp(self, value: str, timezone_name: str) -> str:
        text = str(value or "").strip()
        if not text:
            return ""
        if text.endswith("Z"):
            text = f"{text[:-1]}+00:00"
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            return str(value or "")
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        try:
            parsed = parsed.astimezone(ZoneInfo(timezone_name))
        except Exception:
            parsed = parsed.astimezone(timezone.utc)
        return parsed.strftime("%Y-%m-%d %H:%M:%S %Z")

    def _build_incident_keyboard(self, incident_key: str, callback_ref: str) -> list[list[dict[str, str]]]:
        incident_url = f"{self.config.open_base_url}/app/incidents?view={urllib.parse.quote(self.config.incident_view)}&focus={urllib.parse.quote(incident_key)}"
        keyboard = [[{"text": "Перейти в SIEM", "url": incident_url}]]
        if self.config.enable_callbacks:
            keyboard.extend(
                [
                    [
                        {"text": "В работу", "callback_data": f"claim:{callback_ref}"},
                    ],
                    [
                        {"text": "Закрыть", "callback_data": f"close:{callback_ref}"},
                        {"text": "Снимок хоста", "callback_data": f"snap:{callback_ref}"},
                    ],
                    [
                        {"text": "Освежить телеметрию", "callback_data": f"refresh:{callback_ref}"},
                        {"text": "UTC+3", "callback_data": "tz:Europe/Moscow"},
                        {"text": "UTC", "callback_data": "tz:UTC"},
                    ],
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
            LOG.warning("telegram delivery disabled; incident stored without chat send", extra={"incident_key": incident_key})
            return {"status": "telegram_disabled"}
        text = self._format_incident_message(incident, timezone_name=timezone_name)
        response = self._post_chat_message(chat_id, text, inline_keyboard=self._build_incident_keyboard(incident_key, callback_ref))
        LOG.info("incident delivered to telegram", extra={"incident_key": incident_key})
        return {"status": "sent", "message_id": response.get("result", {}).get("message_id")}

    def _format_incident_message(self, incident: dict[str, Any], *, timezone_name: str) -> str:
        severity = str(incident.get("severity_agg") or incident.get("severity") or "medium").upper()
        status = self._status_label(str(incident.get("status") or "new"))
        title = self._incident_title(incident)
        assignee = str(incident.get("assignee") or "").strip() or "не назначен"
        last_seen = str(incident.get("updated_ts") or incident.get("last_seen_ts") or incident.get("ts") or "")
        summary = str(incident.get("summary") or incident.get("message") or incident.get("rule_name") or "").strip()
        count = _incident_count(incident)
        parts = [
            f"[ИНЦИДЕНТ] {severity}",
            title,
            f"Статус: {status}",
            f"Ответственный: {assignee}",
            f"События: {count}",
        ]
        if last_seen:
            parts.append(f"Обновлено: {self._format_timestamp(last_seen, timezone_name)}")
        if summary and summary != title:
            parts.append("")
            parts.append(summary[:900])
        return "\n".join(parts)

    def _send_ai_followup(self, incident: dict[str, Any], incident_key: str, *, chat_id: str, timezone_name: str) -> dict[str, Any]:
        return {"status": "disabled", "reason": "incident_ai_disabled"}

    def _format_ai_message(self, incident: dict[str, Any], payload: dict[str, Any]) -> str:
        state = str(payload.get("status") or "").strip().lower()
        if state == "pending":
            return "\n".join(
                [
                    f"[AI] {self._incident_title(incident)}",
                    "Разбор OpenClaw поставлен в очередь.",
                    "Контекст от источников и внешнего поиска уже собирается.",
                    "Повторите запрос чуть позже или откройте карточку инцидента в SIEM.",
                ]
            )[:3900]
        if state == "error":
            return "\n".join(
                [
                    f"[AI] {self._incident_title(incident)}",
                    "Не удалось завершить AI-разбор.",
                    str(payload.get("error") or "Проверьте OpenClaw, сетевой доступ и enrich-поля инцидента."),
                ]
            )[:3900]
        assessment = dict(payload.get("assessment") or {})
        why = [str(item).strip() for item in (assessment.get("why_it_matters") or []) if str(item).strip()]
        actions = [str(item).strip() for item in (assessment.get("recommended_actions") or []) if str(item).strip()]
        machine_actions = [str(item).strip() for item in (assessment.get("machine_actions") or []) if str(item).strip()]
        findings = list(payload.get("search", {}).get("results") or [])
        parts = [
            f"[AI] {self._incident_title(incident)}",
            f"Оценка: {assessment.get('score', 'n/a')}",
            f"Уверенность: {assessment.get('confidence', 'n/a')}",
            f"Рекомендуемый статус: {assessment.get('status_suggestion', 'n/a')}",
            "",
            str(assessment.get("summary") or "AI-сводка пока недоступна."),
        ]
        if why:
            parts.extend(["", "Почему это важно:"])
            parts.extend(f"• {item}" for item in why[:4])
        if actions:
            parts.extend(["", "Рекомендации:"])
            parts.extend(f"• {item}" for item in actions[:5])
        if machine_actions:
            parts.extend(["", "Машинные действия:"])
            parts.extend(f"• {item}" for item in machine_actions[:3])
        if findings:
            parts.extend(["", "Внешний контекст:"])
            for item in findings[:3]:
                title = str(item.get("title") or item.get("engine") or "Search result").strip()
                url = str(item.get("url") or "").strip()
                parts.append(f"• {title}: {url}")
        return "\n".join(parts)[:3900]

    def _wait_for_ai_assessment(self, incident_key: str, *, initial: dict[str, Any] | None = None) -> dict[str, Any]:
        payload = dict(initial or {})
        payload.setdefault("status", "disabled")
        payload.setdefault("reason", "incident_ai_disabled")
        return payload

    def _poll_callbacks(self, conn: psycopg.Connection[Any]) -> None:
        if not self.config.telegram_enabled:
            return
        offset = self._get_state_value(conn, "telegram_offset", default="0")
        response = self._telegram_request(
            "getUpdates",
            {"offset": int(offset or "0"), "timeout": 0, "allowed_updates": ["callback_query"]},
        )
        updates = list(response.get("result") or [])
        next_offset = int(offset or "0")
        for update in updates:
            update_id = int(update.get("update_id") or 0)
            next_offset = max(next_offset, update_id + 1)
            callback = dict(update.get("callback_query") or {})
            if callback:
                self._handle_callback(conn, callback)
        self._set_state_value(conn, "telegram_offset", str(next_offset))

    def _handle_callback(self, conn: psycopg.Connection[Any], callback: dict[str, Any]) -> None:
        callback_id = str(callback.get("id") or "").strip()
        data = str(callback.get("data") or "").strip()
        user = dict(callback.get("from") or {})
        label = _safe_chat_title(user)
        chat_id = str(((callback.get("message") or {}) if isinstance(callback.get("message"), dict) else {}).get("chat", {}).get("id") or self.config.telegram_chat_id).strip()
        response_text = self.config.callback_note
        try:
            if data.startswith("tz:"):
                timezone_name = data.split(":", 1)[1].strip() or self.config.default_timezone
                self._set_chat_timezone(conn, chat_id, timezone_name)
                response_text = f"Часовой пояс: {timezone_name}"
                self._post_chat_message(chat_id, f"Локальное время для этого чата переключено на {timezone_name}.")
            elif data.startswith("claim:"):
                incident_key = self._resolve_incident_callback_ref(conn, data.split(":", 1)[1].strip())
                if not incident_key:
                    raise RuntimeError("Incident mapping for Telegram callback was not found")
                self._update_incident(incident_key, status="in_progress", assignee=label, note=f"Taken in work from Telegram by {label}")
                response_text = "Инцидент взят в работу"
                self._post_chat_message(chat_id, f"Инцидент {incident_key} взят в работу пользователем {label}.")
            elif data.startswith("close:"):
                incident_key = self._resolve_incident_callback_ref(conn, data.split(":", 1)[1].strip())
                if not incident_key:
                    raise RuntimeError("Incident mapping for Telegram callback was not found")
                self._update_incident(incident_key, status="closed", assignee=label, note=f"Closed from Telegram by {label}")
                response_text = "Инцидент закрыт"
                self._post_chat_message(chat_id, f"Инцидент {incident_key} переведён в closed пользователем {label}.")
            elif data.startswith("ai:"):
                response_text = "AI-разбор отключён"
                self._post_chat_message(chat_id, "AI-разбор инцидентов отключён в SIEM.")
            elif data.startswith("snap:"):
                incident_key = self._resolve_incident_callback_ref(conn, data.split(":", 1)[1].strip())
                if not incident_key:
                    raise RuntimeError("Incident mapping for Telegram callback was not found")
                payload = self._siem_request_json(
                    f"/api/incident-ops/{urllib.parse.quote(self.config.incident_view, safe='')}/{urllib.parse.quote(incident_key, safe='')}/host-action",
                    method="POST",
                    payload={"action": "snapshot"},
                )
                self._post_chat_message(chat_id, self._format_host_action_message("snapshot", payload))
                response_text = "Снимок хоста отправлен"
            elif data.startswith("refresh:"):
                incident_key = self._resolve_incident_callback_ref(conn, data.split(":", 1)[1].strip())
                if not incident_key:
                    raise RuntimeError("Incident mapping for Telegram callback was not found")
                payload = self._siem_request_json(
                    f"/api/incident-ops/{urllib.parse.quote(self.config.incident_view, safe='')}/{urllib.parse.quote(incident_key, safe='')}/host-action",
                    method="POST",
                    payload={"action": "refresh_telemetry"},
                )
                self._post_chat_message(chat_id, self._format_host_action_message("refresh_telemetry", payload))
                response_text = "Телеметрия обновлена"
        except Exception as exc:  # noqa: BLE001
            response_text = f"Ошибка действия: {exc}"
            LOG.exception("telegram callback failed: %s", exc)
        if callback_id:
            self._telegram_request(
                "answerCallbackQuery",
                {"callback_query_id": callback_id, "text": response_text[:180], "show_alert": False},
            )
        LOG.info("telegram callback received", extra={"callback": data, "user": label})

    def _format_host_action_message(self, action: str, payload: dict[str, Any]) -> str:
        results = list(payload.get("results") or [])
        parts = [
            "[HOST ACTION]",
            f"Action: {action}",
        ]
        for item in results[:2]:
            label = str(item.get("label") or item.get("host") or "host").strip()
            status = str(item.get("status") or "unknown").strip()
            message = str(item.get("message") or item.get("output") or "").strip()
            parts.append(f"{label}: {status}")
            if message:
                parts.append(message[:1200])
        return "\n".join(parts)[:3900]

    def _fetch_incident(self, incident_key: str) -> dict[str, Any]:
        payload = self._siem_request_json(
            f"/api/incidents?view={urllib.parse.quote(self.config.incident_view)}&window={urllib.parse.quote(self.config.incident_window)}&limit={self.config.incident_limit}"
        )
        items = list(payload.get("items") or [])
        selected = next((item for item in items if str((item or {}).get("agg_id") or (item or {}).get("alert_id") or "").strip() == incident_key), None)
        return dict(selected or {})

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
                on conflict (state_key) do update set
                    state_value = excluded.state_value,
                    updated_at = now()
                """,
                (state_key, value),
            )

    def _get_chat_timezone(self, conn: psycopg.Connection[Any], chat_id: str) -> str:
        return self._get_state_value(conn, f"chat:{chat_id}:timezone", default=self.config.default_timezone) or self.config.default_timezone

    def _set_chat_timezone(self, conn: psycopg.Connection[Any], chat_id: str, timezone_name: str) -> None:
        self._set_state_value(conn, f"chat:{chat_id}:timezone", timezone_name)

    def _siem_request_json(self, path: str, *, method: str = "GET", payload: dict[str, Any] | None = None) -> dict[str, Any]:
        headers = {
            "Accept": "application/json",
            "Authorization": f"Bearer {self.config.siem_api_token}",
        }
        data = None
        if payload is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        request = urllib.request.Request(f"{self.config.siem_base_url}{path}", headers=headers, method=method.upper(), data=data)
        try:
            with urllib.request.urlopen(request, timeout=60, context=self._ssl_context) as response:
                return json.loads(response.read().decode("utf-8", errors="replace"))
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"SIEM request failed: {path} -> HTTP {exc.code}; body={body[:400]}") from exc

    def _post_chat_message(self, chat_id: str, text: str, *, inline_keyboard: list[list[dict[str, str]]] | None = None) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "chat_id": chat_id,
            "text": text[:3900],
            "disable_web_page_preview": True,
        }
        if inline_keyboard:
            payload["reply_markup"] = {"inline_keyboard": inline_keyboard}
        return self._telegram_request("sendMessage", payload)

    def _telegram_request(self, method: str, payload: dict[str, Any]) -> dict[str, Any]:
        proxies = None
        proxy_url = self.config.telegram_proxy_url.strip()
        if proxy_url:
            proxies = {"http": proxy_url, "https": proxy_url}
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
        except requests.HTTPError as exc:
            detail = exc.response.text[:400] if exc.response is not None else ""
            raise RuntimeError(f"Telegram request failed: {method} -> HTTP {getattr(exc.response, 'status_code', 'unknown')}; body={detail}") from exc
        except requests.RequestException as exc:
            raise RuntimeError(f"Telegram request failed: {method} -> {exc}") from exc
        if not bool(body.get("ok")):
            raise RuntimeError(f"Telegram request failed: {method} -> {body}")
        return body


def _bot_status_label(self: IncidentTelegramBot, value: str) -> str:
    mapping = {
        "new": "новый",
        "open": "открыт",
        "assigned": "назначен",
        "in_progress": "в работе",
        "closed": "закрыт",
        "deferred": "отложен",
        "false_positive": "фолс",
    }
    safe = str(value or "").strip().lower()
    return mapping.get(safe, safe or "new")


def _bot_build_incident_keyboard(self: IncidentTelegramBot, incident_key: str, callback_ref: str) -> list[list[dict[str, str]]]:
    incident_url = f"{self.config.open_base_url}/app/incidents?view={urllib.parse.quote(self.config.incident_view)}&focus={urllib.parse.quote(incident_key)}"
    keyboard = [[{"text": "Перейти в SIEM", "url": incident_url}]]
    if self.config.enable_callbacks:
        keyboard.extend(
            [
                [
                    {"text": "В работу", "callback_data": f"claim:{callback_ref}"},
                ],
                [
                    {"text": "Закрыть", "callback_data": f"close:{callback_ref}"},
                    {"text": "Снимок хоста", "callback_data": f"snap:{callback_ref}"},
                ],
                [
                    {"text": "Освежить телеметрию", "callback_data": f"refresh:{callback_ref}"},
                    {"text": "UTC+3", "callback_data": "tz:Europe/Moscow"},
                    {"text": "UTC", "callback_data": "tz:UTC"},
                ],
            ]
        )
    return keyboard


def _bot_format_incident_message(self: IncidentTelegramBot, incident: dict[str, Any], *, timezone_name: str) -> str:
    severity = str(incident.get("severity_agg") or incident.get("severity") or "medium").upper()
    status = self._status_label(str(incident.get("status") or "new"))
    title = self._incident_title(incident)
    assignee = str(incident.get("assignee") or "").strip() or "не назначен"
    last_seen = str(incident.get("updated_ts") or incident.get("last_seen_ts") or incident.get("ts") or "")
    summary = str(incident.get("summary") or incident.get("message") or incident.get("rule_name") or "").strip()
    count = _incident_count(incident)
    hosts = _incident_hosts(incident)
    parts = [
        f"[ИНЦИДЕНТ] {severity}",
        title,
        f"Статус: {status}",
        f"Ответственный: {assignee}",
        f"События: {count}",
    ]
    if hosts:
        parts.append(f"Хосты: {', '.join(hosts[:4])}")
    if last_seen:
        parts.append(f"Обновлено: {self._format_timestamp(last_seen, timezone_name)}")
    if summary and summary != title:
        parts.append("")
        parts.append(summary[:900])
    return "\n".join(parts)


def _bot_send_ai_followup(
    self: IncidentTelegramBot,
    incident: dict[str, Any],
    incident_key: str,
    *,
    chat_id: str,
    timezone_name: str,
) -> dict[str, Any]:
    return {"status": "disabled", "reason": "incident_ai_disabled"}


def _bot_format_ai_message(self: IncidentTelegramBot, incident: dict[str, Any], payload: dict[str, Any]) -> str:
    state = str(payload.get("status") or "").strip().lower()
    if state == "pending":
        return "\n".join(
            [
                f"[AI] {self._incident_title(incident)}",
                "Разбор OpenClaw поставлен в очередь.",
                "Контекст от источников и внешнего поиска уже собирается.",
                "Повторите запрос чуть позже или откройте карточку инцидента в SIEM.",
            ]
        )[:3900]
    if state == "error":
        return "\n".join(
            [
                f"[AI] {self._incident_title(incident)}",
                "Не удалось завершить AI-разбор.",
                str(payload.get("error") or "Проверьте OpenClaw, сетевой доступ и enrich-поля инцидента."),
            ]
        )[:3900]
    assessment = dict(payload.get("assessment") or {})
    why = [str(item).strip() for item in (assessment.get("why_it_matters") or []) if str(item).strip()]
    actions = [str(item).strip() for item in (assessment.get("recommended_actions") or []) if str(item).strip()]
    machine_actions = [str(item).strip() for item in (assessment.get("machine_actions") or []) if str(item).strip()]
    findings = list(payload.get("search", {}).get("results") or [])
    parts = [
        f"[AI] {self._incident_title(incident)}",
        f"Оценка: {assessment.get('score', 'n/a')}",
        f"Уверенность: {assessment.get('confidence', 'n/a')}",
        f"Рекомендуемый статус: {assessment.get('status_suggestion', 'n/a')}",
        "",
        str(assessment.get("summary") or "AI-сводка пока недоступна."),
    ]
    if why:
        parts.extend(["", "Почему это важно:"])
        parts.extend(f"• {item}" for item in why[:4])
    if actions:
        parts.extend(["", "Рекомендации:"])
        parts.extend(f"• {item}" for item in actions[:5])
    if machine_actions:
        parts.extend(["", "Машинные действия:"])
        parts.extend(f"• {item}" for item in machine_actions[:3])
    if findings:
        parts.extend(["", "Внешний контекст:"])
        for item in findings[:3]:
            title = str(item.get("title") or item.get("engine") or "Search result").strip()
            url = str(item.get("url") or "").strip()
            parts.append(f"• {title}: {url}")
    return "\n".join(parts)[:3900]


def _bot_format_host_action_message(self: IncidentTelegramBot, action: str, payload: dict[str, Any]) -> str:
    action_label = {
        "snapshot": "Снимок хоста",
        "refresh_telemetry": "Обновление телеметрии",
    }.get(str(action or "").strip().lower(), str(action or "").strip() or "Действие")
    results = list(payload.get("results") or [])
    parts = ["[HOST ACTION]", f"Действие: {action_label}"]
    for item in results[:2]:
        label = str(item.get("label") or item.get("host") or "host").strip()
        status = str(item.get("status") or "unknown").strip()
        message = str(item.get("message") or item.get("output") or "").strip()
        parts.append(f"{label}: {status}")
        if message:
            parts.append(message[:1200])
    return "\n".join(parts)[:3900]


def _bot_handle_callback(self: IncidentTelegramBot, conn: psycopg.Connection[Any], callback: dict[str, Any]) -> None:
    callback_id = str(callback.get("id") or "").strip()
    data = str(callback.get("data") or "").strip()
    user = dict(callback.get("from") or {})
    label = _safe_chat_title(user)
    chat_id = str(((callback.get("message") or {}) if isinstance(callback.get("message"), dict) else {}).get("chat", {}).get("id") or self.config.telegram_chat_id).strip()
    response_text = self.config.callback_note
    try:
        if data.startswith("tz:"):
            timezone_name = data.split(":", 1)[1].strip() or self.config.default_timezone
            self._set_chat_timezone(conn, chat_id, timezone_name)
            response_text = f"Часовой пояс: {timezone_name}"
            self._post_chat_message(chat_id, f"Локальное время для этого чата переключено на {timezone_name}.")
        elif data.startswith("claim:"):
            incident_key = self._resolve_incident_callback_ref(conn, data.split(":", 1)[1].strip())
            if not incident_key:
                raise RuntimeError("Incident mapping for Telegram callback was not found")
            self._update_incident(incident_key, status="in_progress", assignee=label, note=f"Taken in work from Telegram by {label}")
            response_text = "Инцидент взят в работу"
            self._post_chat_message(chat_id, f"Инцидент {incident_key} взят в работу пользователем {label}.")
        elif data.startswith("close:"):
            incident_key = self._resolve_incident_callback_ref(conn, data.split(":", 1)[1].strip())
            if not incident_key:
                raise RuntimeError("Incident mapping for Telegram callback was not found")
            self._update_incident(incident_key, status="closed", assignee=label, note=f"Closed from Telegram by {label}")
            response_text = "Инцидент закрыт"
            self._post_chat_message(chat_id, f"Инцидент {incident_key} переведён в closed пользователем {label}.")
        elif data.startswith("ai:"):
            response_text = "AI-разбор отключён"
            self._post_chat_message(chat_id, "AI-разбор инцидентов отключён в SIEM.")
        elif data.startswith("snap:"):
            incident_key = self._resolve_incident_callback_ref(conn, data.split(":", 1)[1].strip())
            if not incident_key:
                raise RuntimeError("Incident mapping for Telegram callback was not found")
            payload = self._siem_request_json(
                f"/api/incident-ops/{urllib.parse.quote(self.config.incident_view, safe='')}/{urllib.parse.quote(incident_key, safe='')}/host-action",
                method="POST",
                payload={"action": "snapshot"},
            )
            self._post_chat_message(chat_id, self._format_host_action_message("snapshot", payload))
            response_text = "Снимок хоста отправлен"
        elif data.startswith("refresh:"):
            incident_key = self._resolve_incident_callback_ref(conn, data.split(":", 1)[1].strip())
            if not incident_key:
                raise RuntimeError("Incident mapping for Telegram callback was not found")
            payload = self._siem_request_json(
                f"/api/incident-ops/{urllib.parse.quote(self.config.incident_view, safe='')}/{urllib.parse.quote(incident_key, safe='')}/host-action",
                method="POST",
                payload={"action": "refresh_telemetry"},
            )
            self._post_chat_message(chat_id, self._format_host_action_message("refresh_telemetry", payload))
            response_text = "Телеметрия обновлена"
    except Exception as exc:  # noqa: BLE001
        response_text = f"Ошибка действия: {exc}"
        LOG.exception("telegram callback failed: %s", exc)
    if callback_id:
        self._telegram_request(
            "answerCallbackQuery",
            {"callback_query_id": callback_id, "text": response_text[:180], "show_alert": False},
        )
    LOG.info("telegram callback received", extra={"callback": data, "user": label})


IncidentTelegramBot._status_label = _bot_status_label
IncidentTelegramBot._build_incident_keyboard = _bot_build_incident_keyboard
IncidentTelegramBot._format_incident_message = _bot_format_incident_message
IncidentTelegramBot._send_ai_followup = _bot_send_ai_followup
IncidentTelegramBot._format_ai_message = _bot_format_ai_message
IncidentTelegramBot._format_host_action_message = _bot_format_host_action_message
IncidentTelegramBot._handle_callback = _bot_handle_callback


def _bot_status_label_clean(self: IncidentTelegramBot, value: str) -> str:
    mapping = {
        "new": "новый",
        "open": "открыт",
        "assigned": "назначен",
        "in_progress": "в работе",
        "closed": "закрыт",
        "deferred": "отложен",
        "false_positive": "фолс",
    }
    safe = str(value or "").strip().lower()
    return mapping.get(safe, safe or "new")


def _bot_build_incident_keyboard_clean(self: IncidentTelegramBot, incident_key: str, callback_ref: str) -> list[list[dict[str, str]]]:
    incident_url = f"{self.config.open_base_url}/app/incidents?view={urllib.parse.quote(self.config.incident_view)}&focus={urllib.parse.quote(incident_key)}"
    keyboard = [[{"text": "Перейти в SIEM", "url": incident_url}]]
    if self.config.enable_callbacks:
        keyboard.extend(
            [
                [
                    {"text": "В работу", "callback_data": f"claim:{callback_ref}"},
                ],
                [
                    {"text": "Закрыть", "callback_data": f"close:{callback_ref}"},
                    {"text": "Снимок хоста", "callback_data": f"snap:{callback_ref}"},
                ],
                [
                    {"text": "Освежить телеметрию", "callback_data": f"refresh:{callback_ref}"},
                    {"text": "UTC+3", "callback_data": "tz:Europe/Moscow"},
                    {"text": "UTC", "callback_data": "tz:UTC"},
                ],
            ]
        )
    return keyboard


def _bot_format_incident_message_clean(self: IncidentTelegramBot, incident: dict[str, Any], *, timezone_name: str) -> str:
    severity = str(incident.get("severity_agg") or incident.get("severity") or "medium").upper()
    status = self._status_label(str(incident.get("status") or "new"))
    title = self._incident_title(incident)
    assignee = str(incident.get("assignee") or "").strip() or "не назначен"
    last_seen = str(incident.get("updated_ts") or incident.get("last_seen_ts") or incident.get("ts") or "")
    summary = str(incident.get("summary") or incident.get("message") or incident.get("rule_name") or "").strip()
    count = _incident_count(incident)
    hosts = _incident_hosts(incident)
    parts = [
        f"[ИНЦИДЕНТ] {severity}",
        title,
        f"Статус: {status}",
        f"Ответственный: {assignee}",
        f"События: {count}",
    ]
    if hosts:
        parts.append(f"Хосты: {', '.join(hosts[:4])}")
    if last_seen:
        parts.append(f"Обновлено: {self._format_timestamp(last_seen, timezone_name)}")
    if summary and summary != title:
        parts.append("")
        parts.append(summary[:900])
    return "\n".join(parts)


def _bot_send_ai_followup_clean(
    self: IncidentTelegramBot,
    incident: dict[str, Any],
    incident_key: str,
    *,
    chat_id: str,
    timezone_name: str,
) -> dict[str, Any]:
    return {"status": "disabled", "reason": "incident_ai_disabled"}


def _bot_format_ai_message_clean(self: IncidentTelegramBot, incident: dict[str, Any], payload: dict[str, Any]) -> str:
    state = str(payload.get("status") or "").strip().lower()
    if state == "pending":
        return "\n".join(
            [
                f"[AI] {self._incident_title(incident)}",
                "Разбор OpenClaw поставлен в очередь.",
                "Контекст от источников и внешнего поиска уже собирается.",
                "Повторите запрос чуть позже или откройте карточку инцидента в SIEM.",
            ]
        )[:3900]
    if state == "error":
        return "\n".join(
            [
                f"[AI] {self._incident_title(incident)}",
                "Не удалось завершить AI-разбор.",
                str(payload.get("error") or "Проверьте OpenClaw, сетевой доступ и enrich-поля инцидента."),
            ]
        )[:3900]
    assessment = dict(payload.get("assessment") or {})
    why = [str(item).strip() for item in (assessment.get("why_it_matters") or []) if str(item).strip()]
    actions = [str(item).strip() for item in (assessment.get("recommended_actions") or []) if str(item).strip()]
    machine_actions = [str(item).strip() for item in (assessment.get("machine_actions") or []) if str(item).strip()]
    findings = list(payload.get("search", {}).get("results") or [])
    parts = [
        f"[AI] {self._incident_title(incident)}",
        f"Оценка: {assessment.get('score', 'n/a')}",
        f"Уверенность: {assessment.get('confidence', 'n/a')}",
        f"Рекомендуемый статус: {assessment.get('status_suggestion', 'n/a')}",
        "",
        str(assessment.get("summary") or "AI-сводка пока недоступна."),
    ]
    if why:
        parts.extend(["", "Почему это важно:"])
        parts.extend(f"• {item}" for item in why[:4])
    if actions:
        parts.extend(["", "Рекомендации:"])
        parts.extend(f"• {item}" for item in actions[:5])
    if machine_actions:
        parts.extend(["", "Машинные действия:"])
        parts.extend(f"• {item}" for item in machine_actions[:3])
    if findings:
        parts.extend(["", "Внешний контекст:"])
        for item in findings[:3]:
            title = str(item.get("title") or item.get("engine") or "Search result").strip()
            url = str(item.get("url") or "").strip()
            parts.append(f"• {title}: {url}")
    return "\n".join(parts)[:3900]


def _bot_format_host_action_message_clean(self: IncidentTelegramBot, action: str, payload: dict[str, Any]) -> str:
    action_label = {
        "snapshot": "Снимок хоста",
        "refresh_telemetry": "Обновление телеметрии",
    }.get(str(action or "").strip().lower(), str(action or "").strip() or "Действие")
    results = list(payload.get("results") or [])
    parts = ["[HOST ACTION]", f"Действие: {action_label}"]
    for item in results[:2]:
        label = str(item.get("label") or item.get("host") or "host").strip()
        status = str(item.get("status") or "unknown").strip()
        message = str(item.get("message") or item.get("output") or "").strip()
        parts.append(f"{label}: {status}")
        if message:
            parts.append(message[:1200])
    return "\n".join(parts)[:3900]


def _bot_handle_callback_clean(self: IncidentTelegramBot, conn: psycopg.Connection[Any], callback: dict[str, Any]) -> None:
    callback_id = str(callback.get("id") or "").strip()
    data = str(callback.get("data") or "").strip()
    user = dict(callback.get("from") or {})
    label = _safe_chat_title(user)
    chat_id = str(((callback.get("message") or {}) if isinstance(callback.get("message"), dict) else {}).get("chat", {}).get("id") or self.config.telegram_chat_id).strip()
    response_text = self.config.callback_note
    try:
        if data.startswith("tz:"):
            timezone_name = data.split(":", 1)[1].strip() or self.config.default_timezone
            self._set_chat_timezone(conn, chat_id, timezone_name)
            response_text = f"Часовой пояс: {timezone_name}"
            self._post_chat_message(chat_id, f"Локальное время для этого чата переключено на {timezone_name}.")
        elif data.startswith("claim:"):
            incident_key = self._resolve_incident_callback_ref(conn, data.split(":", 1)[1].strip())
            if not incident_key:
                raise RuntimeError("Incident mapping for Telegram callback was not found")
            self._update_incident(incident_key, status="in_progress", assignee=label, note=f"Taken in work from Telegram by {label}")
            response_text = "Инцидент взят в работу"
            self._post_chat_message(chat_id, f"Инцидент {incident_key} взят в работу пользователем {label}.")
        elif data.startswith("close:"):
            incident_key = self._resolve_incident_callback_ref(conn, data.split(":", 1)[1].strip())
            if not incident_key:
                raise RuntimeError("Incident mapping for Telegram callback was not found")
            self._update_incident(incident_key, status="closed", assignee=label, note=f"Closed from Telegram by {label}")
            response_text = "Инцидент закрыт"
            self._post_chat_message(chat_id, f"Инцидент {incident_key} переведён в closed пользователем {label}.")
        elif data.startswith("ai:"):
            response_text = "AI-разбор отключён"
            self._post_chat_message(chat_id, "AI-разбор инцидентов отключён в SIEM.")
        elif data.startswith("snap:"):
            incident_key = self._resolve_incident_callback_ref(conn, data.split(":", 1)[1].strip())
            if not incident_key:
                raise RuntimeError("Incident mapping for Telegram callback was not found")
            payload = self._siem_request_json(
                f"/api/incident-ops/{urllib.parse.quote(self.config.incident_view, safe='')}/{urllib.parse.quote(incident_key, safe='')}/host-action",
                method="POST",
                payload={"action": "snapshot"},
            )
            self._post_chat_message(chat_id, self._format_host_action_message("snapshot", payload))
            response_text = "Снимок хоста отправлен"
        elif data.startswith("refresh:"):
            incident_key = self._resolve_incident_callback_ref(conn, data.split(":", 1)[1].strip())
            if not incident_key:
                raise RuntimeError("Incident mapping for Telegram callback was not found")
            payload = self._siem_request_json(
                f"/api/incident-ops/{urllib.parse.quote(self.config.incident_view, safe='')}/{urllib.parse.quote(incident_key, safe='')}/host-action",
                method="POST",
                payload={"action": "refresh_telemetry"},
            )
            self._post_chat_message(chat_id, self._format_host_action_message("refresh_telemetry", payload))
            response_text = "Телеметрия обновлена"
    except Exception as exc:  # noqa: BLE001
        response_text = f"Ошибка действия: {exc}"
        LOG.exception("telegram callback failed: %s", exc)
    if callback_id:
        self._telegram_request(
            "answerCallbackQuery",
            {"callback_query_id": callback_id, "text": response_text[:180], "show_alert": False},
        )
    LOG.info("telegram callback received", extra={"callback": data, "user": label})


IncidentTelegramBot._status_label = _bot_status_label_clean
IncidentTelegramBot._build_incident_keyboard = _bot_build_incident_keyboard_clean
IncidentTelegramBot._format_incident_message = _bot_format_incident_message_clean
IncidentTelegramBot._send_ai_followup = _bot_send_ai_followup_clean
IncidentTelegramBot._format_ai_message = _bot_format_ai_message_clean
IncidentTelegramBot._format_host_action_message = _bot_format_host_action_message_clean
IncidentTelegramBot._handle_callback = _bot_handle_callback_clean


def _configure_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
        stream=sys.stdout,
    )


def main() -> int:
    _configure_logging()
    config = load_config()
    bot = IncidentTelegramBot(config)
    bot.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
