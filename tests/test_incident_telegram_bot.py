from __future__ import annotations

import sys
import types
import unittest
from unittest.mock import patch
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

if "requests" not in sys.modules:
    requests_stub = types.ModuleType("requests")

    class _RequestException(Exception):
        pass

    class _HTTPError(_RequestException):
        pass

    def _unused_post(*_args, **_kwargs):
        raise AssertionError("requests.post should not be called in unit tests")

    requests_stub.post = _unused_post
    requests_stub.RequestException = _RequestException
    requests_stub.HTTPError = _HTTPError
    sys.modules["requests"] = requests_stub

from services.incident_telegram_bot import (
    BotConfig,
    IncidentTelegramBot,
    _incident_count,
    _incident_should_skip_delivery,
    load_config,
)


class IncidentTelegramBotTests(unittest.TestCase):
    def _bot(self) -> IncidentTelegramBot:
        return IncidentTelegramBot(
            BotConfig(
                siem_base_url="https://siem.local",
                siem_api_token="token",
                incident_view="agg",
                incident_window="24h",
                incident_limit=30,
                poll_seconds=45,
                verify_tls=False,
                telegram_bot_token="bot-token",
                telegram_chat_id="12345",
                postgres_dsn="postgresql://bot:bot@127.0.0.1:5432/bot",
                open_base_url="https://siem.local",
                callback_note="ok",
                enable_callbacks=True,
                telegram_proxy_url="",
                default_timezone="Europe/Moscow",
            )
        )

    def test_incident_count_prefers_raw_hits_total(self) -> None:
        self.assertEqual(17, _incident_count({"raw_hits_total": 17, "events_count": 1}))

    def test_format_incident_message_uses_real_event_count_and_hosts(self) -> None:
        bot = self._bot()
        incident = {
            "record_id": "agg-1",
            "severity_agg": "high",
            "status": "open",
            "summary": "SSH burst against SIEM",
            "assignee": "",
            "raw_hits_total": 9,
            "host_labels": ["Веб-узел SIEM (siem-web)", "Шлюз OpenClaw (openclaw-gateway)"],
            "updated_ts": "2026-03-29T12:00:00Z",
        }
        message = bot._format_incident_message(incident, timezone_name="Europe/Moscow")
        self.assertIn("События: 9", message)
        self.assertIn("Ответственный: не назначен", message)
        self.assertIn("Хосты: Веб-узел SIEM (siem-web), Шлюз OpenClaw (openclaw-gateway)", message)

    def test_timestamp_only_change_does_not_create_a_new_fingerprint(self) -> None:
        bot = self._bot()
        first = {
            "record_id": "agg-1",
            "status": "open",
            "severity": "high",
            "title": "SSH burst",
            "updated_ts": "2026-03-29T12:00:00Z",
            "raw_hits_total": 9,
        }
        second = {**first, "updated_ts": "2026-03-29T12:01:00Z"}
        self.assertEqual(bot._incident_fingerprint(first), bot._incident_fingerprint(second))

    def test_record_id_is_the_canonical_incident_key(self) -> None:
        bot = self._bot()
        self.assertEqual("canonical", bot._incident_key({"record_id": "canonical", "agg_id": "storage"}))

    def test_existing_telegram_card_is_edited_instead_of_sent_again(self) -> None:
        bot = self._bot()
        calls: list[tuple[str, dict]] = []

        def telegram(method: str, payload: dict) -> dict:
            calls.append((method, payload))
            return {"ok": True, "result": {"message_id": 42}}

        bot._telegram_request = telegram  # type: ignore[method-assign]
        result = bot._edit_incident(
            {"record_id": "agg-1", "status": "open", "title": "SSH burst"},
            "agg-1",
            chat_id="12345",
            message_id=42,
            timezone_name="Europe/Moscow",
            callback_ref="callback",
        )
        self.assertEqual("edited", result["status"])
        self.assertEqual("editMessageText", calls[0][0])
        self.assertEqual(42, calls[0][1]["message_id"])

    def test_false_positive_incident_is_skipped_for_delivery(self) -> None:
        self.assertTrue(_incident_should_skip_delivery({"status": "false_positive"}))
        self.assertTrue(_incident_should_skip_delivery({"status": "suppressed_by_tuning"}))
        self.assertTrue(_incident_should_skip_delivery({"status": "merged"}))
        self.assertFalse(_incident_should_skip_delivery({"status": "open"}))

    def test_config_cannot_enable_raw_alert_fanout(self) -> None:
        with patch.dict("os.environ", {"SIEM_BOT_INCIDENT_VIEW": "raw"}):
            self.assertEqual("agg", load_config().incident_view)

    def test_delivery_key_uses_stable_aggregation_scope(self) -> None:
        bot = self._bot()
        first = {
            "record_id": "materialized-high",
            "agg_id": "materialized-high",
            "group_key": {"incident_key": "asset:web|campaign:ssh"},
        }
        second = {
            "record_id": "materialized-critical",
            "agg_id": "materialized-critical",
            "group_key_json": '{"incident_key":"asset:web|campaign:ssh"}',
        }
        self.assertEqual(bot._delivery_key(first), bot._delivery_key(second))
        self.assertEqual(bot._aggregation_fingerprint(first), bot._aggregation_fingerprint(second))

    def test_poll_uses_main_scope_and_reconciles_absent_cards(self) -> None:
        bot = self._bot()
        requested: list[str] = []
        processed: list[str] = []
        reconciled: list[set[str]] = []

        def request(path: str, **_kwargs) -> dict:
            requested.append(path)
            return {
                "items": [
                    {"record_id": "agg-1", "status": "open"},
                    {"record_id": "agg-2", "status": "open"},
                ]
            }

        bot._siem_request_json = request  # type: ignore[method-assign]
        bot._process_incident = lambda _conn, item: processed.append(item["record_id"])  # type: ignore[method-assign]
        bot._reconcile_absent_incidents = lambda _conn, keys: reconciled.append(keys)  # type: ignore[method-assign]
        bot._poll_incidents(object())  # type: ignore[arg-type]

        self.assertIn("scope=main", requested[0])
        self.assertEqual(["agg-2", "agg-1"], processed)
        self.assertEqual([{"agg-1", "agg-2"}], reconciled)

    def test_truncated_poll_does_not_expire_cards_outside_the_page(self) -> None:
        bot = self._bot()
        bot._siem_request_json = lambda *_args, **_kwargs: {  # type: ignore[method-assign]
            "items": [{"record_id": "agg-1", "status": "open"}],
            "available_count": 200,
        }
        bot._process_incident = lambda *_args, **_kwargs: None  # type: ignore[method-assign]
        bot._reconcile_absent_incidents = lambda *_args, **_kwargs: self.fail(  # type: ignore[method-assign]
            "truncated snapshot must not reconcile absent cards"
        )

        bot._poll_incidents(object())  # type: ignore[arg-type]

    def test_unconfirmed_send_is_not_replayed_after_restart(self) -> None:
        bot = self._bot()
        published: list[dict] = []
        incident = {
            "record_id": "web-id",
            "status": "open",
            "severity": "high",
            "title": "SSH burst",
            "group_key": {"incident_key": "asset:web|campaign:ssh"},
        }
        state = {
            "stored_delivery_key": "asset:web|campaign:ssh",
            "fingerprint": "",
            "operation_state": "prepared",
            "operation_fingerprint": bot._incident_fingerprint(incident),
            "operation_kind": "send",
            "operation_key": "attempt-1",
            "telegram_message_id": None,
        }
        bot._get_incident_state = lambda *_args, **_kwargs: state  # type: ignore[method-assign]
        bot._touch_incident_state = lambda *_args, **_kwargs: None  # type: ignore[method-assign]
        bot._publish_delivery_state = lambda *_args, **kwargs: published.append(kwargs)  # type: ignore[method-assign]
        bot._telegram_request = lambda *_args, **_kwargs: self.fail("send must not be replayed")  # type: ignore[method-assign]

        bot._process_incident(object(), incident)  # type: ignore[arg-type]

        self.assertEqual("uncertain", published[0]["telegram"]["status"])
        self.assertEqual("attempt-1", published[0]["attempt_key"])

    def test_failed_edit_keeps_existing_card_and_never_sends_replacement(self) -> None:
        bot = self._bot()
        calls: list[str] = []

        def telegram(method: str, _payload: dict) -> dict:
            calls.append(method)
            raise RuntimeError("edit rejected")

        bot._telegram_request = telegram  # type: ignore[method-assign]
        result = bot._edit_incident(
            {"record_id": "agg-1", "status": "open", "title": "SSH burst"},
            "agg-1",
            chat_id="12345",
            message_id=42,
            timezone_name="Europe/Moscow",
            callback_ref="callback",
        )

        self.assertEqual("edit_failed", result["status"])
        self.assertEqual(["editMessageText"], calls)

    def test_missing_edit_target_is_replaced_once(self) -> None:
        bot = self._bot()
        calls: list[str] = []

        def telegram(method: str, _payload: dict) -> dict:
            calls.append(method)
            if method == "editMessageText":
                raise RuntimeError(
                    'Telegram request failed: editMessageText; {"description":"Bad Request: message to edit not found"}'
                )
            return {"ok": True, "result": {"message_id": 77}}

        bot._telegram_request = telegram  # type: ignore[method-assign]
        result = bot._edit_incident(
            {"record_id": "agg-1", "status": "open", "title": "SSH burst"},
            "agg-1",
            chat_id="12345",
            message_id=42,
            timezone_name="Europe/Moscow",
            callback_ref="callback",
        )

        self.assertEqual("sent", result["status"])
        self.assertEqual(77, result["message_id"])
        self.assertEqual("stale_message_replaced", result["reason"])
        self.assertEqual(["editMessageText", "sendMessage"], calls)

    def test_missing_delete_target_is_already_deleted(self) -> None:
        bot = self._bot()
        bot._telegram_request = lambda *_args, **_kwargs: (_ for _ in ()).throw(  # type: ignore[method-assign]
            RuntimeError(
                'Telegram request failed: deleteMessage; {"description":"Bad Request: message to delete not found"}'
            )
        )

        result = bot._delete_incident_card(chat_id="12345", message_id=42, reason="expired")

        self.assertEqual("deleted", result["status"])
        self.assertEqual("expired:already_absent", result["reason"])

    def test_delete_incident_card_uses_telegram_delete_message(self) -> None:
        bot = self._bot()
        calls: list[tuple[str, dict]] = []
        bot._telegram_request = lambda method, payload: calls.append((method, payload)) or {"ok": True}  # type: ignore[method-assign]

        result = bot._delete_incident_card(
            chat_id="12345",
            message_id=42,
            reason="left_main_incident_queue",
        )

        self.assertEqual("deleted", result["status"])
        self.assertEqual(
            ("deleteMessage", {"chat_id": "12345", "message_id": 42}),
            calls[0],
        )

    def test_old_telegram_card_is_archived_when_delete_is_rejected(self) -> None:
        bot = self._bot()
        calls: list[tuple[str, dict]] = []

        def request(method: str, payload: dict) -> dict:
            calls.append((method, payload))
            if method == "deleteMessage":
                raise RuntimeError("message can't be deleted")
            return {"ok": True}

        bot._telegram_request = request  # type: ignore[method-assign]

        result = bot._delete_incident_card(
            chat_id="12345",
            message_id=42,
            reason="left_main_incident_queue",
        )

        self.assertEqual("archived", result["status"])
        self.assertEqual(["deleteMessage", "editMessageText"], [item[0] for item in calls])
        self.assertEqual({"inline_keyboard": []}, calls[1][1]["reply_markup"])
        self.assertIn("АРХИВ", calls[1][1]["text"])

    def test_telegram_request_redacts_bot_token_from_transport_errors(self) -> None:
        bot = self._bot()
        request_error = sys.modules["requests"].RequestException(
            "timeout at https://api.telegram.org/botbot-token/getUpdates"
        )
        original_post = sys.modules["requests"].post
        sys.modules["requests"].post = lambda *_args, **_kwargs: (_ for _ in ()).throw(request_error)
        try:
            with self.assertRaises(RuntimeError) as raised:
                bot._telegram_request("getUpdates", {})
        finally:
            sys.modules["requests"].post = original_post

        self.assertNotIn("bot-token", str(raised.exception))
        self.assertIn("<redacted>", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
