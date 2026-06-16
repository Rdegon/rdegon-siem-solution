from __future__ import annotations

import sys
import types
import unittest
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

from services.incident_telegram_bot import BotConfig, IncidentTelegramBot, _incident_count, _incident_should_skip_delivery


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
            "agg_id": "agg-1",
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

    def test_false_positive_incident_is_skipped_for_delivery(self) -> None:
        self.assertTrue(_incident_should_skip_delivery({"status": "false_positive"}))
        self.assertFalse(_incident_should_skip_delivery({"status": "open"}))


if __name__ == "__main__":
    unittest.main()
