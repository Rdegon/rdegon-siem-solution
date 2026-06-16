from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import incident_ai_runtime as runtime


class IncidentAiRuntimeTests(unittest.TestCase):
    def test_extract_json_block_finds_embedded_object(self) -> None:
        payload = runtime._extract_json_block('prefix {"score": 72, "summary": "ok"} suffix')
        self.assertIsInstance(payload, dict)
        self.assertEqual(72, payload["score"])

    def test_extract_openclaw_assistant_text_supports_payloads(self) -> None:
        payload = {
            "payloads": [
                {"text": ""},
                {"text": '{"summary":"ok","score":1,"confidence":"medium"}'},
            ]
        }
        self.assertEqual('{"summary":"ok","score":1,"confidence":"medium"}', runtime._extract_openclaw_assistant_text(payload))

    def test_extract_openclaw_assistant_text_ignores_recursive_payloads(self) -> None:
        payload: dict[str, object] = {}
        payload["result"] = payload
        self.assertEqual("", runtime._extract_openclaw_assistant_text(payload))

    def test_openclaw_python_script_uses_multiline_try_block(self) -> None:
        script = runtime._openclaw_python_script("dGVzdA==")
        self.assertIn("\ntry:\n", script)
        self.assertNotIn(";try:", script)
        self.assertIn("body=json.loads", script)

    def test_event_count_uses_raw_hits_total_first(self) -> None:
        row = {"raw_hits_total": 12, "events_count": 3}
        self.assertEqual(12, runtime._event_count(row))

    def test_incident_hosts_maps_aliases_to_inventory(self) -> None:
        row = {
            "source": "45.89.111.208",
            "cluster": {"sources": ["openclaw-gateway", "45.89.111.208"]},
            "samples": [{"host_name": "openclaw-gateway"}],
        }
        inventory = [
            {
                "name": "openclaw-gateway",
                "source_name": "openclaw-gateway",
                "ip": "10.20.30.126",
                "vmid": 126,
                "guest_type": "qemu",
                "os_family": "linux",
                "role": "openclaw-gateway",
                "business_service": "OpenClaw egress gateway",
                "state": "connected",
            }
        ]
        with patch.object(runtime, "list_proxmox_fleet_inventory", return_value=inventory):
            hosts = runtime._incident_hosts(row)
        self.assertEqual(1, len(hosts))
        self.assertEqual("openclaw-gateway", hosts[0]["name"])
        self.assertIn("snapshot", hosts[0]["supported_actions"])

    def test_incident_hosts_accepts_dict_payload_inventory(self) -> None:
        row = {
            "source": "openclaw-gateway",
            "cluster": {"sources": ["openclaw-gateway"]},
        }
        inventory_payload = {
            "items": [
                {
                    "name": "openclaw-gateway",
                    "source_name": "openclaw-gateway",
                    "ip": "10.20.30.126",
                    "vmid": 126,
                    "guest_type": "qemu",
                    "os_family": "linux",
                    "role": "openclaw-gateway",
                    "business_service": "OpenClaw egress gateway",
                    "state": "connected",
                }
            ]
        }
        with patch.object(runtime, "list_proxmox_fleet_inventory", return_value=inventory_payload):
            hosts = runtime._incident_hosts(row)
        self.assertEqual(1, len(hosts))
        self.assertEqual("10.20.30.126", hosts[0]["ip"])

    def test_incident_hosts_survives_inventory_runtime_error(self) -> None:
        row = {"source": "openclaw-gateway", "cluster": {"sources": ["openclaw-gateway"]}}
        with patch.object(runtime, "list_proxmox_fleet_inventory", side_effect=RuntimeError("boom")):
            hosts = runtime._incident_hosts(row)
        self.assertEqual([], hosts)

    def test_queue_incident_ai_assessment_returns_pending_placeholder(self) -> None:
        row = {"agg_id": "agg-1", "title": "Test incident", "status": "new"}
        started: list[tuple[str, str]] = []
        thread_config: list[dict[str, object]] = []

        class DummyThread:
            def __init__(self, *, target=None, args=(), kwargs=None, **_extra) -> None:
                self._args = args
                thread_config.append(dict(_extra))

            def start(self) -> None:
                started.append((self._args[0], self._args[1]))

        with patch.object(runtime, "_get_incident_row", return_value=row), \
             patch.object(runtime, "_incident_hosts", return_value=[{"name": "openclaw-gateway"}]), \
             patch.object(runtime, "get_incident_ai_assessment", return_value={}), \
             patch.object(runtime, "_replace_assessment", side_effect=lambda record: record), \
             patch.object(runtime, "_mark_assessment_running", return_value=True), \
             patch.object(runtime.threading, "Thread", DummyThread):
            queued = runtime.queue_incident_ai_assessment("agg", "agg-1", requested_by="test", timezone_name="Europe/Moscow")
        self.assertEqual("pending", queued["status"])
        self.assertEqual("agg:agg-1", queued["incident_ref"])
        self.assertTrue(started)
        self.assertTrue(thread_config)
        self.assertNotIn("daemon", thread_config[0])

    def test_fallback_assessment_marks_openclaw_research_as_false_positive_candidate(self) -> None:
        bundle = {
            "incident": {
                "title": "Linux System Recon Burst",
                "campaigns": ["reconnaissance"],
                "sources": ["openclaw-gateway"],
                "context": {"host_name": "openclaw-gateway", "process_command": "openclaw agent --agent research"},
            },
            "hosts": [{"name": "openclaw-gateway"}],
        }
        assessment = runtime._fallback_incident_ai_assessment(bundle, error_message="timeout")
        self.assertEqual("closed", assessment["status_suggestion"])
        self.assertIn("служебную", assessment["summary"])
        self.assertTrue(assessment["notes"])

    def test_search_context_short_circuits_after_initial_timeouts(self) -> None:
        row = {"title": "Host Load Pressure Sustained", "cluster": {"sources": ["nextcloud-siem"]}}
        with patch.object(runtime, "_search_bing", side_effect=TimeoutError("timeout")), \
             patch.object(runtime, "_search_duckduckgo", side_effect=TimeoutError("timeout")):
            payload = runtime._search_context(row)
        self.assertEqual([], payload["results"])
        self.assertGreaterEqual(len(payload["errors"]), 2)

    def test_fallback_assessment_marks_operational_sudo_as_false_positive_candidate(self) -> None:
        bundle = {
            "incident": {
                "title": "Linux Sudo To Root",
                "campaigns": ["privilege_escalation"],
                "sources": ["siem-processing"],
                "context": {
                    "host_name": "siem-processing",
                    "process_command": "/usr/bin/systemctl is-active siem-normalizer siem-normalizer@2",
                },
            },
            "hosts": [{"name": "siem-processing"}],
        }
        assessment = runtime._fallback_incident_ai_assessment(bundle, error_message="timeout")
        self.assertEqual("closed", assessment["status_suggestion"])
        self.assertIn("sudo/systemctl", assessment["summary"])


if __name__ == "__main__":
    unittest.main()
