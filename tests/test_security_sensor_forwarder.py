from __future__ import annotations

import json
import tempfile
import unittest
import urllib.error
from argparse import Namespace
from pathlib import Path
from unittest.mock import patch

from deploy.security_sensor_forwarder import (
    _compact_spool,
    _collect_once,
    _decorate,
    _deliver_once,
    _load_state,
    _misp_attributes,
    _read_spool,
    _trivy_findings,
)


class SecuritySensorForwarderTests(unittest.TestCase):
    def test_sensor_host_overrides_protocol_source_identity(self) -> None:
        decorated = _decorate(
            {"source": "HTTP", "log_source": "HTTP", "host.name": "soc-ndr-01"},
            kind="zeek",
            sensor="zeek",
            host_name="soc-ndr-01",
            path=Path("/opt/zeek/logs/current/weird.log"),
            inode=1,
            offset=2,
        )

        self.assertEqual("soc-ndr-01", decorated["source"])
        self.assertEqual("soc-ndr-01", decorated["log_source"])

    def test_trivy_document_is_expanded_into_findings(self) -> None:
        payload = {
            "ArtifactName": "example/image:latest",
            "Results": [
                {
                    "Target": "example/image:latest (alpine 3.20)",
                    "Type": "alpine",
                    "Vulnerabilities": [
                        {"VulnerabilityID": "CVE-2026-0001", "PkgName": "openssl"},
                        {"VulnerabilityID": "CVE-2026-0002", "PkgName": "curl"},
                    ],
                }
            ],
        }

        findings = list(_trivy_findings(payload))

        self.assertEqual(2, len(findings))
        self.assertEqual("alpine", findings[0]["Type"])
        self.assertEqual("CVE-2026-0002", findings[1]["VulnerabilityID"])

    def test_misp_event_is_expanded_into_attributes(self) -> None:
        payload = {
            "Event": {
                "id": "42",
                "Attribute": [
                    {"type": "ip-dst", "value": "203.0.113.10"},
                    {"type": "domain", "value": "example.invalid"},
                ],
            }
        }

        attributes = list(_misp_attributes(payload))

        self.assertEqual(2, len(attributes))
        self.assertEqual("42", attributes[0]["Event"]["id"])
        self.assertEqual("domain", attributes[1]["Attribute"]["type"])

    def test_jsonl_collection_spools_and_tracks_offset(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "conn.log"
            source.write_text(
                json.dumps({"_path": "conn", "uid": "C1"}) + "\n"
                + json.dumps({"_path": "conn", "uid": "C2"}) + "\n",
                encoding="utf-8",
            )
            args = Namespace(
                spool_path=str(root / "spool.jsonl"),
                spool_max_bytes=1_048_576,
                path=[str(source)],
                read_limit=100,
                format="jsonl",
                kind="zeek",
                sensor="soc-ndr-01",
                host_name="soc-ndr-01",
                start_position="beginning",
                state_path=str(root / "state.json"),
            )
            state = _load_state(Path(args.state_path))

            first_count = _collect_once(args, state)
            second_count = _collect_once(args, state)
            events, next_offset = _read_spool(Path(args.spool_path), 100)

            self.assertEqual(2, first_count)
            self.assertEqual(0, second_count)
            self.assertEqual((root / "spool.jsonl").stat().st_size, next_offset)
            self.assertEqual(["C1", "C2"], [event["uid"] for event in events])
            self.assertTrue(all(event["source_type"] == "zeek" for event in events))
            self.assertTrue(all(event["event.id"].startswith("sensor-") for event in events))
            self.assertTrue(all(event["event.ingested"].endswith("Z") for event in events))

    def test_spool_cursor_reads_without_rewriting_and_compacts_after_half_consumed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            spool = root / "spool.jsonl"
            rows = [{"event.id": f"event-{index}"} for index in range(6)]
            spool.write_text(
                "".join(json.dumps(row) + "\n" for row in rows),
                encoding="utf-8",
            )
            first, offset = _read_spool(spool, 3)
            state = {"spool_offset": offset}

            compacted = _compact_spool(spool, state, min_consumed_bytes=1)
            remaining, remaining_offset = _read_spool(spool, 10)

            self.assertTrue(compacted)
            self.assertEqual(0, state["spool_offset"])
            self.assertEqual(["event-0", "event-1", "event-2"], [row["event.id"] for row in first])
            self.assertEqual(["event-3", "event-4", "event-5"], [row["event.id"] for row in remaining])
            self.assertEqual(spool.stat().st_size, remaining_offset)

    def test_collection_waits_for_spool_to_drain_after_backpressure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            spool = root / "spool.jsonl"
            spool.write_bytes(b"x" * 100)
            args = Namespace(
                spool_path=str(spool),
                spool_max_bytes=100,
                path=[],
                read_limit=100,
                format="jsonl",
                kind="zeek",
                sensor="soc-ndr-01",
                host_name="soc-ndr-01",
                start_position="beginning",
                state_path=str(root / "state.json"),
            )
            state: dict[str, object] = {}

            self.assertEqual(0, _collect_once(args, state))
            self.assertTrue(state["spool_backpressure"])
            state["spool_offset"] = 40
            self.assertEqual(0, _collect_once(args, state))
            self.assertTrue(state["spool_backpressure"])
            state["spool_offset"] = 50
            self.assertEqual(0, _collect_once(args, state))
            self.assertFalse(state["spool_backpressure"])

    def test_collection_ignores_file_removed_during_log_rotation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "weird.log"
            source.write_text("{}\n", encoding="utf-8")
            args = Namespace(
                spool_path=str(root / "spool.jsonl"),
                spool_max_bytes=1_048_576,
                path=[str(source)],
                read_limit=100,
                format="jsonl",
                kind="zeek",
                sensor="soc-ndr-01",
                host_name="soc-ndr-01",
                start_position="beginning",
                state_path=str(root / "state.json"),
            )
            state = {"files": {str(source.resolve()): {"inode": 7, "offset": 4}}}

            with patch(
                "deploy.security_sensor_forwarder._read_jsonl",
                side_effect=FileNotFoundError,
            ):
                count = _collect_once(args, state)

            self.assertEqual(0, count)
            self.assertEqual({"inode": 7, "offset": 4}, state["files"][str(source.resolve())])
            self.assertFalse(Path(args.spool_path).exists())

    def test_delivery_reduces_batch_after_http_413_and_remembers_limit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            spool = root / "spool.jsonl"
            rows = [{"event.id": f"event-{index}", "message": "x" * 100} for index in range(4)]
            spool.write_text(
                "".join(json.dumps(row) + "\n" for row in rows),
                encoding="utf-8",
            )
            args = Namespace(
                spool_path=str(spool),
                state_path=str(root / "state.json"),
                batch_size=4,
                ingest_url="https://ingest.example.invalid/ingest/json",
                timeout=10,
                tls_verify="required",
                ca_file="",
                bearer_token="",
            )
            state: dict[str, object] = {}

            def reject_large_batches(_url: str, events: list[dict[str, object]], **_kwargs: object) -> dict[str, int]:
                if len(events) > 2:
                    raise urllib.error.HTTPError(_url, 413, "too large", {}, None)
                return {"ingested": len(events), "rejected": 0}

            with patch("deploy.security_sensor_forwarder._post", side_effect=reject_large_batches):
                first_count = _deliver_once(args, state)
                second_count = _deliver_once(args, state)

            self.assertEqual(2, first_count)
            self.assertEqual(2, second_count)
            self.assertEqual(2, state["delivery_batch_size"])
            self.assertEqual(spool.stat().st_size, state["spool_offset"])

    def test_velociraptor_artifact_is_derived_from_result_path(self) -> None:
        event = _decorate(
            {"Timestamp": "2026-07-26T01:00:00Z"},
            kind="velociraptor",
            sensor="soc-dfir-01",
            host_name="soc-dfir-01",
            path=Path(
                "/var/lib/velociraptor/server_artifacts/"
                "Server.Monitor.Health/Prometheus/2026-07-26.json"
            ),
            inode=1,
            offset=0,
        )

        self.assertEqual("Server.Monitor.Health", event["artifact"])

    def test_velociraptor_client_and_flow_are_derived_from_collection_path(self) -> None:
        event = _decorate(
            {"Hostname": "WIN-RTX-test"},
            kind="velociraptor",
            sensor="soc-dfir-01",
            host_name="soc-dfir-01",
            path=Path(
                "/var/lib/velociraptor/clients/C.123/artifacts/"
                "Generic.Client.Info/F.SMOKE/BasicInformation.json"
            ),
            inode=1,
            offset=0,
        )

        self.assertEqual("Generic.Client.Info", event["artifact"])
        self.assertEqual("C.123", event["client.id"])
        self.assertEqual("F.SMOKE", event["flow.id"])


if __name__ == "__main__":
    unittest.main()
