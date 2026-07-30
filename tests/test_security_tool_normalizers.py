from __future__ import annotations

import json
import time
import unittest

from services.normalizer.normalizer_core import apply_rules
from services.normalizer.worker import _transport_field_value
from services.writer.worker import WriterSettings, WriterWorker


class SecurityToolNormalizerTests(unittest.TestCase):
    def _normalize(self, event: dict) -> dict:
        normalized = apply_rules([], event)
        self.assertIsNotNone(normalized)
        assert normalized is not None
        return normalized

    def test_zeek_conn_preserves_community_id_and_flow(self) -> None:
        normalized = self._normalize(
            {
                "source_type": "zeek",
                "source": "soc-ndr-01",
                "_path": "conn",
                "ts": "1785000000.125",
                "event.ingested": "2026-07-26T14:15:00Z",
                "uid": "C1-test",
                "id.orig_h": "10.20.30.25",
                "id.orig_p": 51512,
                "id.resp_h": "1.1.1.1",
                "id.resp_p": 443,
                "proto": "tcp",
                "service": "ssl",
                "community_id": "1:test-community-id",
                "conn_state": "SF",
            }
        )

        self.assertEqual("zeek", normalized["event.provider"])
        self.assertEqual("zeek.conn", normalized["event.dataset"])
        self.assertEqual("10.20.30.25", normalized["source.ip"])
        self.assertEqual("1:test-community-id", normalized["network.community_id"])
        self.assertEqual("success", normalized["event.outcome"])
        self.assertEqual("2026-07-26T14:15:00Z", normalized["event.ingested"])

    def test_zeek_preserves_per_record_id_and_infers_dataset_from_log_path(self) -> None:
        normalized = self._normalize(
            {
                "source_type": "zeek",
                "source": "soc-ndr-01",
                "event.id": "sensor-record-42",
                "event.dataset": "zeek.event",
                "sensor.file": "/opt/zeek/logs/enp6s19/dns.2026-07-26-04-00-00.log",
                "uid": "C-shared-connection",
                "query": "_matter._tcp.local",
            }
        )

        self.assertEqual("sensor-record-42", normalized["event.id"])
        self.assertEqual("C-shared-connection", normalized["zeek.uid"])
        self.assertEqual("zeek.dns", normalized["event.dataset"])
        self.assertEqual("zeek_dns", normalized["event.type"])

    def test_suricata_eve_alert_inside_syslog_is_structured(self) -> None:
        normalized = self._normalize(
            {
                "source_type": "syslog",
                "source": "10.20.10.102",
                "message": (
                    '<182>1 2026-07-26T08:00:00+03:00 lab-edge-01 suricata-eve - - - '
                    '{"timestamp":"2026-07-26T08:00:00+0300","flow_id":42,'
                    '"event_type":"alert","src_ip":"8.8.8.8","src_port":55123,'
                    '"dest_ip":"10.20.30.123","dest_port":443,"proto":"TCP",'
                    '"alert":{"signature_id":2024364,"signature":"ET EXPLOIT Possible RCE",'
                    '"category":"Web Application Attack","severity":1}}'
                ),
            }
        )

        self.assertEqual("suricata", normalized["event.provider"])
        self.assertEqual("suricata_alert", normalized["event.type"])
        self.assertEqual("critical", normalized["event.severity"])
        self.assertEqual("2024364", normalized["rule.id"])
        self.assertEqual("ET EXPLOIT Possible RCE", normalized["rule.name"])
        self.assertEqual("inbound", normalized["network.direction"])
        self.assertEqual("443", normalized["destination.port"])

    def test_suricata_eve_dns_inside_syslog_maps_dns_fields(self) -> None:
        normalized = self._normalize(
            {
                "source_type": "syslog",
                "source": "10.20.10.102",
                "message": (
                    '<182>1 2026-07-26T08:00:00+03:00 lab-edge-01 suricata-eve - - - '
                    '{"timestamp":"2026-07-26T08:00:00+0300","event_type":"dns",'
                    '"src_ip":"10.20.30.124","src_port":53001,"dest_ip":"1.1.1.1",'
                    '"dest_port":53,"proto":"UDP","dns":{"type":"answer",'
                    '"rrname":"missing.example","rrtype":"A","rcode":"NXDOMAIN"}}'
                ),
            }
        )

        self.assertEqual("suricata_dns", normalized["event.type"])
        self.assertEqual("missing.example", normalized["dns.question.name"])
        self.assertEqual("NXDOMAIN", normalized["dns.response_code"])
        self.assertEqual("outbound", normalized["network.direction"])

    def test_suricata_flow_id_is_not_reused_as_source_event_id(self) -> None:
        base_payload = {
            "timestamp": "2026-07-28T12:47:08.911206Z",
            "flow_id": 1380328458185220,
            "src_ip": "192.168.3.102",
            "dest_ip": "1.1.1.1",
            "proto": "UDP",
        }
        def event(payload: dict) -> dict:
            return {
                "source_type": "syslog",
                "source": "192.168.3.102",
                "message": (
                    "<182>1 2026-07-28T15:47:08+03:00 "
                    "lab-edge-01 suricata-eve - - - "
                    + json.dumps(payload, separators=(",", ":"))
                ),
            }

        query = self._normalize(
            event({
                **base_payload,
                "event_type": "dns",
                "dns": {"type": "query", "id": 3684, "rrname": "_ta"},
            })
        )
        answer = self._normalize(
            event({
                **base_payload,
                "event_type": "dns",
                "dns": {"type": "answer", "id": 3684, "rrname": "_ta"},
            })
        )
        replay = self._normalize(
            event({
                **base_payload,
                "event_type": "dns",
                "dns": {"type": "query", "id": 3684, "rrname": "_ta"},
            })
        )

        self.assertEqual("1380328458185220", query["suricata.flow_id"])
        self.assertRegex(query["event.id"], r"^suricata-[0-9a-f]{32}$")
        self.assertNotEqual(query["event.id"], answer["event.id"])
        self.assertEqual(query["event.id"], replay["event.id"])
        transport_fields = {
            key: _transport_field_value(value) for key, value in query.items()
        }
        stored = json.loads(
            WriterWorker(WriterSettings())._build_normalized_json(transport_fields)
        )
        self.assertEqual("1380328458185220", stored["suricata"]["flow_id"])
        self.assertEqual("1380328458185220", stored["network"]["flow_id"])

    def test_suricata_fast_alert_is_not_left_as_generic_syslog(self) -> None:
        normalized = self._normalize(
            {
                "source_type": "syslog",
                "source": "10.20.10.102",
                "message": (
                    "<180>1 2026-07-26T08:00:00+03:00 lab-edge-01 suricata-fast - - - "
                    "07/26/2026-08:00:00.000000  [**] [1:2001219:20] "
                    "ET SCAN Potential SSH Scan [**] [Classification: Attempted Information Leak] "
                    "[Priority: 2] {TCP} 8.8.8.8:55000 -> 10.20.30.123:22"
                ),
            }
        )

        self.assertEqual("suricata.fast", normalized["event.dataset"])
        self.assertEqual("suricata_alert", normalized["event.type"])
        self.assertEqual("ET SCAN Potential SSH Scan", normalized["rule.name"])
        self.assertEqual("22", normalized["destination.port"])

    def test_falco_alert_maps_runtime_and_container_fields(self) -> None:
        normalized = self._normalize(
            {
                "source_type": "falco",
                "source": "gamepanel-01",
                "rule": "Terminal shell in container",
                "priority": "Warning",
                "output": "A shell was spawned in a container",
                "output_fields": {
                    "proc.name": "bash",
                    "proc.cmdline": "bash -i",
                    "user.name": "gamesvc",
                    "container.id": "abcdef123456",
                    "container.name": "minecraft",
                },
            }
        )

        self.assertEqual("falco.runtime", normalized["event.dataset"])
        self.assertEqual("Terminal shell in container", normalized["rule.name"])
        self.assertEqual("medium", normalized["event.severity"])
        self.assertEqual("abcdef123456", normalized["container.id"])
        self.assertEqual("bash -i", normalized["process.command_line"])

    def test_security_sensor_heartbeat_stays_out_of_detection_category(self) -> None:
        normalized = self._normalize(
            {
                "event.id": "sensor-heartbeat-1",
                "source_type": "falco",
                "source": "gamepanel-01",
                "host.name": "gamepanel-01",
                "event.provider": "falco",
                "event.dataset": "falco.health",
                "event.category": "health",
                "event.type": "security_integration_heartbeat",
                "event.action": "heartbeat",
                "event.outcome": "success",
                "event.severity": "info",
                "sensor.status": "running",
            }
        )

        self.assertEqual("falco", normalized["event.provider"])
        self.assertEqual("health", normalized["event.category"])
        self.assertEqual("security_integration_heartbeat", normalized["event.type"])
        self.assertEqual("info", normalized["event.severity"])
        self.assertEqual("success", normalized["event.outcome"])
        self.assertIn("suppress:correlation", normalized["tags"])

    def test_trivy_finding_maps_vulnerability_fields(self) -> None:
        normalized = self._normalize(
            {
                "source_type": "trivy",
                "source": "gamepanel-01",
                "Target": "ghcr.io/example/panel:latest",
                "Type": "alpine",
                "VulnerabilityID": "CVE-2026-4242",
                "PkgName": "openssl",
                "InstalledVersion": "3.0.1",
                "FixedVersion": "3.0.2",
                "Severity": "HIGH",
                "Title": "Example OpenSSL issue",
            }
        )

        self.assertEqual("CVE-2026-4242", normalized["vulnerability.id"])
        self.assertEqual("high", normalized["vulnerability.severity"])
        self.assertEqual("openssl", normalized["vulnerability.package.name"])
        self.assertEqual("failure", normalized["event.outcome"])

    def test_velociraptor_artifact_maps_endpoint_fields(self) -> None:
        normalized = self._normalize(
            {
                "source_type": "velociraptor",
                "artifact": "Windows.System.Pslist",
                "client_id": "C.1234",
                "hostname": "WIN-RTX-test",
                "Name": "powershell.exe",
                "Exe": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                "CommandLine": "powershell.exe -NoProfile",
            }
        )

        self.assertEqual("velociraptor.Windows.System.Pslist", normalized["event.dataset"])
        self.assertEqual("C.1234", normalized["agent.id"])
        self.assertEqual("WIN-RTX-test", normalized["host.name"])
        self.assertEqual("powershell.exe -NoProfile", normalized["process.command_line"])

    def test_misp_attribute_maps_indicator(self) -> None:
        normalized = self._normalize(
            {
                "source_type": "misp",
                "source": "soc-ti-01",
                "Attribute": {
                    "id": "7",
                    "type": "ip-dst",
                    "value": "203.0.113.50",
                    "to_ids": True,
                    "timestamp": str(int(time.time())),
                },
                "Event": {
                    "id": "42",
                    "threat_level_id": "1",
                    "info": "Lab campaign",
                    "Orgc": {"name": "Rdegon-SOC"},
                },
            }
        )

        self.assertEqual("misp-42-attribute-7", normalized["event.id"])
        self.assertEqual("203.0.113.50", normalized["threat.indicator.value"])
        self.assertEqual("ip-dst", normalized["threat.indicator.type"])
        self.assertEqual("Rdegon-SOC", normalized["threat.feed.name"])
        self.assertEqual("high", normalized["event.severity"])
        self.assertEqual("true", normalized["threat.indicator.active"])
        self.assertIn("ioc:active", normalized["tags"])

    def test_misp_context_only_attribute_cannot_enter_active_enrichment(self) -> None:
        normalized = self._normalize(
            {
                "source_type": "misp",
                "source": "soc-ti-01",
                "Attribute": {
                    "id": "8",
                    "type": "domain",
                    "value": "context.example",
                    "to_ids": False,
                },
                "Event": {"id": "42", "threat_level_id": "1"},
            }
        )

        self.assertEqual("false", normalized["threat.indicator.active"])
        self.assertEqual("info", normalized["event.severity"])
        self.assertIn("ioc:context-only", normalized["tags"])

    def test_misp_stale_to_ids_attribute_is_context_only(self) -> None:
        normalized = self._normalize(
            {
                "source_type": "misp",
                "Attribute": {
                    "id": "9",
                    "type": "ip-dst",
                    "value": "203.0.113.99",
                    "to_ids": True,
                    "timestamp": "1451606400",
                },
                "Event": {"id": "42", "threat_level_id": "1"},
            }
        )

        self.assertEqual("false", normalized["threat.indicator.active"])
        self.assertIn("ioc:context-only", normalized["tags"])

    def test_step_ca_issue_maps_pki_audit_fields(self) -> None:
        normalized = self._normalize(
            {
                "source_type": "step-ca",
                "source": "soc-pki-01",
                "method": "POST",
                "path": "/1.0/sign",
                "status": 201,
                "remote-address": "10.20.10.133:42210",
                "request-id": "pki-request-1",
            }
        )

        self.assertEqual("step-ca", normalized["event.provider"])
        self.assertEqual("certificate_issued", normalized["event.type"])
        self.assertEqual("certificate_issued", normalized["event.action"])
        self.assertEqual("10.20.10.133", normalized["source.ip"])
        self.assertEqual("success", normalized["event.outcome"])

    def test_minio_put_object_maps_evidence_uri(self) -> None:
        normalized = self._normalize(
            {
                "source_type": "minio",
                "source": "soc-evidence-01",
                "requestID": "minio-request-1",
                "remotehost": "10.20.10.128",
                "api": {
                    "name": "PutObject",
                    "bucket": "soc-evidence",
                    "object": "cases/42/evidence.json",
                    "statusCode": 200,
                },
            }
        )

        self.assertEqual("minio", normalized["event.provider"])
        self.assertEqual("object_storage_access", normalized["event.type"])
        self.assertEqual("PutObject", normalized["event.action"])
        self.assertEqual("s3://soc-evidence/cases/42/evidence.json", normalized["evidence.uri"])
        self.assertEqual("success", normalized["event.outcome"])

    def test_arkime_metrics_map_ndr_health(self) -> None:
        normalized = self._normalize(
            {
                "source_type": "arkime",
                "source": "soc-ndr-01",
                "event.outcome": "success",
                "event.severity": "info",
                "service.state": "active",
                "arkime.sessions": 42,
                "arkime.pcap.files": 3,
                "arkime.pcap.bytes": 8192,
                "opensearch.status": "green",
            }
        )

        self.assertEqual("arkime", normalized["event.provider"])
        self.assertEqual("ndr_capture_health", normalized["event.type"])
        self.assertEqual("42", normalized["network.sessions"])
        self.assertEqual("green", normalized["cluster.health"])

    def test_malware_result_maps_hash_rule_and_evidence(self) -> None:
        normalized = self._normalize(
            {
                "source_type": "yara",
                "source": "soc-analysis-01",
                "file_name": "sample.bin",
                "sha256": "a" * 64,
                "rule": "Suspicious_PowerShell_Dropper",
                "verdict": "malicious",
                "evidence_id": "ev-20260726-001",
                "evidence_uri": "s3://soc-evidence/ev-20260726-001",
            }
        )

        self.assertEqual("a" * 64, normalized["file.sha256"])
        self.assertEqual("Suspicious_PowerShell_Dropper", normalized["rule.name"])
        self.assertEqual("ev-20260726-001", normalized["evidence.id"])
        self.assertEqual("failure", normalized["event.outcome"])

    def test_writer_retains_security_analytics_structures(self) -> None:
        normalized = self._normalize(
            {
                "source_type": "falco",
                "source": "gamepanel-01",
                "rule": "Terminal shell in container",
                "priority": "Critical",
                "output_fields": json.dumps(
                    {
                        "proc.name": "bash",
                        "container.id": "abcdef123456",
                    }
                ),
            }
        )
        transport_fields = {key: _transport_field_value(value) for key, value in normalized.items()}
        payload = json.loads(WriterWorker(WriterSettings())._build_normalized_json(transport_fields))

        self.assertEqual("falco", payload["provider"])
        self.assertEqual("falco.runtime", payload["event"]["dataset"])
        self.assertEqual("abcdef123456", payload["container"]["id"])
        self.assertEqual("Terminal shell in container", payload["rule"]["name"])

    def test_writer_prefers_source_event_id_over_transport_offset(self) -> None:
        worker = WriterWorker(WriterSettings())
        worker._match_cmdb_asset = lambda fields: None
        worker._match_threat_intel = lambda fields: ([], [])
        worker._match_active_lists = lambda fields: ([], [])

        row = worker._build_row(
            "siem.filtered:0:42",
            {
                "event.id": "sensor-event-123",
                "event.provider": "zeek",
                "event.category": "network",
                "event.type": "zeek_conn",
                "event.original": "canary",
            },
        )

        self.assertEqual("sensor-event-123", row[1])


if __name__ == "__main__":
    unittest.main()
