from __future__ import annotations

import importlib
import json
import os
import sys
import types
import unittest
from unittest import mock
from pathlib import Path
from services.filter.filter_core import eval_expr, parse_expr

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

os.environ.setdefault("SIEM_CH_HOST", "127.0.0.1")
os.environ.setdefault("SIEM_CH_USER", "default")
os.environ.setdefault("SIEM_CH_PASSWORD", "test-password")
os.environ.setdefault("SIEM_ADMIN_DEFAULT_PASSWORD", "test-password")
os.environ.setdefault("SIEM_JWT_SECRET", "test-jwt-secret")

builder = importlib.import_module("deploy.build_assignment_detection_pack")
curated_rules = importlib.import_module("deploy.curated_assignment_rules")


def _row(source_id: str, logic: str, sources: str = "auth.log/sudo") -> dict[str, str]:
    return {
        "section": "Unit test",
        "source_id": source_id,
        "title": "Unit test rule",
        "scope": "Unit test scope",
        "sources": sources,
        "logic": logic,
        "severity": "medium",
        "response": "Review event",
    }


class AssignmentDetectionPackTests(unittest.TestCase):
    def test_curated_cmdb_queries_use_clickhouse_final_after_alias(self) -> None:
        for source_id, rule_id in (
            ("HB-001", 8001),
            ("HB-012", 8012),
            ("HB-014", 8014),
        ):
            sql = curated_rules.curated_batch_sql(
                {
                    "id": rule_id,
                    "source_id": source_id,
                    "title": source_id,
                    "severity": "high",
                }
            )
            self.assertNotIn("FINAL AS", sql)
            self.assertIn("AS c FINAL", sql)

    def test_curated_heartbeat_rules_use_timestamps_instead_of_keywords(self) -> None:
        base = {
            "id": 8002,
            "source_id": "HB-002",
            "title": "HB-002 source silence",
            "severity": "high",
        }
        silence_sql = curated_rules.curated_batch_sql(base)
        future_sql = curated_rules.curated_batch_sql(
            {
                **base,
                "id": 8010,
                "source_id": "HB-010",
                "title": "HB-010 future timestamp",
                "legacy_event_offset_cutoffs": {"vpn-host-khanov": 8625000},
            }
        )

        self.assertIn("max(ts) AS last_seen_ts", silence_sql)
        self.assertIn(
            "HAVING max(e.last_seen_ts) < now() - INTERVAL 48 HOUR",
            silence_sql,
        )
        self.assertIn("GROUP BY c.hostname", silence_sql)
        self.assertIn("heartbeat.last_seen_ts AS ts_last", silence_sql)
        self.assertIn("INNER JOIN", silence_sql)
        self.assertNotIn("positionCaseInsensitiveUTF8(toString(tags), 'allowlist:')", silence_sql)
        self.assertIn("positionCaseInsensitiveUTF8(toString(tags), 'synthetic') = 0", silence_sql)
        self.assertNotIn("positionCaseInsensitiveUTF8(toString(message), 'last_seen')", silence_sql)
        self.assertIn("PREWHERE ts > now() + INTERVAL 2 MINUTE", future_sql)
        self.assertIn("lowerUTF8(if(host_name != '' AND host_name != '-', host_name, log_source)) = 'vpn-host-khanov'", future_sql)
        self.assertIn("toUInt64OrZero(extract(event_id, '([0-9]+)$')) <= 8625000", future_sql)
        self.assertNotIn("positionCaseInsensitiveUTF8(toString(message), 'event_ts')", future_sql)

    def test_pack_builder_passes_legacy_future_event_cutoff_to_curated_rule(self) -> None:
        rows = [
            {
                **_row("HB-010", "event_ts > ingest_ts+2m"),
                "_index": "10",
            }
        ]
        pack = builder.build_pack(
            rows,
            active_overrides={
                "HB-010": {
                    "legacy_event_offset_cutoffs": {"vpn-host-khanov": 8625000}
                }
            },
        )

        self.assertIn(
            "toUInt64OrZero(extract(event_id, '([0-9]+)$')) <= 8625000",
            pack["batch_rules"][0]["sql_template"],
        )
        self.assertEqual(
            pack["batch_rules"][0]["legacy_event_offset_cutoffs"],
            {"vpn-host-khanov": 8625000},
        )

    def test_cpu_pressure_rule_requires_sustained_unique_runtime_snapshots(self) -> None:
        sql = curated_rules.curated_batch_sql(
            {
                "id": 8419,
                "source_id": "MET-002",
                "title": "MET-002 CPU > 95% 15m",
                "severity": "high",
            }
        )

        self.assertIn("subcategory = 'host_runtime_snapshot'", sql)
        self.assertIn("countIf(cpu_pct > 95) AS hits", sql)
        self.assertIn("HAVING count() >= 5", sql)
        self.assertIn("hits / count() >= 0.8", sql)
        self.assertIn("avg(cpu_pct) > 90", sql)

    def test_generated_correlation_sql_qualifies_child_alert_columns(self) -> None:
        row = _row("CORR-999", "AUTH-001 then AUTH-002")
        row["_index"] = "487"

        sql = builder._generic_correlation_sql_template(
            row,
            {"AUTH-001": 8001, "AUTH-002": 8002, "CORR-999": 8487},
        )

        self.assertIn("FROM siem.alerts_raw AS child", sql)
        self.assertIn("groupUniqArray(child.rule_id)", sql)
        self.assertIn("child.rule_id IN (8001, 8002)", sql)
        self.assertNotIn("groupUniqArray(rule_id)", sql)

    def test_curated_stream_correlation_health_rule_has_no_outer_aggregate_aliases(self) -> None:
        sql = curated_rules.curated_batch_sql(
            {
                "id": 8212,
                "source_id": "CORR-S-002",
                "title": "Stream correlation health",
                "severity": "low",
            }
        )

        self.assertIn("subcategory = 'host_runtime_snapshot'", sql)
        self.assertIn("'\"name\":\"siem-stream-corr\"'", sql)
        self.assertIn("unhealthy_snapshots >= 3", sql)
        self.assertNotIn("alerts_24h", sql)
        self.assertIn("WHERE NOT EXISTS", sql)

    def test_curated_asset_discovery_rules_use_supported_single_key_joins(self) -> None:
        rules = {
            source_id: curated_rules.curated_batch_sql(
                {
                    "id": rule_id,
                    "source_id": source_id,
                    "title": source_id,
                    "severity": "high",
                }
            )
            for source_id, rule_id in (
                ("HB-006", 8006),
                ("HB-013", 8013),
                ("HB-014", 8014),
            )
        }

        self.assertIn("known.ip = IPv4NumToString(e.src_ip)", rules["HB-006"])
        self.assertIn("'10.20.0.0/16'", rules["HB-006"])
        self.assertNotIn("'192.168.0.0/16'", rules["HB-006"])
        self.assertIn("known.ip = IPv4NumToString(e.dst_ip)", rules["HB-013"])
        self.assertIn("'192.168.3.0/24'", rules["HB-013"])
        self.assertNotIn("'192.168.0.0/16'", rules["HB-013"])
        self.assertIn("c.ip = IPv4NumToString(e.dst_ip)", rules["HB-014"])
        for sql in rules.values():
            self.assertNotIn(" OR (e.asset_id", sql)
            self.assertNotIn(" OR lowerUTF8(c.hostname)", sql)

    def test_keyword_linux_rule_gets_guarded_stream_expr(self) -> None:
        rows = [_row("AUTH-007", "message contains 'sudo:' AND 'COMMAND='")]

        pack = builder.build_pack(rows, active_source_ids={"AUTH-007"})

        self.assertEqual(1, len(pack["stream_rules"]))
        rule = pack["stream_rules"][0]
        self.assertEqual("active", rule["status"])
        self.assertEqual("stream-expr", rule["source_format"])
        self.assertIn("allowlist:", rule["expr"])
        self.assertIn("event.provider == 'linux.sudo'", rule["expr"])
        self.assertIn("event.type == 'sudo_command'", rule["expr"])
        self.assertNotIn("auth.log/sudo", rule["expr"])

    def test_windows_structured_rule_gets_guarded_stream_expr_without_manual_publish_flag(self) -> None:
        rows = [
            _row(
                "WIN-003",
                "EventID=4624 AND LogonType=10",
                sources="Windows Security Event via agent",
            )
        ]

        pack = builder.build_pack(rows, active_source_ids={"WIN-003"})

        self.assertEqual(1, len(pack["stream_rules"]))
        rule = pack["stream_rules"][0]
        self.assertEqual("active", rule["status"])
        self.assertEqual("stream-expr", rule["source_format"])
        self.assertEqual(["windows"], rule["asset_groups"])
        self.assertIn("event.provider == 'windows.security'", rule["expr"])
        self.assertIn("auth.logon_type == '10'", rule["expr"])
        self.assertIn("RdegonSIEMCollector", rule["expr"])

    def test_windows_structured_rule_can_publish_with_manual_publish_flag(self) -> None:
        rows = [
            _row(
                "WIN-003",
                "EventID=4624 AND LogonType=10",
                sources="Windows Security Event via agent",
            )
        ]

        pack = builder.build_pack(
            rows,
            active_source_ids={"WIN-003"},
            active_overrides={"WIN-003": {"publish_generated_sigma": True}},
        )

        self.assertEqual(1, len(pack["stream_rules"]))
        rule = pack["stream_rules"][0]
        self.assertEqual("active", rule["status"])
        self.assertEqual("sigma", rule["source_format"])
        self.assertIn("event.code: '4624'", rule["sigma_yaml"])
        self.assertIn("auth.logon_type: '10'", rule["sigma_yaml"])
        self.assertNotIn("keywords:", rule["sigma_yaml"])
        self.assertEqual(["windows"], rule["asset_groups"])
        self.assertIn("asset_group.windows", rule["sigma_yaml"])

    def test_publisher_deduplicates_asset_group_tags_from_sigma(self) -> None:
        fake_deps = types.ModuleType("deps")
        fake_deps.convert_sigma_to_stream_rule = lambda *args, **kwargs: {"tags": "asset_group.windows"}
        sys.modules.pop("deploy.publish_assignment_detection_pack", None)

        with mock.patch.dict(sys.modules, {"deps": fake_deps}):
            publisher = importlib.import_module("deploy.publish_assignment_detection_pack")
            published = publisher._publish_stream_rule(
                {
                    "id": 8395,
                    "source_id": "WIN-003",
                    "status": "active",
                    "severity": "medium",
                    "sigma_yaml": "title: Unit test\n",
                    "asset_groups": ["windows"],
                },
                pack_id="unit-test",
            )

        tags = str(published["tags"]).split(",")
        self.assertEqual(1, tags.count("asset_group.windows"))

    def test_explicit_stream_expr_override_publishes_non_windows_rule(self) -> None:
        rows = [_row("AUTH-007", "message contains 'sudo:' AND 'COMMAND='")]

        pack = builder.build_pack(
            rows,
            active_overrides={
                "AUTH-007": {
                    "expr": "event.type == 'sudo_command' and event.original icontains 'COMMAND='",
                    "threshold": 2,
                }
            },
        )

        self.assertEqual(1, len(pack["stream_rules"]))
        rule = pack["stream_rules"][0]
        self.assertEqual("stream-expr", rule["source_format"])
        self.assertEqual("event.type == 'sudo_command' and event.original icontains 'COMMAND='", rule["expr"])
        self.assertEqual(2, rule["threshold"])
        self.assertNotIn("sigma_yaml", rule)

    def test_stream_override_can_use_composite_entity_field(self) -> None:
        rows = [_row("SVC-004", "message contains 'entered failed state'", sources="systemd")]

        pack = builder.build_pack(
            rows,
            active_overrides={
                "SVC-004": {
                    "expr": "event.type == 'linux_systemd_unit_failed'",
                    "entity_field": "host.name+service.name",
                }
            },
        )

        self.assertEqual("host.name+service.name", pack["stream_rules"][0]["entity_field"])

    def test_batch_override_can_extend_dedupe_window_without_widening_detection_window(self) -> None:
        rows = [_row("HB-006", "count > 3 in 5m baseline known_host inventory")]

        pack = builder.build_pack(
            rows,
            active_overrides={"HB-006": {"threshold": 4, "dedupe_window_s": 86400}},
        )

        self.assertEqual(1, len(pack["batch_rules"]))
        rule = pack["batch_rules"][0]
        self.assertEqual(300, rule["window_s"])
        self.assertIn("ts >= now() - INTERVAL {WINDOW_S} SECOND", rule["sql_template"])
        self.assertIn("AND ts >= now() - INTERVAL 86400 SECOND", rule["sql_template"])
        self.assertNotIn("AND ts_last >= now() - INTERVAL 86400 SECOND", rule["sql_template"])

    def test_gateway_staleness_rule_uses_host_runtime_snapshot(self) -> None:
        rows = [_row("GW-010", "source=openclaw-gateway last_seen>10m", sources="SIEM last_seen")]

        pack = builder.build_pack(rows)

        sql = pack["batch_rules"][0]["sql_template"]
        self.assertIn("device_product = 'host.metrics'", sql)
        self.assertIn("subcategory = 'host_runtime_snapshot'", sql)
        self.assertIn("ts_last < now() - INTERVAL {WINDOW_S} SECOND", sql)
        self.assertNotIn("positionCaseInsensitiveUTF8(toString(normalized_json), 'openclaw-gateway')", sql)

    def test_navidrome_mass_transfer_rule_ignores_empty_normalized_bytes(self) -> None:
        rows = [
            _row(
                "NAV-004",
                "download/stream bytes or count > baseline*5",
                sources="Navidrome/nginx logs",
            )
        ]

        pack = builder.build_pack(rows)

        sql = pack["batch_rules"][0]["sql_template"]
        self.assertIn("lowerUTF8(host_name) = 'navidrome-01'", sql)
        self.assertIn("transferred_bytes >= 1073741824 OR hits >= 100", sql)
        self.assertIn("'stream started'", sql)
        self.assertNotIn("positionCaseInsensitiveUTF8(toString(normalized_json), 'bytes')", sql)

    def test_publisher_normalizes_existing_alert_dedupe_and_auth_allowlist(self) -> None:
        fake_deps = types.ModuleType("deps")
        sys.modules.pop("deploy.publish_assignment_detection_pack", None)
        with mock.patch.dict(sys.modules, {"deps": fake_deps}):
            publisher = importlib.import_module("deploy.publish_assignment_detection_pack")
            row = publisher._publish_batch_rule(
                {
                    "id": 8065,
                    "source_id": "AUTH-005",
                    "title": "New SSH source",
                    "severity": "high",
                    "window_s": 3600,
                    "trusted_admin_ips": ["192.168.3.81", "192.168.3.101"],
                    "sql_template": (
                        "SELECT * FROM siem.events WHERE "
                        "if(src_ip = 0, '', IPv4NumToString(src_ip)) NOT IN ('192.168.1.38') "
                        "LEFT JOIN (SELECT entity_key FROM siem.alerts_raw WHERE rule_id = 8065 "
                        "AND ts_last >= now() - INTERVAL 86400 SECOND) AS existing"
                    ),
                }
            )

        sql = str(row[6])
        self.assertIn("'192.168.3.81'", sql)
        self.assertIn("'192.168.3.101'", sql)
        self.assertNotIn("'192.168.1.38'", sql)
        self.assertIn("AND ts >= now() - INTERVAL 86400 SECOND", sql)

    def test_numeric_asset_markers_do_not_match_inside_event_ids(self) -> None:
        rows = [
            _row(
                "WIN-011",
                "EventID=1102",
                sources="Windows Security Event via agent",
            )
        ]

        pack = builder.build_pack(
            rows,
            active_source_ids={"WIN-011"},
            active_overrides={"WIN-011": {"publish_generated_sigma": True}},
        )

        rule = pack["stream_rules"][0]
        self.assertEqual(["windows"], rule["asset_groups"])
        self.assertNotIn("asset_group.edge_gateway", rule["sigma_yaml"])

    def test_asset_groups_are_attached_to_catalog_rules(self) -> None:
        rows = [
            _row("PVE-001", "action in [qmcreate, create VM]", sources="Proxmox task log/syslog/API audit"),
            _row("IAM-001", "Keycloak admin login", sources="Keycloak audit"),
            _row("NC-001", "Nextcloud admin login", sources="Nextcloud app logs"),
            _row("MC-001", "Minecraft server stopped", sources="minecraft logs"),
        ]

        pack = builder.build_pack(rows)

        self.assertIn("asset_groups", pack)
        by_id = {rule["source_id"]: rule for rule in [*pack["stream_rules"], *pack["batch_rules"]]}
        self.assertIn("proxmox", by_id["PVE-001"]["asset_groups"])
        self.assertIn("identity", by_id["IAM-001"]["asset_groups"])
        self.assertIn("public_services", by_id["NC-001"]["asset_groups"])
        self.assertIn("game", by_id["MC-001"]["asset_groups"])

    def test_ids_dns_rules_reject_generic_sensor_syslog_and_accept_structured_signals(self) -> None:
        pack = json.loads((ROOT / "correlation_rule_packs" / "siem_detection_pack_v1.json").read_text(encoding="utf-8"))
        rules = {
            int(item["id"]): item
            for item in pack["stream_rules"]
            if 8101 <= int(item["id"]) <= 8123
        }
        generic_sensor_log = {
            "event.provider": "linux.suricata-eve",
            "event.type": "syslog",
            "event.original": (
                '{"event_type":"dns","flow_id":42,"src_ip":"10.20.30.124",'
                '"dest_ip":"10.20.10.102","dst_port":53,"alert":false,"signature":null}'
            ),
            "host.name": "lab-edge-01",
            "log_source": "lab-edge-01",
            "source.ip": "10.20.30.124",
            "tags": "sensor:syslog",
        }
        for rule_id, rule in rules.items():
            with self.subTest(rule_id=rule_id):
                self.assertFalse(eval_expr(parse_expr(rule["expr"]), generic_sensor_log))

        positives = {
            8101: {
                "event.provider": "host.metrics",
                "event.type": "host_service_down",
                "event.original": "Service stopped on lab-edge-01: rsyslog (failed)",
                "host.name": "lab-edge-01",
            },
            8102: {
                "event.provider": "suricata",
                "event.type": "suricata_alert",
                "suricata.alert.severity": "1",
            },
            8103: {
                "event.provider": "suricata",
                "event.type": "suricata_alert",
                "suricata.alert.severity": "2",
            },
            8104: {
                "event.provider": "suricata",
                "event.type": "suricata_alert",
                "rule.name": "ET EXPLOIT Possible RCE",
            },
            8105: {
                "event.provider": "suricata",
                "event.type": "suricata_alert",
                "rule.name": "ET MALWARE Command and Control",
            },
            8106: {
                "event.provider": "suricata",
                "event.type": "suricata_alert",
                "rule.name": "ET SCAN Nmap Scripting Engine",
            },
            8107: {
                "event.provider": "suricata",
                "event.type": "suricata_alert",
                "destination.port": "22",
                "rule.name": "ET SCAN SSH Brute Force",
            },
            8108: {
                "event.provider": "suricata",
                "event.type": "suricata_alert",
                "destination.port": "3389",
                "rule.name": "ET SCAN RDP Brute Force",
            },
            8109: {
                "event.provider": "suricata",
                "event.type": "suricata_flow",
                "network.direction": "inbound",
                "destination.port": "5432",
            },
            8110: {
                "event.provider": "suricata",
                "event.type": "suricata_flow",
                "network.direction": "outbound",
                "destination.port": "4444",
            },
            8111: {
                "event.provider": "suricata",
                "event.type": "suricata_alert",
                "rule.name": "ET TOR Exit Node Traffic",
            },
            8112: {
                "event.provider": "suricata",
                "event.type": "suricata_alert",
                "rule.name": "ET Mining Stratum Protocol",
            },
            8114: {
                "event.provider": "suricata",
                "event.type": "suricata_alert",
                "network.direction": "internal",
                "rule.name": "ET SCAN Nmap",
            },
            8115: {"event.type": "external_service_exposed"},
            8116: {
                "event.provider": "suricata",
                "event.type": "suricata_alert",
                "rule.name": "ET DNS Tunnel Detected",
            },
            8117: {
                "event.provider": "suricata",
                "event.type": "suricata_dns",
                "dns.response_code": "NXDOMAIN",
            },
            8118: {
                "event.provider": "suricata",
                "event.type": "suricata_dns",
                "tags": "dynamic_dns",
            },
            8119: {
                "event.provider": "zeek",
                "event.type": "zeek_dns",
                "tags": "dns:newly_seen",
            },
            8120: {
                "event.provider": "suricata",
                "event.type": "suricata_dns",
                "tags": "ti:misp",
            },
            8121: {
                "event.provider": "suricata",
                "event.type": "suricata_flow",
                "network.direction": "outbound",
                "source.ip": "10.20.20.100",
                "destination.ip": "8.8.8.8",
                "destination.port": "53",
            },
            8122: {
                "event.provider": "suricata",
                "event.type": "suricata_flow",
                "network.direction": "outbound",
                "destination.port": "853",
            },
            8123: {
                "event.provider": "suricata",
                "event.type": "suricata_dns",
                "dns.response_code": "SERVFAIL",
            },
        }
        self.assertEqual(set(rules), set(positives))
        for rule_id, event in positives.items():
            with self.subTest(rule_id=rule_id):
                self.assertTrue(eval_expr(parse_expr(rules[rule_id]["expr"]), event))


if __name__ == "__main__":
    unittest.main()
