import unittest
from unittest.mock import patch

import vuln_maturity_runtime as runtime


class VulnerabilityMaturityRuntimeTests(unittest.TestCase):
    def test_build_status_computes_asset_coverage_and_candidates(self) -> None:
        with patch(
            "vuln_maturity_runtime.fetch_vulnerability_reports",
            return_value=[{"report_id": "r1", "asset_id": "asset-1"}],
        ):
            with patch(
                "vuln_maturity_runtime.fetch_vulnerability_findings",
                return_value={
                    "items": [
                        {
                            "report_id": "r1",
                            "external_report_id": "ext-r1",
                            "host_name": "srv-auth-01",
                            "dst_ip": "192.168.1.10",
                            "service": "ssh",
                            "severity": "critical",
                            "cvss_score": 9.8,
                            "status": "open",
                            "delta_state": "new",
                            "cves": ["CVE-2026-1234"],
                        }
                    ]
                },
            ):
                with patch("vuln_maturity_runtime.fetch_vulnerability_inventory", return_value={"summary": {"findings": 1}}):
                    with patch(
                        "vuln_maturity_runtime.fetch_cmdb_assets",
                        return_value=[{"asset_id": "asset-1", "hostname": "srv-auth-01", "ip": "192.168.1.10"}],
                    ):
                        with patch("vuln_maturity_runtime.build_vulnerability_runtime_status", return_value={"healthy": True}):
                            with patch("vuln_maturity_runtime.list_cases", return_value=[]):
                                payload = runtime.build_vulnerability_maturity_status(days=14, limit=50)

        self.assertEqual(1.0, payload["asset_binding_coverage"])
        self.assertEqual(1, payload["critical_candidates_total"])
        self.assertTrue(payload["ready_for_incident_policies"])

    def test_build_status_reports_ready_without_current_critical_candidates(self) -> None:
        with patch("vuln_maturity_runtime.fetch_vulnerability_reports", return_value=[]):
            with patch("vuln_maturity_runtime.fetch_vulnerability_findings", return_value={"items": []}):
                with patch("vuln_maturity_runtime.fetch_vulnerability_inventory", return_value={"summary": {"findings": 0}}):
                    with patch("vuln_maturity_runtime.fetch_cmdb_assets", return_value=[]):
                        with patch("vuln_maturity_runtime.build_vulnerability_runtime_status", return_value={"healthy": True}):
                            with patch("vuln_maturity_runtime.list_cases", return_value=[]):
                                payload = runtime.build_vulnerability_maturity_status(days=14, limit=50)

        self.assertEqual(0, payload["critical_candidates_total"])
        self.assertTrue(payload["ready_for_incident_policies"])

    def test_build_status_counts_report_binding_from_matched_findings(self) -> None:
        with patch("vuln_maturity_runtime.fetch_vulnerability_reports", return_value=[{"report_id": "r1"}]):
            with patch(
                "vuln_maturity_runtime.fetch_vulnerability_findings",
                return_value={"items": [{"report_id": "r1", "host_name": "srv-auth-01", "dst_ip": "192.168.1.10", "severity": "medium"}]},
            ):
                with patch("vuln_maturity_runtime.fetch_vulnerability_inventory", return_value={"summary": {"findings": 1}}):
                    with patch("vuln_maturity_runtime.fetch_cmdb_assets", return_value=[{"asset_id": "asset-1", "hostname": "srv-auth-01", "ip": "192.168.1.10"}]):
                        with patch("vuln_maturity_runtime.build_vulnerability_runtime_status", return_value={"healthy": True}):
                            with patch("vuln_maturity_runtime.list_cases", return_value=[]):
                                payload = runtime.build_vulnerability_maturity_status(days=14, limit=50)

        self.assertEqual(1, payload["reports_with_asset_binding"])
        self.assertEqual(1, payload["findings_with_asset_binding"])

    def test_build_status_uses_source_inventory_aliases_for_binding(self) -> None:
        with patch("vuln_maturity_runtime.fetch_vulnerability_reports", return_value=[{"report_id": "r1"}]):
            with patch(
                "vuln_maturity_runtime.fetch_vulnerability_findings",
                return_value={"items": [{"report_id": "r1", "host_name": "siem-storage.internal.lab", "severity": "critical"}]},
            ):
                with patch("vuln_maturity_runtime.fetch_vulnerability_inventory", return_value={"summary": {"findings": 1}}):
                    with patch("vuln_maturity_runtime.fetch_cmdb_assets", return_value=[{"asset_id": "asset-3", "hostname": "vm3-storage", "ip": "192.168.1.38"}]):
                        with patch(
                            "vuln_maturity_runtime.fetch_source_inventory",
                            return_value=[{"source_name": "siem-storage.internal.lab", "cmdb_asset_id": "asset-3", "aliases": ["siem-storage"]}],
                        ):
                            with patch("vuln_maturity_runtime.build_vulnerability_runtime_status", return_value={"healthy": True}):
                                with patch("vuln_maturity_runtime.list_cases", return_value=[]):
                                    payload = runtime.build_vulnerability_maturity_status(days=14, limit=50)

        self.assertEqual(1, payload["findings_with_asset_binding"])
        self.assertEqual(0, payload["unmapped_targets_total"])
        self.assertGreater(payload["asset_binding_avg_confidence"], 0.7)
        self.assertTrue(payload["asset_binding_breakdown"])

    def test_apply_policies_creates_case_and_signal_for_new_candidate(self) -> None:
        candidate = {
            "finding_key": "r1|192.168.1.10|srv-auth-01|ssh|CVE-2026-1234",
            "report_id": "r1",
            "external_report_id": "ext-r1",
            "target": "srv-auth-01",
            "service": "ssh",
            "severity": "critical",
            "cvss_score": 9.8,
            "cves": ["CVE-2026-1234"],
            "asset_id": "asset-1",
        }
        with patch("vuln_maturity_runtime.build_vulnerability_maturity_status", return_value={"critical_candidates": [candidate]}):
            with patch(
                "vuln_maturity_runtime.fetch_vulnerability_findings",
                return_value={
                    "items": [
                        {
                            "report_id": "r1",
                            "external_report_id": "ext-r1",
                            "host_name": "srv-auth-01",
                            "dst_ip": "192.168.1.10",
                            "service": "ssh",
                            "severity": "critical",
                            "cvss_score": 9.8,
                            "status": "open",
                            "delta_state": "new",
                            "cves": ["CVE-2026-1234"],
                            "solution": "Patch OpenSSH",
                        }
                    ]
                },
            ):
                with patch("vuln_maturity_runtime.list_cases", return_value=[]):
                    with patch("vuln_maturity_runtime.save_case", return_value={"id": "case-1", "title": "case"}):
                        with patch("vuln_maturity_runtime.append_case_comment") as append_comment:
                            with patch("vuln_maturity_runtime.record_risk_signal") as record_signal:
                                result = runtime.apply_vulnerability_incident_policies(actor="tester", days=14, limit=10)

        self.assertEqual(1, result["created"])
        self.assertEqual("case-1", result["created_cases"][0]["case_id"])
        append_comment.assert_called_once()
        record_signal.assert_called_once()

    def test_build_status_uses_binding_override_for_unmapped_target(self) -> None:
        with patch("vuln_maturity_runtime.fetch_vulnerability_reports", return_value=[{"report_id": "r1"}]):
            with patch(
                "vuln_maturity_runtime.fetch_vulnerability_findings",
                return_value={"items": [{"report_id": "r1", "host_name": "legacy-target-01", "severity": "high"}]},
            ):
                with patch("vuln_maturity_runtime.fetch_vulnerability_inventory", return_value={"summary": {"findings": 1}}):
                    with patch("vuln_maturity_runtime.fetch_cmdb_assets", return_value=[{"asset_id": "asset-vuln-01", "hostname": "legacy-target-01"}]):
                        with patch("vuln_maturity_runtime.fetch_source_inventory", return_value=[]):
                            with patch(
                                "vuln_maturity_runtime.list_binding_overrides",
                                return_value=[{"id": "bind-1", "target": "asset-vuln-01", "hostname": "legacy-target-01", "scope": "vulnerability", "enabled": True}],
                            ):
                                with patch("vuln_maturity_runtime.build_vulnerability_runtime_status", return_value={"healthy": True}):
                                    with patch("vuln_maturity_runtime.list_cases", return_value=[]):
                                        payload = runtime.build_vulnerability_maturity_status(days=14, limit=50)

        self.assertEqual(1, payload["binding_overrides_total"])
        self.assertEqual(1, payload["binding_overrides_active"])
        self.assertEqual(0, payload["unmapped_targets_total"])
        self.assertEqual(1, payload["findings_with_asset_binding"])


if __name__ == "__main__":
    unittest.main()
