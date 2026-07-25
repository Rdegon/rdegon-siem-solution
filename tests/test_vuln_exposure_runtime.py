from __future__ import annotations

from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from services.web.app import vuln_exposure_runtime as exposure
from services.web.app import vuln_store


class _QueryModule:
    def __init__(self, findings):
        self.findings = findings

    def fetch_vulnerability_findings(self, **_kwargs):
        return {"items": list(self.findings)}


class _CaseOps:
    def __init__(self, cases=None):
        self.cases = list(cases or [])
        self.tasks = []
        self.comments = []
        self.signals = []

    def list_cases(self, **_kwargs):
        return list(self.cases)

    def save_case(self, payload, *, actor):
        item = {**payload, "id": f"case-{len(self.cases) + 1}", "created_by": actor}
        self.cases.append(item)
        return item

    def append_case_task(self, case_id, **kwargs):
        self.tasks.append({"case_id": case_id, **kwargs})
        return {}

    def append_case_comment(self, case_id, **kwargs):
        self.comments.append({"case_id": case_id, **kwargs})
        return {}

    def record_risk_signal(self, payload, *, actor):
        self.signals.append({**payload, "actor": actor})
        return {}


def _finding(**updates):
    payload = {
        "report_id": "report-1",
        "external_report_id": "external-1",
        "host_name": "pilot-web-01",
        "dst_ip": "10.20.50.123",
        "service": "openssl",
        "package_name": "openssl",
        "fixed_version": "3.0.14",
        "severity": "high",
        "status": "open",
        "cvss_score": 9.8,
        "qod": 95,
        "cves": ["CVE-2021-44228"],
        "ts": "2026-07-26T00:00:00Z",
        "solution": "Update the package.",
        "title": "Test exposure",
    }
    payload.update(updates)
    return payload


class VulnerabilityExposureRuntimeTests(unittest.TestCase):
    def test_intelligence_sync_normalizes_kev_and_epss(self) -> None:
        def fetcher(url: str):
            if "first.org" in url:
                return {
                    "data": [
                        {
                            "cve": "CVE-2021-44228",
                            "epss": "0.975",
                            "percentile": "0.999",
                            "date": "2026-07-26",
                        }
                    ]
                }
            return {
                "vulnerabilities": [
                    {
                        "cveID": "CVE-2021-44228",
                        "vendorProject": "Apache",
                        "product": "Log4j",
                        "vulnerabilityName": "Remote code execution",
                        "dateAdded": "2021-12-10",
                        "dueDate": "2021-12-24",
                        "requiredAction": "Apply vendor updates.",
                    }
                ]
            }

        with tempfile.TemporaryDirectory() as temp_dir:
            cache = Path(temp_dir) / "intel.json"
            result = exposure.sync_vulnerability_intelligence(
                cves=["cve-2021-44228", "invalid"],
                fetcher=fetcher,
                cache_path=cache,
            )
            stored = exposure.load_vulnerability_intelligence(cache)

        self.assertEqual("ok", result["status"])
        self.assertEqual(1, result["kev_records"])
        self.assertEqual(1, result["epss_updated"])
        self.assertAlmostEqual(0.975, stored["epss"]["CVE-2021-44228"]["epss"])

    def test_score_prioritizes_kev_epss_and_asset_context(self) -> None:
        result = exposure.calculate_exposure_score(
            _finding(),
            epss=0.8,
            kev=True,
            asset={"criticality": "critical", "tags": ["public_services"]},
        )
        self.assertGreaterEqual(result["score"], 95.0)
        self.assertEqual("urgent", result["band"])
        self.assertEqual(24, result["sla_hours"])
        self.assertIn("CISA KEV", result["reasons"])

    def test_workbench_quarantines_stale_scanner_targets(self) -> None:
        query = _QueryModule([_finding(dst_ip="192.168.1.123")])
        case_ops = _CaseOps()
        intel = {
            "updated_ts": "2026-07-26T00:00:00Z",
            "kev": {"CVE-2021-44228": {"cve": "CVE-2021-44228"}},
            "epss": {"CVE-2021-44228": {"epss": 0.9, "percentile": 0.99}},
            "sources": {},
            "errors": [],
        }
        assets = [
            {
                "asset_id": "asset-pilot-web-01",
                "hostname": "pilot-web-01",
                "ip": "10.20.50.123",
                "owner": "platform",
                "criticality": "high",
                "tags": ["public_services"],
            }
        ]
        with patch.object(exposure, "_query_module", return_value=query), patch.object(
            exposure, "_case_ops_module", return_value=case_ops
        ), patch.object(exposure, "fetch_cmdb_assets", return_value=assets), patch.object(
            exposure, "load_vulnerability_intelligence", return_value=intel
        ):
            result = exposure.build_exposure_workbench(days=30, limit=100)

        self.assertEqual(1, result["summary"]["stale_targets"])
        self.assertEqual(0, result["summary"]["actionable"])
        self.assertTrue(result["items"][0]["stale_target"])

    def test_policy_creates_case_task_and_signal_once(self) -> None:
        case_ops = _CaseOps()
        workbench = {
            "summary": {"actionable": 1},
            "items": [
                {
                    "finding_key": "finding-1",
                    "priority_score": 91.0,
                    "priority_band": "urgent",
                    "kev": True,
                    "epss": 0.8,
                    "stale_target": False,
                    "case_id": "",
                    "asset_id": "asset-pilot-web-01",
                    "asset_hostname": "pilot-web-01",
                    "asset_owner": "platform",
                    "cves": ["CVE-2021-44228"],
                    "report_id": "report-1",
                    "due_ts": "2026-07-27T00:00:00Z",
                    "remediation": {"action": "Update openssl"},
                }
            ],
        }
        with patch.object(exposure, "build_exposure_workbench", return_value=workbench), patch.object(
            exposure, "_case_ops_module", return_value=case_ops
        ):
            result = exposure.apply_exposure_management_policies(actor="tester", days=30, limit=10)

        self.assertEqual(1, result["created"])
        self.assertEqual(1, len(case_ops.tasks))
        self.assertEqual(1, len(case_ops.comments))
        self.assertEqual(1, len(case_ops.signals))

    def test_policy_does_not_remediate_an_unmapped_finding(self) -> None:
        case_ops = _CaseOps()
        workbench = {
            "summary": {"actionable": 0, "unmapped": 1},
            "items": [
                {
                    "finding_key": "unmapped-1",
                    "priority_score": 100.0,
                    "priority_band": "urgent",
                    "kev": True,
                    "stale_target": False,
                    "asset_id": "",
                    "case_id": "",
                }
            ],
        }
        with patch.object(exposure, "build_exposure_workbench", return_value=workbench), patch.object(
            exposure, "_case_ops_module", return_value=case_ops
        ):
            result = exposure.apply_exposure_management_policies(actor="tester", days=30, limit=10)

        self.assertEqual(0, result["created"])
        self.assertEqual("unmapped_asset", result["skipped_items"][0]["reason"])
        self.assertEqual([], case_ops.cases)

    def test_targeted_scan_rejects_stale_binding(self) -> None:
        assets = [
            {
                "asset_id": "asset-1",
                "hostname": "node-1",
                "ip": "10.20.50.10",
                "enabled": True,
                "vuln_enabled": True,
            }
        ]
        bindings = [
            {
                "asset_id": "asset-1",
                "target_ref": "192.168.1.10",
                "task_id": "task-1",
                "sync_status": "synced",
            }
        ]
        start_tasks = Mock()
        with patch.object(vuln_store, "fetch_cmdb_assets", return_value=assets), patch.object(
            vuln_store, "_fetch_vuln_asset_bindings", return_value=bindings
        ), patch.dict(
            sys.modules,
            {"services.web.app.vuln_greenbone": SimpleNamespace(start_tasks=start_tasks)},
        ):
            result = vuln_store.start_vulnerability_scans(["asset-1"])

        start_tasks.assert_not_called()
        self.assertEqual("stale_binding", result["rejected"][0]["reason"])


if __name__ == "__main__":
    unittest.main()
