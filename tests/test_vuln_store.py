import unittest
from unittest.mock import patch

import vuln_store


class _QueryResult:
    def __init__(self, rows):
        self._rows = rows

    def named_results(self):
        return list(self._rows)


class _DepsStub:
    def __init__(self):
        self.captured_query = ""

    @staticmethod
    def ensure_cmdb_ti_support():
        return True

    def _sql_quote(self, value):
        escaped = str(value or "").replace("'", "''")
        return f"'{escaped}'"

    def get_ch_client(self):
        outer = self

        class _Client:
            def query(self, query):
                outer.captured_query = query
                return _QueryResult(
                    [
                        {
                            "finding_id": "finding-1",
                            "scan_run_id": "run-1",
                            "external_report_id": "report-1",
                            "asset_id": "asset-1",
                            "target": "host-1",
                            "hostname": "host-1",
                            "ip": "192.168.1.20",
                            "port": 443,
                            "protocol": "tcp",
                            "service": "https",
                            "package_name": "openssl",
                            "installed_version": "1.0",
                            "fixed_version": "1.1",
                            "cve": "CVE-2026-0001",
                            "cvss_score": 9.8,
                            "severity_vendor": "High",
                            "severity_normalized": "critical",
                            "qod": 95.0,
                            "solution": "upgrade",
                            "scanner_plugin_id": "oid-1",
                            "title": "critical finding",
                            "description": "desc",
                            "evidence": "evidence",
                            "status": "open",
                            "delta_state": "new",
                            "first_seen": "2026-03-28 03:00:00",
                            "last_seen": "2026-03-28 03:10:00",
                            "task_id": "task-1",
                            "target_id": "target-1",
                            "artifact_path": "/tmp/report.xml",
                            "report_url": "https://scanner/report/1",
                            "latest_updated_ts": "2026-03-28 03:10:00",
                        }
                    ]
                )

        return _Client()

    @staticmethod
    def _fmt(value):
        return str(value or "")


class VulnStoreTests(unittest.TestCase):
    def test_load_previous_latest_findings_uses_distinct_latest_updated_alias(self) -> None:
        deps = _DepsStub()
        with patch("vuln_store._deps", return_value=deps):
            with patch("vuln_store.ensure_vulnerability_support", return_value=True):
                rows = vuln_store._load_previous_latest_findings(
                    asset_id="asset-1",
                    task_id="task-1",
                    target_id="target-1",
                    target="host-1",
                )

        self.assertIn("max(updated_ts) AS latest_updated_ts", deps.captured_query)
        self.assertNotIn("max(updated_ts) AS updated_ts", deps.captured_query)
        self.assertEqual("2026-03-28 03:10:00", rows["finding-1"]["updated_ts"])

    def test_fetch_vulnerability_reports_prefers_openvas_before_nmap(self) -> None:
        class _ReportQueryResult:
            def __init__(self, rows):
                self._rows = rows

            def named_results(self):
                return list(self._rows)

        class _ReportDepsStub(_DepsStub):
            def get_ch_client(self):
                outer = self

                class _Client:
                    def query(self, query):
                        outer.captured_query = query
                        return _ReportQueryResult(
                            [
                                {
                                    "scan_run_id": "nmap-20260328-071050",
                                    "external_report_id": "",
                                    "started_at": "2026-03-28 07:10:40",
                                    "finished_at": "2026-03-28 07:10:50",
                                    "scanner_family": "nmap",
                                    "finding_count": 12,
                                    "asset_count": 4,
                                    "unique_port_count": 6,
                                    "notable_findings": 2,
                                    "summary_message": "Nmap secondary scan",
                                    "scanner_source": "vuln.nmap",
                                    "artifact_path": "/tmp/nmap.xml",
                                    "greenbone_report_url": "",
                                    "new_count": 0,
                                    "fixed_count": 0,
                                    "reopened_count": 0,
                                    "targets_csv": "192.168.1.120",
                                    "ports_csv": "80,443",
                                    "cves_csv": "",
                                    "status": "completed",
                                },
                                {
                                    "scan_run_id": "greenbone-20260328-064255",
                                    "external_report_id": "8f0d",
                                    "started_at": "2026-03-28 06:30:00",
                                    "finished_at": "2026-03-28 06:42:55",
                                    "scanner_family": "greenbone",
                                    "finding_count": 37,
                                    "asset_count": 12,
                                    "unique_port_count": 9,
                                    "notable_findings": 8,
                                    "summary_message": "Greenbone fleet import",
                                    "scanner_source": "greenbone",
                                    "artifact_path": "/tmp/greenbone.xml",
                                    "greenbone_report_url": "http://scanner/report/8f0d",
                                    "new_count": 5,
                                    "fixed_count": 1,
                                    "reopened_count": 0,
                                    "targets_csv": "192.168.1.120,10.20.30.126",
                                    "ports_csv": "80,443,9392",
                                    "cves_csv": "CVE-2026-0001",
                                    "status": "completed",
                                },
                            ]
                        )

                return _Client()

        deps = _ReportDepsStub()
        with patch("vuln_store._deps", return_value=deps):
            with patch("vuln_store.ensure_vulnerability_support", return_value=True):
                rows = vuln_store.fetch_vulnerability_reports(limit=20, days=14)

        self.assertIn("scanner_family", deps.captured_query)
        self.assertEqual("greenbone-20260328-064255", rows[0]["report_id"])
        self.assertEqual("nmap-20260328-071050", rows[1]["report_id"])

    def test_has_structured_vulnerability_data_uses_scan_runs_and_findings(self) -> None:
        class _StructuredQueryResult:
            def __init__(self, rows):
                self._rows = rows

            def named_results(self):
                return list(self._rows)

        class _StructuredDepsStub(_DepsStub):
            def get_ch_client(self):
                outer = self

                class _Client:
                    def query(self, query):
                        outer.captured_query = query
                        return _StructuredQueryResult([{"scan_run_total": 0, "finding_total": 3}])

                return _Client()

        deps = _StructuredDepsStub()
        with patch("vuln_store._deps", return_value=deps):
            with patch("vuln_store.ensure_vulnerability_support", return_value=True):
                status = vuln_store.has_structured_vulnerability_data(days=7)

        self.assertTrue(status)
        self.assertIn("scan_run_total", deps.captured_query)
        self.assertIn("finding_total", deps.captured_query)

    def test_latest_findings_subquery_uses_wrapped_aggregate_aliases(self) -> None:
        with patch("vuln_store.ensure_vulnerability_support", return_value=True):
            sql = vuln_store._vuln_latest_findings_subquery(14)

        self.assertIn("agg_last_seen AS last_seen", sql)
        self.assertIn("agg_updated_ts AS updated_ts", sql)
        self.assertIn("FROM\n        (\n", sql)


if __name__ == "__main__":
    unittest.main()
