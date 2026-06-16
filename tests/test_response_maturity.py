import unittest
import importlib
import sys
import types
from unittest.mock import patch

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MODULE_DIR = str(ROOT)


if MODULE_DIR not in sys.path:
    sys.path.insert(0, MODULE_DIR)

if "app" not in sys.modules:
    app_module = types.ModuleType("app")
    app_module.__path__ = [MODULE_DIR]  # type: ignore[attr-defined]
    app_module.__file__ = str(ROOT / "__init__.py")
    sys.modules["app"] = app_module

response_ops = importlib.import_module("app.control_plane_response_ops")


class ResponseMaturityTests(unittest.TestCase):
    def test_response_analytics_reports_governance_coverage_fields(self) -> None:
        actions = [
            {
                "id": "a1",
                "kind": "webhook",
                "owners": ["soc-lead"],
                "evidence_contract": ["incident"],
                "rollback_contract": ["ticket-rollback"],
                "compliance_controls": ["SOC2-CC7"],
                "preconditions": ["ticket_open"],
                "integration_targets": ["jira"],
            },
            {
                "id": "a2",
                "kind": "account_disable",
                "owners": ["iam-admin"],
                "evidence_contract": ["identity"],
                "rollback_contract": ["account-enable"],
                "compliance_controls": ["NIST-IR.4"],
                "preconditions": [],
                "integration_targets": [],
            },
        ]
        with patch.object(response_ops, "list_response_actions", return_value=actions):
            with patch.object(response_ops, "list_response_executions", return_value=[]):
                with patch.object(response_ops, "list_response_dlq", return_value=[]):
                    with patch.object(response_ops, "list_response_ledger", return_value=[]):
                        analytics = response_ops.get_response_analytics(limit=20)

        self.assertEqual(100.0, analytics["metrics"]["owner_coverage_pct"])
        self.assertEqual(100.0, analytics["metrics"]["evidence_contract_pct"])
        self.assertEqual(100.0, analytics["metrics"]["rollback_ready_pct"])
        self.assertEqual(100.0, analytics["metrics"]["compliance_coverage_pct"])
        self.assertEqual(50.0, analytics["metrics"]["precondition_coverage_pct"])
        self.assertEqual(50.0, analytics["metrics"]["integration_target_pct"])
        self.assertEqual(2, analytics["metrics"]["governed_actions"])

    def test_response_analytics_counts_partial_failures_and_latency(self) -> None:
        with patch.object(response_ops, "list_response_actions", return_value=[{"id": "a1", "kind": "webhook"}]):
            with patch.object(
                response_ops,
                "list_response_executions",
                return_value=[
                    {"status": "executed", "details": {"latency_ms": 100}},
                    {"status": "partial_failure", "details": {"latency_ms": 250, "steps": [{"status": "failed"}]}},
                ],
            ):
                with patch.object(response_ops, "list_response_dlq", return_value=[{"id": "dlq1"}]):
                    analytics = response_ops.get_response_analytics(limit=50)

        self.assertEqual(1, analytics["metrics"]["partial_failures"])
        self.assertEqual(1, analytics["metrics"]["dlq_total"])
        self.assertGreaterEqual(analytics["metrics"]["p95_latency_ms"], 100.0)

    def test_response_analytics_ignores_smoke_actions_for_governance_gates(self) -> None:
        actions = [
            {
                "id": "telegram-primary",
                "kind": "telegram",
                "owners": ["soc-lead"],
                "evidence_contract": ["incident"],
                "rollback_contract": ["notify-correction"],
                "compliance_controls": ["SOC2-CC7"],
                "preconditions": ["incident-context-present"],
                "integration_targets": ["telegram"],
            },
            {
                "id": "smoke-approval-gate-1",
                "title": "Smoke approval gate 1",
                "kind": "approval_gate",
                "owners": [],
                "evidence_contract": [],
                "rollback_contract": [],
                "compliance_controls": [],
                "preconditions": [],
                "integration_targets": [],
            },
        ]
        with patch.object(response_ops, "list_response_actions", return_value=actions):
            with patch.object(response_ops, "list_response_executions", return_value=[]):
                with patch.object(response_ops, "list_response_dlq", return_value=[]):
                    with patch.object(response_ops, "list_response_ledger", return_value=[]):
                        analytics = response_ops.get_response_analytics(limit=20)

        self.assertEqual(1, analytics["metrics"]["actions_total"])
        self.assertEqual(2, analytics["metrics"]["catalog_actions_total"])
        self.assertEqual(1, analytics["metrics"]["ignored_nonprod_actions"])
        self.assertEqual(100.0, analytics["metrics"]["owner_coverage_pct"])
        self.assertEqual(1, analytics["metrics"]["governed_actions"])

    def test_runtime_doc_executor_supports_dry_run(self) -> None:
        result = response_ops._run_response_executor(  # noqa: SLF001
            {"kind": "runtime_doc", "target": {"name": "ops.md"}},
            {"content": "hello"},
            dry_run=True,
        )

        self.assertEqual("dry_run", result["status"])
        self.assertEqual("runtime_doc", result["details"]["executor"])

    def test_case_comment_executor_supports_dry_run(self) -> None:
        result = response_ops._run_response_executor(  # noqa: SLF001
            {"kind": "case_comment", "target": {"case_id": "case-1"}},
            {"body": "note"},
            dry_run=True,
        )

        self.assertEqual("dry_run", result["status"])
        self.assertEqual("case-1", result["details"]["case_id"])

    def test_vuln_sync_executor_supports_dry_run(self) -> None:
        result = response_ops._run_response_executor(  # noqa: SLF001
            {
                "kind": "vuln_sync",
                "target": {
                    "limit": 10,
                    "assets": [
                        {"asset_id": "siem-vm1", "hostname": "siem-ingest", "ip": "192.168.1.35", "vuln_enabled": True},
                        {"asset_id": "siem-vm2", "hostname": "siem-processing", "ip": "192.168.1.37", "vuln_enabled": True},
                    ],
                },
            },
            {},
            dry_run=True,
        )

        self.assertEqual("dry_run", result["status"])
        self.assertEqual("vuln_sync", result["details"]["executor"])
        self.assertEqual(2, result["details"]["asset_seed_total"])

    def test_vuln_import_and_policy_executors_support_dry_run(self) -> None:
        import_result = response_ops._run_response_executor(  # noqa: SLF001
            {"kind": "vuln_import", "target": {"limit": 25}},
            {},
            dry_run=True,
        )
        policy_result = response_ops._run_response_executor(  # noqa: SLF001
            {"kind": "vuln_policy_apply", "target": {"days": 30, "limit": 40}},
            {},
            dry_run=True,
        )

        self.assertEqual("dry_run", import_result["status"])
        self.assertEqual("vuln_import", import_result["details"]["executor"])
        self.assertEqual("dry_run", policy_result["status"])
        self.assertEqual("vuln_policy_apply", policy_result["details"]["executor"])


if __name__ == "__main__":
    unittest.main()
