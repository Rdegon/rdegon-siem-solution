from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


REPO_ROOT = Path(__file__).resolve().parents[1]
MINIMAL_WEB_ENV = {
    "SIEM_CH_HOST": "127.0.0.1",
    "SIEM_CH_USER": "default",
    "SIEM_CH_PASSWORD": "secret",
    "SIEM_ADMIN_DEFAULT_PASSWORD": "secret",
    "SIEM_JWT_SECRET": "secret",
}


def _load_script(path: Path, module_name: str):
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load script: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class DeployVulnerabilityScriptsTests(unittest.TestCase):
    def test_greenbone_feed_sync_defers_during_active_scans(self) -> None:
        script = (REPO_ROOT / "deploy" / "vuln" / "rdegon_greenbone_feed_sync.sh").read_text(encoding="utf-8")
        service = (
            REPO_ROOT / "deploy" / "vuln" / "systemd" / "rdegon-greenbone-feed-sync.service"
        ).read_text(encoding="utf-8")
        timer = (
            REPO_ROOT / "deploy" / "vuln" / "systemd" / "rdegon-greenbone-feed-sync.timer"
        ).read_text(encoding="utf-8")

        self.assertIn("[o]penvas --scan-start", script)
        self.assertIn("greenbone-feed-sync", script)
        self.assertIn("--user gvm", script)
        self.assertIn("CPUQuota=200%", service)
        self.assertIn("Persistent=true", timer)

    def test_greenbone_sync_script_imports_and_runs(self) -> None:
        with patch.dict(os.environ, MINIMAL_WEB_ENV, clear=False):
            module = _load_script(REPO_ROOT / "deploy" / "vuln" / "rdegon_greenbone_sync.py", "test_rdegon_greenbone_sync")
            with tempfile.TemporaryDirectory() as temp_dir:
                state_path = Path(temp_dir) / "greenbone-state.json"
                with patch.object(module, "greenbone_is_configured", return_value=True):
                    with patch.object(module, "probe_greenbone", return_value={"status": "ok", "authenticated": True}):
                        with patch.object(module, "sync_vulnerability_targets", return_value={"status": "ok", "synced": 3}):
                            with patch.object(module, "import_greenbone_reports", return_value={"status": "ok", "imported": 2}):
                                with patch.object(module, "write_vulnerability_runtime_state") as write_state:
                                    result = module.run_greenbone_cycle(
                                        sync_limit=50,
                                        import_limit=10,
                                        skip_target_sync=False,
                                        skip_report_import=False,
                                        probe_only=False,
                                        state_path=state_path,
                                    )

        self.assertEqual("ok", result["status"])
        self.assertEqual("ok", result["probe"]["status"])
        self.assertEqual(3, result["target_sync"]["synced"])
        self.assertEqual(2, result["report_import"]["imported"])
        write_state.assert_called_once()

    def test_vuln_policy_apply_script_imports_and_runs(self) -> None:
        with patch.dict(os.environ, MINIMAL_WEB_ENV, clear=False):
            module = _load_script(REPO_ROOT / "deploy" / "vuln" / "rdegon_vuln_policy_apply.py", "test_rdegon_vuln_policy_apply")
            with tempfile.TemporaryDirectory() as temp_dir:
                state_path = Path(temp_dir) / "vuln-policy-state.json"
                with patch.object(
                    module,
                    "apply_vulnerability_incident_policies",
                    return_value={"created": 1, "skipped": 0, "created_cases": [{"case_id": "case-1"}]},
                ):
                    with patch.object(module, "write_vulnerability_runtime_state") as write_state:
                        result = module.run_policy_cycle(days=30, limit=25, actor="tester", state_path=state_path)

        self.assertEqual("ok", result["status"])
        self.assertEqual(1, result["apply"]["created"])
        write_state.assert_called_once()


if __name__ == "__main__":
    unittest.main()
