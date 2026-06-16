import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from deploy.distribution_toolkit import build_topology_manifest, build_upgrade_plan, export_distribution_toolkit


class DistributionToolkitTests(unittest.TestCase):
    def test_build_topology_manifest_includes_backend_roles(self) -> None:
        payload = build_topology_manifest(
            env={
                "SIEM_TRANSPORT_BACKEND": "kafka",
                "SIEM_KAFKA_BOOTSTRAP_SERVERS": "vm1:9093,vm2:9093,vm5:9093",
                "SIEM_CONTROL_PLANE_BACKEND": "postgres",
                "SIEM_CONTENT_STORE_BACKEND": "mongo",
                "SIEM_STREAM_STATE_BACKEND": "sqlite",
            }
        )

        self.assertEqual("kafka", payload["transport_backend"])
        self.assertEqual("postgres", payload["control_plane_backend"])
        self.assertEqual("mongo", payload["content_store_backend"])
        self.assertEqual("sqlite", payload["stream_state_backend"])
        self.assertEqual(5, len(payload["hosts"]))

    def test_build_upgrade_plan_contains_release_steps(self) -> None:
        plan = build_upgrade_plan(target_version="2026.03.25")

        self.assertEqual("2026.03.25", plan["target_version"])
        self.assertEqual("backup", plan["ordered_steps"][0]["id"])
        self.assertEqual("post_checks", plan["ordered_steps"][-1]["id"])

    def test_export_distribution_toolkit_writes_topology_and_launchers(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            project_root = root / "repo"
            project_root.mkdir()
            (project_root / "main.py").write_text("print('ok')\n", encoding="utf-8")
            (project_root / "deploy").mkdir()
            (project_root / "docs").mkdir()
            (project_root / "docs" / "README.md").write_text("# Docs\n", encoding="utf-8")
            (project_root / "tools").mkdir()
            (project_root / "tools" / "siem_operator_cli.py").write_text("print('cli')\n", encoding="utf-8")
            target_root = root / "bundle"

            fake_bundle = {
                "target_root": str(target_root),
                "binary": {"built": True, "binary_path": str(target_root / "bin" / "siem-operator.exe")},
            }
            with patch("deploy.distribution_toolkit.export_clean_project_bundle", return_value=fake_bundle):
                result = export_distribution_toolkit(target_root=target_root, project_root=project_root, build_binary=True)

            topology = json.loads((target_root / "distribution" / "topology.json").read_text(encoding="utf-8"))
            self.assertEqual(str(target_root), result["target_root"])
            self.assertEqual("kafka", topology["transport_backend"])
            self.assertTrue((target_root / "distribution" / "upgrade-plan.json").exists())
            self.assertTrue((target_root / "bin" / "siem-operator.cmd").exists())
            self.assertTrue((target_root / "bin" / "siem-operator.ps1").exists())


if __name__ == "__main__":
    unittest.main()
