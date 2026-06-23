import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from tools import siem_operator_cli


def _write_minimal_repo(root: Path) -> None:
    (root / "services" / "web").mkdir(parents=True)
    (root / "services" / "web" / "main.py").write_text("print('ok')\n", encoding="utf-8")
    (root / "deploy").mkdir()
    (root / "docs").mkdir()


class SiemOperatorCliTests(unittest.TestCase):
    def test_users_create_calls_access_module_with_permission_bundles(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            _write_minimal_repo(root)
            captured: list[dict] = []

            class FakeAccessModule:
                @staticmethod
                def save_local_user(payload, actor="system"):
                    captured.append({"payload": payload, "actor": actor})
                    return {"status": "ok", **payload}

            stdout = io.StringIO()
            with patch("tools.siem_operator_cli._access_module", return_value=FakeAccessModule()):
                with redirect_stdout(stdout):
                    rc = siem_operator_cli.main(
                        [
                            "--repo-root",
                            str(root),
                            "users",
                            "create",
                            "--username",
                            "analyst",
                            "--password",
                            "Secret!23",
                            "--permission-bundle",
                            "dashboard-editor",
                            "--permission",
                            "health:view",
                        ]
                    )

            payload = json.loads(stdout.getvalue())
            self.assertEqual(0, rc)
            self.assertEqual("analyst", captured[0]["payload"]["username"])
            self.assertEqual(["dashboard-editor"], captured[0]["payload"]["permission_bundles"])
            self.assertEqual("ok", payload["status"])

    def test_bundle_export_clean_routes_to_bundle_module(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            _write_minimal_repo(root)
            stdout = io.StringIO()

            class FakeBundleModule:
                @staticmethod
                def export_clean_project_bundle(*, target_root, project_root, build_binary):
                    return {
                        "target_root": str(target_root),
                        "project_root": str(project_root),
                        "build_binary": bool(build_binary),
                    }

            with patch("tools.siem_operator_cli._bundle_module", return_value=FakeBundleModule()):
                with redirect_stdout(stdout):
                    rc = siem_operator_cli.main(
                        [
                            "--repo-root",
                            str(root),
                            "bundle",
                            "export-clean",
                            "--target-root",
                            str(root / "bundle"),
                            "--build-binary",
                        ]
                    )

            payload = json.loads(stdout.getvalue())
            self.assertEqual(0, rc)
            self.assertEqual(str(root / "bundle"), payload["target_root"])
            self.assertTrue(payload["build_binary"])

    def test_distribution_export_routes_to_distribution_module(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            _write_minimal_repo(root)
            stdout = io.StringIO()

            class FakeDistributionModule:
                @staticmethod
                def export_distribution_toolkit(*, target_root, project_root, build_binary):
                    return {
                        "target_root": str(target_root),
                        "project_root": str(project_root),
                        "build_binary": bool(build_binary),
                    }

                @staticmethod
                def build_topology_manifest(*, project_root):
                    return {"project_root": str(project_root), "transport_backend": "kafka"}

                @staticmethod
                def build_upgrade_plan(*, project_root, target_version):
                    return {"project_root": str(project_root), "target_version": str(target_version)}

            with patch("tools.siem_operator_cli._distribution_module", return_value=FakeDistributionModule()):
                with redirect_stdout(stdout):
                    rc = siem_operator_cli.main(
                        [
                            "--repo-root",
                            str(root),
                            "distribution",
                            "export",
                            "--target-root",
                            str(root / "dist"),
                            "--build-binary",
                        ]
                    )

            payload = json.loads(stdout.getvalue())
            self.assertEqual(0, rc)
            self.assertEqual(str(root / "dist"), payload["target_root"])
            self.assertTrue(payload["build_binary"])

    def test_performance_distributed_eps_routes_to_module_main(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            _write_minimal_repo(root)

            class FakePerfModule:
                @staticmethod
                def main(argv):
                    print(json.dumps({"argv": argv}))
                    return 0

            stdout = io.StringIO()
            with patch("tools.siem_operator_cli._distributed_eps_module", return_value=FakePerfModule()):
                with redirect_stdout(stdout):
                    rc = siem_operator_cli.main(
                        [
                            "--repo-root",
                            str(root),
                            "performance",
                            "distributed-eps",
                            "--ingest-url",
                            "https://ingest.local/ingest/json",
                            "--duration-sec",
                            "15",
                            "--batch-size",
                            "400",
                            "--stages",
                            "1000,2000",
                        ]
                    )

            payload = json.loads(stdout.getvalue())
            self.assertEqual(0, rc)
            self.assertIn("--ingest-url", payload["argv"])


if __name__ == "__main__":
    unittest.main()
