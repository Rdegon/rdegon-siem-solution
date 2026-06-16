import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from deploy.export_clean_project_bundle import export_clean_project_bundle


class ExportCleanProjectBundleTests(unittest.TestCase):
    def test_export_bundle_copies_project_and_writes_manifest(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            project_root = root / "repo"
            project_root.mkdir(parents=True, exist_ok=True)
            (project_root / "main.py").write_text("print('ok')\n", encoding="utf-8")
            (project_root / "deploy").mkdir()
            (project_root / "docs").mkdir()
            (project_root / "docs" / "README.md").write_text("# Docs\n", encoding="utf-8")
            (project_root / "deploy" / "sample.py").write_text("print('deploy')\n", encoding="utf-8")
            target_root = root / "bundle"
            operator_bundle = root / "OPERATOR_ACCESS_BUNDLE.md"
            operator_bundle.write_text("# Operator\n", encoding="utf-8")

            def _fake_docs_export(*, target_root: Path):
                target_root.mkdir(parents=True, exist_ok=True)
                (target_root / "README.md").write_text("# Exported docs\n", encoding="utf-8")
                return {"target_root": str(target_root), "docs_exported": 1}

            with patch("deploy.export_clean_project_bundle._tracked_files", return_value=["main.py", "docs/README.md", "deploy/sample.py"]):
                with patch("deploy.export_clean_project_bundle.export_siem_docs", side_effect=_fake_docs_export):
                    with patch("deploy.export_clean_project_bundle.OPERATOR_BUNDLE", operator_bundle):
                        result = export_clean_project_bundle(target_root=target_root, project_root=project_root, build_binary=False)

            manifest = json.loads((target_root / "manifest.json").read_text(encoding="utf-8"))
            self.assertEqual(3, result["copied_files_total"])
            self.assertTrue((target_root / "project" / "main.py").exists())
            self.assertTrue((target_root / "operator_bundle" / "OPERATOR_ACCESS_BUNDLE.md").exists())
            self.assertEqual(3, manifest["copied_files_total"])


if __name__ == "__main__":
    unittest.main()
