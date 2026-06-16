import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from deploy.storage_ha_restore_verify import build_restore_verification


class StorageHaRestoreVerifyTests(unittest.TestCase):
    def test_build_restore_verification_detects_artifacts_and_binaries(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir)
            (root / "siem-web-backup-20260325").write_text("ok", encoding="utf-8")
            with patch("deploy.storage_ha_restore_verify.shutil.which", return_value="/usr/bin/tool"):
                payload = build_restore_verification(backup_root=root)

        self.assertTrue(payload["all_binaries_present"])
        self.assertTrue(payload["restore_ready"])
        self.assertEqual(1, payload["artifacts_total"])


if __name__ == "__main__":
    unittest.main()
