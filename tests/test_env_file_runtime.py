from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from deploy.env_file_runtime import load_env_file, parse_env_file


class EnvFileRuntimeTests(unittest.TestCase):
    def test_parse_env_file_preserves_spaces_and_special_characters(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            env_path = Path(temp_dir) / "web.env"
            env_path.write_text(
                "\n".join(
                    (
                        "SIEM_WEB_BASE_URL=https://192.168.1.39",
                        "SIEM_MONGO_URI=mongodb://user:pa_ss@127.0.0.1:27017/db?authSource=db&replicaSet=siem-rs",
                        "SIEM_GREENBONE_DAILY_SCHEDULE_NAME=SIEM Daily Exposure Sweep",
                    )
                ),
                encoding="utf-8",
            )
            loaded = parse_env_file(env_path)
        self.assertEqual(loaded["SIEM_WEB_BASE_URL"], "https://192.168.1.39")
        self.assertEqual(
            loaded["SIEM_MONGO_URI"],
            "mongodb://user:pa_ss@127.0.0.1:27017/db?authSource=db&replicaSet=siem-rs",
        )
        self.assertEqual(loaded["SIEM_GREENBONE_DAILY_SCHEDULE_NAME"], "SIEM Daily Exposure Sweep")

    def test_load_env_file_sets_values_without_shell_parsing(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            env_path = Path(temp_dir) / "web.env"
            env_path.write_text(
                "SIEM_CONTROL_PLANE_PG_DSN=host=192.168.1.39,192.168.1.35 port=5432,5432 dbname=siem_control_plane user=siem_control password=test target_session_attrs=read-write connect_timeout=2\n",
                encoding="utf-8",
            )
            previous = os.environ.pop("SIEM_CONTROL_PLANE_PG_DSN", None)
            try:
                load_env_file(env_path)
                self.assertIn("password=test", os.environ["SIEM_CONTROL_PLANE_PG_DSN"])
            finally:
                if previous is None:
                    os.environ.pop("SIEM_CONTROL_PLANE_PG_DSN", None)
                else:
                    os.environ["SIEM_CONTROL_PLANE_PG_DSN"] = previous


if __name__ == "__main__":
    unittest.main()
