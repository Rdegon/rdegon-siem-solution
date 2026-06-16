from datetime import datetime, timezone
import importlib
import sys
import types
import unittest
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

control_plane_health = importlib.import_module("app.control_plane_health")


class ControlPlaneHealthTests(unittest.TestCase):
    def test_old_stream_shadow_mismatch_total_is_advisory_not_release_blocker(self) -> None:
        issue, advisory = control_plane_health._stream_shadow_mismatch_gate(
            {
                "shadow_compare_mismatches_total": 1429,
                "last_mismatch_ts": "2026-04-26 17:01:24",
            },
            now=datetime(2026, 5, 7, 4, 39, 28, tzinfo=timezone.utc),
        )

        self.assertEqual("", issue)
        self.assertIn("Historical Stream correlation shadow mismatches: 1429", advisory)

    def test_recent_stream_shadow_mismatch_total_blocks_release(self) -> None:
        issue, advisory = control_plane_health._stream_shadow_mismatch_gate(
            {
                "shadow_compare_mismatches_total": 1429,
                "last_mismatch_ts": "2026-05-07T04:35:00Z",
            },
            now=datetime(2026, 5, 7, 4, 39, 28, tzinfo=timezone.utc),
        )

        self.assertIn("Stream correlation shadow mismatches: 1429", issue)
        self.assertEqual("", advisory)


if __name__ == "__main__":
    unittest.main()
