from __future__ import annotations

import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from runtime_humanization import humanize_source_name, humanize_technical_value


class RuntimeHumanizationTests(unittest.TestCase):
    def test_source_name_renders_clean_russian_label(self) -> None:
        self.assertEqual("Прыжковый и VPN-хост", humanize_source_name("vpn-host-khanov", lang="ru", technical_suffix=True))

    def test_pipe_delimited_identity_is_humanized(self) -> None:
        self.assertEqual("Прыжковый и VPN-хост | 204.76.203.83", humanize_technical_value("vpn-host-khanov|204.76.203.83", lang="ru"))


if __name__ == "__main__":
    unittest.main()
