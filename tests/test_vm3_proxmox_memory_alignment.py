from __future__ import annotations

import unittest

from deploy.vm3_proxmox_memory_alignment import _parse_free_bytes, _parse_qm_config_value


class Vm3ProxmoxMemoryAlignmentTests(unittest.TestCase):
    def test_parse_qm_config_value_reads_balloon(self) -> None:
        payload = (
            "agent: 1\n"
            "memory: 28672\n"
            "balloon: 24576\n"
            "name: SIEM-Storage\n"
        )
        self.assertEqual(_parse_qm_config_value(payload, "balloon"), "24576")
        self.assertEqual(_parse_qm_config_value(payload, "memory"), "28672")

    def test_parse_qm_config_value_returns_empty_string_when_missing(self) -> None:
        self.assertEqual(_parse_qm_config_value("name: SIEM-Storage\n", "balloon"), "")

    def test_parse_free_bytes_extracts_available(self) -> None:
        payload = _parse_free_bytes(
            "               total        used        free      shared  buff/cache   available\n"
            "Mem:     25769803776  2433028096  4294967296    29204480 19025362944 22548578304\n"
            "Swap:     8589930496     1048576 8588881920\n"
        )
        self.assertEqual(payload["total"], 25769803776)
        self.assertEqual(payload["available"], 22548578304)


if __name__ == "__main__":
    unittest.main()
