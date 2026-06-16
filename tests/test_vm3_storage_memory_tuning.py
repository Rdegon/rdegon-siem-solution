from __future__ import annotations

import unittest

from deploy.vm3_storage_memory_tuning import (
    _render_clickhouse_metrics_grants_sql,
    _render_memory_tuning_xml,
)
from deploy.vm3_storage_memory_smoke import _format_bytes, _parse_free_bytes


class Vm3StorageMemoryTuningTests(unittest.TestCase):
    def test_render_memory_tuning_xml_contains_expected_knobs(self) -> None:
        payload = _render_memory_tuning_xml(
            max_server_memory_usage=17179869184,
            max_server_memory_usage_to_ram_ratio="0.6",
            mark_cache_size=1073741824,
            uncompressed_cache_size=1073741824,
        )
        self.assertIn("<max_server_memory_usage>17179869184</max_server_memory_usage>", payload)
        self.assertIn("<max_server_memory_usage_to_ram_ratio>0.6</max_server_memory_usage_to_ram_ratio>", payload)
        self.assertIn("<mark_cache_size>1073741824</mark_cache_size>", payload)
        self.assertIn("<uncompressed_cache_size>1073741824</uncompressed_cache_size>", payload)

    def test_parse_free_bytes_extracts_available_and_cache(self) -> None:
        payload = _parse_free_bytes(
            "               total        used        free      shared  buff/cache   available\n"
            "Mem:     28914937856  2433028096  1818236928    29204480 24663183360 26557444096\n"
            "Swap:     8589930496     1048576 8588881920\n"
        )
        self.assertEqual(payload["total"], 28914937856)
        self.assertEqual(payload["used"], 2433028096)
        self.assertEqual(payload["buff_cache"], 24663183360)
        self.assertEqual(payload["available"], 26557444096)

    def test_format_bytes_prefers_human_units(self) -> None:
        self.assertEqual(_format_bytes(1073741824), "1.00 GiB")

    def test_render_clickhouse_metrics_grants_sql_targets_app_user(self) -> None:
        payload = _render_clickhouse_metrics_grants_sql("siem_admin")
        self.assertIn(
            "GRANT SELECT(metric, value) ON system.asynchronous_metrics TO siem_admin;",
            payload,
        )
        self.assertIn("GRANT SELECT(name, value) ON system.metrics TO siem_admin;", payload)
        self.assertIn(
            "GRANT SELECT(name, value) ON system.server_settings TO siem_admin;",
            payload,
        )


if __name__ == "__main__":
    unittest.main()
