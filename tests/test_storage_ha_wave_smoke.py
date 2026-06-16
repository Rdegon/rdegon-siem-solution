import unittest
from unittest import mock

from deploy.storage_ha_wave_smoke import _events_count_query, _storage_ha_payload


class StorageHaWaveSmokeTests(unittest.TestCase):
    def test_storage_ha_payload_prefers_nested_storage_status(self) -> None:
        payload = {
            "generated_ts": "2026-03-24T15:00:00Z",
            "storage_ha": {
                "clickhouse": {"healthy": True},
                "postgres": {"healthy": True},
                "mongo": {"healthy": True},
            },
        }

        resolved = _storage_ha_payload(payload)

        self.assertTrue(resolved["clickhouse"]["healthy"])
        self.assertTrue(resolved["postgres"]["healthy"])
        self.assertTrue(resolved["mongo"]["healthy"])

    def test_events_count_query_uses_recent_bootstrap_window(self) -> None:
        with mock.patch.dict("os.environ", {"SIEM_CH_STANDBY_BOOTSTRAP_EVENTS_LOOKBACK_HOURS": "12"}):
            query = _events_count_query()

        self.assertIn("WHERE ts >= now() - INTERVAL 12 HOUR", query)


if __name__ == "__main__":
    unittest.main()
