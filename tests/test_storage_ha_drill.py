import unittest

from deploy.storage_ha_drill import build_storage_ha_drill_report


class StorageHaDrillTests(unittest.TestCase):
    def test_build_storage_ha_drill_report_flags_replication_lag(self) -> None:
        report = build_storage_ha_drill_report(
            {
                "clickhouse": {"healthy": True, "standby_present": True, "replication_lag_seconds_max": 10},
                "postgres": {"healthy": True, "standby": {"replay_lag_seconds": 91}},
                "mongo": {"healthy": True, "secondary": {"host": "vm5"}, "replication_lag_seconds_max": 5},
            },
            thresholds={"postgres_lag_warn_sec": 60},
        )

        self.assertFalse(report["healthy"])
        self.assertIn("postgres_replication_lag>60s", report["alarms"])

    def test_build_storage_ha_drill_report_marks_failover_ready_when_all_layers_are_healthy(self) -> None:
        report = build_storage_ha_drill_report(
            {
                "clickhouse": {"healthy": True, "standby_present": True, "replication_lag_seconds_max": 0},
                "postgres": {"healthy": True, "standby": {"replay_lag_seconds": 0}},
                "mongo": {"healthy": True, "secondary": {"host": "vm5"}, "replication_lag_seconds_max": 0},
            }
        )

        self.assertTrue(report["healthy"])
        self.assertTrue(report["failover_ready"])


if __name__ == "__main__":
    unittest.main()
