import unittest
from unittest.mock import patch

from storage_ha_runtime import _sanitize_probe_dsn, build_storage_ha_status


class StorageHaRuntimeTests(unittest.TestCase):
    def test_sanitize_probe_dsn_removes_target_session_attrs(self) -> None:
        dsn = "host=192.168.1.39,192.168.1.35 port=5432,5432 dbname=siem user=siem password=secret target_session_attrs=read-write connect_timeout=2"

        sanitized = _sanitize_probe_dsn(dsn)

        self.assertNotIn("target_session_attrs", sanitized)
        self.assertIn("host=192.168.1.39,192.168.1.35", sanitized)

    def test_build_storage_ha_status_reports_primary_and_replicas(self) -> None:
        env = {
            "SIEM_CONTROL_PLANE_PG_DSN": "host=192.168.1.39,192.168.1.35 port=5432,5432 dbname=siem user=siem password=secret",
            "SIEM_MONGO_URI": "mongodb://siem:secret@192.168.1.39:27017,192.168.1.35:27017,192.168.1.40:27017/siem_content?replicaSet=siem-rs",
        }
        pg_nodes = [
            {"host": "192.168.1.39", "port": 5432, "healthy": True, "role": "primary"},
            {"host": "192.168.1.35", "port": 5432, "healthy": True, "role": "standby"},
        ]
        mongo_nodes = [
            {"host": "192.168.1.39", "port": 27017, "healthy": True, "role": "primary", "set_name": "siem-rs"},
            {"host": "192.168.1.35", "port": 27017, "healthy": True, "role": "secondary", "set_name": "siem-rs"},
            {"host": "192.168.1.40", "port": 27017, "healthy": True, "role": "secondary", "set_name": "siem-rs"},
        ]
        with patch("storage_ha_runtime.clickhouse_failover_status", return_value={"healthy": True, "configured_hosts": [{"host": "192.168.1.38"}, {"host": "192.168.1.40"}], "replica_hosts_total": 1}):
            with patch("storage_ha_runtime.clickhouse_replication_snapshot", return_value={"nodes": [], "failed_nodes": [], "replication_lag_seconds_max": 0}):
                with patch("storage_ha_runtime._probe_postgres_host", side_effect=pg_nodes):
                    with patch("storage_ha_runtime._probe_mongo_host", side_effect=mongo_nodes):
                        payload = build_storage_ha_status(
                            platform_status={"content_store_status": {"backend": "mongo"}},
                            control_plane_status={"backend": "postgres", "requested_backend": "postgres"},
                            content_status={"backend": "mongo", "requested_backend": "mongo"},
                            env=env,
                        )

        self.assertTrue(payload["clickhouse"]["healthy"])
        self.assertTrue(payload["postgres"]["healthy"])
        self.assertEqual("192.168.1.39", payload["postgres"]["primary"]["host"])
        self.assertEqual("192.168.1.35", payload["postgres"]["standby"]["host"])
        self.assertTrue(payload["mongo"]["healthy"])
        self.assertEqual("siem-rs", payload["mongo"]["replica_set"])
        self.assertTrue(payload["failover_ready"])
        self.assertTrue(payload["postgres"]["replay_lag_ok"])
        self.assertTrue(payload["mongo"]["replication_lag_ok"])

    def test_build_storage_ha_status_backfills_backend_metadata_from_env(self) -> None:
        env = {
            "SIEM_CONTROL_PLANE_BACKEND": "postgres",
            "SIEM_CONTROL_PLANE_PG_DSN": "host=192.168.1.39,192.168.1.35 port=5432,5432 dbname=siem user=siem password=secret",
            "SIEM_CONTENT_STORE_BACKEND": "mongo",
            "SIEM_MONGO_URI": "mongodb://siem:secret@192.168.1.39:27017,192.168.1.35:27017/siem_content?replicaSet=siem-rs",
        }
        pg_nodes = [
            {"host": "192.168.1.39", "port": 5432, "healthy": True, "role": "primary"},
            {"host": "192.168.1.35", "port": 5432, "healthy": False, "error": "pg_hba"},
        ]
        mongo_nodes = [
            {"host": "192.168.1.39", "port": 27017, "healthy": True, "role": "primary", "set_name": "siem-rs"},
            {"host": "192.168.1.35", "port": 27017, "healthy": True, "role": "secondary", "set_name": "siem-rs"},
        ]
        with patch("storage_ha_runtime.clickhouse_failover_status", return_value={"healthy": True, "configured_hosts": [{"host": "192.168.1.38"}, {"host": "192.168.1.40"}], "replica_hosts_total": 1}):
            with patch("storage_ha_runtime.clickhouse_replication_snapshot", return_value={"nodes": [], "failed_nodes": [], "replication_lag_seconds_max": 0}):
                with patch("storage_ha_runtime._probe_postgres_host", side_effect=pg_nodes):
                    with patch("storage_ha_runtime._probe_mongo_host", side_effect=mongo_nodes):
                        payload = build_storage_ha_status(platform_status={}, env=env)

        self.assertEqual("postgres", payload["postgres"]["backend"])
        self.assertEqual("postgres", payload["postgres"]["requested_backend"])
        self.assertFalse(payload["postgres"]["healthy"])
        self.assertEqual("mongo", payload["mongo"]["backend"])
        self.assertEqual("mongo", payload["mongo"]["requested_backend"])
        self.assertIn("postgres_unhealthy", payload["alarms"])

    def test_build_storage_ha_status_marks_postgres_unhealthy_when_lag_exceeds_threshold(self) -> None:
        env = {
            "SIEM_CONTROL_PLANE_PG_DSN": "host=192.168.1.39,192.168.1.35 port=5432,5432 dbname=siem user=siem password=secret",
            "SIEM_MONGO_URI": "mongodb://siem:secret@192.168.1.39:27017,192.168.1.35:27017/siem_content?replicaSet=siem-rs",
            "SIEM_STORAGE_HA_POSTGRES_REPLAY_LAG_THRESHOLD_SECONDS": "300",
        }
        pg_nodes = [
            {"host": "192.168.1.39", "port": 5432, "healthy": True, "role": "primary"},
            {"host": "192.168.1.35", "port": 5432, "healthy": True, "role": "standby", "replay_lag_seconds": 1200},
        ]
        mongo_nodes = [
            {"host": "192.168.1.39", "port": 27017, "healthy": True, "role": "primary", "set_name": "siem-rs", "last_write_epoch": 1000},
            {"host": "192.168.1.35", "port": 27017, "healthy": True, "role": "secondary", "set_name": "siem-rs", "last_write_epoch": 995},
        ]
        with patch("storage_ha_runtime.clickhouse_failover_status", return_value={"healthy": True, "configured_hosts": [{"host": "192.168.1.38"}, {"host": "192.168.1.40"}], "replica_hosts_total": 1, "replication_lag_seconds_max": 0}):
            with patch("storage_ha_runtime.clickhouse_replication_snapshot", return_value={"nodes": [], "failed_nodes": [], "replication_lag_seconds_max": 0}):
                with patch("storage_ha_runtime._probe_postgres_host", side_effect=pg_nodes):
                    with patch("storage_ha_runtime._probe_mongo_host", side_effect=mongo_nodes):
                        payload = build_storage_ha_status(
                            platform_status={"content_store_status": {"backend": "mongo"}},
                            control_plane_status={"backend": "postgres", "requested_backend": "postgres"},
                            content_status={"backend": "mongo", "requested_backend": "mongo"},
                            env=env,
                        )

        self.assertFalse(payload["postgres"]["healthy"])
        self.assertFalse(payload["postgres"]["replay_lag_ok"])
        self.assertIn("postgres_replay_lag=1200s", payload["alarms"])
        self.assertFalse(payload["failover_ready"])

    def test_build_storage_ha_status_treats_idle_caught_up_standby_as_healthy(self) -> None:
        env = {
            "SIEM_CONTROL_PLANE_PG_DSN": "host=192.168.1.39,192.168.1.35 port=5432,5432 dbname=siem user=siem password=secret",
            "SIEM_MONGO_URI": "mongodb://siem:secret@192.168.1.39:27017,192.168.1.35:27017/siem_content?replicaSet=siem-rs",
            "SIEM_STORAGE_HA_POSTGRES_REPLAY_LAG_THRESHOLD_SECONDS": "300",
        }
        pg_nodes = [
            {"host": "192.168.1.39", "port": 5432, "healthy": True, "role": "primary"},
            {
                "host": "192.168.1.35",
                "port": 5432,
                "healthy": True,
                "role": "standby",
                "replay_lag_seconds": 1200,
                "wal_receive_replay_synced": True,
            },
        ]
        mongo_nodes = [
            {"host": "192.168.1.39", "port": 27017, "healthy": True, "role": "primary", "set_name": "siem-rs", "last_write_epoch": 1000},
            {"host": "192.168.1.35", "port": 27017, "healthy": True, "role": "secondary", "set_name": "siem-rs", "last_write_epoch": 995},
        ]
        with patch("storage_ha_runtime.clickhouse_failover_status", return_value={"healthy": True, "configured_hosts": [{"host": "192.168.1.38"}, {"host": "192.168.1.40"}], "replica_hosts_total": 1, "replication_lag_seconds_max": 0}):
            with patch("storage_ha_runtime.clickhouse_replication_snapshot", return_value={"nodes": [], "failed_nodes": [], "replication_lag_seconds_max": 0}):
                with patch("storage_ha_runtime._probe_postgres_host", side_effect=pg_nodes):
                    with patch("storage_ha_runtime._probe_mongo_host", side_effect=mongo_nodes):
                        payload = build_storage_ha_status(
                            platform_status={"content_store_status": {"backend": "mongo"}},
                            control_plane_status={"backend": "postgres", "requested_backend": "postgres"},
                            content_status={"backend": "mongo", "requested_backend": "mongo"},
                            env=env,
                        )

        self.assertTrue(payload["postgres"]["healthy"])
        self.assertTrue(payload["postgres"]["replay_lag_ok"])
        self.assertTrue(payload["failover_ready"])


if __name__ == "__main__":
    unittest.main()
