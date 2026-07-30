import os
import unittest
from unittest.mock import patch

import clickhouse_runtime
from clickhouse_runtime import ClickHouseEndpoint, clear_clickhouse_runtime_cache, clickhouse_failover_status, clickhouse_replication_snapshot, configured_clickhouse_endpoints, get_clickhouse_client


class _FakeClient:
    def __init__(
        self,
        host: str,
        port: int,
        broken: bool = False,
        latest_event_epoch: int = 1774797100,
    ) -> None:
        self.host = host
        self.port = port
        self.broken = broken
        self.latest_event_epoch = latest_event_epoch
        self.commands: list[str] = []

    def command(self, sql: str):
        self.commands.append(sql)
        if self.broken:
            raise RuntimeError(f"{self.host}:{self.port} down")
        if "EXISTS TABLE siem.events_shadow" in sql:
            return 1
        if "count() FROM siem.events_shadow WHERE ts >= now() - INTERVAL 5 MINUTE" in sql:
            return 11
        if "count() FROM siem.events_shadow WHERE ts >= now() - INTERVAL 15 MINUTE" in sql:
            return 29
        if "toUnixTimestamp(max(ts)) FROM siem.events_shadow" in sql:
            return 1774797000
        if "count() FROM siem.events WHERE ts >= now() - INTERVAL 5 MINUTE" in sql:
            return 31
        if "count() FROM siem.events WHERE ts >= now() - INTERVAL 15 MINUTE" in sql:
            return 77
        if "count() FROM siem.alerts_raw WHERE ts >= now() - INTERVAL 5 MINUTE" in sql:
            return 2
        if "toUnixTimestamp(max(ts)) FROM siem.events" in sql:
            return self.latest_event_epoch
        return 1


class ClickHouseRuntimeTests(unittest.TestCase):
    def tearDown(self) -> None:
        clear_clickhouse_runtime_cache()

    def test_configured_clickhouse_endpoints_prefers_configured_host_list(self) -> None:
        endpoints = configured_clickhouse_endpoints({"SIEM_CH_HOSTS": "vm3:8123,vm5:8123"})
        self.assertEqual(ClickHouseEndpoint("127.0.0.1", 8123), endpoints[0])
        self.assertEqual(ClickHouseEndpoint("vm3", 8123), endpoints[1])
        self.assertEqual(ClickHouseEndpoint("vm5", 8123), endpoints[2])

    def test_get_clickhouse_client_fails_over_to_next_host(self) -> None:
        fake_clients = {
            ("vm3", 8123): _FakeClient("vm3", 8123, broken=True),
            ("vm5", 8123): _FakeClient("vm5", 8123, broken=False),
        }

        def _build(endpoint: ClickHouseEndpoint):
            return fake_clients[(endpoint.host, endpoint.port)]

        with patch("clickhouse_runtime.configured_clickhouse_endpoints", return_value=(ClickHouseEndpoint("vm3", 8123), ClickHouseEndpoint("vm5", 8123))):
            with patch("clickhouse_runtime._build_client", side_effect=_build):
                client = get_clickhouse_client()

        self.assertIs(client, fake_clients[("vm5", 8123)])

    def test_get_clickhouse_client_skips_reachable_but_stale_replica(self) -> None:
        fake_clients = {
            ("vm3", 8123): _FakeClient("vm3", 8123, latest_event_epoch=1774793500),
            ("vm5", 8123): _FakeClient("vm5", 8123, latest_event_epoch=1774797100),
        }

        def _build(endpoint: ClickHouseEndpoint):
            return fake_clients[(endpoint.host, endpoint.port)]

        with patch(
            "clickhouse_runtime.configured_clickhouse_endpoints",
            return_value=(ClickHouseEndpoint("vm3", 8123), ClickHouseEndpoint("vm5", 8123)),
        ):
            with patch("clickhouse_runtime._build_client", side_effect=_build):
                client = get_clickhouse_client()
                status = clickhouse_failover_status()

        self.assertIs(client, fake_clients[("vm5", 8123)])
        self.assertEqual("vm5", status["active_endpoint"]["host"])
        self.assertFalse(status["healthy_endpoints"][0]["data_fresh"])
        self.assertEqual(3600, status["healthy_endpoints"][0]["replication_lag_seconds"])

    def test_get_clickhouse_client_reuses_recent_healthcheck(self) -> None:
        client = _FakeClient("vm3", 8123)

        with patch("clickhouse_runtime.configured_clickhouse_endpoints", return_value=(ClickHouseEndpoint("vm3", 8123),)):
            with patch("clickhouse_runtime._build_client", return_value=client):
                first = get_clickhouse_client()
                second = get_clickhouse_client()

        self.assertIs(first, client)
        self.assertIs(second, client)
        self.assertEqual(["SELECT 1"], client.commands)

    def test_get_clickhouse_client_rechecks_after_healthcheck_ttl(self) -> None:
        client = _FakeClient("vm3", 8123)

        with patch("clickhouse_runtime.configured_clickhouse_endpoints", return_value=(ClickHouseEndpoint("vm3", 8123),)):
            with patch("clickhouse_runtime._build_client", return_value=client):
                with patch("clickhouse_runtime.monotonic", side_effect=(10.0, 10.0, 13.0, 13.0)):
                    first = get_clickhouse_client()
                    second = get_clickhouse_client()

        self.assertIs(first, client)
        self.assertIs(second, client)
        self.assertEqual(["SELECT 1", "SELECT 1"], client.commands)

    def test_clickhouse_failover_status_reports_active_and_failed_nodes(self) -> None:
        fake_clients = {
            ("vm3", 8123): _FakeClient("vm3", 8123, broken=False),
            ("vm5", 8123): _FakeClient("vm5", 8123, broken=True),
        }

        def _build(endpoint: ClickHouseEndpoint):
            return fake_clients[(endpoint.host, endpoint.port)]

        with patch("clickhouse_runtime.configured_clickhouse_endpoints", return_value=(ClickHouseEndpoint("vm3", 8123), ClickHouseEndpoint("vm5", 8123))):
            with patch("clickhouse_runtime._build_client", side_effect=_build):
                status = clickhouse_failover_status()

        self.assertTrue(status["healthy"])
        self.assertEqual("vm3", status["active_endpoint"]["host"])
        self.assertEqual("vm5", status["failed_endpoints"][0]["host"])

    def test_clickhouse_replication_snapshot_includes_shadow_metrics(self) -> None:
        fake_clients = {
            ("vm3", 8123): _FakeClient("vm3", 8123, broken=False),
            ("vm5", 8123): _FakeClient("vm5", 8123, broken=False),
        }

        def _build(endpoint: ClickHouseEndpoint):
            return fake_clients[(endpoint.host, endpoint.port)]

        with patch("clickhouse_runtime.configured_clickhouse_endpoints", return_value=(ClickHouseEndpoint("vm3", 8123), ClickHouseEndpoint("vm5", 8123))):
            with patch("clickhouse_runtime._build_client", side_effect=_build):
                snapshot = clickhouse_replication_snapshot()

        self.assertTrue(snapshot["healthy"])
        self.assertEqual(2, len(snapshot["nodes"]))
        self.assertEqual(29, snapshot["nodes"][0]["shadow_events_15m"])
        self.assertEqual(1774797000, snapshot["nodes"][0]["shadow_latest_event_epoch"])

    def test_fallback_clickhouse_config_resolves_secret_refs(self) -> None:
        with patch.object(clickhouse_runtime, "_CONFIG", None):
            with patch.object(clickhouse_runtime, "resolve_secret_value", return_value=("resolved-password", "vault://kv/siem/clickhouse#value", {"status": "configured"})):
                with patch.dict(
                    os.environ,
                    {
                        "SIEM_CH_HOST": "192.168.1.38",
                        "SIEM_CH_PORT": "8123",
                        "SIEM_CH_USER": "siem_admin",
                        "SIEM_CH_DB": "siem",
                        "SIEM_CH_PASSWORD_REF": "vault://kv/siem/clickhouse#value",
                    },
                    clear=False,
                ):
                    cfg = clickhouse_runtime._FallbackClickHouseConfig()

        self.assertEqual("resolved-password", cfg.password)
        self.assertEqual("siem_admin", cfg.user)

    def test_clickhouse_client_uses_bounded_network_timeouts(self) -> None:
        fake_config = type(
            "FakeConfig",
            (),
            {
                "ch": type(
                    "FakeClickHouseConfig",
                    (),
                    {"host": "vm3", "port": 8123, "user": "siem", "password": "secret", "db": "siem"},
                )()
            },
        )()
        captured: dict[str, object] = {}

        def fake_get_client(**kwargs):
            captured.update(kwargs)
            return _FakeClient(str(kwargs["host"]), int(kwargs["port"]))

        with patch.object(clickhouse_runtime, "_CONFIG", fake_config):
            with patch.object(clickhouse_runtime, "clickhouse_connect") as module:
                module.get_client.side_effect = fake_get_client
                with patch.dict(
                    os.environ,
                    {
                        "SIEM_CH_CONNECT_TIMEOUT_SECONDS": "4",
                        "SIEM_CH_SEND_RECEIVE_TIMEOUT_SECONDS": "12",
                    },
                    clear=False,
                ):
                    client = clickhouse_runtime._build_client(ClickHouseEndpoint("vm3", 8123))

        self.assertIsInstance(client, _FakeClient)
        self.assertEqual(4, captured["connect_timeout"])
        self.assertEqual(12, captured["send_receive_timeout"])


if __name__ == "__main__":
    unittest.main()
