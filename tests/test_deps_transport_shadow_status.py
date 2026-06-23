import importlib.util
import os
import sys
import time
import types
import unittest
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
APP_ROOT = ROOT / "services" / "web" / "app"


def _load_deps_module():
    package_name = "testrepo"
    if package_name not in sys.modules:
        package = types.ModuleType(package_name)
        package.__path__ = [str(APP_ROOT)]  # type: ignore[attr-defined]
        sys.modules[package_name] = package
    module_name = f"{package_name}.deps"
    for stale in (
        module_name,
        f"{package_name}.config",
        f"{package_name}.clickhouse_runtime",
        f"{package_name}.content_store",
        f"{package_name}.inventory_catalog",
        f"{package_name}.transport_health_runtime",
        f"{package_name}.stream_state_runtime",
        f"{package_name}.proxmox_fleet_runtime",
        f"{package_name}.runtime_humanization",
    ):
        sys.modules.pop(stale, None)
    spec = importlib.util.spec_from_file_location(module_name, APP_ROOT / "deps.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


class TransportShadowStatusTests(unittest.TestCase):
    def test_fetch_transport_shadow_status_prefers_freshest_shadow_node(self) -> None:
        env_overrides = {
            "SIEM_ENV": "dev",
            "SIEM_CH_HOST": "127.0.0.1",
            "SIEM_CH_PORT": "8123",
            "SIEM_CH_USER": "siem_admin",
            "SIEM_CH_PASSWORD": "secret",
            "SIEM_CH_DB": "siem",
            "SIEM_JWT_SECRET": "test-secret",
            "SIEM_ADMIN_DEFAULT_PASSWORD_HASH": "pbkdf2_sha256$390000$test$hash",
            "SIEM_HOT_RETENTION_HOURS": "168",
            "SIEM_COLD_RETENTION_DAYS": "365",
        }
        original = {key: os.environ.get(key) for key in env_overrides}
        os.environ.update(env_overrides)
        self.addCleanup(lambda: [os.environ.pop(key, None) if value is None else os.environ.__setitem__(key, value) for key, value in original.items()])
        deps = _load_deps_module()
        snapshot = {
            "nodes": [
                {
                    "host": "vm5",
                    "port": 8123,
                    "healthy": True,
                    "events_5m": 120,
                    "events_15m": 360,
                    "shadow_table_exists": True,
                    "shadow_events_5m": 0,
                    "shadow_events_15m": 0,
                    "shadow_latest_event_epoch": None,
                },
                {
                    "host": "vm3",
                    "port": 8123,
                    "healthy": True,
                    "events_5m": 118,
                    "events_15m": 355,
                    "shadow_table_exists": True,
                    "shadow_events_5m": 52,
                    "shadow_events_15m": 201,
                    "shadow_latest_event_epoch": int(time.time()),
                },
            ]
        }

        with patch.object(deps, "clickhouse_replication_snapshot", return_value=snapshot):
            payload = deps.fetch_transport_shadow_status()

        self.assertTrue(payload["healthy"])
        self.assertEqual("healthy", payload["status"])
        self.assertEqual(201, payload["shadow_events_15m"])
        self.assertEqual("vm3", payload["shadow_source_endpoint"]["host"])


if __name__ == "__main__":
    unittest.main()
