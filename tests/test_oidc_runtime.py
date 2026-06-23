import importlib.util
import os
import sys
import types
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
PACKAGE_NAME = "fake_oidc_runtime"


def _clear_fake_modules() -> None:
    for name in list(sys.modules):
        if name == PACKAGE_NAME or name.startswith(f"{PACKAGE_NAME}."):
            sys.modules.pop(name, None)


def _install_stubs() -> None:
    package = types.ModuleType(PACKAGE_NAME)
    package.__path__ = []  # type: ignore[attr-defined]
    sys.modules[PACKAGE_NAME] = package

    secret_runtime = types.ModuleType(f"{PACKAGE_NAME}.secret_runtime")
    secret_runtime.resolve_secret_value = lambda name, explicit_value="": (explicit_value or "secret", "env", name)  # noqa: E731
    sys.modules[f"{PACKAGE_NAME}.secret_runtime"] = secret_runtime


def _load_oidc_module():
    spec = importlib.util.spec_from_file_location(f"{PACKAGE_NAME}.oidc_runtime", ROOT / "services" / "web" / "app" / "oidc_runtime.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    module.__package__ = PACKAGE_NAME
    sys.modules[f"{PACKAGE_NAME}.oidc_runtime"] = module
    spec.loader.exec_module(module)
    return module


class OidcRuntimeTests(unittest.TestCase):
    def setUp(self) -> None:
        _clear_fake_modules()
        _install_stubs()
        os.environ["SIEM_OIDC_ENABLED"] = "true"
        os.environ["SIEM_OIDC_ISSUER_URL"] = "https://idp.example.test/realms/siem"
        os.environ["SIEM_OIDC_CLIENT_ID"] = "siem-web"
        os.environ["SIEM_OIDC_STATUS_CACHE_SECONDS"] = "30"
        self.module = _load_oidc_module()

    def tearDown(self) -> None:
        for name in (
            "SIEM_OIDC_ENABLED",
            "SIEM_OIDC_ISSUER_URL",
            "SIEM_OIDC_CLIENT_ID",
            "SIEM_OIDC_STATUS_CACHE_SECONDS",
        ):
            os.environ.pop(name, None)
        _clear_fake_modules()

    def test_provider_status_uses_cache_between_calls(self) -> None:
        calls: list[int] = []

        def fake_probe():
            calls.append(1)
            return True, []

        self.module._probe_provider = fake_probe
        first = self.module.provider_status(force_refresh=True)
        second = self.module.provider_status()

        self.assertTrue(first["healthy"])
        self.assertEqual(second["issuer"], "https://idp.example.test/realms/siem")
        self.assertEqual(len(calls), 1)

    def test_providers_inventory_reuses_prefetched_status(self) -> None:
        calls: list[int] = []

        def fake_probe():
            calls.append(1)
            return True, []

        self.module._probe_provider = fake_probe
        status = self.module.provider_status(force_refresh=True)
        inventory = self.module.providers_inventory(status)

        self.assertEqual(inventory[0]["id"], "enterprise-oidc")
        self.assertEqual(inventory[1]["id"], "break-glass-local")
        self.assertEqual(len(calls), 1)


if __name__ == "__main__":
    unittest.main()
