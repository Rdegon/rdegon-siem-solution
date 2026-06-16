from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import unittest
from unittest.mock import patch
import urllib.error

import deploy.host_runtime_wave_deploy as wave_deploy


REPO_ROOT = Path(__file__).resolve().parents[1]


def _load_script(path: Path, module_name: str):
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load script: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class _FakeResponse:
    def __init__(self, payload: dict[str, object]) -> None:
        self._payload = json.dumps(payload).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        return False

    def read(self) -> bytes:
        return self._payload


class HostRuntimeDeliveryTests(unittest.TestCase):
    def test_agent_retries_transient_http_error(self) -> None:
        module = _load_script(REPO_ROOT / "deploy" / "host_runtime_agent.py", "test_host_runtime_agent")
        transient = urllib.error.HTTPError(
            module._ingest_url(),
            502,
            "Bad Gateway",
            hdrs=None,
            fp=None,
        )
        with patch.object(module.urllib.request, "urlopen", side_effect=[transient, _FakeResponse({"status": "ok", "ingested": 1})]) as urlopen:
            with patch.object(module.time, "sleep"):
                result = module._post_events([{"message": "snapshot"}])

        self.assertEqual({"status": "ok", "ingested": 1}, result)
        self.assertEqual(2, urlopen.call_count)

    def test_wave_env_writes_delivery_timeout_and_attempts(self) -> None:
        spec = wave_deploy.HOSTS[0]
        env_text = wave_deploy._host_runtime_env(
            spec,
            ingest_url="https://192.168.1.35/ingest/json",
            tls_verify="disabled",
            timeout_seconds="20",
        )

        self.assertIn("SIEM_HOST_RUNTIME_TIMEOUT_SECONDS=20", env_text)
        self.assertIn("SIEM_HOST_RUNTIME_DELIVERY_ATTEMPTS=4", env_text)

    def test_vm1_uses_local_ingest_target(self) -> None:
        url, tls_verify = wave_deploy._agent_ingest_target(
            wave_deploy.HOSTS[0],
            ingest_url="https://192.168.1.35/ingest/json",
            tls_verify="disabled",
            local_ingest_url="http://127.0.0.1:8443/ingest/json",
        )

        self.assertEqual("http://127.0.0.1:8443/ingest/json", url)
        self.assertEqual("disabled", tls_verify)


if __name__ == "__main__":
    unittest.main()
