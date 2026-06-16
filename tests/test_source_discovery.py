import importlib
import importlib.util
import json
import os
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


MODULE_NAME = "source_discovery"
ROOT = Path(__file__).resolve().parents[1]
IMPORT_ROOTS = (ROOT, ROOT / "services" / "web" / "app")
for candidate in IMPORT_ROOTS:
    candidate_text = str(candidate)
    if candidate.exists() and candidate_text not in sys.path:
        sys.path.insert(0, candidate_text)


def _load_module_by_path(module_name: str, *relative_candidates: str):
    for candidate in relative_candidates:
        path = ROOT / candidate
        if not path.exists():
            continue
        parent_text = str(path.parent)
        if parent_text not in sys.path:
            sys.path.insert(0, parent_text)
        spec = importlib.util.spec_from_file_location(module_name, path)
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module
        spec.loader.exec_module(module)
        return module
    raise ModuleNotFoundError(module_name)


class SourceDiscoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        os.environ["SIEM_CONTROL_PLANE_DIR"] = self.temp_dir.name
        sys.modules.pop(MODULE_NAME, None)
        try:
            self.module = importlib.import_module(MODULE_NAME)
        except ModuleNotFoundError:
            self.module = _load_module_by_path(
                MODULE_NAME,
                "source_discovery.py",
                "services/web/app/source_discovery.py",
            )

    def tearDown(self) -> None:
        sys.modules.pop(MODULE_NAME, None)
        os.environ.pop("SIEM_CONTROL_PLANE_DIR", None)
        os.environ.pop("SIEM_INGEST_BASE_URL", None)
        os.environ.pop("SIEM_INGEST_API_SHARED_SECRET", None)
        os.environ.pop("SIEM_WEBHOOK_SHARED_SECRET", None)
        self.temp_dir.cleanup()

    def _start_http_server(self):
        class Handler(BaseHTTPRequestHandler):
            server_version = "pveproxy/8.0"
            sys_version = ""

            def do_GET(self):  # noqa: N802
                body = b"<html><title>Proxmox Virtual Environment</title><body>ok</body></html>"
                self.send_response(200)
                self.send_header("Content-Type", "text/html")
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format: str, *args) -> None:  # noqa: A003
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        return server, thread

    def test_scan_classifies_candidate_and_prepares_linux_onboarding(self) -> None:
        server, thread = self._start_http_server()
        try:
            payload = self.module.scan_source_candidates(
                "127.0.0.1/32",
                ports=[server.server_address[1]],
                max_hosts=1,
                timeout_seconds=0.5,
                actor="tester",
            )
            self.assertEqual(payload["scan"]["discovered"], 1)
            candidate = payload["items"][0]
            self.assertEqual(candidate["probable_role"], "proxmox")
            self.assertEqual(candidate["recommendation"]["auto_monitoring_method"], "linux_rsyslog_ssh")
            prepared = self.module.prepare_source_onboarding(candidate["id"], actor="tester", requested_telemetry=["syslog", "auditd"])
            self.assertTrue(prepared["job"]["execution_supported"])
            self.assertEqual(["syslog", "auditd"], prepared["job"]["requested_telemetry"])
            executed = self.module.execute_source_onboarding(prepared["job"]["id"], actor="tester", dry_run=True)
            self.assertEqual(executed["execution"]["status"], "dry_run")
            self.assertEqual(["syslog", "auditd"], executed["execution"]["requested_telemetry"])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_scan_marks_connected_host_when_source_inventory_matches(self) -> None:
        server, thread = self._start_http_server()
        try:
            payload = self.module.scan_source_candidates(
                "127.0.0.1/32",
                ports=[server.server_address[1]],
                max_hosts=1,
                timeout_seconds=0.5,
                connected_sources=[{"source_name": "127.0.0.1"}],
                actor="tester",
            )
            candidate = payload["items"][0]
            self.assertTrue(candidate["connected"])
            self.assertEqual(candidate["status"], "connected")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_alias_override_marks_known_platform_host_as_connected(self) -> None:
        connected, alias = self.module._candidate_connected(  # type: ignore[attr-defined]
            "192.168.1.38",
            "",
            {self.module._normalize_token("siem-storage")},  # type: ignore[attr-defined]
        )

        self.assertTrue(connected)
        self.assertEqual(alias, "siem-storage")

    def test_reverse_dns_is_bounded_for_smoke_scans(self) -> None:
        original_lookup = self.module.socket.gethostbyaddr

        def slow_lookup(_ip: str):
            time.sleep(1.0)
            return ("slow.example", [], [])

        self.module.socket.gethostbyaddr = slow_lookup
        try:
            start = time.perf_counter()
            hostname = self.module._reverse_dns("192.0.2.10", timeout_seconds=0.05)  # type: ignore[attr-defined]
            elapsed = time.perf_counter() - start
        finally:
            self.module.socket.gethostbyaddr = original_lookup

        self.assertEqual("", hostname)
        self.assertLess(elapsed, 0.3)

    def test_connected_inventory_load_is_bounded_for_scan_endpoint(self) -> None:
        server, thread = self._start_http_server()
        original_fetch = self.module.fetch_source_inventory

        def slow_inventory(**_: object):
            time.sleep(1.0)
            return [{"source_name": "127.0.0.1"}]

        self.module.fetch_source_inventory = slow_inventory
        try:
            start = time.perf_counter()
            payload = self.module.scan_source_candidates(
                "127.0.0.1/32",
                ports=[server.server_address[1]],
                max_hosts=1,
                timeout_seconds=0.05,
                actor="tester",
            )
            elapsed = time.perf_counter() - start
        finally:
            self.module.fetch_source_inventory = original_fetch
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

        self.assertEqual(1, payload["scan"]["discovered"])
        self.assertLess(elapsed, 0.6)

    def test_connected_candidate_cannot_prepare_onboarding_job(self) -> None:
        server, thread = self._start_http_server()
        try:
            payload = self.module.scan_source_candidates(
                "127.0.0.1/32",
                ports=[server.server_address[1]],
                max_hosts=1,
                timeout_seconds=0.5,
                connected_sources=[{"source_name": "127.0.0.1"}],
                actor="tester",
            )
            candidate = payload["items"][0]
            with self.assertRaisesRegex(ValueError, "already connected"):
                self.module.prepare_source_onboarding(candidate["id"], actor="tester")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_list_reconciles_stored_candidate_with_live_source_inventory(self) -> None:
        self.module._save_rows(  # type: ignore[attr-defined]
            self.module.DISCOVERY_CANDIDATES_COLLECTION,  # type: ignore[attr-defined]
            [
                {
                    "id": "candidate-192-168-1-39",
                    "ip": "192.168.1.39",
                    "hostname": "",
                    "connected": False,
                    "status": "candidate",
                    "monitoring_status": "candidate",
                    "last_seen_ts": "2026-05-07T00:00:00Z",
                    "recommendation": {"auto_monitoring_supported": True},
                }
            ],
        )
        self.module.fetch_source_inventory = lambda **_: [{"source_name": "siem-web", "aliases": []}]  # type: ignore[attr-defined]

        inventory = self.module.list_source_discovery_candidates()
        candidate = inventory["items"][0]

        self.assertTrue(candidate["connected"])
        self.assertEqual(candidate["monitoring_status"], "connected")
        self.assertEqual(candidate["connected_source"], "siem-web")
        self.assertEqual(0, inventory["metrics"]["unmanaged"])

    def test_binding_override_is_exposed_on_discovery_candidate(self) -> None:
        server, thread = self._start_http_server()
        try:
            try:
                import asset_binding_overrides as overrides
            except ModuleNotFoundError:
                overrides = _load_module_by_path("asset_binding_overrides", "asset_binding_overrides.py")

            overrides.save_binding_override(
                {
                    "target": "asset-proxmox-01",
                    "ip": "127.0.0.1",
                    "aliases": ["pve-lab"],
                    "scope": "source_discovery",
                    "note": "manual remediation",
                },
                actor="tester",
            )

            payload = self.module.scan_source_candidates(
                "127.0.0.1/32",
                ports=[server.server_address[1]],
                max_hosts=1,
                timeout_seconds=0.5,
                actor="tester",
            )
            candidate = payload["items"][0]

            self.assertEqual("asset-proxmox-01", candidate["binding_target"])
            self.assertTrue(candidate["binding_override"])
            self.assertEqual(1, payload["metrics"]["binding_overrides_total"])
            self.assertEqual(1, payload["metrics"]["binding_overrides_applied"])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_rescan_supersedes_prepared_job_when_candidate_becomes_connected(self) -> None:
        server, thread = self._start_http_server()
        try:
            payload = self.module.scan_source_candidates(
                "127.0.0.1/32",
                ports=[server.server_address[1]],
                max_hosts=1,
                timeout_seconds=0.5,
                actor="tester",
            )
            candidate = payload["items"][0]
            prepared = self.module.prepare_source_onboarding(candidate["id"], actor="tester")
            self.assertEqual(prepared["job"]["status"], "prepared")

            rescanned = self.module.scan_source_candidates(
                "127.0.0.1/32",
                ports=[server.server_address[1]],
                max_hosts=1,
                timeout_seconds=0.5,
                connected_sources=[{"source_name": "127.0.0.1"}],
                actor="tester",
            )
            refreshed = rescanned["items"][0]
            self.assertTrue(refreshed["connected"])
            self.assertEqual(refreshed["monitoring_status"], "connected")

            jobs = rescanned["jobs"]
            job = next(item for item in jobs if item["id"] == prepared["job"]["id"])
            self.assertEqual(job["status"], "superseded")
            self.assertEqual(job["superseded_reason"], "candidate_connected")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def test_windows_onboarding_generates_package_artifacts(self) -> None:
        os.environ["SIEM_INGEST_BASE_URL"] = "https://siem.example.test"
        os.environ["SIEM_INGEST_API_SHARED_SECRET"] = "runtime-secret"

        candidate = {
            "id": "cand-win-1",
            "ip": "192.168.1.77",
            "hostname": "win-lab-01",
            "connected": False,
            "recommendation": {
                "collector_profile": "windows-event-http",
                "integration_template": "webhook-source",
                "auto_monitoring_method": "windows_onboarding_package",
            },
        }
        self.module._save_rows(  # type: ignore[attr-defined]
            self.module.DISCOVERY_CANDIDATES_COLLECTION,  # type: ignore[attr-defined]
            [candidate],
        )

        prepared = self.module.prepare_source_onboarding(candidate["id"], actor="tester")
        self.assertTrue(prepared["job"]["execution_supported"])
        self.assertEqual(prepared["job"]["method"], "windows_onboarding_package")
        self.assertIn('"delivery_mode": "native_service_agent"', prepared["job"]["config_preview"])

        dry_run = self.module.execute_source_onboarding(prepared["job"]["id"], actor="tester", dry_run=True)
        self.assertEqual(dry_run["execution"]["status"], "dry_run")
        self.assertTrue(dry_run["execution"]["package_spec"]["shared_secret_required"])

        executed = self.module.execute_source_onboarding(prepared["job"]["id"], actor="tester", dry_run=False)
        self.assertEqual(executed["execution"]["status"], "package_generated")
        artifacts = executed["execution"]["artifacts"]

        package_dir = Path(artifacts["directory"])
        zip_path = Path(artifacts["zip_path"])
        install_script = package_dir / "install-native-agent.cmd"
        manifest_path = package_dir / "package-manifest.json"

        self.assertTrue(package_dir.is_dir())
        self.assertTrue(zip_path.is_file())
        self.assertTrue((package_dir / "windows-agent-profile.local.json").is_file())
        self.assertTrue((package_dir / "install-windows-event-agent.ps1").is_file())
        self.assertTrue(install_script.is_file())
        self.assertIn("install-windows-event-agent.ps1", install_script.read_text(encoding="utf-8"))
        self.assertNotIn("runtime-secret", install_script.read_text(encoding="utf-8"))

        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        self.assertEqual(manifest["package_spec"]["base_url"], "https://siem.example.test")
        self.assertTrue(manifest["package_spec"]["shared_secret_required"])

        inventory = self.module.list_source_discovery_candidates()
        refreshed = next(item for item in inventory["items"] if item["id"] == candidate["id"])
        self.assertEqual(refreshed["monitoring_status"], "package_ready")

    def test_network_onboarding_plan_supports_dry_run_and_command_preview(self) -> None:
        candidate = {
            "id": "cand-net-1",
            "ip": "192.168.1.88",
            "hostname": "edge-router-01",
            "connected": False,
            "open_ports": [{"port": 22, "banner": "EdgeOS ssh"}],
            "recommendation": {
                "collector_profile": "network-syslog",
                "integration_template": "webhook-source",
                "auto_monitoring_method": "network_cli_ssh",
            },
        }
        self.module._save_rows(  # type: ignore[attr-defined]
            self.module.DISCOVERY_CANDIDATES_COLLECTION,  # type: ignore[attr-defined]
            [candidate],
        )

        prepared = self.module.prepare_source_onboarding(candidate["id"], actor="tester")
        self.assertEqual(prepared["job"]["method"], "network_cli_ssh")
        self.assertEqual(prepared["job"]["network_vendor"], "ubiquiti_edgeos")
        self.assertTrue(prepared["job"]["execution_supported"])
        self.assertTrue(prepared["job"]["credential_requirements"])

        dry_run = self.module.execute_source_onboarding(prepared["job"]["id"], actor="tester", dry_run=True)
        self.assertEqual(dry_run["execution"]["status"], "dry_run")
        self.assertEqual(dry_run["execution"]["network_vendor"], "ubiquiti_edgeos")
        self.assertTrue(dry_run["execution"]["commands"])

    def test_repo_root_resolves_workspace_when_module_is_mirrored_under_app(self) -> None:
        original_file = self.module.__file__
        self.module.__file__ = str(ROOT / "services" / "web" / "app" / "source_discovery.py")
        try:
            resolved = self.module._repo_root()  # type: ignore[attr-defined]
        finally:
            self.module.__file__ = original_file
        self.assertEqual(resolved, ROOT)
