import io
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


class _FakeSftp:
    def stat(self, _path: str):
        return types.SimpleNamespace()

    def close(self) -> None:
        return None


class _FakeClient:
    def __init__(self) -> None:
        self.sftp = _FakeSftp()

    def open_sftp(self):
        return self.sftp

    def close(self) -> None:
        return None


class DeployRolloutRegressionTests(unittest.TestCase):
    def test_vm1_smoke_quotes_runtime_urls_with_query_strings(self) -> None:
        import deploy.vm1_ingest_fabric_smoke as vm1_smoke

        command = vm1_smoke._curl_json("/health/sources?limit=200")
        self.assertIn("'http://127.0.0.1:8443/health/sources?limit=200'", command)

    def test_vm1_ingest_override_uses_eight_http_workers(self) -> None:
        override_text = (ROOT / "deploy" / "vm1" / "siem-ingest.override.conf").read_text(encoding="utf-8")

        self.assertIn("--workers 8", override_text)

    def test_vm1_deploy_uses_staging_and_sudo_install(self) -> None:
        import deploy.vm1_ingest_fabric_deploy as vm1_deploy

        commands: list[tuple[str, bool]] = []
        uploads: list[str] = []
        original_root = vm1_deploy.ROOT
        original_mappings = vm1_deploy.FILE_MAPPINGS
        original_connect = vm1_deploy._connect_client
        original_backup = vm1_deploy._backup_file
        original_upload = vm1_deploy._upload_text
        original_run = vm1_deploy._run_command
        try:
            with tempfile.TemporaryDirectory() as tmp:
                tmp_root = Path(tmp)
                source = tmp_root / "services/ingest/app.py"
                source.parent.mkdir(parents=True, exist_ok=True)
                source.write_text("print('ok')\n", encoding="utf-8")

                vm1_deploy.ROOT = tmp_root
                vm1_deploy.FILE_MAPPINGS = (vm1_deploy.FileMapping("services/ingest/app.py", "services/ingest/app.py"),)
                vm1_deploy._connect_client = lambda *args, **kwargs: _FakeClient()  # type: ignore[assignment]
                vm1_deploy._backup_file = lambda *args, **kwargs: None  # type: ignore[assignment]
                vm1_deploy._upload_text = lambda sftp, *, content, remote_temp_path: uploads.append(remote_temp_path)  # type: ignore[assignment]

                def fake_run(client, command: str, *, sudo_password: str = "", use_sudo: bool = False):  # noqa: ARG001
                    commands.append((command, use_sudo))
                    if "systemctl is-active" in command:
                        return 0, "active\n", ""
                    return 0, "", ""

                vm1_deploy._run_command = fake_run  # type: ignore[assignment]

                env = {
                    "SIEM_VM1_HOST": "vm1",
                    "SIEM_VM1_USER": "rdegon",
                    "SIEM_VM1_PASSWORD": "secret",
                    "SIEM_VM1_BASE_DIR": "/opt/siem/siem-solution",
                }
                previous = {key: os.environ.get(key) for key in env}
                os.environ.update(env)
                try:
                    result = vm1_deploy.main()
                finally:
                    for key, value in previous.items():
                        if value is None:
                            os.environ.pop(key, None)
                        else:
                            os.environ[key] = value

                self.assertEqual(result, 0)
                self.assertTrue(any(path.endswith("/.siem-tmp/app.py") for path in uploads))
                self.assertTrue(any("install -m 0644" in command and use_sudo for command, use_sudo in commands))
                self.assertTrue(any("SIEM_KAFKA_NODE_ID=1" in command for command, _ in commands))
        finally:
            vm1_deploy.ROOT = original_root
            vm1_deploy.FILE_MAPPINGS = original_mappings
            vm1_deploy._connect_client = original_connect  # type: ignore[assignment]
            vm1_deploy._backup_file = original_backup  # type: ignore[assignment]
            vm1_deploy._upload_text = original_upload  # type: ignore[assignment]
            vm1_deploy._run_command = original_run  # type: ignore[assignment]

    def test_vm3_deploy_uses_staging_and_sudo_install(self) -> None:
        import deploy.vm3_stream_corr_event_time_deploy as vm3_deploy

        commands: list[tuple[str, bool]] = []
        uploads: list[str] = []
        original_root = vm3_deploy.ROOT
        original_mappings = vm3_deploy.FILE_MAPPINGS
        original_connect = vm3_deploy._connect_client
        original_backup = vm3_deploy._backup_path
        original_upload = vm3_deploy._upload_text
        original_run = vm3_deploy._run_command
        original_set_env = vm3_deploy._set_remote_env_values
        original_template = vm3_deploy.WRITER_TEMPLATE_LOCAL
        try:
            with tempfile.TemporaryDirectory() as tmp:
                tmp_root = Path(tmp)
                runtime_file = tmp_root / "services/transport_runtime.py"
                runtime_file.parent.mkdir(parents=True, exist_ok=True)
                runtime_file.write_text("print('ok')\n", encoding="utf-8")
                template_file = tmp_root / "deploy/vm3/siem-writer@.service"
                template_file.parent.mkdir(parents=True, exist_ok=True)
                template_file.write_text("[Unit]\nDescription=test\n", encoding="utf-8")

                vm3_deploy.ROOT = tmp_root
                vm3_deploy.FILE_MAPPINGS = (vm3_deploy.FileMapping("services/transport_runtime.py", "services/transport_runtime.py"),)
                vm3_deploy.WRITER_TEMPLATE_LOCAL = template_file
                vm3_deploy._connect_client = lambda *args, **kwargs: _FakeClient()  # type: ignore[assignment]
                vm3_deploy._backup_path = lambda *args, **kwargs: None  # type: ignore[assignment]
                vm3_deploy._upload_text = lambda sftp, *, content, remote_temp_path: uploads.append(remote_temp_path)  # type: ignore[assignment]
                vm3_deploy._set_remote_env_values = lambda *args, **kwargs: None  # type: ignore[assignment]

                def fake_run(client, command: str, *, sudo_password: str = "", use_sudo: bool = False):  # noqa: ARG001
                    commands.append((command, use_sudo))
                    if "systemctl is-active" in command:
                        return 0, "active\nactive\nactive\nactive\n", ""
                    return 0, "", ""

                vm3_deploy._run_command = fake_run  # type: ignore[assignment]

                env = {
                    "SIEM_VM3_HOST": "vm3",
                    "SIEM_VM3_USER": "rdegon",
                    "SIEM_VM3_PASSWORD": "secret",
                    "SIEM_VM3_BASE_DIR": "/opt/siem/siem-solution",
                }
                previous = {key: os.environ.get(key) for key in env}
                os.environ.update(env)
                try:
                    result = vm3_deploy.main()
                finally:
                    for key, value in previous.items():
                        if value is None:
                            os.environ.pop(key, None)
                        else:
                            os.environ[key] = value

                self.assertEqual(result, 0)
                self.assertTrue(any(path.endswith("/.siem-tmp/transport_runtime.py") for path in uploads))
                self.assertTrue(any("install -m 0644" in command and use_sudo for command, use_sudo in commands))
        finally:
            vm3_deploy.ROOT = original_root
            vm3_deploy.FILE_MAPPINGS = original_mappings
            vm3_deploy.WRITER_TEMPLATE_LOCAL = original_template
            vm3_deploy._connect_client = original_connect  # type: ignore[assignment]
            vm3_deploy._backup_path = original_backup  # type: ignore[assignment]
            vm3_deploy._upload_text = original_upload  # type: ignore[assignment]
            vm3_deploy._run_command = original_run  # type: ignore[assignment]
            vm3_deploy._set_remote_env_values = original_set_env  # type: ignore[assignment]

    def test_vm3_stream_corr_shadow_compare_defaults_to_production_off(self) -> None:
        deploy_text = (ROOT / "deploy" / "vm3_stream_corr_event_time_deploy.py").read_text(encoding="utf-8")
        smoke_text = (ROOT / "deploy" / "vm3_stream_corr_event_time_smoke.py").read_text(encoding="utf-8")
        runbook_text = (ROOT / "docs" / "deployment_runbook_vm3_stream_corr_event_time.md").read_text(encoding="utf-8")

        self.assertIn('os.getenv("SIEM_STREAM_CORR_SHADOW_COMPARE", "false") or "false"', deploy_text)
        self.assertIn('os.getenv("SIEM_STREAM_CORR_SHADOW_COMPARE", "false") or "false"', smoke_text)
        self.assertIn("SIEM_STREAM_CORR_SHADOW_COMPARE=false", runbook_text)
        self.assertIn('os.getenv("SIEM_STREAM_CORR_BATCH_SIZE", "1000") or "1000"', deploy_text)
        self.assertIn("SIEM_STREAM_CORR_BATCH_SIZE=1000", runbook_text)

    def test_vm4_smoke_waits_for_backend_warmup(self) -> None:
        import deploy.vm4_enterprise_foundation_smoke as vm4_smoke

        client = types.SimpleNamespace()
        calls = {"request_with_meta": 0}

        def fake_request_with_meta(path: str, *, attempts: int = 4, delay_seconds: float = 2.0, method: str = "GET", headers=None, data=None):  # noqa: ARG001
            calls["request_with_meta"] += 1
            if calls["request_with_meta"] < 3:
                raise RuntimeError("HTTP 502")
            return 200, "", "https://example.test/auth/login"

        client.request_with_meta = fake_request_with_meta
        original_sleep = vm4_smoke.time.sleep
        try:
            vm4_smoke.time.sleep = lambda *_args, **_kwargs: None  # type: ignore[assignment]
            vm4_smoke._wait_for_backend_ready(client, attempts=4, delay_seconds=0.01)
        finally:
            vm4_smoke.time.sleep = original_sleep  # type: ignore[assignment]
        self.assertEqual(calls["request_with_meta"], 3)

    def test_vm4_final_smoke_tolerates_low_signal_ingest_residuals_without_env_gate(self) -> None:
        smoke_text = (ROOT / "deploy" / "vm4_enterprise_foundation_smoke.py").read_text(encoding="utf-8")

        self.assertIn('if issues and all(_is_noncritical_residual_ingest_issue(item) for item in issues):', smoke_text)
        self.assertNotIn(
            'if issues and _env_enabled("SIEM_SMOKE_REMEDIATE_INGEST_OVERVIEW_ISSUES") and all(',
            smoke_text,
        )

    def test_vm4_final_smoke_uses_bounded_slow_api_timeouts(self) -> None:
        smoke_text = (ROOT / "deploy" / "vm4_enterprise_foundation_smoke.py").read_text(encoding="utf-8")

        self.assertIn("SLOW_API_TIMEOUT_SECONDS = 75.0", smoke_text)
        self.assertIn('os.getenv("SIEM_VM4_SSH_HOST") or vm4_host', smoke_text)
        self.assertIn("def _vm4_runtime_state(", smoke_text)
        self.assertIn('os.getenv("SIEM_PROXMOX_PASSWORD"', smoke_text)
        self.assertIn("pve.guest_exec(vmid, command", smoke_text)
        self.assertIn("_connect_client(vm4_ssh_host, vm4_user, vm4_password)", smoke_text)
        self.assertIn("/api/dashboard/summary?window=24h&bucket_minutes=60&recent_limit=10", smoke_text)
        self.assertIn("timeout_seconds=SLOW_API_TIMEOUT_SECONDS if path in slow_json_paths", smoke_text)
        self.assertNotIn("/api/dashboard/summary?window=72h&bucket_minutes=15&recent_limit=20", smoke_text)

    def test_watchdog_and_smoke_raise_dlq_replay_batch_limit(self) -> None:
        watchdog_text = (ROOT / "deploy" / "homelab_watchdog.py").read_text(encoding="utf-8")
        vm4_smoke_text = (ROOT / "deploy" / "vm4_enterprise_foundation_smoke.py").read_text(encoding="utf-8")

        self.assertIn('SIEM_INGEST_REPLAY_BATCH_LIMIT", default="2000"', watchdog_text)
        self.assertIn('SIEM_INGEST_REPLAY_BATCHES_PER_ATTEMPT", default="5"', watchdog_text)
        self.assertIn('SIEM_INGEST_REPLAY_BATCH_LIMIT", "2000"', vm4_smoke_text)
        self.assertIn('SIEM_INGEST_REPLAY_BATCHES_PER_ATTEMPT", "5"', vm4_smoke_text)

    def test_storage_ha_redis_retirement_is_timeout_bounded(self) -> None:
        import deploy.storage_ha_wave_deploy as storage_ha

        command = storage_ha._redis_retirement_command()

        self.assertIn("timeout 90s apt-get", command)
        self.assertIn("Dpkg::Lock::Timeout=20", command)
        self.assertNotIn("autoremove", command)

    def test_vm4_deploy_includes_vulnerability_maturity_modules(self) -> None:
        import deploy.vm4_enterprise_foundation_deploy as vm4_deploy

        remote_paths = {mapping.remote_rel for mapping in vm4_deploy.FILE_MAPPINGS}
        self.assertIn("services/web/app/vuln_maturity_runtime.py", remote_paths)
        self.assertIn("services/web/app/vuln_store.py", remote_paths)
        self.assertIn("services/web/app/vuln_greenbone.py", remote_paths)
        self.assertIn("deploy/vm4/siem-vault-unseal.sh", remote_paths)
        self.assertIn("deploy/vm4/siem-ingest-recovery-watchdog.service", remote_paths)
        self.assertIn("deploy/vm4/siem-ingest-recovery-watchdog.timer", remote_paths)
        self.assertIn("query/__init__.py", remote_paths)
        self.assertIn("services/web/app/query/__init__.py", remote_paths)
        self.assertFalse(any("__pycache__" in path for path in remote_paths))
        self.assertFalse(any(path.endswith((".pyc", ".pyo")) for path in remote_paths))

    def test_vm4_runtime_bridge_sets_meaningful_watchdog_event_floor(self) -> None:
        import deploy.vm4_enterprise_foundation_deploy as vm4_deploy

        previous = os.environ.pop("SIEM_WATCHDOG_MIN_EVENTS_5M", None)
        try:
            updates = vm4_deploy._runtime_bridge_env_updates()
        finally:
            if previous is not None:
                os.environ["SIEM_WATCHDOG_MIN_EVENTS_5M"] = previous
        self.assertEqual(updates.get("SIEM_WATCHDOG_MIN_EVENTS_5M"), "1600")

    def test_vm4_vault_service_auto_unseals_and_web_waits_for_vault(self) -> None:
        vault_unit = (ROOT / "deploy" / "vm4" / "siem-vault.service").read_text(encoding="utf-8")
        vault_unseal = (ROOT / "deploy" / "vm4" / "siem-vault-unseal.sh").read_text(encoding="utf-8")
        web_override = (ROOT / "deploy" / "vm4" / "siem-web.override.conf").read_text(encoding="utf-8")
        keycloak_unit = (ROOT / "deploy" / "vm4" / "siem-keycloak.service").read_text(encoding="utf-8")
        smoke_text = (ROOT / "deploy" / "vm4_enterprise_foundation_smoke.py").read_text(encoding="utf-8")

        self.assertIn("ExecStartPost=/usr/local/bin/siem-vault-unseal.sh", vault_unit)
        self.assertIn("Environment=VAULT_ADDR=http://127.0.0.1:8200", vault_unit)
        self.assertIn("TimeoutStartSec=180", vault_unit)
        self.assertIn('timeout 6s "$VAULT_BIN" status -format=json >"$STATUS_PATH"', vault_unseal)
        self.assertIn('if [[ -s "$STATUS_PATH" ]]; then', vault_unseal)
        self.assertIn("Requires=siem-vault.service", keycloak_unit)
        self.assertIn("After=siem-vault.service siem-keycloak.service", web_override)
        self.assertIn("Requires=siem-vault.service siem-keycloak.service", web_override)
        self.assertIn('/opt/siem/vault/current/vault status -format=json', smoke_text)

    def test_vm4_deploy_restarts_vault_before_dependent_services(self) -> None:
        deploy_text = (ROOT / "deploy" / "vm4_enterprise_foundation_deploy.py").read_text(encoding="utf-8")

        self.assertIn("systemctl restart siem-vault", deploy_text)
        self.assertIn("_ensure_vault_runtime_ready(client, sudo_password=password)", deploy_text)
        self.assertIn("systemctl restart siem-keycloak openvpn-client@home-gateway", deploy_text)
        self.assertLess(
            deploy_text.index("systemctl restart siem-vault"),
            deploy_text.index("_ensure_vault_runtime_ready(client, sudo_password=password)"),
        )
        self.assertLess(
            deploy_text.index("_ensure_vault_runtime_ready(client, sudo_password=password)"),
            deploy_text.index("systemctl restart siem-keycloak openvpn-client@home-gateway"),
        )

    def test_vm4_deploy_bounds_cleanup_ssh_wait(self) -> None:
        deploy_text = (ROOT / "deploy" / "vm4_enterprise_foundation_deploy.py").read_text(encoding="utf-8")

        self.assertIn("timeout 240s", deploy_text)
        self.assertIn("timeout_seconds=270.0", deploy_text)

    def test_vm4_openvpn_routes_cover_current_management_and_user_segments(self) -> None:
        up_script = (ROOT / "deploy" / "vm4" / "home-gateway-up.sh").read_text(encoding="utf-8")
        down_script = (ROOT / "deploy" / "vm4" / "home-gateway-down.sh").read_text(encoding="utf-8")
        full_profile_routes = (
            ROOT / "deploy" / "windows-agent" / "openvpn-routes-04-siem-full-lab.txt"
        ).read_text(encoding="utf-8")

        for script in (up_script, down_script):
            self.assertIn("192.168.3.0/24", script)
            self.assertIn("10.20.40.0/24", script)
            self.assertIn("LAN_SUBNETS", script)
            self.assertIn("SEG_SUBNETS", script)
        self.assertIn("route 192.168.3.0 255.255.255.0 vpn_gateway", full_profile_routes)
        self.assertIn("route 10.20.40.0 255.255.255.0 vpn_gateway", full_profile_routes)

    def test_segmented_edge_supports_vpn_hairpin_to_public_siem_entrypoint(self) -> None:
        staging = (
            ROOT / "deploy" / "network_relocation" / "stage_full_segmentation.py"
        ).read_text(encoding="utf-8")

        self.assertIn(
            'iifname "eth2" ip saddr {sec["hosts"]["siem-web"]} '
            'ip daddr {mgmt["hosts"]["lab-edge-01"]} tcp dport 443',
            staging,
        )
        self.assertIn(
            'ip saddr {sec["hosts"]["siem-web"]} '
            'ip daddr {sec["hosts"]["siem-web"]} tcp dport {{ 80, 443 }} '
            'snat to {sec["gateway"]}',
            staging,
        )
        self.assertIn(
            'ip saddr {sec["hosts"]["siem-web"]} '
            'ip daddr {sec["hosts"]["siem-ingest"]} tcp dport 443 '
            'snat to {sec["gateway"]}',
            staging,
        )

    def test_vm4_deploy_prepares_writable_vuln_runtime_dirs(self) -> None:
        deploy_text = (ROOT / "deploy" / "vm4_enterprise_foundation_deploy.py").read_text(encoding="utf-8")
        self.assertIn("services/web/runtime-vuln/greenbone-artifacts", deploy_text)
        self.assertIn("Failed to prepare writable VM4 runtime directories", deploy_text)
        self.assertIn("chown -R", deploy_text)

    def test_vm4_deploy_includes_decomposition_and_frontend_modules(self) -> None:
        import deploy.vm4_enterprise_foundation_deploy as vm4_deploy

        remote_paths = {mapping.remote_rel for mapping in vm4_deploy.FILE_MAPPINGS}
        self.assertIn("enterprise_control_plane_defaults.py", remote_paths)
        self.assertIn("inventory_catalog.py", remote_paths)
        self.assertIn("proxmox_fleet_runtime.py", remote_paths)
        self.assertIn("response_workflow_runtime.py", remote_paths)
        self.assertIn("source_onboarding_runtime.py", remote_paths)
        self.assertIn("vuln_asset_binding.py", remote_paths)
        self.assertIn("services/web/app/enterprise_control_plane_defaults.py", remote_paths)
        self.assertIn("services/web/app/inventory_catalog.py", remote_paths)
        self.assertIn("services/web/app/proxmox_fleet_runtime.py", remote_paths)
        self.assertIn("services/web/app/response_workflow_runtime.py", remote_paths)
        self.assertIn("services/web/app/source_onboarding_runtime.py", remote_paths)
        self.assertIn("source_discovery.py", remote_paths)
        self.assertIn("services/web/app/vuln_asset_binding.py", remote_paths)
        self.assertIn("services/web/app/vuln_exposure_runtime.py", remote_paths)
        self.assertIn("services/web/app/routes/console_router_registry.py", remote_paths)
        self.assertIn("services/web/frontend-react/src/shell/pages/HostRuntimePage.tsx", remote_paths)
        self.assertIn("services/web/frontend-react/src/shell/pages/ResponsePage.tsx", remote_paths)
        self.assertIn("services/web/frontend-react/src/shell/timeControls.ts", remote_paths)
        self.assertIn("tests/test_response_maturity.py", remote_paths)
        self.assertIn("tests/test_proxmox_fleet_runtime.py", remote_paths)
        self.assertIn("tests/test_vuln_maturity_runtime.py", remote_paths)
        self.assertIn("tests/test_vuln_exposure_runtime.py", remote_paths)
        self.assertIn("tests/test_vuln_greenbone.py", remote_paths)
        self.assertIn("deploy/ansible/vuln_validate.yml", remote_paths)
        self.assertIn("deploy/ansible/vuln_patch_package.yml", remote_paths)
        self.assertIn("deploy/windows-agent/build-openvpn-route-profile.ps1", remote_paths)
        self.assertIn("deploy/windows-agent/get-windows-event-agent-status.ps1", remote_paths)
        self.assertIn("deploy/windows-agent/install-windows-event-agent.ps1", remote_paths)
        self.assertIn("deploy/windows-agent/package-windows-event-agent.ps1", remote_paths)
        self.assertIn("deploy/vuln/rdegon_greenbone_start_wave.py", remote_paths)
        self.assertIn("deploy/publish_operational_rule_packs.py", remote_paths)
        self.assertIn("deploy/publish_assignment_detection_pack.py", remote_paths)
        self.assertIn("deploy/publish_rule_noise_tuning.py", remote_paths)
        self.assertIn("correlation_rule_packs/fleet_observability_v1.json", remote_paths)
        self.assertIn("correlation_rule_packs/openclaw_behavior_v1.json", remote_paths)
        self.assertIn("correlation_rule_packs/vuln_coverage_v1.json", remote_paths)
        self.assertIn("correlation_rule_packs/pilot_services_v1.json", remote_paths)
        self.assertIn("ops/windows-agent-profile.local.example.json", remote_paths)

    def test_operational_rule_pack_publisher_avoids_clickhouse_mutations(self) -> None:
        publish_text = (ROOT / "deploy" / "publish_operational_rule_packs.py").read_text(encoding="utf-8")

        self.assertNotIn("ALTER TABLE", publish_text)
        self.assertIn("_existing_rule_ids(rule_ids)", publish_text)
        self.assertIn("stream_missing", publish_text)

    def test_assignment_rule_pack_publisher_retires_noisy_demoted_rules(self) -> None:
        publish_text = (ROOT / "deploy" / "publish_assignment_detection_pack.py").read_text(encoding="utf-8")
        deploy_text = (ROOT / "deploy" / "vm4_enterprise_foundation_deploy.py").read_text(encoding="utf-8")

        self.assertIn("retired_runtime_rule_ids", publish_text)
        self.assertIn("false_positive", publish_text)
        self.assertIn("lightweight_deletes_sync=2", publish_text)
        self.assertNotIn("SETTINGS mutations_sync=1", publish_text)
        self.assertIn("publish_assignment_detection_pack.py", deploy_text)

    def test_rule_noise_tuning_publisher_is_in_vm4_deploy(self) -> None:
        publish_text = (ROOT / "deploy" / "publish_rule_noise_tuning.py").read_text(encoding="utf-8")
        deploy_text = (ROOT / "deploy" / "vm4_enterprise_foundation_deploy.py").read_text(encoding="utf-8")

        self.assertIn("REPUBLISH_STREAM_RULE_IDS", publish_text)
        self.assertIn("RETIRE_OPEN_ALERT_RULE_IDS", publish_text)
        self.assertIn("publish_rule_noise_tuning.py", deploy_text)

    def test_proxmox_fleet_wave_includes_secondary_nmap_bundle(self) -> None:
        import deploy.proxmox_fleet_wave_deploy as fleet_wave

        navidrome = next(spec for spec in fleet_wave.GUESTS if spec.name == "navidrome-01")
        vuln_manager = next(spec for spec in fleet_wave.GUESTS if spec.name == "vuln-mgr-01")
        self.assertFalse(navidrome.needs_nmap_exporter)
        self.assertNotIn("rdegon-vuln-scan.timer", navidrome.services)
        self.assertTrue(vuln_manager.needs_nmap_exporter)
        self.assertIn("rdegon-vuln-scan.timer", vuln_manager.services)
        self.assertIn("10.20.10.107", fleet_wave.NMAP_EXPOSURE_TARGETS)
        self.assertNotIn("192.168.1.39", fleet_wave.NMAP_EXPOSURE_TARGETS)
        deploy_text = (ROOT / "deploy" / "proxmox_fleet_wave_deploy.py").read_text(encoding="utf-8")
        self.assertIn("/etc/default/rdegon-vuln-scan", deploy_text)
        self.assertIn("/opt/rdegon-siem-vuln/targets.txt", deploy_text)

    def test_proxmox_fleet_wave_enables_linux_audit_for_qemu_guests(self) -> None:
        import deploy.proxmox_fleet_wave_deploy as fleet_wave

        qemu_guests = [spec for spec in fleet_wave.GUESTS if spec.guest_type == "qemu"]
        self.assertTrue(qemu_guests)
        self.assertTrue(all("auditd" in spec.services for spec in qemu_guests))
        deploy_text = (ROOT / "deploy" / "proxmox_fleet_wave_deploy.py").read_text(encoding="utf-8")
        smoke_text = (ROOT / "deploy" / "proxmox_fleet_wave_smoke.py").read_text(encoding="utf-8")
        self.assertIn("/etc/audit/rules.d/50-siem-linux-audit.rules", deploy_text)
        self.assertIn("audispd-plugins", deploy_text)
        self.assertIn("auditd", smoke_text)

    def test_windows_collection_defaults_include_extended_security_channels(self) -> None:
        expected_channels = (
            "Microsoft-Windows-Windows Defender/Operational",
            "Microsoft-Windows-WMI-Activity/Operational",
            "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
            "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
            "Microsoft-Windows-TaskScheduler/Operational",
            "Microsoft-Windows-WinRM/Operational",
        )
        file_paths = (
            ROOT / "deploy" / "windows" / "rdegon-siem-collector.ps1",
            ROOT / "windows-event-agent" / "src" / "Rdegon.WindowsEventAgent" / "AgentOptions.cs",
            ROOT / "ops" / "windows-agent-profile.local.example.json",
            ROOT / "deploy" / "windows-agent" / "remote-vpn-profile-01-windows-agent-vpn-ingest-only-no-sysmon.json",
            ROOT / "deploy" / "windows-agent" / "remote-vpn-profile-04-windows-agent-vpn-high-latency-sysmon.json",
        )
        for file_path in file_paths:
            contents = file_path.read_text(encoding="utf-8")
            for channel in expected_channels:
                self.assertIn(channel, contents)

    def test_vm4_identity_bootstrap_reuses_existing_vault_runtime(self) -> None:
        import deploy.vm4_identity_governance_bootstrap as identity_bootstrap

        commands: list[str] = []
        original_run = identity_bootstrap._run_command
        original_download = identity_bootstrap._download_vendor_artifact
        original_upload = identity_bootstrap._upload_vendor_artifact
        try:
            def fake_run(_client, command: str, *, sudo_password: str = "", use_sudo: bool = False):  # noqa: ARG001
                commands.append(command)
                if command.startswith("test -e "):
                    return 0, "", ""
                return 0, "", ""

            def fail_download(*_args, **_kwargs):
                raise AssertionError("download should not run when Vault runtime is already installed")

            identity_bootstrap._run_command = fake_run  # type: ignore[assignment]
            identity_bootstrap._download_vendor_artifact = fail_download  # type: ignore[assignment]
            identity_bootstrap._upload_vendor_artifact = fail_download  # type: ignore[assignment]

            identity_bootstrap._ensure_vault_binary(_FakeClient(), _FakeSftp(), sudo_password="secret")
        finally:
            identity_bootstrap._run_command = original_run  # type: ignore[assignment]
            identity_bootstrap._download_vendor_artifact = original_download  # type: ignore[assignment]
            identity_bootstrap._upload_vendor_artifact = original_upload  # type: ignore[assignment]

        self.assertTrue(any(command.startswith("test -e ") for command in commands))
        self.assertTrue(any("/opt/siem/vault" in command and "current.symlink_to" in command for command in commands))

    def test_vm4_identity_bootstrap_reuses_existing_keycloak_runtime(self) -> None:
        import deploy.vm4_identity_governance_bootstrap as identity_bootstrap

        commands: list[str] = []
        original_run = identity_bootstrap._run_command
        original_download = identity_bootstrap._download_vendor_artifact
        original_upload = identity_bootstrap._upload_vendor_artifact
        try:
            def fake_run(_client, command: str, *, sudo_password: str = "", use_sudo: bool = False):  # noqa: ARG001
                commands.append(command)
                if command.startswith("test -e "):
                    return 0, "", ""
                return 0, "", ""

            def fail_download(*_args, **_kwargs):
                raise AssertionError("download should not run when Keycloak runtime is already installed")

            identity_bootstrap._run_command = fake_run  # type: ignore[assignment]
            identity_bootstrap._download_vendor_artifact = fail_download  # type: ignore[assignment]
            identity_bootstrap._upload_vendor_artifact = fail_download  # type: ignore[assignment]

            identity_bootstrap._ensure_keycloak_binary(_FakeClient(), _FakeSftp(), sudo_password="secret")
        finally:
            identity_bootstrap._run_command = original_run  # type: ignore[assignment]
            identity_bootstrap._download_vendor_artifact = original_download  # type: ignore[assignment]
            identity_bootstrap._upload_vendor_artifact = original_upload  # type: ignore[assignment]

        self.assertTrue(any(command.startswith("test -e ") for command in commands))
        self.assertTrue(any("/opt/siem/keycloak" in command and "current.symlink_to" in command for command in commands))

    def test_vm4_identity_bootstrap_keycloak_config_uses_user_ids(self) -> None:
        import deploy.vm4_identity_governance_bootstrap as identity_bootstrap

        commands: list[str] = []
        original_run = identity_bootstrap._run_command
        try:
            def fake_run(_client, command: str, *, sudo_password: str = "", use_sudo: bool = False):  # noqa: ARG001
                commands.append(command)
                return 0, "", ""

            identity_bootstrap._run_command = fake_run  # type: ignore[assignment]
            identity_bootstrap._configure_keycloak(
                _FakeClient(),
                admin_user="siem-admin",
                admin_password="secret-admin",
                realm_name="siem",
                base_url="https://192.168.1.39",
                operator_username="admin",
                operator_password="secret-operator",
                client_secret="oidc-secret",
                admin_client_secret="admin-client-secret",
                sudo_password="secret",
            )
        finally:
            identity_bootstrap._run_command = original_run  # type: ignore[assignment]

        self.assertEqual(len(commands), 1)
        script = commands[0]
        self.assertIn("-q exact=true", script)
        self.assertIn('--userid "$user_id"', script)
        self.assertIn('--uid "$user_id"', script)


if __name__ == "__main__":
    unittest.main()
