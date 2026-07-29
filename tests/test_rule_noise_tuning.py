from __future__ import annotations

import json
from pathlib import Path

from services.filter.filter_core import eval_expr, parse_expr


ROOT = Path(__file__).resolve().parents[1]


def _pack_rule(pack_name: str, rule_id: int) -> dict[str, object]:
    payload = json.loads((ROOT / "correlation_rule_packs" / pack_name).read_text(encoding="utf-8"))
    for rule in payload.get("stream_rules") or []:
        if isinstance(rule, dict) and int(rule.get("id") or 0) == rule_id:
            return rule
    raise AssertionError(f"Rule {rule_id} not found in {pack_name}")


def _matches(expr: str, event: dict[str, str]) -> bool:
    return bool(eval_expr(parse_expr(expr), event))


def test_windows_noise_rules_exclude_collector_system_and_wmi_lifecycle() -> None:
    service_install = _pack_rule("windows_activity_v1.json", 2605)
    explicit_creds = _pack_rule("windows_activity_v1.json", 2612)
    powershell = _pack_rule("windows_activity_v1.json", 2604)
    privileges = _pack_rule("windows_activity_v1.json", 2611)
    defender = _pack_rule("windows_activity_v1.json", 2616)
    wmi = _pack_rule("windows_activity_v1.json", 2618)

    assert "sigma_yaml" not in service_install
    assert "RdegonSIEMCollector" in str(service_install["expr"])
    assert "collector-state.json" in str(service_install["expr"])
    assert "sigma_yaml" not in explicit_creds
    assert "svchost.exe" in str(explicit_creds["expr"])
    assert "S-1-5-18" in str(explicit_creds["expr"])
    assert "sigma_yaml" not in powershell
    assert "RdegonSIEMCollector" in str(powershell["expr"])
    assert "collector-state.json" in str(powershell["expr"])
    assert "SYSTEM" in str(privileges["expr"])
    assert "S-1-5-18" in str(privileges["expr"])
    assert "sigma_yaml" not in defender
    assert "DisableRealtimeMonitoring" in str(defender["expr"])
    assert "TamperProtection" in str(defender["expr"])
    assert "Exclusions\\Paths" in str(defender["expr"])
    assert "ToastOrSsoTrigger" in str(defender["expr"])
    assert "MpEngine" in str(defender["expr"])
    assert "Features\\EcsConfigs" in str(defender["expr"])
    assert "Features\\Controls" in str(defender["expr"])
    assert "wmi_remote_query" in str(wmi["expr"])
    assert "wmi_remote_execution" in str(wmi["expr"])
    assert "wmi_local_query" not in str(wmi["expr"])
    wmi_persistence = _pack_rule("windows_activity_v1.json", 2619)
    assert int(wmi_persistence["threshold"]) == 1
    assert "wmi_persistence" in str(wmi_persistence["expr"])


def test_windows_defender_rule_matches_tamper_settings_not_update_churn() -> None:
    defender = _pack_rule("windows_activity_v1.json", 2616)
    expr = str(defender["expr"])

    benign_update = {
        "event.type": "windows_defender_configuration_changed",
        "event.original": (
            "Microsoft Defender Antivirus Configuration has changed. "
            "Old value: HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Features\\EcsConfigs\\ETag\\Tag = old "
            "New value: HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Features\\EcsConfigs\\ETag\\Tag = new"
        ),
        "tags": "",
    }
    tamper_disable = {
        "event.type": "windows_defender_configuration_changed",
        "event.original": (
            "Microsoft Defender Antivirus Configuration has changed. "
            "New value: HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Real-Time Protection\\DisableRealtimeMonitoring = 0x1"
        ),
        "tags": "",
    }

    assert not _matches(expr, benign_update)
    assert _matches(expr, tamper_disable)


def test_linux_systemd_unit_rules_ignore_dpkg_tmp_package_updates() -> None:
    linux_rule = _pack_rule("linux_activity_v1.json", 2706)
    tmp_exec_rule = _pack_rule("linux_activity_v1.json", 2711)
    openclaw_rule = _pack_rule("openclaw_behavior_v1.json", 2303)
    dpkg_path_event = {
        "event.provider": "linux.auditd",
        "event.type": "linux_systemd_unit_modified",
        "event.original": 'type=PATH name="/lib/systemd/system/rsync.service.dpkg-tmp" nametype=DELETE',
        "host.name": "openclaw-gateway",
        "tags": "",
    }
    direct_unit_change = {
        "event.provider": "linux.auditd",
        "event.type": "linux_systemd_unit_modified",
        "event.original": 'type=PATH name="/etc/systemd/system/xray.service" nametype=NORMAL',
        "host.name": "openclaw-gateway",
        "tags": "",
    }
    managed_siem_unit_change = {
        "event.provider": "linux.auditd",
        "event.type": "linux_systemd_unit_modified",
        "event.original": 'type=PATH name="/etc/systemd/system/siem-web.service" nametype=NORMAL',
        "host.name": "siem-web",
        "tags": "siem-core",
    }

    assert "sigma_yaml" not in linux_rule
    assert "dpkg-tmp" in str(linux_rule["expr"])
    assert "ubuntu-advantage.service" in str(linux_rule["expr"])
    assert "ua-timer.service" in str(linux_rule["expr"])
    assert not _matches(str(linux_rule["expr"]), dpkg_path_event)
    assert not _matches(str(linux_rule["expr"]), managed_siem_unit_change)
    assert _matches(str(linux_rule["expr"]), direct_unit_change)
    assert not _matches(
        str(linux_rule["expr"]),
        {
            "event.provider": "linux.auditd",
            "event.type": "linux_systemd_unit_modified",
            "event.original": (
                'type=PATH name="/etc/systemd/system/'
                'snap.lxd.daemon.service.X3Y7~" nametype=CREATE'
            ),
            "host.name": "siem-ingest",
            "log_source": "siem-ingest",
            "tags": "",
        },
    )
    assert _matches(
        str(linux_rule["expr"]),
        {
            "event.provider": "linux.auditd",
            "event.type": "linux_systemd_unit_modified",
            "event.original": (
                'type=PATH name="/etc/systemd/system/evil-persistence.service" '
                "nametype=CREATE"
            ),
            "host.name": "siem-ingest",
            "log_source": "siem-ingest",
            "tags": "",
        },
    )
    assert "sigma_yaml" not in tmp_exec_rule
    assert "apt-dpkg-install" in str(tmp_exec_rule["expr"])
    assert not _matches(
        str(tmp_exec_rule["expr"]),
        {
            "event.provider": "linux.auditd",
            "event.type": "linux_exec_from_tmp",
            "process.command_line": "/usr/bin/dpkg --status-fd 11 --recursive /tmp/apt-dpkg-install-c0Qr1W",
            "user.target.name": "/tmp/apt-dpkg-install-c0Qr1W",
            "tags": "",
        },
    )
    assert _matches(
        str(tmp_exec_rule["expr"]),
        {
            "event.provider": "linux.auditd",
            "event.type": "linux_exec_from_tmp",
            "process.command_line": "/tmp/.x/payload --connect 198.51.100.9",
            "user.target.name": "/tmp/.x/payload",
            "tags": "",
        },
    )
    assert not _matches(
        str(tmp_exec_rule["expr"]),
        {
            "event.provider": "linux.auditd",
            "event.type": "linux_exec_from_tmp",
            "process.command_line": "install -m 0644 /tmp/deploy-unit.service /etc/systemd/system/deploy-unit.service",
            "user.target.name": "/etc/systemd/system/deploy-unit.service",
            "tags": "",
        },
    )
    assert "sigma_yaml" not in openclaw_rule
    assert not _matches(str(openclaw_rule["expr"]), dpkg_path_event)
    assert _matches(str(openclaw_rule["expr"]), direct_unit_change)


def test_gitea_admin_rule_ignores_qemu_agent_commands_but_keeps_admin_changes() -> None:
    rule = _pack_rule("source_coverage_v1.json", 2902)
    expr = str(rule["expr"])

    assert "sigma_yaml" not in rule
    assert not _matches(
        expr,
        {
            "event.provider": "linux.qemu-ga",
            "event.original": (
                "guest-exec docker exec pilot-gitea gitea admin user list"
            ),
            "host.name": "pilot-web-01",
            "log_source": "pilot-web-01",
            "tags": "",
        },
    )
    assert _matches(
        expr,
        {
            "event.provider": "linux.pilot-gitea",
            "event.action": "user_promote_admin",
            "event.original": "user promoted to admin",
            "host.name": "pilot-web-01",
            "log_source": "pilot-web-01",
            "tags": "",
        },
    )


def test_pilot_traversal_and_proxmox_root_rules_require_structured_attack_signal() -> None:
    traversal = _pack_rule("siem_detection_pack_v1.json", 8328)
    root_login = _pack_rule("siem_detection_pack_v1.json", 8046)

    assert not _matches(
        str(traversal["expr"]),
        {
            "event.provider": "linux.pilot-gitea",
            "event.original": (
                "modules/actions/notifier_helper.go:167 notify reference update"
            ),
            "host.name": "pilot-web-01",
            "log_source": "pilot-web-01",
            "tags": "",
        },
    )
    assert _matches(
        str(traversal["expr"]),
        {
            "event.provider": "linux.nginx-access",
            "event.original": 'GET /../../etc/passwd HTTP/1.1" 400',
            "url.path": "/../../etc/passwd",
            "url.original": "/../../etc/passwd",
            "host.name": "pilot-web-01",
            "log_source": "pilot-web-01",
            "source.ip": "198.51.100.20",
            "tags": "",
        },
    )
    assert not _matches(
        str(root_login["expr"]),
        {
            "event.provider": "linux.pvedaemon",
            "event.type": "proxmox_authentication_success",
            "event.outcome": "success",
            "user.name": "root@pam",
            "host.name": "pve",
            "log_source": "pve",
            "source.ip": "192.168.3.101",
            "tags": "",
        },
    )
    assert _matches(
        str(root_login["expr"]),
        {
            "event.provider": "linux.pveproxy",
            "event.type": "proxmox_authentication_success",
            "event.outcome": "success",
            "user.name": "root@pam",
            "host.name": "pve",
            "log_source": "pve",
            "source.ip": "198.51.100.40",
            "tags": "",
        },
    )


def test_linux_file_and_process_rules_use_stable_composite_entities() -> None:
    expected = {
        2704: "host.name+file.path",
        2706: "host.name+file.path",
        2711: "host.name+process.executable",
        2715: "host.name+file.path",
        2716: "host.name+file.path",
        2717: "host.name+file.path",
    }
    for rule_id, entity_field in expected.items():
        assert _pack_rule("linux_activity_v1.json", rule_id)["entity_field"] == entity_field

    for rule_id in (2702, 2705, 2707, 2709):
        assert _pack_rule("linux_activity_v1.json", rule_id)["entity_field"] == "host.name"


def test_linux_system_recon_replacement_excludes_openclaw_health_checks() -> None:
    rule = _pack_rule("linux_activity_v1.json", 2726)

    assert int(rule["threshold"]) >= 5
    assert "openclaw_send" in str(rule["expr"])
    assert "who -q" in str(rule["expr"])
    assert "/usr/lib/node_modules/openclaw" in str(rule["expr"])
    assert "apparmor_parser" in str(rule["expr"])
    assert "audit.type == 'EXECVE'" in str(rule["expr"])
    assert "uname -m" in str(rule["expr"])
    assert not _matches(
        str(rule["expr"]),
        {
            "event.provider": "linux.auditd",
            "event.type": "linux_system_recon",
            "event.original": "type=EXECVE",
            "process.command_line": "apparmor_parser -r -T -W /etc/apparmor.d/ubuntu_pro_esm_cache",
            "tags": "",
        },
    )
    assert not _matches(
        str(rule["expr"]),
        {
            "event.provider": "linux.auditd",
            "event.type": "linux_system_recon",
            "audit.type": "EXECVE",
            "event.original": "type=EXECVE",
            "host.name": "lab-edge-01",
            "log_source": "lab-edge-01",
            "process.command_line": "uname -r",
            "tags": "",
        },
    )
    assert _matches(
        str(rule["expr"]),
        {
            "event.provider": "linux.auditd",
            "event.type": "linux_system_recon",
            "audit.type": "EXECVE",
            "event.original": "type=EXECVE",
            "host.name": "pilot-web-01",
            "log_source": "pilot-web-01",
            "process.command_line": "uname -a",
            "tags": "",
        },
    )
    assert not _matches(
        str(rule["expr"]),
        {
            "event.provider": "linux.auditd",
            "event.type": "linux_system_recon",
            "event.original": "type=EXECVE",
            "process.command_line": "who -q",
            "tags": "",
        },
    )


def test_windows_rdp_burst_excludes_trusted_opnsense_gateway() -> None:
    rule = _pack_rule("windows_activity_v1.json", 2617)

    assert "sigma_yaml" not in rule
    assert "192.168.3.103" in str(rule["expr"])
    assert not _matches(
        str(rule["expr"]),
        {
            "event.type": "windows_rdp_auth_success",
            "source.ip": "192.168.3.103",
            "tags": "",
        },
    )
    assert _matches(
        str(rule["expr"]),
        {
            "event.type": "windows_rdp_auth_success",
            "source.ip": "198.51.100.24",
            "tags": "",
        },
    )

    deps_text = (ROOT / "services" / "web" / "app" / "deps.py").read_text(encoding="utf-8")
    retired_block = deps_text.split("DEFAULT_SIGMA_RETIRED_DUPLICATE_IDS", 1)[1].split("}", 1)[0]
    for rule_id in ("1002", "1004", "1005", "1006", "1007", "1008", "1012", "1013", "1014", "1017", "1018", "1019", "1020", "1021", "1026", "1027", "1028", "1029"):
        assert rule_id in retired_block


def test_linux_ssh_burst_rules_exclude_internal_edge_source() -> None:
    failure = _pack_rule("linux_activity_v1.json", 2701)
    root_login = _pack_rule("linux_activity_v1.json", 2702)
    invalid_user = _pack_rule("linux_activity_v1.json", 2708)

    for rule in (failure, invalid_user):
        assert "sigma_yaml" not in rule
        assert "192.168.1.102" in str(rule["expr"])
        assert "not tags icontains 'allowlist:'" in str(rule["expr"])
    assert "sigma_yaml" not in root_login
    assert "e2e-host-" in str(root_login["expr"])


def test_openclaw_dns_burst_is_retired_as_regular_transaction_noise() -> None:
    rule = _pack_rule("openclaw_behavior_v1.json", 2302)

    assert rule["status"] == "retired_noise"
    assert "Regular transaction" in str(rule["sigma_yaml"])


def test_host_service_flapping_requires_repeated_flaps() -> None:
    host_rule = _pack_rule("host_runtime_observability_v1.json", 2108)
    fleet_rule = _pack_rule("fleet_observability_v1.json", 2202)

    assert int(host_rule["threshold"]) >= 3
    assert int(host_rule["window_s"]) >= 1800
    assert int(fleet_rule["threshold"]) >= 3
    assert int(fleet_rule["window_s"]) >= 1800


def test_network_destination_rule_requires_repeated_high_signal_ids_alerts() -> None:
    rule = _pack_rule("diploma_core_stream_v1.json", 9005)
    expr = str(rule["expr"])
    high_signal = {
        "event.provider": "suricata",
        "event.type": "suricata_alert",
        "suricata.alert.severity": "2",
        "source.ip": "198.51.100.10",
        "destination.ip": "198.51.100.20",
        "rule.id": "2100001",
        "rule.name": "ET EXPLOIT Possible RCE Attempt",
        "rule.category": "Web Application Attack",
        "tags": "",
    }

    assert _matches(expr, high_signal)
    assert not _matches(
        expr,
        {
            **high_signal,
            "rule.name": "ET INFO External IP Lookup Domain in DNS Lookup",
            "rule.category": "Potentially Bad Traffic",
        },
    )
    assert not _matches(
        expr,
        {
            "event.provider": "opnsense",
            "event.type": "firewall_connection_denied",
            "destination.ip": "224.0.0.251",
            "tags": "",
        },
    )


def test_edge_service_rules_require_exact_service_and_terminal_state() -> None:
    suricata = _pack_rule("siem_detection_pack_v1.json", 8096)
    unbound = _pack_rule("siem_detection_pack_v1.json", 8097)
    rsyslog = _pack_rule("siem_detection_pack_v1.json", 8098)
    common = {
        "event.provider": "linux.systemd",
        "process.name": "systemd",
        "host.name": "lab-edge-01",
        "log_source": "lab-edge-01",
        "tags": "",
    }

    dns_query = {
        **common,
        "event.provider": "linux.unbound",
        "process.name": "unbound",
        "event.original": "info: 10.20.10.128 docs.velociraptor.app. AAAA IN",
    }
    unrelated_stop = {
        **common,
        "event.type": "linux_systemd_unit_deactivated",
        "service.name": "siem-host-runtime-agent.service",
        "event.original": "siem-host-runtime-agent.service: Deactivated successfully.",
    }

    assert not _matches(str(unbound["expr"]), dns_query)
    assert not _matches(str(suricata["expr"]), unrelated_stop)
    assert not _matches(str(rsyslog["expr"]), unrelated_stop)
    assert _matches(
        str(suricata["expr"]),
        {
            **common,
            "event.type": "linux_systemd_unit_failed",
            "service.name": "suricata.service",
            "event.original": "suricata.service: Failed with result 'exit-code'.",
        },
    )
    assert not _matches(
        str(unbound["expr"]),
        {
            **common,
            "event.type": "linux_systemd_unit_stopped",
            "service.name": "unbound.service",
            "event.original": "Stopped unbound.service - Unbound DNS server.",
        },
    )
    assert _matches(
        str(unbound["expr"]),
        {
            **common,
            "event.type": "linux_systemd_unit_failed",
            "service.name": "unbound.service",
            "event.original": "unbound.service: Failed with result 'exit-code'.",
        },
    )
    assert not _matches(
        str(rsyslog["expr"]),
        {**common, "event.original": "rsyslog.service: Deactivated successfully."},
    )
    assert _matches(
        str(rsyslog["expr"]),
        {
            **common,
            "event.type": "linux_systemd_unit_failed",
            "service.name": "rsyslog.service",
            "event.original": "rsyslog.service: Failed with result 'exit-code'.",
        },
    )


def test_mongodb_package_and_dump_rules_require_source_specific_signals() -> None:
    mongo = _pack_rule("siem_detection_pack_v1.json", 8279)
    package = _pack_rule("siem_detection_pack_v1.json", 8090)
    dump = _pack_rule("siem_detection_pack_v1.json", 8283)

    assert not _matches(
        str(mongo["expr"]),
        {
            "event.provider": "linux.systemd",
            "event.type": "linux_systemd_unit_started",
            "event.original": "Started Authorization Manager.",
            "process.name": "systemd",
            "tags": "",
        },
    )
    assert _matches(
        str(mongo["expr"]),
        {
            "event.provider": "linux.mongod",
            "event.dataset": "mongodb.mongodb",
            "event.original": "Access control is not enabled for the database",
            "process.name": "mongod",
            "tags": "",
        },
    )

    assert not _matches(
        str(package["expr"]),
        {
            "event.provider": "linux.systemd",
            "event.type": "linux_systemd_unit_started",
            "event.original": "Started nginx.service",
            "tags": "",
        },
    )
    assert _matches(
        str(package["expr"]),
        {
            "event.provider": "linux.dpkg",
            "event.type": "linux_package_removed",
            "event.action": "package_removed",
            "package.name": "suricata",
            "event.original": "remove suricata:amd64 1:7.0.0",
            "tags": "",
        },
    )

    assert not _matches(
        str(dump["expr"]),
        {
            "event.provider": "linux.python",
            "event.type": "syslog",
            "event.original": "temporary path /tmp/app.sock",
            "file.path": "/tmp/app.sock",
            "tags": "",
        },
    )
    assert _matches(
        str(dump["expr"]),
        {
            "event.provider": "database.backup",
            "event.type": "database_dump_created",
            "event.original": "pg_dump wrote /var/www/html/export.sql",
            "file.path": "/var/www/html/export.sql",
            "tags": "",
        },
    )


def test_linux_sudo_and_openclaw_proxy_rules_have_operational_noise_guards() -> None:
    sudo_rule = _pack_rule("linux_activity_v1.json", 2703)
    proxy_rule = _pack_rule("openclaw_behavior_v1.json", 2304)
    systemd_failed_rule = _pack_rule("siem_detection_pack_v1.json", 8084)

    assert "sigma_yaml" not in sudo_rule
    assert int(sudo_rule["threshold"]) >= 12
    assert "python3 deploy/" in str(sudo_rule["expr"])
    assert "systemctl restart siem-" in str(sudo_rule["expr"])
    assert "systemctl is-active " in str(sudo_rule["expr"])
    assert int(proxy_rule["threshold"]) >= 180
    assert int(proxy_rule["window_s"]) >= 1800
    assert int(systemd_failed_rule["threshold"]) >= 3


def test_invalid_batch_overdue_keyword_rule_is_replaced_by_runtime_health_coverage() -> None:
    payload = json.loads(
        (ROOT / "correlation_rule_packs" / "siem_detection_pack_v1.json").read_text(
            encoding="utf-8"
        )
    )
    overdue_rule = next(
        rule
        for rule in payload.get("batch_rules") or []
        if isinstance(rule, dict) and int(rule.get("id") or 0) == 8215
    )
    publisher = (ROOT / "deploy" / "publish_rule_noise_tuning.py").read_text(
        encoding="utf-8"
    )

    assert overdue_rule["status"] == "retired_duplicate"
    assert int(overdue_rule["replacement_rule_id"]) == 8081
    assert "ACTIVE_ASSIGNMENT_BATCH_STATUSES" in publisher
    assert "RESOLVE_OPEN_ALERT_RULE_IDS" in publisher
    assert "SUPPRESS_OPEN_ALERT_RULE_IDS" in publisher


def test_batch_rules_exclude_internal_edge_and_emit_valid_numeric_json() -> None:
    ssh_batch = (ROOT / "sql" / "13_batch_corr_seed.sql").read_text(encoding="utf-8")
    soc_batch = (ROOT / "sql" / "15_batch_corr_soc_seed.sql").read_text(encoding="utf-8")
    assignment_overrides = (ROOT / "correlation_rule_packs" / "siem_detection_pack_v1_active_overrides.json").read_text(encoding="utf-8")
    cmdb_seed = (ROOT / "sql" / "16_lab_cmdb_seed.sql").read_text(encoding="utf-8")

    assert "''192.168.1.29'', ''192.168.1.102''" in ssh_batch
    assert "''10.20.30.122'', ''192.168.1.102''" in soc_batch
    assert "asset-proxmox-pve" in cmdb_seed
    assert "asset-siem-transport" in cmdb_seed
    assert "'pve', 'proxmox', 'siem-transport'" in assignment_overrides
    assert "toString(host_count),\n            ''\",\"failures\":''" not in ssh_batch
    assert "toString(host_count),\n            '',\"failures\":''" in ssh_batch
    assert ")),\n            ''\",\"targets\":\"''" not in soc_batch
    assert ")),\n            '',\"targets\":\"''" in soc_batch
    assert "toString(sum(recon_hits)),\n            ''\",\"privileged_hits\":''" not in soc_batch
    assert "toString(sum(recon_hits)),\n            '',\"privileged_hits\":''" in soc_batch
    assert "AND recon_hits >= 5" in soc_batch
    assert "AND priv_hits >= 3" in soc_batch


def test_filter_seed_republishes_rules_without_async_delete_race() -> None:
    filter_seed = (ROOT / "sql" / "12_filter_rule_seed.sql").read_text(encoding="utf-8")

    assert "ALTER TABLE siem.filter_rules DELETE" in filter_seed
    publisher = (ROOT / "deploy" / "publish_filter_rules.py").read_text(encoding="utf-8")
    assert "_wait_for_filter_rule_deletion" in publisher
    assert 'settings={"mutations_sync": 0}' in publisher
    assert 'SIEM_CH_SEND_RECEIVE_TIMEOUT_SECONDS"] = str(' in publisher


def test_rule_noise_publisher_refreshes_second_layer_targets() -> None:
    publish_text = (ROOT / "deploy" / "publish_rule_noise_tuning.py").read_text(encoding="utf-8")

    for rule_id in ("2601", "2605", "2607", "2612", "2616", "2701", "2702", "2703", "2706", "2708", "2907", "8056", "8067", "8077", "8070", "8071", "8091", "8093", "8134", "8213", "8224", "8225", "8226", "8227", "8228", "8231", "8232", "8263", "8269", "8286", "8307", "8308", "8331", "8339", "8367", "9006", "1001", "1003", "1013", "1018", "1019", "1020", "1021", "2000", "2302", "2718", "2723", "4002", "4003", "4004", "8012", "8442", "8431", "8432", "8481"):
        assert rule_id in publish_text
    assert "    2303," not in publish_text
    assert "    2304," not in publish_text
    assert "REFRESH_BATCH_RULE_IDS" in publish_text
    assert "REFRESH_ASSIGNMENT_BATCH_RULE_IDS" in publish_text
    assert "_refresh_batch_rules" in publish_text
    assert "_refresh_assignment_batch_rules" in publish_text
    assert "lightweight_deletes_sync = 2" in publish_text
    assert "mutations_sync = 1" not in publish_text


def test_assignment_publisher_uses_maintenance_sized_clickhouse_timeout() -> None:
    publisher = (ROOT / "deploy" / "publish_assignment_detection_pack.py").read_text(encoding="utf-8")

    assert "SIEM_RULE_PUBLISH_TIMEOUT_SECONDS" in publisher
    assert 'os.environ["SIEM_CH_SEND_RECEIVE_TIMEOUT_SECONDS"]' in publisher


def test_assignment_overrides_replace_broad_fp_keywords_with_source_event_semantics() -> None:
    overrides = json.loads(
        (ROOT / "correlation_rule_packs" / "siem_detection_pack_v1_active_overrides.json").read_text(encoding="utf-8")
    )
    pack = json.loads(
        (ROOT / "correlation_rule_packs" / "siem_detection_pack_v1.json").read_text(encoding="utf-8")
    )
    heartbeat_sql = next(
        str(rule["sql_template"])
        for rule in pack["batch_rules"]
        if int(rule["id"]) == 8001
    )

    assert "process.name == 'su'" in str(overrides["AUTH-013"]["expr"])
    assert "cron:session" in str(overrides["AUTH-013"]["expr"])
    assert "pam_unix(su:auth)" in str(overrides["AUTH-014"]["expr"])
    assert "linux.gamepanel-audit" in str(overrides["GAME-009"]["expr"])
    assert "not event.provider == 'linux.gamepanel-audit'" in str(overrides["GAME-009"]["expr"])
    assert "/api/remote/backups/" in str(overrides["WEB-011"]["expr"])
    assert "${jndi:" in str(overrides["MC-008"]["expr"])
    assert "dpkg-db-backup" in str(overrides["BCK-002"]["sql_template"])
    assert "postgresql_connections" in str(overrides["MET-017"]["sql_template"])
    assert "mongodb_connections" in str(overrides["MET-018"]["sql_template"])
    assert "unhealthy_snapshots" in str(overrides["CORR-S-002"]["sql_template"])
    assert '"name":"siem-stream-corr"' in str(overrides["CORR-S-002"]["sql_template"])
    assert "(inactive|failed|dead|unknown)" in str(overrides["CORR-S-002"]["sql_template"])
    assert "sql_template" not in overrides["HB-001"]
    assert "auto-discovered" in heartbeat_sql
    assert "GROUP BY c.hostname" in heartbeat_sql
    assert "HAVING max(e.last_seen_ts)" in heartbeat_sql
    assert "positionCaseInsensitiveUTF8(toString(tags), 'allowlist:')" not in heartbeat_sql
    assert "baseline_30m" in str(overrides["HB-012"]["sql_template"])
    assert "linux.kafka" in str(overrides["KFK-004"]["expr"])
    assert "linux.kernel" in str(overrides["SVC-007"]["expr"])
    assert "clickhouse.query_log" in str(overrides["CH-007"]["expr"])
    assert "system-fp-remediation" in str(overrides["CH-008"]["expr"])
    assert "new user: name=" in str(overrides["AUTH-010"]["expr"])
    assert "not event.original icontains 'user.slice'" in str(overrides["AUTH-010"]["expr"])
    assert "userdel[" in str(overrides["AUTH-011"]["expr"])
    assert "nametype=DELETE" in str(overrides["AUTH-011"]["expr"])
    assert "linux_systemd_restart_scheduled" in str(overrides["SVC-003"]["expr"])
    assert "System Logging Service" in str(overrides["SVC-011"]["expr"])
    assert "Stopped System Logging Service" in str(overrides["SVC-011"]["expr"])
    assert "host.name == 'siem-ingest'" in str(overrides["ING-006"]["expr"])
    assert "host.name == 'siem-web'" in str(overrides["WEB-005"]["expr"])
    assert "host.name == 'pilot-db-01'" in str(overrides["PILOT-007"]["expr"])
    assert "event.provider == 'postgresql'" in str(overrides["PG-002"]["expr"])
    assert "Stopped containerd" in str(overrides["DCK-002"]["expr"])
    assert "siem-stream-corr" in str(overrides["CORR-S-003"]["sql_template"])
    assert "pilot-db-01" not in str(overrides["CORR-S-003"]["sql_template"])
    assert ":qmreboot:107:" in str(overrides["PVE-016"]["expr"])
    assert "status update time" not in str(overrides["PVE-016"]["expr"])
    assert "\\SoftLanding\\" in str(overrides["WIN-010"]["expr"])
    assert "host.name == 'siem-web'" in str(overrides["WEB-003"]["expr"])
    assert "host.name == 'siem-web'" in str(overrides["WEB-004"]["expr"])
    assert "host.name == 'siem-web'" in str(overrides["WEB-006"]["expr"])
    assert "host.name == 'siem-web'" in str(overrides["WEB-007"]["expr"])
    assert "host.name == 'pilot-cache-01'" in str(overrides["PILOT-015"]["expr"])
    assert "docker_container_metrics" in str(overrides["DCK-024"]["expr"])
    assert "host.name == 'siem-web'" in str(overrides["WEB-001"]["expr"])
    assert "host.name == 'pilot-web-01'" in str(overrides["PILOT-001"]["expr"])
    assert "host.name == 'pilot-cache-01'" in str(overrides["PILOT-016"]["expr"])
    assert "host.name == 'navidrome-01'" in str(overrides["NAV-003"]["expr"])
    assert "host.name == 'nextcloud-siem'" in str(overrides["NC-004"]["expr"])
    assert "host.name == 'vuln-mgr-01'" in str(overrides["DCK-018"]["expr"])
    assert "host.name == 'openclaw-gateway'" in str(overrides["DCK-019"]["expr"])
    assert "host.name == 'gamepanel-01'" in str(overrides["DCK-021"]["expr"])
    assert "host.name == 'minecraft-01'" not in str(overrides["DCK-021"]["expr"])
    assert "wings.service" in str(overrides["DCK-021"]["expr"])
    assert "event.provider == 'linux.docker'" in str(overrides["DCK-004"]["expr"])
    assert "host.name == 'pve'" in str(overrides["PVE-009"]["expr"])
    assert "assignment-full" in str(overrides["EDGE-004"]["sql_template"])
    assert "baseline_hits >= 1000" in str(overrides["EDGE-004"]["sql_template"])
    assert "baseline_last >= now() - INTERVAL 2 HOUR" in str(overrides["EDGE-004"]["sql_template"])
    assert "other_edge_hits" in str(overrides["EDGE-004"]["sql_template"])
    assert "lower(status) IN ('open', 'false_positive', 'suppressed')" in str(overrides["EDGE-004"]["sql_template"])
    assert int(overrides["HB-012"]["window_s"]) == 3600
    assert "baseline_30m >= 300" in str(overrides["HB-012"]["sql_template"])
    assert "b.baseline_30m * 0.05" in str(overrides["HB-012"]["sql_template"])
    assert "dropped_entities <= 2" in str(overrides["HB-012"]["sql_template"])
    assert "lower(status) IN ('open', 'false_positive', 'suppressed')" in str(overrides["HB-012"]["sql_template"])
    assert "siem-storage" in str(overrides["MET-014"]["sql_template"])
    assert "usage_percent|disk_pct|used_pct" in str(overrides["MET-014"]["sql_template"])
    assert "nextcloud-siem" not in str(overrides["MET-014"]["sql_template"])
    assert "siem-transport" in str(overrides["MET-015"]["sql_template"])
    assert "usage_percent|disk_pct|used_pct" in str(overrides["MET-015"]["sql_template"])
    assert "openclaw-gateway" not in str(overrides["MET-015"]["sql_template"])
    assert "rsyslog" in str(overrides["CORR-034"]["sql_template"])
    assert "heartbeat" in str(overrides["CORR-034"]["sql_template"])
    assert "dependent senders" in str(overrides["CORR-034"]["sql_template"])
    assert "host runtime snapshot" in str(overrides["CORR-034"]["sql_template"])
    assert "toString(normalized_json), 'rsyslog'" not in str(overrides["CORR-034"]["sql_template"])
    assert "HAVING hits >= 3" in str(overrides["CORR-034"]["sql_template"])
    assert int(overrides["AUTH-005"]["window_s"]) == 3600
    assert "192.168.1.38" in str(overrides["AUTH-005"]["sql_template"])
    assert "WITH recent AS" in str(overrides["AUTH-005"]["sql_template"])
    assert "known AS" in str(overrides["AUTH-005"]["sql_template"])
    assert "k.src_ip_text = ''" in str(overrides["AUTH-005"]["sql_template"])
    assert "lower(status) IN ('open', 'false_positive', 'suppressed')" in str(overrides["AUTH-005"]["sql_template"])


def test_windows_scheduled_task_rule_excludes_only_known_softlanding_tasks() -> None:
    rule = _pack_rule("windows_activity_v1.json", 2607)
    benign = {
        "event.type": "windows_scheduled_task_created",
        "event.original": (
            'User "DESKTOP-5JMJVBH\\Rdegon" registered Task Scheduler task '
            '"\\SoftLanding\\S-1-5-21\\SoftLandingDeferralTask-{id}"'
        ),
        "host.name": "DESKTOP-5JMJVBH",
        "log_source": "DESKTOP-5JMJVBH",
        "tags": [],
    }
    suspicious = {
        **benign,
        "event.original": (
            'User "DESKTOP-5JMJVBH\\Rdegon" registered Task Scheduler task '
            '"\\UpdaterPersistence"'
        ),
    }

    assert not _matches(str(rule["expr"]), benign)
    assert _matches(str(rule["expr"]), suspicious)


def test_assignment_overrides_reject_observed_false_positive_shapes() -> None:
    overrides = json.loads(
        (ROOT / "correlation_rule_packs" / "siem_detection_pack_v1_active_overrides.json").read_text(encoding="utf-8")
    )

    assert not _matches(
        str(overrides["DCK-023"]["expr"]),
        {
            "event.provider": "linux.systemd",
            "event.original": "Listening on systemd Password Requests Watch.",
            "tags": "",
        },
    )
    assert _matches(
        str(overrides["DCK-023"]["expr"]),
        {
            "event.provider": "linux.docker",
            "event.original": "container output: AWS_SECRET_ACCESS_KEY=EXPOSED_TEST_VALUE",
            "tags": "",
        },
    )
    assert not _matches(
        str(overrides["NC-005"]["expr"]),
        {
            "event.provider": "linux.systemd",
            "host.name": "nextcloud-siem",
            "event.original": "Found left-over process in control group while starting unit.",
            "tags": "",
        },
    )
    assert _matches(
        str(overrides["NC-005"]["expr"]),
        {
            "event.provider": "linux.nextcloud",
            "host.name": "nextcloud-siem",
            "event.original": '{"action":"group_add","group":"admin","user":"alice"}',
            "tags": "",
        },
    )
    assert not _matches(
        str(overrides["PG-008"]["expr"]),
        {
            "event.provider": "linux.systemd",
            "host.name": "pilot-db-01",
            "event.original": "siem-host-runtime-agent.service: Deactivated successfully.",
            "tags": "",
        },
    )
    assert _matches(
        str(overrides["PG-008"]["expr"]),
        {
            "event.provider": "postgresql",
            "host.name": "pilot-db-01",
            "event.original": "database system was interrupted; automatic recovery in progress",
            "tags": "",
        },
    )
    assert not _matches(
        str(overrides["WEB-011"]["expr"]),
        {
            "event.provider": "linux.gitea",
            "host.name": "gamepanel-01",
            "event.original": "/go/pkg/mod/code.gitea.io/gitea/modules/indexer/issues/indexer.go",
            "tags": "",
        },
    )
    assert _matches(
        str(overrides["WEB-011"]["expr"]),
        {
            "event.provider": "linux.nginx-access",
            "host.name": "pilot-web-01",
            "event.original": '198.51.100.44 - - "GET /..%2f..%2fetc/passwd HTTP/1.1" 400 0',
            "tags": "",
        },
    )
    assert not _matches(
        str(overrides["DNS-005"]["expr"]),
        {
            "event.provider": "zeek",
            "event.type": "zeek_conn",
            "network.direction": "outbound",
            "source.ip": "10.20.10.108",
            "destination.ip": "10.20.10.1",
            "destination.port": "53",
            "tags": "",
        },
    )
    assert not _matches(
        str(overrides["DNS-005"]["expr"]),
        {
            "event.provider": "zeek",
            "event.type": "zeek_conn",
            "network.direction": "outbound",
            "source.ip": "10.20.10.108",
            "destination.ip": "10.20.10.254",
            "destination.port": "53",
            "tags": "",
        },
    )
    assert _matches(
        str(overrides["DNS-005"]["expr"]),
        {
            "event.provider": "zeek",
            "event.type": "zeek_conn",
            "network.direction": "outbound",
            "source.ip": "10.20.10.108",
            "destination.ip": "8.8.8.8",
            "destination.port": "53",
            "tags": "",
        },
    )
    assert _matches(
        str(overrides["DNS-005"]["expr"]),
        {
            "event.provider": "zeek",
            "event.type": "zeek_conn",
            "network.direction": "outbound",
            "source.ip": "10.20.10.108",
            "destination.ip": "9.9.9.9",
            "destination.port": "53",
            "tags": "",
        },
    )
    assert not _matches(
        str(overrides["DNS-005"]["expr"]),
        {
            "event.provider": "zeek",
            "event.type": "zeek_conn",
            "network.direction": "outbound",
            "source.ip": "192.168.3.102",
            "destination.ip": "8.8.8.8",
            "destination.port": "53",
            "tags": "",
        },
    )
    assert _matches(
        str(overrides["DNS-005"]["expr"]),
        {
            "event.provider": "zeek",
            "event.type": "zeek_conn",
            "network.direction": "outbound",
            "source.ip": "10.20.20.100",
            "destination.ip": "8.8.8.8",
            "destination.port": "53",
            "tags": "",
        },
    )
    assert not _matches(
        str(overrides["DNS-005"]["expr"]),
        {
            "event.provider": "zeek",
            "event.type": "zeek_conn",
            "network.direction": "outbound",
            "source.ip": "192.168.3.81",
            "destination.ip": "1.1.1.1",
            "destination.port": "53",
            "tags": "",
        },
    )


def test_assignment_auth_rules_require_parsed_sudo_and_real_pam_failures() -> None:
    overrides = json.loads(
        (ROOT / "correlation_rule_packs" / "siem_detection_pack_v1_active_overrides.json").read_text(encoding="utf-8")
    )
    sudo_expr = str(overrides["AUTH-007"]["expr"])
    pam_expr = str(overrides["AUTH-017"]["expr"])

    assert _matches(
        sudo_expr,
        {
            "event.provider": "linux.sudo",
            "event.type": "sudo_command",
            "user.name": "unexpected-admin",
            "tags": "",
        },
    )
    assert not _matches(
        sudo_expr,
        {
            "event.provider": "linux.sudo",
            "event.type": "sudo_event",
            "user.name": "",
            "tags": "",
        },
    )
    assert not _matches(
        sudo_expr,
        {
            "event.provider": "linux.sudo",
            "event.type": "sudo_command",
            "user.name": "rdegon",
            "tags": "allowlist:siem_operational_sudo",
        },
    )
    assert not _matches(
        sudo_expr,
        {
            "event.provider": "linux.sudo",
            "event.type": "sudo_command",
            "event.original": "sudo: root : COMMAND=/usr/bin/psql -d siem_incident_bot -Atc select",
            "tags": "",
        },
    )
    assert _matches(
        pam_expr,
        {
            "event.provider": "linux.auditd",
            "event.type": "audit_user_auth_failure",
            "event.action": "authentication_failed",
            "event.outcome": "failure",
            "event.original": "op=PAM:authentication res=failed",
            "tags": "",
        },
    )
    assert not _matches(
        pam_expr,
        {
            "event.provider": "linux.auditd",
            "event.type": "audit_user_auth_success",
            "event.action": "authentication",
            "event.outcome": "success",
            "event.original": "op=PAM:authentication grantors=pam_permit res=success",
            "tags": "",
        },
    )
    assert not _matches(
        pam_expr,
        {
            "event.provider": "linux.auditd",
            "event.type": "audit_service_stop",
            "event.action": "service_stop",
            "event.outcome": "failure",
            "event.original": (
                "type=SERVICE_STOP msg=audit(1.0:2): "
                "unit=siem-normalizer res=failed"
            ),
            "tags": "",
        },
    )
    assert not _matches(
        pam_expr,
        {
            "event.provider": "linux.cron",
            "event.type": "linux_cron_event",
            "event.action": "observe",
            "event.outcome": "",
            "event.original": "pam_unix(cron:session): session opened for user root",
            "tags": "",
        },
    )


def test_ssh_batch_rules_ignore_trusted_admin_source_ip() -> None:
    seed_sql = (ROOT / "sql" / "13_batch_corr_seed.sql").read_text(encoding="utf-8")

    assert "''192.168.3.81'', ''192.168.3.101''" in seed_sql
    assert "''10.20.30.122'', ''10.66.66.4''" in seed_sql
    assert "ts_last >= now() - INTERVAL 86400 SECOND" in seed_sql
    assert "lower(status) IN (''open'', ''false_positive'', ''suppressed'')" in seed_sql


def test_restart_loop_rules_ignore_lxc_container_getty_noise() -> None:
    overrides = json.loads(
        (ROOT / "correlation_rule_packs" / "siem_detection_pack_v1_active_overrides.json").read_text(encoding="utf-8")
    )
    getty_restart = {
        "event.provider": "linux.systemd",
        "event.original": "container-getty@1.service: Scheduled restart job, restart counter is at 33908.",
        "host.name": "nextcloud-siem",
        "log_source": "nextcloud-siem",
        "tags": "",
    }
    real_container_loop = {
        "event.provider": "linux.docker",
        "event.original": "docker container nextcloud-app start request repeated too quickly; Back-off restarting failed container",
        "host.name": "nextcloud-siem",
        "log_source": "nextcloud-siem",
        "tags": "",
    }

    assert not _matches(str(overrides["SVC-003"]["expr"]), getty_restart)
    assert not _matches(str(overrides["DCK-010"]["expr"]), getty_restart)
    assert _matches(str(overrides["DCK-010"]["expr"]), real_container_loop)


def test_docker_api_exposure_ignores_systemd_numeric_noise() -> None:
    overrides = json.loads(
        (ROOT / "correlation_rule_packs" / "siem_detection_pack_v1_active_overrides.json").read_text(encoding="utf-8")
    )
    systemd_resolved_transaction = {
        "event.provider": "linux.systemd-resolved",
        "event.original": "Freeing transaction 23750.",
        "host.name": "openclaw-gateway",
        "log_source": "openclaw-gateway",
        "tags": "",
    }
    container_getty = {
        "event.provider": "linux.systemd",
        "event.original": "container-getty@1.service: Scheduled restart job, restart counter is at 34337.",
        "host.name": "nextcloud-siem",
        "log_source": "nextcloud-siem",
        "tags": "",
    }
    exposed_dockerd = {
        "event.provider": "linux.docker",
        "event.original": "dockerd started with -H tcp://0.0.0.0:2375",
        "host.name": "openclaw-gateway",
        "log_source": "openclaw-gateway",
        "tags": "",
    }

    assert not _matches(str(overrides["DCK-014"]["expr"]), systemd_resolved_transaction)
    assert not _matches(str(overrides["DCK-014"]["expr"]), container_getty)
    assert _matches(str(overrides["DCK-014"]["expr"]), exposed_dockerd)


def test_assignment_overrides_do_not_match_observed_service_and_auth_noise() -> None:
    overrides = json.loads(
        (ROOT / "correlation_rule_packs" / "siem_detection_pack_v1_active_overrides.json").read_text(encoding="utf-8")
    )
    dpkg_systemd_event = {
        "event.provider": "linux.auditd",
        "event.type": "linux_systemd_unit_modified",
        "event.action": "service_unit_modify",
        "event_action": "service_unit_modify",
        "event.original": 'type=PATH name="/lib/systemd/system/rsync.service.dpkg-tmp" nametype=DELETE',
        "source.ip": "10.20.30.124",
        "tags": "",
    }
    normal_postgres_stop = {
        "event.provider": "linux.systemd",
        "event.original": "Stopped PostgreSQL Cluster 15-main.",
        "host.name": "pilot-db-01",
        "log_source": "pilot-db-01",
        "tags": "",
    }
    failed_postgres = {
        "event.provider": "linux.systemd",
        "event.original": "postgresql@15-main.service: Main process exited, code=exited, status=1/FAILURE; Failed with result 'exit-code'.",
        "host.name": "pilot-db-01",
        "log_source": "pilot-db-01",
        "tags": "",
    }
    broad_nextcloud_stop = {
        "event.provider": "linux.systemd",
        "event.original": "Stopped nginx service during normal maintenance window.",
        "host.name": "nextcloud-siem",
        "log_source": "nextcloud-siem",
        "tags": "",
    }
    real_web_failure = {
        "event.provider": "linux.systemd",
        "event.original": "siem-web.service: Main process exited, status=1/FAILURE; Failed with result 'exit-code'.",
        "host.name": "siem-web",
        "log_source": "siem-web",
        "tags": "",
    }

    assert not _matches(str(overrides["AUTH-010"]["expr"]), dpkg_systemd_event)
    assert not _matches(str(overrides["AUTH-011"]["expr"]), dpkg_systemd_event)
    assert not _matches(str(overrides["PILOT-007"]["expr"]), normal_postgres_stop)
    assert _matches(str(overrides["PILOT-007"]["expr"]), failed_postgres)
    assert not _matches(str(overrides["WEB-001"]["expr"]), broad_nextcloud_stop)
    assert _matches(str(overrides["WEB-001"]["expr"]), real_web_failure)
    assert not _matches(
        str(overrides["DCK-019"]["expr"]),
        {
            "event.provider": "linux.systemd",
            "event.original": "container down on nextcloud",
            "host.name": "nextcloud-siem",
            "log_source": "nextcloud-siem",
            "tags": "",
        },
    )
    assert _matches(
        str(overrides["DCK-019"]["expr"]),
        {
            "event.provider": "linux.docker",
            "event.original": "openclaw gateway container die exited",
            "host.name": "openclaw-gateway",
            "log_source": "openclaw-gateway",
            "tags": "",
        },
    )


def test_remaining_service_scope_rules_do_not_match_openclaw_reboot_noise() -> None:
    overrides = json.loads(
        (ROOT / "correlation_rule_packs" / "siem_detection_pack_v1_active_overrides.json").read_text(encoding="utf-8")
    )
    openclaw_normal_stop = {
        "event.provider": "linux.systemd",
        "event.original": "Stopped siem-keycloak service during reboot.",
        "host.name": "openclaw-gateway",
        "log_source": "openclaw-gateway",
        "tags": "",
    }
    web_failed_keycloak = {
        "event.provider": "linux.systemd",
        "event.original": "siem-keycloak.service: Main process exited, status=1/FAILURE; Failed with result 'exit-code'.",
        "host.name": "siem-web",
        "log_source": "siem-web",
        "tags": "",
    }
    openclaw_container_text = {
        "event.provider": "linux.systemd",
        "event.type": "syslog",
        "event.original": "container_cpu>90% OR memory>90% for 10m",
        "host.name": "openclaw-gateway",
        "log_source": "openclaw-gateway",
        "tags": "",
    }
    docker_metric = {
        "event.provider": "docker.metrics",
        "event.type": "docker_container_metrics",
        "event.original": "container_cpu=96 memory_pct=93",
        "host.name": "openclaw-gateway",
        "log_source": "openclaw-gateway",
        "tags": "",
    }

    assert not _matches(str(overrides["WEB-003"]["expr"]), openclaw_normal_stop)
    assert _matches(str(overrides["WEB-003"]["expr"]), web_failed_keycloak)
    assert not _matches(str(overrides["DCK-024"]["expr"]), openclaw_container_text)
    assert _matches(str(overrides["DCK-024"]["expr"]), docker_metric)
