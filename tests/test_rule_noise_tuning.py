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
    assert "event.code != '5857'" in str(wmi["expr"])
    assert "event.code != '5860'" in str(wmi["expr"])
    assert "WmiPerfInst provider started" in str(wmi["expr"])
    assert "WMIProv provider started" in str(wmi["expr"])
    assert "Could not send status to client" in str(wmi["expr"])
    assert "IWbemServices::ExecNotificationQuery" in str(wmi["expr"])
    assert "DESKTOP-5JMJVBH" in str(wmi["expr"])
    assert "NT AUTHORITY\\SYSTEM" in str(wmi["expr"])
    assert "wsmprovhost.exe" in str(wmi["expr"])


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

    assert "sigma_yaml" not in linux_rule
    assert "dpkg-tmp" in str(linux_rule["expr"])
    assert not _matches(str(linux_rule["expr"]), dpkg_path_event)
    assert _matches(str(linux_rule["expr"]), direct_unit_change)
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
    assert "sigma_yaml" not in openclaw_rule
    assert not _matches(str(openclaw_rule["expr"]), dpkg_path_event)
    assert _matches(str(openclaw_rule["expr"]), direct_unit_change)


def test_linux_system_recon_replacement_excludes_openclaw_health_checks() -> None:
    rule = _pack_rule("linux_activity_v1.json", 2726)

    assert int(rule["threshold"]) >= 5
    assert "openclaw_send" in str(rule["expr"])
    assert "/usr/lib/node_modules/openclaw" in str(rule["expr"])

    deps_text = (ROOT / "deps.py").read_text(encoding="utf-8")
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


def test_linux_sudo_and_openclaw_proxy_rules_have_operational_noise_guards() -> None:
    sudo_rule = _pack_rule("linux_activity_v1.json", 2703)
    proxy_rule = _pack_rule("openclaw_behavior_v1.json", 2304)

    assert "sigma_yaml" not in sudo_rule
    assert int(sudo_rule["threshold"]) >= 6
    assert "python3 deploy/" in str(sudo_rule["expr"])
    assert "systemctl restart siem-" in str(sudo_rule["expr"])
    assert int(proxy_rule["threshold"]) >= 180
    assert int(proxy_rule["window_s"]) >= 1800


def test_batch_rules_exclude_internal_edge_and_emit_valid_numeric_json() -> None:
    ssh_batch = (ROOT / "sql_13_batch_corr_seed.sql").read_text(encoding="utf-8")
    soc_batch = (ROOT / "sql_15_batch_corr_soc_seed.sql").read_text(encoding="utf-8")
    assignment_overrides = (ROOT / "correlation_rule_packs" / "siem_detection_pack_v1_active_overrides.json").read_text(encoding="utf-8")
    cmdb_seed = (ROOT / "sql_16_lab_cmdb_seed.sql").read_text(encoding="utf-8")

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


def test_rule_noise_publisher_refreshes_second_layer_targets() -> None:
    publish_text = (ROOT / "deploy" / "publish_rule_noise_tuning.py").read_text(encoding="utf-8")

    for rule_id in ("2303", "2605", "2607", "2612", "2616", "2701", "2702", "2703", "2706", "2708", "8070", "8071", "8091", "8093", "8134", "8213", "8224", "8225", "8226", "8227", "8228", "8263", "8286", "8308", "8331", "8339", "1001", "1003", "1013", "1018", "1019", "1020", "1021", "2000", "2302", "2718", "2723", "4002", "4003", "4004", "8012", "8431", "8432", "8481"):
        assert rule_id in publish_text
    assert "REFRESH_BATCH_RULE_IDS" in publish_text
    assert "REFRESH_ASSIGNMENT_BATCH_RULE_IDS" in publish_text
    assert "_refresh_batch_rules" in publish_text
    assert "_refresh_assignment_batch_rules" in publish_text


def test_assignment_overrides_replace_broad_fp_keywords_with_source_event_semantics() -> None:
    overrides = json.loads(
        (ROOT / "correlation_rule_packs" / "siem_detection_pack_v1_active_overrides.json").read_text(encoding="utf-8")
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
    assert "events_24h" in str(overrides["CORR-S-002"]["sql_template"])
    assert "auto-discovered" in str(overrides["HB-001"]["sql_template"])
    assert "baseline_30m" in str(overrides["HB-012"]["sql_template"])
    assert "linux.kafka" in str(overrides["KFK-004"]["expr"])
    assert "linux.kernel" in str(overrides["SVC-007"]["expr"])
    assert "clickhouse.query_log" in str(overrides["CH-007"]["expr"])
    assert "system-fp-remediation" in str(overrides["CH-008"]["expr"])
    assert "new user: name=" in str(overrides["AUTH-010"]["expr"])
    assert "not event.original icontains 'user.slice'" in str(overrides["AUTH-010"]["expr"])
    assert "userdel[" in str(overrides["AUTH-011"]["expr"])
    assert "nametype=DELETE" in str(overrides["AUTH-011"]["expr"])
    assert "start request repeated too quickly" in str(overrides["SVC-003"]["expr"])
    assert "System Logging Service" in str(overrides["SVC-011"]["expr"])
    assert "Stopped System Logging Service" in str(overrides["SVC-011"]["expr"])
    assert "host.name == 'siem-ingest'" in str(overrides["ING-006"]["expr"])
    assert "host.name == 'siem-web'" in str(overrides["WEB-005"]["expr"])
    assert "host.name == 'pilot-db-01'" in str(overrides["PILOT-007"]["expr"])
    assert "event.provider == 'postgresql'" in str(overrides["PG-002"]["expr"])
    assert "Stopped containerd" in str(overrides["DCK-002"]["expr"])
    assert "siem-stream-corr" in str(overrides["CORR-S-003"]["sql_template"])
    assert "pilot-db-01" not in str(overrides["CORR-S-003"]["sql_template"])
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
    assert "event.provider == 'linux.docker'" in str(overrides["DCK-004"]["expr"])
    assert "host.name == 'pve'" in str(overrides["PVE-009"]["expr"])
    assert "assignment-full" in str(overrides["EDGE-004"]["sql_template"])
    assert "baseline_hits >= 1000" in str(overrides["EDGE-004"]["sql_template"])
    assert "baseline_last >= now() - INTERVAL 2 HOUR" in str(overrides["EDGE-004"]["sql_template"])
    assert "other_edge_hits" in str(overrides["EDGE-004"]["sql_template"])
    assert "lower(status) IN ('open', 'false_positive', 'suppressed')" in str(overrides["EDGE-004"]["sql_template"])
    assert int(overrides["HB-012"]["window_s"]) == 1800
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


def test_ssh_batch_rules_ignore_trusted_admin_source_ip() -> None:
    seed_sql = (ROOT / "sql_13_batch_corr_seed.sql").read_text(encoding="utf-8")

    assert "''192.168.1.25'', ''192.168.1.29'', ''192.168.1.102''" in seed_sql
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
