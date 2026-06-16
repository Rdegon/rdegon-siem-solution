# Windows / Linux Telemetry Expansion Wave

Date: `2026-03-30`

## Scope

This wave expanded defensive telemetry and detection coverage for the monitored Linux and Windows estates so that parallel operator testing and pentest activity lands in SIEM with better context and stronger rule coverage.

## What Changed

### Linux

- Added a common Linux audit bundle for Proxmox-backed `qemu` guests:
  - `deploy/common/50-siem-linux-audit.rules`
  - file and directory watches for accounts, sudoers, SSH config, systemd, cron, rsyslog, and auditd config
  - interactive and privileged `execve` coverage for higher-fidelity operator and attacker activity
- Enabled `auditd` and `audispd-plugins` on monitored Linux `qemu` guests through:
  - `deploy/proxmox_fleet_wave_deploy.py`
  - `deploy/proxmox_fleet_wave_smoke.py`
- Kept `lxc` guests on the lighter rsyslog-only path to avoid unsafe audit expectations inside containers.

### Windows

- Expanded default Windows collection channels in:
  - `deploy/windows/rdegon-siem-collector.ps1`
  - `windows-event-agent/src/Rdegon.WindowsEventAgent/AgentOptions.cs`
  - `windows-event-agent/src/Rdegon.WindowsEventAgent/appsettings.json`
  - `ops/windows-agent-profile.local.example.json`
  - all `deploy/windows-agent/remote-vpn-profile-0*.json`
- New default channels now include:
  - `Microsoft-Windows-Windows Defender/Operational`
  - `Microsoft-Windows-WMI-Activity/Operational`
  - `Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational`
  - `Microsoft-Windows-TerminalServices-LocalSessionManager/Operational`
  - `Microsoft-Windows-TaskScheduler/Operational`
  - `Microsoft-Windows-WinRM/Operational`

### Normalization and detection

- Added new Windows normalized event families:
  - `windows_explicit_credentials_logon`
  - `windows_special_privileges_assigned`
  - `windows_audit_policy_changed`
  - `windows_password_changed`
  - `windows_password_reset`
  - `windows_defender_malware_detected`
  - `windows_defender_configuration_changed`
  - `windows_rdp_auth_success`
  - `windows_wmi_activity`
- Extended Linux correlation coverage with:
  - `linux_audit_config_changed`
  - `linux_sshd_config_modified`
  - `linux_rsyslog_config_modified`
  - `linux_user_created`
  - `linux_user_deleted`
  - `linux_password_changed`
  - `linux_user_added_to_admin_group`
  - `linux_download_utility`
  - `linux_network_tool`
  - `linux_packet_capture`
  - `linux_kernel_module_modified`
  - `linux_sysctl_modified`
  - `linux_file_capability_modified`
  - `linux_setuid_bit_modified`
  - `linux_ld_preload_modified`
  - `linux_pkexec_execution`
  - `linux_data_compressed`
- Published rule packs after rollout:
  - `windows-activity-v1` -> `18` published rules
  - `linux-activity-v1` -> `25` published rules

## Verification

Local verification:

- `pytest tests/test_normalizer_core.py tests/test_service_normalizer_core.py tests/test_deploy_rollout_regressions.py tests/test_correlation_pack_runtime.py`
  - `48 passed`

Live verification:

- `deploy/vm4_enterprise_foundation_deploy.py` -> `deployment=success`
- `deploy/proxmox_fleet_wave_deploy.py --skip-greenbone-wave` -> `guests=ok`, `fleet_sync count=15`
- `deploy/vm4_enterprise_foundation_smoke.py` -> `smoke=success`
- `deploy/proxmox_fleet_wave_smoke.py` -> `smoke=success`

End-to-end Linux proof:

- After the audit rollout, a controlled rsyslog config probe on `pilot-db-01` produced a live correlated incident with:
  - `rule_id=2717`
  - `title=Linux Logging Configuration Changed`
  - `host=pilot-db-01`

## Known Limitation

- `WIN-RTX-test` remains `inventory-only` from the Proxmox side because `QEMU guest agent` is not running on that VM.
- The Windows collector and Windows agent defaults are updated and ready, but live in-place reconfiguration of that guest was not possible from the current control path during this wave.
