import importlib.util
import json
from pathlib import Path
import re
import sys
import types
import unittest


ROOT = Path(__file__).resolve().parents[1]
PACKAGE = "test_normalizer_pkg"


def _load_normalizer():
    if PACKAGE not in sys.modules:
        package = types.ModuleType(PACKAGE)
        package.__path__ = [str(ROOT / "services" / "normalizer")]
        sys.modules[PACKAGE] = package
    config_name = f"{PACKAGE}.config"
    if config_name not in sys.modules:
        config_module = types.ModuleType(config_name)
        class NormalizerSettings:  # noqa: D401 - test stub
            pass
        config_module.NormalizerSettings = NormalizerSettings
        sys.modules[config_name] = config_module
    full_name = f"{PACKAGE}.normalizer_core"
    if full_name in sys.modules:
        return sys.modules[full_name]
    spec = importlib.util.spec_from_file_location(full_name, ROOT / "services" / "normalizer" / "normalizer_core.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load normalizer_core.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[full_name] = module
    spec.loader.exec_module(module)
    return module


normalizer_module = _load_normalizer()
apply_rules = normalizer_module.apply_rules


class NormalizerCoreTests(unittest.TestCase):
    def test_copying_deployment_file_from_tmp_is_not_tmp_execution(self) -> None:
        normalized = apply_rules(
            [],
            {
                "source_type": "syslog",
                "message": (
                    "<182>1 2026-07-26T09:55:00+00:00 siem-web auditd - - - "
                    'type=EXECVE msg=audit(1785069300.100:222): argc=6 '
                    'a0="install" a1="-m" a2="0644" a3="/tmp/deploy.service" '
                    'a4="/etc/systemd/system/deploy.service" a5=""'
                ),
                "source": "10.20.10.107",
            },
        )

        assert normalized is not None
        self.assertNotEqual("linux_exec_from_tmp", normalized.get("event.type"))

    def test_executing_binary_from_tmp_is_tmp_execution(self) -> None:
        normalized = apply_rules(
            [],
            {
                "source_type": "syslog",
                "message": (
                    "<182>1 2026-07-26T09:55:00+00:00 siem-web auditd - - - "
                    'type=EXECVE msg=audit(1785069300.100:223): argc=2 '
                    'a0="/tmp/.cache/payload" a1="--run"'
                ),
                "source": "10.20.10.107",
            },
        )

        assert normalized is not None
        self.assertEqual("linux_exec_from_tmp", normalized.get("event.type"))

    def test_local_wmi_query_is_not_remote_activity(self) -> None:
        normalized = apply_rules(
            [],
            {
                "source_type": "json",
                "message": json.dumps(
                    {
                        "winlog": {
                            "event_id": 5858,
                            "channel": "Microsoft-Windows-WMI-Activity/Operational",
                            "provider_name": "Microsoft-Windows-WMI-Activity",
                            "computer_name": "DESKTOP-5JMJVBH",
                        },
                        "message": (
                            "ClientMachine = DESKTOP-5JMJVBH; User = NT AUTHORITY\\SYSTEM; "
                            "Operation = Start IWbemServices::ExecQuery - root\\cimv2 : "
                            "SELECT * FROM Win32_DeviceGuard; ResultCode = 0x80041032"
                        ),
                    }
                ),
                "source": "DESKTOP-5JMJVBH",
            },
        )

        assert normalized is not None
        self.assertEqual("wmi_local_query", normalized.get("event.action"))
        self.assertEqual("DESKTOP-5JMJVBH", normalized.get("wmi.client_machine"))

    def test_remote_wmi_process_creation_is_high_signal(self) -> None:
        normalized = apply_rules(
            [],
            {
                "source_type": "json",
                "message": json.dumps(
                    {
                        "winlog": {
                            "event_id": 5858,
                            "channel": "Microsoft-Windows-WMI-Activity/Operational",
                            "provider_name": "Microsoft-Windows-WMI-Activity",
                            "computer_name": "WIN-SERVER-01",
                        },
                        "message": (
                            "ClientMachine = ADMIN-WS-01; User = LAB\\operator; "
                            "Operation = Start IWbemServices::ExecMethod - root\\cimv2 : "
                            "Win32_Process::Create"
                        ),
                    }
                ),
                "source": "WIN-SERVER-01",
            },
        )

        assert normalized is not None
        self.assertEqual("wmi_remote_execution", normalized.get("event.action"))

    def test_rfc5424_timestamp_and_audit_identity_are_stable(self) -> None:
        raw_event = {
            "source_type": "syslog",
            "message": (
                "<182>1 2026-07-26T07:37:54.426413+00:00 siem-processing auditd - - - "
                'type=EXECVE msg=audit(1785051474.424:280833): argc=2 a0="id" a1="-u"'
            ),
            "source": "10.20.10.105",
            "log_source": "10.20.10.105",
        }

        first = apply_rules([], raw_event)
        second = apply_rules([], dict(raw_event))

        self.assertIsNotNone(first)
        self.assertIsNotNone(second)
        assert first is not None and second is not None
        self.assertEqual("2026-07-26T07:37:54.426413Z", first.get("@timestamp"))
        self.assertEqual("1785051474.424:280833", first.get("audit.id"))
        self.assertRegex(str(first.get("event.id")), r"^audit-[0-9a-f]{32}$")
        self.assertEqual(first.get("event.id"), second.get("event.id"))

    def test_audit_syscall_fragment_is_not_counted_as_a_second_recon_command(self) -> None:
        normalized = apply_rules(
            [],
            {
                "source_type": "syslog",
                "message": (
                    "<182>1 2026-07-28T12:26:47+00:00 lab-edge-01 auditd - - - "
                    "type=SYSCALL msg=audit(1785241607.493:20237): "
                    'syscall=59 success=yes comm="uname" exe="/usr/bin/uname" '
                    'key="siem_user_execve"'
                ),
                "source": "10.20.10.102",
            },
        )

        assert normalized is not None
        self.assertEqual("audit_syscall", normalized.get("event.type"))
        self.assertNotEqual("linux_system_recon", normalized.get("event.type"))

    def test_audit_path_records_have_distinct_stable_event_ids(self) -> None:
        prefix = (
            "<182>1 2026-07-26T07:37:54+00:00 siem-processing auditd - - - "
            "type=PATH msg=audit(1785051474.424:280834): "
        )
        first = apply_rules(
            [],
            {
                "source_type": "syslog",
                "message": prefix + 'item=0 name="/tmp/one" nametype=NORMAL',
                "source": "10.20.10.105",
            },
        )
        second = apply_rules(
            [],
            {
                "source_type": "syslog",
                "message": prefix + 'item=1 name="/tmp/two" nametype=NORMAL',
                "source": "10.20.10.105",
            },
        )

        assert first is not None and second is not None
        self.assertNotEqual(first.get("event.id"), second.get("event.id"))

    def test_bsd_syslog_timestamp_is_normalized(self) -> None:
        normalized = apply_rules(
            [],
            {
                "source_type": "syslog",
                "message": "<6>Jul 26 07:37:54 siem-processing sshd[42]: Accepted publickey for ops from 192.168.3.81 port 51111",
                "source": "10.20.10.105",
            },
        )

        assert normalized is not None
        self.assertRegex(str(normalized.get("@timestamp")), r"^\d{4}-07-26T07:37:54Z$")

    def test_ingest_timestamp_survives_normalization_as_stable_fallback(self) -> None:
        normalized = apply_rules(
            [],
            {
                "source_type": "syslog",
                "message": (
                    "<30>1 2026-07-28T12:47:17Z pve systemd 1 - - "
                    "Runtime telemetry started"
                ),
                "source": "192.168.3.101",
                "ingest_ts": "2026-07-28T09:47:17Z",
            },
        )

        assert normalized is not None
        self.assertEqual("2026-07-28T09:47:17Z", normalized["ingest_ts"])

    def test_pve_bsd_syslog_timestamp_uses_moscow_timezone(self) -> None:
        normalized = apply_rules(
            [],
            {
                "source_type": "syslog",
                "message": "<6>Jul 26 06:00:00 pve pvedaemon[42]: production transport check",
                "source": "10.20.10.1",
            },
        )

        assert normalized is not None
        self.assertRegex(str(normalized.get("@timestamp")), r"^\d{4}-07-26T03:00:00Z$")

    def test_vpn_host_bsd_syslog_timestamp_uses_moscow_timezone(self) -> None:
        normalized = apply_rules(
            [],
            {
                "source_type": "syslog",
                "message": "<4>Jul 26 15:28:25 vpn-host-khanov kernel: [UFW BLOCK] SRC=85.217.140.8 DST=176.108.250.215",
                "source": "176.108.250.215",
            },
        )

        assert normalized is not None
        self.assertRegex(str(normalized.get("@timestamp")), r"^\d{4}-07-26T12:28:25Z$")

    def test_systemd_resolved_transaction_becomes_dns_query(self) -> None:
        raw_event = {
            "source_type": "syslog",
            "message": "<6>Mar 28 01:00:44 openclaw-gateway systemd-resolved[103589]: Regular transaction 45792 for <openai.com IN A> on scope dns on eth0/* now complete with <success> from network (unsigned; non-confidential).",
            "source": "openclaw-gateway",
            "log_source": "openclaw-gateway",
        }

        normalized = apply_rules([], raw_event)

        self.assertIsNotNone(normalized)
        assert normalized is not None
        self.assertEqual("linux.systemd-resolved", normalized.get("event.provider"))
        self.assertEqual("linux_dns_query", normalized.get("event.type"))
        self.assertEqual("dns_query", normalized.get("event.action"))
        self.assertEqual("network", normalized.get("event.category"))
        self.assertEqual("success", normalized.get("event.outcome"))
        self.assertEqual("openai.com", normalized.get("dns.question.name"))
        self.assertEqual("A", normalized.get("dns.question.type"))
        self.assertEqual("45792", normalized.get("event.id"))
        self.assertEqual("openclaw-gateway", normalized.get("host.name"))
        self.assertIn("allowlist:openclaw_expected_dns", normalized.get("tags") or [])

    def test_systemd_resolved_cache_line_becomes_dns_cache_event(self) -> None:
        raw_event = {
            "source_type": "syslog",
            "message": "<6>Mar 28 01:00:44 openclaw-gateway systemd-resolved[103589]: Added positive unauthenticated non-confidential cache entry for openai.com IN A 29s on eth0/INET/192.168.1.1",
            "source": "openclaw-gateway",
            "log_source": "openclaw-gateway",
        }

        normalized = apply_rules([], raw_event)

        self.assertIsNotNone(normalized)
        assert normalized is not None
        self.assertEqual("linux_dns_cache_entry", normalized.get("event.type"))
        self.assertEqual("dns_cache", normalized.get("event.action"))
        self.assertEqual("openai.com", normalized.get("dns.question.name"))
        self.assertEqual("A", normalized.get("dns.question.type"))
        self.assertEqual("29", normalized.get("dns.answers.ttl"))

    def test_openclaw_proxy_probe_is_allowlisted(self) -> None:
        raw_event = {
            "source_type": "syslog",
            "message": "<6>Mar 29 01:00:44 openclaw-gateway sudo: openclaw : PWD=/home/openclaw ; USER=root ; COMMAND=/usr/bin/ncat --proxy 127.0.0.1:10809 --proxy-type socks5 45.89.111.208 443",
            "source": "openclaw-gateway",
            "log_source": "openclaw-gateway",
        }

        normalized = apply_rules([], raw_event)

        self.assertIsNotNone(normalized)
        assert normalized is not None
        self.assertEqual("sudo_command", normalized.get("event.type"))
        self.assertIn("allowlist:openclaw_research_activity", normalized.get("tags") or [])

    def test_openclaw_ip_neigh_probe_is_allowlisted(self) -> None:
        raw_event = {
            "source_type": "syslog",
            "message": "<182>1 2026-03-29T07:37:54.426413+00:00 openclaw-gateway auditd - - - type=EXECVE msg=audit(1774769874.424:280833): argc=3 a0=\"ip\" a1=\"neigh\" a2=\"show\"",
            "source": "openclaw-gateway",
            "log_source": "openclaw-gateway",
        }

        normalized = apply_rules([], raw_event)

        self.assertIsNotNone(normalized)
        assert normalized is not None
        self.assertEqual("audit_execve", normalized.get("event.type"))
        self.assertIn("allowlist:openclaw_research_activity", normalized.get("tags") or [])

    def test_openclaw_shell_wrapped_ip_neigh_probe_is_allowlisted(self) -> None:
        raw_event = {
            "source_type": "syslog",
            "message": "<182>1 2026-03-29T07:37:54.426413+00:00 openclaw-gateway auditd - - - type=EXECVE msg=audit(1774769874.424:280833): argc=3 a0=\"/bin/sh\" a1=\"-c\" a2=\"ip neigh show\"",
            "source": "openclaw-gateway",
            "log_source": "openclaw-gateway",
        }

        normalized = apply_rules([], raw_event)

        self.assertIsNotNone(normalized)
        assert normalized is not None
        self.assertEqual("audit_execve", normalized.get("event.type"))
        self.assertIn("allowlist:openclaw_research_activity", normalized.get("tags") or [])

    def test_openclaw_node_gateway_exec_is_allowlisted(self) -> None:
        raw_event = {
            "source_type": "syslog",
            "message": "<182>1 2026-03-29T07:37:54.426413+00:00 openclaw-gateway auditd - - - type=EXECVE msg=audit(1774769874.424:280833): argc=5 a0=\"/usr/bin/node\" a1=\"/usr/lib/node_modules/openclaw/dist/index.js\" a2=\"gateway\" a3=\"--port\" a4=\"18789\"",
            "source": "openclaw-gateway",
            "log_source": "openclaw-gateway",
        }

        normalized = apply_rules([], raw_event)

        self.assertIsNotNone(normalized)
        assert normalized is not None
        self.assertEqual("audit_execve", normalized.get("event.type"))
        self.assertIn("allowlist:openclaw_research_activity", normalized.get("tags") or [])

    def test_openclaw_env_research_command_is_allowlisted(self) -> None:
        raw_event = {
            "source_type": "syslog",
            "message": "<182>1 2026-03-29T07:39:54.426413+00:00 openclaw-gateway auditd - - - type=EXECVE msg=audit(1774769994.424:280900): argc=6 a0=\"env\" a1=\"HOME=/home/openclaw\" a2=\"openclaw\" a3=\"agent\" a4=\"--agent\" a5=\"research\"",
            "source": "openclaw-gateway",
            "log_source": "openclaw-gateway",
        }

        normalized = apply_rules([], raw_event)

        self.assertIsNotNone(normalized)
        assert normalized is not None
        self.assertEqual("audit_execve", normalized.get("event.type"))
        self.assertIn("allowlist:openclaw_research_activity", normalized.get("tags") or [])

    def test_openclaw_expected_aaaa_dns_is_allowlisted(self) -> None:
        raw_event = {
            "source_type": "syslog",
            "message": "<6>Mar 29 01:00:44 openclaw-gateway systemd-resolved[103589]: Regular transaction 45793 for <api.telegram.org IN AAAA> on scope dns on eth0/* now complete with <success> from network (unsigned; non-confidential).",
            "source": "openclaw-gateway",
            "log_source": "openclaw-gateway",
        }

        normalized = apply_rules([], raw_event)

        self.assertIsNotNone(normalized)
        assert normalized is not None
        self.assertEqual("linux_dns_query", normalized.get("event.type"))
        self.assertIn("allowlist:openclaw_expected_dns", normalized.get("tags") or [])

    def test_openclaw_proxy_runtime_error_without_provider_is_allowlisted(self) -> None:
        raw_event = {
            "source_type": "syslog",
            "message": "<3>Mar 29 01:00:44 openclaw-gateway node[1042]: upstream timeout while proxy request to 45.89.111.208 via 127.0.0.1:10809",
            "source": "openclaw-gateway",
            "log_source": "openclaw-gateway",
        }

        normalized = apply_rules([], raw_event)

        self.assertIsNotNone(normalized)
        assert normalized is not None
        self.assertIn("allowlist:openclaw_proxy_runtime", normalized.get("tags") or [])

    def test_openclaw_expected_proctitle_is_allowlisted(self) -> None:
        raw_event = {
            "source_type": "syslog",
            "message": "<182>1 2026-03-29T09:59:22.572420+00:00 openclaw-gateway auditd - - - type=PROCTITLE msg=audit(1774778362.570:366621): proctitle=\"openclaw-agent\"",
            "source": "openclaw-gateway",
            "log_source": "openclaw-gateway",
        }

        normalized = apply_rules([], raw_event)

        self.assertIsNotNone(normalized)
        assert normalized is not None
        self.assertEqual("audit_proctitle", normalized.get("event.type"))
        self.assertIn("allowlist:openclaw_expected_activity", normalized.get("tags") or [])

    def test_openclaw_expected_dns_without_query_name_uses_message_fallback(self) -> None:
        self.assertTrue(
            normalizer_module._looks_like_openclaw_expected_dns(
                "",
                "systemd-resolved",
                "linux.systemd-resolved",
                "success",
                "Regular transaction 45792 for <openrouter.ai IN A> on scope dns now complete with <success>",
            )
        )

    def test_siem_operational_sudo_is_allowlisted(self) -> None:
        raw_event = {
            "source_type": "syslog",
            "message": "<6>Mar 29 01:00:44 siem-processing sudo: rdegon : PWD=/home/rdegon ; USER=root ; COMMAND=/usr/bin/systemctl is-active siem-normalizer siem-normalizer@2",
            "source": "siem-processing",
            "log_source": "siem-processing",
        }

        normalized = apply_rules([], raw_event)

        self.assertIsNotNone(normalized)
        assert normalized is not None
        self.assertEqual("sudo_command", normalized.get("event.type"))
        self.assertIn("allowlist:siem_operational_sudo", normalized.get("tags") or [])

    def test_sudo_command_with_tty_metadata_is_parsed_and_allowlisted(self) -> None:
        raw_event = {
            "source_type": "syslog",
            "message": (
                "<85>Jul 27 10:15:18 siem-web sudo: rdegon : TTY=pts/0 ; "
                "PWD=/home/rdegon ; USER=root ; COMMAND=/usr/bin/bash -lc "
                "'/opt/siem/siem-solution/deploy/system_cleanup.py --check'"
            ),
            "source": "siem-web",
            "log_source": "siem-web",
        }

        normalized = apply_rules([], raw_event)

        self.assertIsNotNone(normalized)
        assert normalized is not None
        self.assertEqual("sudo_command", normalized.get("event.type"))
        self.assertEqual("rdegon", normalized.get("user.name"))
        self.assertEqual("root", normalized.get("user.target.name"))
        self.assertIn("system_cleanup.py", normalized.get("process.command_line") or "")
        self.assertIn("allowlist:siem_operational_sudo", normalized.get("tags") or [])

    def test_windows_rdp_auth_success_is_normalized(self) -> None:
        raw_event = {
            "source_type": "json",
            "message": json.dumps(
                {
                    "winlog": {
                        "event_id": 1149,
                        "channel": "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
                        "provider_name": "Microsoft-Windows-TerminalServices-RemoteConnectionManager",
                        "computer_name": "win-rdp-01",
                        "event_data": {
                            "User": "alice",
                            "ClientAddress": "10.10.10.8",
                        },
                    },
                    "event": {"code": "1149"},
                    "host": {"name": "win-rdp-01"},
                }
            ),
            "source": "win-rdp-01",
        }

        normalized = apply_rules([], raw_event)

        self.assertIsNotNone(normalized)
        assert normalized is not None
        self.assertEqual("windows.rdp", normalized.get("event.provider"))
        self.assertEqual("windows_rdp_auth_success", normalized.get("event.type"))
        self.assertEqual("rdp_authentication_success", normalized.get("event.action"))
        self.assertEqual("10.10.10.8", normalized.get("source.ip"))
        self.assertEqual("alice", normalized.get("user.name"))

    def test_windows_defender_detection_is_normalized(self) -> None:
        raw_event = {
            "source_type": "json",
            "message": json.dumps(
                {
                    "winlog": {
                        "event_id": 1116,
                        "channel": "Microsoft-Windows-Windows Defender/Operational",
                        "provider_name": "Microsoft-Windows-Windows Defender",
                        "computer_name": "win-edr-01",
                        "event_data": {
                            "ThreatName": "EICAR-Test-File",
                        },
                    },
                    "event": {"code": "1116"},
                    "host": {"name": "win-edr-01"},
                }
            ),
            "source": "win-edr-01",
        }

        normalized = apply_rules([], raw_event)

        self.assertIsNotNone(normalized)
        assert normalized is not None
        self.assertEqual("windows.defender", normalized.get("event.provider"))
        self.assertEqual("windows_defender_malware_detected", normalized.get("event.type"))
        self.assertEqual("malware_detected", normalized.get("event.action"))
        self.assertEqual("high", normalized.get("event.severity"))

    def test_windows_collector_top_level_event_code_is_normalized(self) -> None:
        raw_event = {
            "source_type": "windows_event_json",
            "source": "DESKTOP-5JMJVBH",
            "host": {"name": "DESKTOP-5JMJVBH"},
            "computer_name": "DESKTOP-5JMJVBH",
            "channel": "Security",
            "provider": "Microsoft-Windows-Security-Auditing",
            "event_id": 4625,
            "event_code": "4625",
            "message": "An account failed to log on.",
            "windows": {
                "event_data": {
                    "TargetUserName": "Administrator",
                    "IpAddress": "10.20.30.40",
                    "LogonType": "10",
                }
            },
        }

        normalized = apply_rules([], raw_event)

        self.assertIsNotNone(normalized)
        assert normalized is not None
        self.assertEqual("windows.security", normalized.get("event.provider"))
        self.assertEqual("4625", normalized.get("event.code"))
        self.assertEqual("windows_logon_failure", normalized.get("event.type"))
        self.assertEqual("authentication_failed", normalized.get("event.action"))
        self.assertEqual("Administrator", normalized.get("user.name"))
        self.assertEqual("10.20.30.40", normalized.get("source.ip"))

    def test_windows_powershell_encoding_word_is_not_encoded_command(self) -> None:
        raw_event = {
            "source_type": "windows_event_json",
            "source": "DESKTOP-5JMJVBH",
            "computer_name": "DESKTOP-5JMJVBH",
            "channel": "Microsoft-Windows-PowerShell/Operational",
            "provider": "Microsoft-Windows-PowerShell",
            "event_id": 4104,
            "message": "Creating Scriptblock text: [Console]::OutputEncoding=[System.Text.Encoding]::UTF8; Get-Content repo\\deps.py",
        }

        normalized = apply_rules([], raw_event)

        self.assertIsNotNone(normalized)
        assert normalized is not None
        self.assertEqual("windows.powershell", normalized.get("event.provider"))
        self.assertNotEqual("windows_powershell_encoded_command", normalized.get("event.type"))

    def test_windows_powershell_encoded_command_switch_is_detected(self) -> None:
        raw_event = {
            "source_type": "windows_event_json",
            "source": "DESKTOP-5JMJVBH",
            "computer_name": "DESKTOP-5JMJVBH",
            "channel": "Microsoft-Windows-PowerShell/Operational",
            "provider": "Microsoft-Windows-PowerShell",
            "event_id": 4104,
            "message": "HostApplication=powershell.exe -NoProfile -EncodedCommand SQBFAFgA",
        }

        normalized = apply_rules([], raw_event)

        self.assertIsNotNone(normalized)
        assert normalized is not None
        self.assertEqual("windows_powershell_encoded_command", normalized.get("event.type"))
        self.assertEqual("powershell_encoded_command", normalized.get("event.action"))

    def test_windows_siem_operator_automation_is_narrowly_allowlisted(self) -> None:
        raw_event = {
            "source_type": "windows_event_json",
            "source": "DESKTOP-5JMJVBH",
            "computer_name": "DESKTOP-5JMJVBH",
            "channel": "Microsoft-Windows-PowerShell/Operational",
            "provider": "Microsoft-Windows-PowerShell",
            "event_id": 4100,
            "message": (
                r"$env:SIEM_PROXMOX_HOST='192.168.3.101'; "
                r"Set-Location C:\Users\Rdegon\Projects\siem-solution-clean; "
                "from deploy.soc_foundation_provision import Proxmox"
            ),
        }

        normalized = apply_rules([], raw_event)

        self.assertIsNotNone(normalized)
        assert normalized is not None
        self.assertIn("allowlist:siem_operator_automation", normalized.get("tags") or [])

    def test_generic_windows_powershell_is_not_operator_allowlisted(self) -> None:
        raw_event = {
            "source_type": "windows_event_json",
            "source": "DESKTOP-5JMJVBH",
            "computer_name": "DESKTOP-5JMJVBH",
            "channel": "Microsoft-Windows-PowerShell/Operational",
            "provider": "Microsoft-Windows-PowerShell",
            "event_id": 4104,
            "message": "Invoke-WebRequest https://example.invalid/payload.ps1",
        }

        normalized = apply_rules([], raw_event)

        self.assertIsNotNone(normalized)
        assert normalized is not None
        self.assertNotIn("allowlist:siem_operator_automation", normalized.get("tags") or [])

    def test_approved_scanner_windows_network_logon_probe_is_allowlisted(self) -> None:
        raw_event = {
            "source_type": "windows_event_json",
            "source": "DESKTOP-5JMJVBH",
            "computer_name": "DESKTOP-5JMJVBH",
            "channel": "Security",
            "provider": "Microsoft-Windows-Security-Auditing",
            "event_id": 4625,
            "message": "An account failed to log on.\r\n\r\nLogon Type:\t\t\t3",
            "windows": {
                "event_data": {
                    "TargetUserName": "administrator",
                        "IpAddress": "10.20.30.122",
                    "LogonType": "3",
                }
            },
        }

        normalized = apply_rules([], raw_event)

        self.assertIsNotNone(normalized)
        assert normalized is not None
        self.assertIn("allowlist:siem_approved_scanner", normalized.get("tags") or [])

    def test_approved_scanner_suricata_alert_is_allowlisted(self) -> None:
        raw_event = {
            "source_type": "syslog",
            "source": "lab-edge-01",
            "log_source": "lab-edge-01",
            "message": (
                "<180>1 2026-07-26T17:55:44+03:00 lab-edge-01 suricata-fast - - - "
                "07/26/2026-17:55:44 [**] [1:2024364:5] "
                "SURICATA TLS invalid record/traffic [**] "
                "[Classification: Protocol Command Decode] [Priority: 3] "
                "{TCP} 10.20.30.122:47538 -> 10.20.10.107:80"
            ),
        }

        normalized = apply_rules([], raw_event)

        self.assertIsNotNone(normalized)
        assert normalized is not None
        self.assertEqual("suricata_alert", normalized.get("event.type"))
        self.assertIn("allowlist:siem_approved_scanner", normalized.get("tags") or [])

    def test_unapproved_suricata_nmap_alert_is_not_allowlisted(self) -> None:
        raw_event = {
            "source_type": "syslog",
            "source": "lab-edge-01",
            "log_source": "lab-edge-01",
            "message": (
                "<180>1 2026-07-26T17:55:44+03:00 lab-edge-01 suricata-fast - - - "
                "07/26/2026-17:55:44 [**] [1:2024364:5] "
                "ET SCAN Possible Nmap User-Agent Observed [**] "
                "[Classification: Web Application Attack] [Priority: 1] "
                "{TCP} 10.20.20.121:47538 -> 10.20.10.107:80"
            ),
        }

        normalized = apply_rules([], raw_event)

        self.assertIsNotNone(normalized)
        assert normalized is not None
        self.assertNotIn("allowlist:siem_approved_scanner", normalized.get("tags") or [])

    def test_managed_lab_edge_rsyslog_change_is_allowlisted(self) -> None:
        raw_event = {
            "source_type": "syslog",
            "source": "lab-edge-01",
            "log_source": "lab-edge-01",
            "message": (
                '<182>1 2026-07-26T13:44:38+03:00 lab-edge-01 auditd - - - '
                'type=SYSCALL msg=audit(1785062678.697:5362): syscall=257 success=yes '
                'auid=4294967295 uid=0 gid=0 tty=(none) comm="bash" exe="/usr/bin/bash" '
                'key="rsyslog_config"'
            ),
        }

        normalized = apply_rules([], raw_event)

        self.assertIsNotNone(normalized)
        assert normalized is not None
        self.assertEqual("linux_rsyslog_config_modified", normalized.get("event.type"))
        self.assertIn("allowlist:siem_managed_rsyslog_change", normalized.get("tags") or [])

    def test_managed_systemd_unit_change_is_allowlisted_without_suppressing_arbitrary_units(self) -> None:
        managed = apply_rules(
            [],
            {
                "source_type": "syslog",
                "source": "siem-processing",
                "log_source": "siem-processing",
                "message": (
                    '<182>1 2026-07-28T02:10:00+03:00 siem-processing auditd - - - '
                    'type=PATH name="/etc/systemd/system/siem-normalizer.service.d/'
                    '60-static-kafka-member.conf" nametype=NORMAL'
                ),
            },
        )
        arbitrary = apply_rules(
            [],
            {
                "source_type": "syslog",
                "source": "pilot-web-01",
                "log_source": "pilot-web-01",
                "message": (
                    '<182>1 2026-07-28T02:11:00+03:00 pilot-web-01 auditd - - - '
                    'type=PATH name="/etc/systemd/system/backdoor.service" nametype=NORMAL'
                ),
            },
        )

        self.assertIsNotNone(managed)
        self.assertIsNotNone(arbitrary)
        assert managed is not None
        assert arbitrary is not None
        self.assertEqual("linux_systemd_unit_modified", managed.get("event.type"))
        self.assertIn("allowlist:siem_managed_systemd_change", managed.get("tags") or [])
        self.assertEqual("linux_systemd_unit_modified", arbitrary.get("event.type"))
        self.assertNotIn("allowlist:siem_managed_systemd_change", arbitrary.get("tags") or [])

    def test_windows_rendered_security_message_is_normalized_without_event_code(self) -> None:
        raw_event = {
            "source_type": "windows_event_json",
            "source": "DESKTOP-5JMJVBH",
            "collector_profile": "windows-security-http",
            "message": (
                "An account was successfully logged on.\r\n\r\n"
                "Subject:\r\n\tAccount Name:\t\tDESKTOP-5JMJVBH$\r\n\r\n"
                "Logon Information:\r\n\tLogon Type:\t\t5\r\n\r\n"
                "New Logon:\r\n\tAccount Name:\t\tSYSTEM\r\n\r\n"
                "Process Information:\r\n\tProcess Name:\t\tC:\\Windows\\System32\\services.exe\r\n"
            ),
        }

        normalized = apply_rules([], raw_event)

        self.assertIsNotNone(normalized)
        assert normalized is not None
        self.assertEqual("windows.security", normalized.get("event.provider"))
        self.assertEqual("4624", normalized.get("event.code"))
        self.assertEqual("windows_logon_success", normalized.get("event.type"))
        self.assertEqual("SYSTEM", normalized.get("user.name"))
        self.assertEqual("5", normalized.get("auth.logon_type"))


if __name__ == "__main__":
    unittest.main()
