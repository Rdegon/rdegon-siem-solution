import json
import unittest

from services.normalizer import normalizer_core as normalizer_module

apply_rules = normalizer_module.apply_rules


class ServiceNormalizerCoreTests(unittest.TestCase):
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
        self.assertEqual("network", normalized.get("event.category"))
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

    def test_openclaw_ufw_caps_probe_is_allowlisted(self) -> None:
        raw_event = {
            "source_type": "syslog",
            "message": "<182>1 2026-03-29T07:37:54.426413+00:00 openclaw-gateway auditd - - - type=EXECVE msg=audit(1774769874.424:280833): argc=4 a0=\"/usr/sbin/ip6tables\" a1=\"-A\" a2=\"ufw6-caps-test\" a3=\"-j\"",
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

    def test_openclaw_audit_socket_noise_is_allowlisted(self) -> None:
        raw_event = {
            "source_type": "syslog",
            "message": "<182>1 2026-03-29T09:59:22.572420+00:00 openclaw-gateway auditd - - - type=SYSCALL msg=audit(1774778362.570:366621): arch=c000003e syscall=44 success=yes exit=120 a0=6 a1=55a1cb8b2000 a2=120 a3=0 items=0 ppid=1031 pid=1032 auid=1000 uid=1000 gid=1000 euid=1000 suid=1000 fsuid=1000 egid=1000 sgid=1000 fsgid=1000 tty=(none) ses=42 comm=\"openclaw-agent\" exe=\"/usr/bin/node\" key=\"openclaw_send\"",
            "source": "openclaw-gateway",
            "log_source": "openclaw-gateway",
        }

        normalized = apply_rules([], raw_event)

        self.assertIsNotNone(normalized)
        assert normalized is not None
        self.assertIn("allowlist:openclaw_audit_socket_noise", normalized.get("tags") or [])
        self.assertIn("allowlist:openclaw_expected_activity", normalized.get("tags") or [])

    def test_internal_syslog_reconnect_noise_is_allowlisted(self) -> None:
        raw_event = {
            "source_type": "syslog",
            "message": "<46>Mar 29 10:22:41 openclaw-gateway rsyslogd[671]: omfwd: TCPSendBuf error -2027, destruct TCP Connection to 192.168.1.35:1514 [v8.2302.0 try https://www.rsyslog.com/e/2027 ]",
            "source": "openclaw-gateway",
            "log_source": "openclaw-gateway",
            "source.ip": "10.20.30.126",
            "destination.ip": "192.168.1.35",
            "destination.port": "1514",
        }

        normalized = apply_rules([], raw_event)

        self.assertIsNotNone(normalized)
        assert normalized is not None
        self.assertIn("allowlist:siem_internal_syslog_reconnect", normalized.get("tags") or [])

    def test_segmented_internal_syslog_reconnect_noise_is_allowlisted(self) -> None:
        raw_event = {
            "source_type": "syslog",
            "message": "omfwd: connection to 10.20.10.104:1514 closed connection",
            "source": "openclaw-gateway",
            "log_source": "openclaw-gateway",
            "source.ip": "10.20.30.126",
            "destination.ip": "10.20.10.104",
            "destination.port": "1514",
        }

        normalized = apply_rules([], raw_event)

        self.assertIsNotNone(normalized)
        assert normalized is not None
        self.assertIn("allowlist:siem_internal_syslog_reconnect", normalized.get("tags") or [])

    def test_greenbone_expected_ssh_probe_is_allowlisted(self) -> None:
        raw_event = {
            "source_type": "syslog",
            "message": "<5>Mar 29 12:10:21 siem-ingest sshd[1188]: Invalid user admin from 10.20.30.122 port 55890",
            "source": "siem-ingest",
            "log_source": "siem-ingest",
        }

        normalized = apply_rules([], raw_event)

        self.assertIsNotNone(normalized)
        assert normalized is not None
        self.assertEqual("ssh_invalid_user", normalized.get("event.type"))
        self.assertIn("allowlist:greenbone_expected_ssh_probe", normalized.get("tags") or [])

    def test_openclaw_libuv_worker_recon_helper_is_allowlisted(self) -> None:
        self.assertTrue(
            normalizer_module._looks_like_openclaw_expected_recon(
                "linux_system_recon",
                "libuv-worker",
                "",
                "",
            )
        )

    def test_siem_operational_deploy_command_is_allowlisted(self) -> None:
        raw_event = {
            "source_type": "syslog",
            "message": "<6>Mar 29 01:00:44 siem-web sudo: rdegon : PWD=/home/rdegon ; USER=root ; COMMAND=/usr/bin/python3 deploy/vm4_enterprise_foundation_deploy.py",
            "source": "siem-web",
            "log_source": "siem-web",
        }

        normalized = apply_rules([], raw_event)

        self.assertIsNotNone(normalized)
        assert normalized is not None
        self.assertEqual("sudo_command", normalized.get("event.type"))
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
