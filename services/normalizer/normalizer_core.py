from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import re
import shlex
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

try:
    import jmespath
    _JMESPATH_IMPORT_ERROR: ModuleNotFoundError | None = None
except ModuleNotFoundError as exc:  # pragma: no cover - CI fallback when optional extras are absent
    jmespath = None  # type: ignore[assignment]
    _JMESPATH_IMPORT_ERROR = exc

try:
    from clickhouse_driver import Client
    _CLICKHOUSE_DRIVER_IMPORT_ERROR: ModuleNotFoundError | None = None
except ModuleNotFoundError as exc:  # pragma: no cover - CI fallback when optional extras are absent
    Client = Any  # type: ignore[assignment,misc]
    _CLICKHOUSE_DRIVER_IMPORT_ERROR = exc

from .config import NormalizerSettings
from .security_tool_normalizers import parse_security_tool_event, parse_suricata_payload

logger = logging.getLogger(__name__)

SYSLOG_RE = re.compile(
    r"^(?:<(?P<pri>\d+)>)?(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<clock>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<program>[\w./-]+?)(?:\[(?P<pid>\d+)\])?:\s?(?P<body>.*)$"
)
SYSLOG_RFC5424_RE = re.compile(
    r"^<(?P<pri>\d+)>(?P<version>\d)\s+(?P<timestamp>\S+)\s+(?P<host>\S+)\s+"
    r"(?P<program>\S+)\s+(?P<pid>\S+)\s+(?P<msgid>\S+)\s+(?P<structured>(?:-|\[[^\]]*\](?:\[[^\]]*\])*))\s*(?P<body>.*)$"
)
AUDIT_ID_RE = re.compile(r"\bmsg=audit\((?P<audit_id>[^)]+)\)")
KV_RE = re.compile(r'([A-Za-z0-9_.-]+)=(".*?"|\'.*?\'|[^ ]+)')
IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
UFW_BLOCK_RE = re.compile(
    r"\[UFW BLOCK\].*?\bSRC=(?P<src>\d+\.\d+\.\d+\.\d+)\b.*?\bDST=(?P<dst>\d+\.\d+\.\d+\.\d+)\b"
    r"(?:.*?\bPROTO=(?P<proto>[A-Z0-9]+))?(?:.*?\bSPT=(?P<spt>\d+))?(?:.*?\bDPT=(?P<dpt>\d+))?",
    re.IGNORECASE,
)
SSHD_ACCEPT_RE = re.compile(
    r"Accepted (?P<method>\w+) for (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+) port (?P<port>\d+)",
    re.IGNORECASE,
)
SSHD_FAIL_RE = re.compile(
    r"Failed (?P<method>\w+) for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+) port (?P<port>\d+)",
    re.IGNORECASE,
)
SSHD_SESSION_RE = re.compile(
    r"pam_unix\(sshd:session\): session (?P<state>opened|closed) for user (?P<user>\S+)",
    re.IGNORECASE,
)
SSHD_INVALID_USER_RE = re.compile(
    r"Invalid user (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+) port (?P<port>\d+)",
    re.IGNORECASE,
)
XRAY_ACCESS_RE = re.compile(
    r"from\s+(?P<src_endpoint>.+?)\s+accepted\s+(?P<dst_endpoint>\S+)\s+\[(?P<route>[^\]]+)\]"
    r"(?:\s+email:\s*(?P<email>[^,\s]+))?(?:,\s*Domain:\s*(?P<domain>\S+))?",
    re.IGNORECASE,
)
SUDO_COMMAND_RE = re.compile(
    r"^\s*(?P<user>\S+)\s*:\s*PWD=(?P<pwd>[^;]+)\s*;\s*USER=(?P<target>[^;]+)\s*;\s*COMMAND=(?P<command>.+)$"
)
SUDO_SESSION_RE = re.compile(
    r"pam_unix\(sudo:session\): session (?P<state>opened|closed) for user (?P<target>\S+)",
    re.IGNORECASE,
)
SU_SESSION_RE = re.compile(
    r"pam_unix\(su:session\): session (?P<state>opened|closed) for user (?P<target>\S+) by (?P<user>\S+)",
    re.IGNORECASE,
)
CRON_CMD_RE = re.compile(r"\((?P<user>[^)]+)\)\s+CMD\s+\((?P<command>.+)\)")
PASSWD_CHANGE_RE = re.compile(r"password changed for (?P<user>\S+)", re.IGNORECASE)
POWERSHELL_ENCODED_SWITCH_RE = re.compile(r"(?i)(?:^|[\s\"'])[-/](?:enc|encodedcommand)\b")
USERADD_RE = re.compile(r"new user:\s+name=(?P<user>[^,\s]+)", re.IGNORECASE)
USERDEL_RE = re.compile(r"delete user\s+'(?P<user>[^']+)'", re.IGNORECASE)
USERMOD_RE = re.compile(r"(?:add|adding)\s+'?(?P<user>[^'\s]+)'?\s+to\s+(?:group|groups?)\s+'?(?P<group>[^'\s]+)'?", re.IGNORECASE)
RESOLVED_TRANSACTION_RE = re.compile(
    r"Regular transaction\s+(?P<transaction_id>\d+)\s+for\s+<(?P<query_name>[^>\s]+)\s+IN\s+(?P<query_type>[A-Z0-9]+)>"
    r".*?complete with <(?P<outcome>[^>]+)>",
    re.IGNORECASE,
)
RESOLVED_CACHE_RE = re.compile(
    r"Added positive .* cache entry for (?P<query_name>\S+)\s+IN\s+(?P<query_type>[A-Z0-9]+)\s+(?P<ttl>\d+)s",
    re.IGNORECASE,
)
WINDOWS_RENDERED_EVENT_HINTS: tuple[tuple[str, str], ...] = (
    ("an account failed to log on", "4625"),
    ("an account was successfully logged on", "4624"),
    ("special privileges assigned to new logon", "4672"),
    ("the audit log was cleared", "1102"),
    ("a user account was created", "4720"),
    ("a user account was deleted", "4726"),
    ("a member was added to a security-enabled global group", "4728"),
    ("a member was added to a security-enabled local group", "4732"),
    ("a member was added to a security-enabled universal group", "4756"),
)
SYSLOG_LEVEL_MAP = {
    0: "critical",
    1: "critical",
    2: "high",
    3: "high",
    4: "medium",
    5: "low",
    6: "info",
    7: "low",
}
HIGH_RISK_EVENT_TYPES = {
    "audit_exec_as_root",
    "linux_root_ssh_login",
    "linux_reverse_shell_possible",
    "linux_authorized_keys_modified",
    "linux_ld_preload_modified",
    "linux_firewall_disabled",
    "linux_sudoers_modified",
    "linux_systemd_unit_modified",
}
OPENCLAW_EXPECTED_HOST = "openclaw-gateway"
OPENCLAW_PROXY_ERROR_MARKERS = (
    "timeout",
    "timed out",
    "broken pipe",
    "connection reset",
    "connection refused",
    "closed pipe",
    "deadline exceeded",
    "eof",
)
OPENCLAW_PROXY_RUNTIME_MARKERS = (
    "deletewebhook failed",
    "webhook cleanup failed",
    "fetch fallback",
    "sticky ipv4-only dispatcher",
    "cannot connect to 192.168.1.35:1514",
    "remote server at 192.168.1.35:1514 seems to have closed connection",
    "action 'action-0-builtin:omfwd' suspended",
    "omfwd",
)
OPENCLAW_RESEARCH_COMMAND_MARKERS = (
    "openclaw agent --agent research",
    "openclaw agent --agent research --message",
    "/usr/bin/openclaw",
    "/usr/bin/env node /usr/bin/openclaw agent --agent research",
    "/usr/lib/node_modules/openclaw/dist/index.js gateway",
    "/usr/bin/node /usr/lib/node_modules/openclaw/dist/index.js gateway --port",
    "openclaw-gateway.service",
    "openclaw-vless.service",
    "openclaw-sbx-agent-research",
    "docker inspect -f {{ index .config.labels \"openclaw.confighash\" }}",
    "docker inspect -f {{.state.running}} openclaw-sbx-agent-research",
    "ip neigh show",
    "ufw6-caps-test",
    "ufw-caps-test",
    "ip6tables -a ufw6-caps-test",
    "iptables -a ufw-caps-test",
    "--json --local",
    "ты soc-аналитик",
)
OPENCLAW_PROXY_PROBE_MARKERS = (
    "127.0.0.1:10809",
    "45.89.111.208",
    "--proxy 127.0.0.1:10809",
    "--proxy-type socks5",
    "-x 127.0.0.1:10809",
)
OPENCLAW_EXPECTED_DNS_SUFFIXES = (
    "api.telegram.org",
    "openrouter.ai",
    "bing.com",
    "duckduckgo.com",
    "duck.com",
    "search.brave.com",
    "brave.com",
    "google.com",
    "googleapis.com",
    "gstatic.com",
    "yandex.ru",
    "ya.ru",
    "search.yahoo.com",
    "github.com",
    "githubusercontent.com",
    "wikipedia.org",
)
OPENCLAW_EXPECTED_PROCTITLE_VALUES = {
    "openclaw-agent",
    "openclaw-gateway",
    "(node)",
    "node",
}
OPENCLAW_EXPECTED_RECON_PROCESSES = {
    "openclaw-gateway",
    "openclaw-gatewa",
    "node",
    "libuv-worker",
}
OPENCLAW_AUDIT_SOCKET_KEYS = {"openclaw_send", "openclaw_connect"}
GREENBONE_SCANNER_HOST = "vuln-mgr-01"
GREENBONE_SCANNER_IPS = {"10.20.30.122"}
SIEM_INTERNAL_SYSLOG_INGEST_IPS = {"10.20.10.104", "192.168.1.35"}
SIEM_INTERNAL_SYSLOG_TARGET_IP = "10.20.30.126"
SIEM_INTERNAL_SYSLOG_PORT = "1514"
SIEM_OPERATIONAL_SUDO_HOSTS = {
    "siem-ingest",
    "siem-processing",
    "siem-storage",
    "siem-web",
    "siem-standby-transport",
}
SIEM_OPERATIONAL_SUDO_MARKERS = (
    "systemctl is-active siem-",
    "systemctl status siem-",
    "systemctl restart siem-",
    "systemctl start siem-",
    "systemctl reload siem-",
    "systemctl --failed",
    "journalctl -u siem-",
    "journalctl --unit siem-",
    "python3 deploy/",
    "/opt/siem/siem-solution/deploy/",
    "install -m 0644 /opt/siem/siem-solution/",
    "clickhouse-client",
    "kafka-topics.sh",
    "kafka-consumer-groups.sh",
)
SIEM_OPERATOR_AUTOMATION_HOSTS = {"desktop-5jmjvbh", "win-rtx-test"}
SIEM_OPERATOR_AUTOMATION_PATH_MARKERS = (
    r"c:\users\rdegon\projects\siem-solution-clean",
    r"c:\users\rdegon\projects\siem_xfer_2026-03-25\docs\operator_bundle\operator_access_bundle.md",
)
SIEM_OPERATOR_AUTOMATION_ACTION_MARKERS = (
    "from deploy.soc_foundation_provision import proxmox",
    "from deploy.security_analytics_qga_deploy import",
    "$env:siem_proxmox_host",
    "/opt/siem/siem-solution/",
)
SIEM_APPROVED_SCANNER_IPS = {"10.20.30.122"}
MEDIUM_RISK_EVENT_TYPES = {
    "audit_user_login_failure",
    "audit_user_auth_failure",
    "linux_accounts_modified",
    "linux_audit_tool_execution",
    "linux_common_service_port_connection",
    "linux_credentials_in_files",
    "linux_dbus_send",
    "linux_user_created",
    "linux_user_deleted",
    "linux_user_added_to_admin_group",
    "linux_password_changed",
    "linux_cron_modified",
    "linux_audit_config_changed",
    "linux_audit_rules_cleared",
    "linux_network_connections_discovery",
    "linux_network_configuration_discovery",
    "linux_process_discovery",
    "linux_remote_access_tool",
    "linux_remote_services_discovery",
    "linux_shell_execute",
    "linux_sysctl_modified",
    "linux_system_information_discovery",
    "linux_system_owner_user_discovery",
    "linux_valid_accounts_discovery",
    "linux_download_utility",
    "linux_network_tool",
    "linux_packet_capture",
    "linux_exec_from_tmp",
    "linux_system_recon",
    "linux_passwd_shadow_access",
}
HIGH_RISK_EVENT_TYPES.update(
    {
        "linux_binary_modified",
        "linux_init_system_modified",
        "linux_kernel_module_modified",
        "linux_library_modified",
        "linux_pkexec_execution",
        "linux_privilege_escalation_file_modified",
        "linux_privilege_escalation_tool",
        "linux_rsyslog_config_modified",
        "linux_sshd_config_modified",
    }
)
AUDIT_KEY_SHAPES = {
    "account_discovery": ("discovery", "recon", "linux_account_discovery"),
    "accounts_modify": ("identity", "account_modify", "linux_accounts_modified"),
    "audit_config": ("defense_evasion", "audit_config_change", "linux_audit_config_changed"),
    "audit_tools": ("defense_evasion", "audit_tool_execution", "linux_audit_tool_execution"),
    "bin_modify": ("defense_evasion", "file_modify", "linux_binary_modified"),
    "commonly_used_port": ("network", "connection_attempt", "linux_common_service_port_connection"),
    "credentials_in_files": ("credential", "file_access", "linux_credentials_in_files"),
    "cron": ("persistence", "scheduled_task_modify", "linux_cron_modified"),
    "dbus_send": ("execution", "dbus_send", "linux_dbus_send"),
    "init_modify": ("persistence", "service_unit_modify", "linux_init_system_modified"),
    "kernel_modules": ("defense_evasion", "module_modify", "linux_kernel_module_modified"),
    "lib_modify": ("defense_evasion", "file_modify", "linux_library_modified"),
    "lib_preloads_modify": ("defense_evasion", "preload_modify", "linux_ld_preload_modified"),
    "pkexec": ("privilege", "pkexec", "linux_pkexec_execution"),
    "priv_esc": ("privilege", "execute_as_root", "linux_privilege_escalation_tool"),
    "priv_esc_file": ("privilege", "file_modify", "linux_privilege_escalation_file_modified"),
    "priv_esc_sudo_cache": ("privilege", "sudo_cache_modify", "linux_sudo_cache_modified"),
    "process_discovery": ("discovery", "recon", "linux_process_discovery"),
    "recon_execute": ("discovery", "recon", "linux_system_recon"),
    "remote_access_tools": ("command_and_control", "remote_access_tool", "linux_remote_access_tool"),
    "remote_services_discovery": ("discovery", "recon", "linux_remote_services_discovery"),
    "root_execute": ("privilege", "execute_as_root", "linux_exec_as_root"),
    "rsyslog_config": ("defense_evasion", "service_config_modify", "linux_rsyslog_config_modified"),
    "setuid_and_setgid": ("privilege", "setuid_modify", "linux_setuid_bit_modified"),
    "shell_execute": ("execution", "shell_execute", "linux_shell_execute"),
    "sshd_config": ("defense_evasion", "service_config_modify", "linux_sshd_config_modified"),
    "sysctl": ("defense_evasion", "kernel_param_modify", "linux_sysctl_modified"),
    "system_information_discovery": ("discovery", "recon", "linux_system_information_discovery"),
    "system_network_configuration_discovery": ("discovery", "recon", "linux_network_configuration_discovery"),
    "system_network_connections_discovery": ("discovery", "recon", "linux_network_connections_discovery"),
    "system_owner_user_discovery": ("discovery", "recon", "linux_system_owner_user_discovery"),
    "t1166_seuid_and_setgid": ("privilege", "setuid_modify", "linux_setuid_bit_modified"),
    "tmp_execute": ("execution", "exec_tmp", "linux_exec_from_tmp"),
    "valid_accounts": ("discovery", "recon", "linux_valid_accounts_discovery"),
}


@dataclass
class NormalizerRule:
    id: int
    priority: int
    source_type: str
    event_matcher_expr: str
    compiled_matcher: Optional[Any]
    compiled_mapping: Dict[str, Any]


def _repair_mojibake(value: Any) -> str:
    text = str(value or "")
    if not text or not any(marker in text for marker in ("Ð", "Ñ", "Â", "Ã", "â")):
        return text
    for source_encoding in ("latin1", "cp1252"):
        try:
            repaired = text.encode(source_encoding).decode("utf-8")
        except UnicodeError:
            continue
        if repaired != text:
            return repaired
    return text


def _clean_value(value: Any) -> str:
    return _repair_mojibake(str(value or "").replace("\x1d", " ")).strip()


def _json_loads_safe(value: str) -> Dict[str, Any]:
    text = _clean_value(value)
    if not text:
        return {}
    try:
        payload = json.loads(text)
    except Exception:
        return {}
    return payload if isinstance(payload, dict) else {}


def _dotted_get(mapping: Dict[str, Any], path: str) -> Any:
    if path in mapping:
        return mapping.get(path)
    current: Any = mapping
    for part in path.split("."):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return None
    return current


def _first_non_empty(mapping: Dict[str, Any], *paths: str) -> str:
    for path in paths:
        value = _dotted_get(mapping, path)
        text = _clean_value(value)
        if text:
            return text
    return ""


def _flatten_prefixed(mapping: Dict[str, Any], prefix: str) -> Dict[str, str]:
    result: Dict[str, str] = {}
    for key, value in mapping.items():
        if not isinstance(key, str) or not key.startswith(prefix):
            continue
        suffix = key[len(prefix):]
        text = _clean_value(value)
        if suffix and text:
            result[suffix] = text
    return result


def _is_ipv4(value: str) -> bool:
    return bool(value and IPV4_RE.match(value))


def _strip_quotes(value: str) -> str:
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        return value[1:-1]
    return value


def _canonical_host_name(value: str) -> str:
    host = _clean_value(value)
    if not host or _is_ipv4(host):
        return host
    if "." in host:
        head = host.split(".", 1)[0].strip()
        if head:
            return head
    return host


def _decode_hex(value: str) -> str:
    raw = value.strip()
    if not raw or len(raw) % 2 != 0 or not re.fullmatch(r"[0-9A-Fa-f]+", raw):
        return raw
    try:
        decoded = bytes.fromhex(raw).decode("utf-8", errors="replace").replace("\x00", " ").strip()
    except Exception:
        return raw
    return decoded or raw


def _normalize_audit_key(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", _clean_value(value).lower()).strip("_")


def _decode_audit_sockaddr(value: str) -> Dict[str, str]:
    raw = _clean_value(value).replace("0x", "")
    if not raw or len(raw) % 2 != 0 or not re.fullmatch(r"[0-9A-Fa-f]+", raw):
        return {}
    try:
        data = bytes.fromhex(raw)
    except Exception:
        return {}
    if len(data) < 8:
        return {}
    family = int.from_bytes(data[0:2], "little")
    if family == 2 and len(data) >= 8:
        try:
            return {
                "destination.ip": str(ipaddress.IPv4Address(data[4:8])),
                "destination.port": str(int.from_bytes(data[2:4], "big")),
            }
        except Exception:
            return {}
    if family == 10 and len(data) >= 24:
        try:
            return {
                "destination.ip": str(ipaddress.IPv6Address(data[8:24])),
                "destination.port": str(int.from_bytes(data[2:4], "big")),
            }
        except Exception:
            return {}
    return {}


def _merge_non_empty(target: Dict[str, Any], updates: Dict[str, Any]) -> Dict[str, Any]:
    for key, value in updates.items():
        if value in (None, "", [], {}, "?"):
            continue
        target[key] = value
    return target


def _normalize_tag_values(value: Any) -> List[str]:
    if value in (None, "", [], {}):
        return []
    if isinstance(value, list):
        items = value
    else:
        text = str(value).strip()
        if not text:
            return []
        if text.startswith("[") and text.endswith("]"):
            try:
                parsed = json.loads(text)
            except Exception:
                parsed = []
            items = parsed if isinstance(parsed, list) else [parsed]
        else:
            items = [part.strip() for part in text.split(",")]
    tags: List[str] = []
    seen: set[str] = set()
    for item in items:
        tag = _clean_value(item)
        if not tag or tag in seen:
            continue
        seen.add(tag)
        tags.append(tag)
    return tags


def _append_tags(event: Dict[str, Any], *tags: str) -> None:
    existing = _normalize_tag_values(event.get("tags"))
    seen = set(existing)
    for tag in tags:
        safe_tag = _clean_value(tag)
        if not safe_tag or safe_tag in seen:
            continue
        seen.add(safe_tag)
        existing.append(safe_tag)
    if existing:
        event["tags"] = existing


def _looks_like_openclaw_research_command(command_line: str) -> bool:
    safe_command = str(command_line or "").strip().lower()
    if not safe_command:
        return False
    return any(marker in safe_command for marker in OPENCLAW_RESEARCH_COMMAND_MARKERS)


def _looks_like_openclaw_proxy_probe(command_line: str, process_name: str, user_name: str) -> bool:
    safe_command = str(command_line or "").strip().lower()
    safe_process = str(process_name or "").strip().lower()
    safe_user = str(user_name or "").strip().lower()
    if any(marker in safe_command for marker in OPENCLAW_PROXY_PROBE_MARKERS):
        return (
            safe_process in {"nc", "ncat", "curl", "wget", "sh", "bash", "env"}
            or safe_user in {"openclaw", "root"}
            or "openclaw" in safe_command
        )
    if safe_process not in {"nc", "ncat", "curl", "wget"} and safe_user != "openclaw":
        return False
    return safe_process in {"nc", "ncat"} and safe_user == "openclaw"


def _looks_like_openclaw_expected_dns(query_name: str, process_name: str, provider: str, outcome: str, message: str = "") -> bool:
    safe_query = str(query_name or "").strip().lower().rstrip(".")
    safe_process = str(process_name or "").strip().lower()
    safe_provider = str(provider or "").strip().lower()
    safe_outcome = str(outcome or "").strip().lower()
    safe_message = str(message or "").strip().lower()
    if safe_query and any(safe_query == suffix or safe_query.endswith(f".{suffix}") for suffix in OPENCLAW_EXPECTED_DNS_SUFFIXES):
        return True
    if "regular transaction" in safe_message and safe_provider == "linux.systemd-resolved" and safe_process in {"systemd-resolved", "resolved", ""}:
        return safe_outcome in {"", "success", "allowed", "cache_hit"}
    return safe_provider == "linux.systemd-resolved" and safe_process in {"systemd-resolved", "resolved", ""} and safe_outcome in {
        "",
        "success",
        "allowed",
        "cache_hit",
    }


def _looks_like_openclaw_expected_proctitle(command_line: str, target_user: str, message: str) -> bool:
    safe_command = str(command_line or "").strip().lower()
    safe_target = str(target_user or "").strip().lower()
    safe_message = str(message or "").strip().lower()
    if safe_command in OPENCLAW_EXPECTED_PROCTITLE_VALUES:
        return True
    if safe_target in OPENCLAW_EXPECTED_PROCTITLE_VALUES:
        return True
    return any(
        marker in safe_message
        for marker in (
            'proctitle="openclaw-agent"',
            'proctitle="openclaw-gateway"',
            'proctitle="(node)"',
            'proctitle="node"',
        )
    )


def _looks_like_openclaw_proxy_runtime_noise(event_type: str, process_name: str, provider: str, command_or_message: str) -> bool:
    safe_event_type = str(event_type or "").strip().lower()
    safe_process = str(process_name or "").strip().lower()
    safe_provider = str(provider or "").strip().lower()
    safe_message = str(command_or_message or "").strip().lower()
    if any(marker in safe_message for marker in OPENCLAW_PROXY_RUNTIME_MARKERS):
        return (
            safe_process.startswith("openclaw")
            or safe_process in {"node", "xray", "rsyslogd", "omfwd", "sh", "bash", ""}
            or safe_provider in {"linux.rsyslogd", "linux.systemd-resolved"}
            or "openclaw" in safe_message
        )
    return (
        safe_event_type in {"syslog", "app_log", "application_log"}
        and any(marker in safe_message for marker in OPENCLAW_PROXY_ERROR_MARKERS)
        and (
            safe_process.startswith("openclaw")
            or safe_process in {"node", "xray", "rsyslogd", "omfwd", "sh", "bash"}
            or "openclaw" in safe_message
        )
    )


def _looks_like_openclaw_expected_audit_socket_noise(event_type: str, audit_key: str, process_name: str, command_or_message: str) -> bool:
    safe_event_type = str(event_type or "").strip().lower()
    safe_audit_key = _normalize_audit_key(audit_key)
    safe_process = str(process_name or "").strip().lower()
    safe_message = str(command_or_message or "").strip().lower()
    if safe_event_type not in {"audit_syscall", "linux_network_connection", "audit_execve"}:
        return False
    if safe_audit_key not in OPENCLAW_AUDIT_SOCKET_KEYS:
        return False
    return (
        safe_process.startswith("openclaw")
        or safe_process in {"node", "xray", "ip", ""}
        or "openclaw" in safe_message
        or 'key="openclaw_' in safe_message
    )


def _looks_like_openclaw_expected_recon(event_type: str, process_name: str, target_user: str, command_or_message: str) -> bool:
    safe_event_type = str(event_type or "").strip().lower()
    safe_process = str(process_name or "").strip().lower()
    safe_target = str(target_user or "").strip().lower()
    safe_message = str(command_or_message or "").strip().lower()
    if safe_event_type not in {"linux_system_recon", "audit_execve", "audit_user_command"}:
        return False
    if _looks_like_openclaw_research_command(safe_message):
        return True
    if safe_target.startswith("openclaw-sbx-agent-research"):
        return True
    if safe_process == "auditd" and any(
        marker in safe_message
        for marker in (
            "ufw6-caps-test",
            "ufw-caps-test",
            "ip6tables -a",
            "iptables -a",
            "ip neigh show",
            "--json --local",
            "ты soc-аналитик",
        )
    ):
        return True
    return safe_process in OPENCLAW_EXPECTED_RECON_PROCESSES


def _looks_like_internal_syslog_reconnect_noise(host_name: str, source_ip: str, destination_ip: str, source_port: str, destination_port: str, message: str) -> bool:
    safe_host = _canonical_host_name(str(host_name or "")).lower()
    safe_source_ip = str(source_ip or "").strip()
    safe_destination_ip = str(destination_ip or "").strip()
    safe_source_port = str(source_port or "").strip()
    safe_destination_port = str(destination_port or "").strip()
    safe_message = str(message or "").strip().lower()
    if safe_host != OPENCLAW_EXPECTED_HOST:
        return False
    if safe_source_ip in SIEM_INTERNAL_SYSLOG_INGEST_IPS and safe_source_port == SIEM_INTERNAL_SYSLOG_PORT:
        return True
    if safe_source_ip in SIEM_INTERNAL_SYSLOG_INGEST_IPS and safe_destination_ip == SIEM_INTERNAL_SYSLOG_TARGET_IP:
        return True
    if safe_destination_ip in SIEM_INTERNAL_SYSLOG_INGEST_IPS and safe_destination_port == SIEM_INTERNAL_SYSLOG_PORT:
        return True
    return any(
        f"{ingest_ip}:{SIEM_INTERNAL_SYSLOG_PORT}" in safe_message
        for ingest_ip in SIEM_INTERNAL_SYSLOG_INGEST_IPS
    ) and (
        "connection refused" in safe_message or "closed connection" in safe_message or "omfwd" in safe_message
    )


def _looks_like_siem_operational_sudo(command_line: str, host_name: str, user_name: str) -> bool:
    safe_command = str(command_line or "").strip().lower()
    safe_host = _canonical_host_name(str(host_name or "")).lower()
    safe_user = str(user_name or "").strip().lower()
    if safe_host not in SIEM_OPERATIONAL_SUDO_HOSTS:
        return False
    if safe_user not in {"rdegon", "root", "siem"}:
        return False
    return any(marker in safe_command for marker in SIEM_OPERATIONAL_SUDO_MARKERS)


def _looks_like_greenbone_expected_ssh_probe(event_type: str, source_ip: str, host_name: str, log_source: str) -> bool:
    safe_event_type = str(event_type or "").strip().lower()
    safe_source_ip = str(source_ip or "").strip()
    safe_host = _canonical_host_name(str(host_name or "")).lower()
    safe_log_source = _canonical_host_name(str(log_source or "")).lower()
    if safe_event_type not in {"ssh_login_failure", "ssh_invalid_user"}:
        return False
    if safe_source_ip not in GREENBONE_SCANNER_IPS:
        return False
    return safe_host not in {GREENBONE_SCANNER_HOST, ""} and safe_log_source not in {GREENBONE_SCANNER_HOST, ""}


def _looks_like_siem_operator_automation(provider: str, host_name: str, message: str) -> bool:
    safe_provider = str(provider or "").strip().lower()
    safe_host = _canonical_host_name(str(host_name or "")).lower()
    safe_message = str(message or "").strip().lower()
    return (
        safe_provider == "windows.powershell"
        and safe_host in SIEM_OPERATOR_AUTOMATION_HOSTS
        and any(marker in safe_message for marker in SIEM_OPERATOR_AUTOMATION_PATH_MARKERS)
        and any(marker in safe_message for marker in SIEM_OPERATOR_AUTOMATION_ACTION_MARKERS)
    )


def _looks_like_approved_scanner_auth_probe(
    event_type: str,
    source_ip: str,
    logon_type: str,
    message: str,
) -> bool:
    safe_event_type = str(event_type or "").strip().lower()
    safe_source_ip = str(source_ip or "").strip()
    safe_logon_type = str(logon_type or "").strip()
    safe_message = str(message or "").lower()
    return (
        safe_event_type == "windows_logon_failure"
        and safe_source_ip in SIEM_APPROVED_SCANNER_IPS
        and (safe_logon_type == "3" or "logon type:\t\t\t3" in safe_message)
    )


def _looks_like_approved_scanner_network_detection(
    event_type: str,
    provider: str,
    source_ip: str,
) -> bool:
    return (
        str(event_type or "").strip().lower() == "suricata_alert"
        and str(provider or "").strip().lower() == "suricata"
        and str(source_ip or "").strip() in SIEM_APPROVED_SCANNER_IPS
    )


def _looks_like_managed_rsyslog_change(
    event_type: str,
    audit_key: str,
    host_name: str,
    process_name: str,
    message: str,
) -> bool:
    safe_event_type = str(event_type or "").strip().lower()
    safe_key = _normalize_audit_key(audit_key)
    safe_host = _canonical_host_name(str(host_name or "")).lower()
    safe_process = _basename(str(process_name or "")).lower()
    safe_message = str(message or "").lower()
    return (
        safe_event_type == "linux_rsyslog_config_modified"
        and safe_key == "rsyslog_config"
        and safe_host == "lab-edge-01"
        and safe_process in {"bash", "chmod"}
        and "auid=4294967295" in safe_message
        and "uid=0" in safe_message
        and "tty=(none)" in safe_message
    )


def _apply_openclaw_allowlist_tags(event: Dict[str, Any]) -> Dict[str, Any]:
    host_name = _canonical_host_name(str(event.get("host.name") or event.get("log_source") or ""))
    if host_name != OPENCLAW_EXPECTED_HOST:
        return event

    provider = _clean_value(event.get("event.provider")).lower()
    event_type = _clean_value(event.get("event.type")).lower()
    outcome = _clean_value(event.get("event.outcome")).lower()
    message = _clean_value(event.get("event.original") or event.get("message")).lower()
    process_name = _clean_value(event.get("process.name")).lower()
    command_line = _clean_value(event.get("process.command_line") or event.get("process.command")).lower()
    user_name = _clean_value(event.get("user.name")).lower()
    target_user = _clean_value(event.get("user.target.name")).lower()
    dns_query_name = _clean_value(event.get("dns.question.name")).lower()
    audit_key = _clean_value(event.get("audit.key")).lower()
    source_ip = _clean_value(event.get("source.ip"))
    destination_ip = _clean_value(event.get("destination.ip"))
    source_port = _clean_value(event.get("source.port"))
    destination_port = _clean_value(event.get("destination.port"))
    command_or_message = " ".join(part for part in (command_line, message) if part).strip()

    if event_type == "linux_dns_query" and _looks_like_openclaw_expected_dns(dns_query_name, process_name, provider, outcome, message):
        _append_tags(event, "allowlist:openclaw_expected_dns", "openclaw:expected-dns")

    if event_type == "audit_proctitle" and _looks_like_openclaw_expected_proctitle(command_line, target_user, message):
        _append_tags(event, "allowlist:openclaw_expected_activity", "openclaw:expected-activity")

    if (
        event_type in {"syslog", "app_log", "application_log"}
        and process_name in {"node", "xray", "sh", "bash"}
        and any(marker in command_or_message for marker in OPENCLAW_PROXY_ERROR_MARKERS)
        and (
            any(marker in command_or_message for marker in OPENCLAW_PROXY_PROBE_MARKERS)
            or "openclaw-gateway.service" in command_or_message
            or "openclaw-vless.service" in command_or_message
        )
    ):
        _append_tags(event, "allowlist:openclaw_proxy_runtime", "openclaw:proxy-runtime")
    elif _looks_like_openclaw_proxy_runtime_noise(event_type, process_name, provider, command_or_message):
        _append_tags(event, "allowlist:openclaw_proxy_runtime", "openclaw:proxy-runtime")

    if event_type in {
        "linux_system_recon",
        "audit_user_command",
        "audit_execve",
        "audit_proctitle",
        "audit_exec_as_root",
        "sudo_command",
    }:
        if (
            _looks_like_openclaw_research_command(command_or_message)
            or _looks_like_openclaw_proxy_probe(command_or_message, process_name, user_name)
            or target_user.startswith("openclaw-sbx-agent-research")
            or _looks_like_openclaw_expected_recon(event_type, process_name, target_user, command_or_message)
        ):
            _append_tags(event, "allowlist:openclaw_research_activity", "openclaw:research-activity")

    if _looks_like_openclaw_expected_audit_socket_noise(event_type, audit_key, process_name, command_or_message):
        _append_tags(event, "allowlist:openclaw_audit_socket_noise", "openclaw:audit-socket-noise", "allowlist:openclaw_expected_activity")

    if _looks_like_internal_syslog_reconnect_noise(host_name, source_ip, destination_ip, source_port, destination_port, command_or_message):
        _append_tags(event, "allowlist:siem_internal_syslog_reconnect", "siem:internal-syslog-reconnect")

    return event


def _apply_operational_allowlist_tags(event: Dict[str, Any]) -> Dict[str, Any]:
    host_name = _canonical_host_name(str(event.get("host.name") or event.get("log_source") or ""))
    log_source = _canonical_host_name(str(event.get("log_source") or ""))
    event_type = _clean_value(event.get("event.type")).lower()
    provider = _clean_value(event.get("event.provider")).lower()
    message = _clean_value(event.get("event.original") or event.get("message"))
    process_name = _clean_value(event.get("process.name"))
    command_line = _clean_value(event.get("process.command_line") or event.get("process.command")).lower()
    user_name = _clean_value(event.get("user.name")).lower()
    source_ip = _clean_value(event.get("source.ip"))
    logon_type = _clean_value(event.get("auth.logon_type"))
    audit_key = _clean_value(event.get("audit.key"))
    if event_type == "sudo_command" and _looks_like_siem_operational_sudo(command_line, host_name, user_name):
        _append_tags(event, "allowlist:siem_operational_sudo", "siem:operational-sudo")
    if _looks_like_greenbone_expected_ssh_probe(event_type, source_ip, host_name, log_source):
        _append_tags(event, "allowlist:greenbone_expected_ssh_probe", "greenbone:expected-ssh-probe")
    if _looks_like_siem_operator_automation(provider, host_name, message):
        _append_tags(event, "allowlist:siem_operator_automation", "siem:operator-automation")
    if _looks_like_approved_scanner_auth_probe(event_type, source_ip, logon_type, message):
        _append_tags(event, "allowlist:siem_approved_scanner", "siem:approved-scanner")
    if _looks_like_approved_scanner_network_detection(event_type, provider, source_ip):
        _append_tags(event, "allowlist:siem_approved_scanner", "siem:approved-scanner")
    if _looks_like_managed_rsyslog_change(event_type, audit_key, host_name, process_name, message):
        _append_tags(event, "allowlist:siem_managed_rsyslog_change", "siem:managed-rsyslog-change")
    return event


def _parse_key_values(text: str) -> Dict[str, str]:
    parsed: Dict[str, str] = {}
    for key, value in KV_RE.findall(text):
        parsed[key] = _strip_quotes(value)
    return parsed


def _derive_outcome(values: Dict[str, str]) -> str:
    for key in ("res", "success", "result"):
        raw = values.get(key, "")
        lowered = raw.lower()
        if lowered in {"success", "yes", "ok", "opened"}:
            return "success"
        if lowered in {"failed", "failure", "no", "denied", "closed"}:
            return "failure"
    return "unknown"


def _derive_severity(program: str, event_type: str, outcome: str, default_level: str) -> str:
    if program == "sshd" and outcome == "failure":
        return "medium"
    if program == "sudo" and event_type == "sudo_command":
        return "medium"
    if event_type.startswith("audit_service_"):
        return "low"
    if event_type in {"audit_cred_acq_success", "audit_cred_disp_success", "audit_cred_refr_success", "audit_user_start_success", "audit_user_end_success"}:
        return "info"
    if event_type in HIGH_RISK_EVENT_TYPES:
        return "high"
    if event_type in MEDIUM_RISK_EVENT_TYPES:
        return "medium"
    return default_level or "info"


def _basename(value: str) -> str:
    raw = _clean_value(value).replace("\\", "/")
    return raw.rsplit("/", 1)[-1].lower()


def _extract_execve_command(values: Dict[str, str], fallback: str) -> str:
    args: List[str] = []
    for key in sorted((item for item in values if re.fullmatch(r"a\d+", item)), key=lambda item: int(item[1:])):
        candidate = _decode_hex(values.get(key, ""))
        if candidate:
            args.append(candidate)
    if args:
        return " ".join(args).strip()
    return _decode_hex(values.get("cmd", "")) or _decode_hex(values.get("proctitle", "")) or fallback


def _extract_target_user(command_line: str) -> str:
    try:
        tokens = shlex.split(command_line)
    except Exception:
        tokens = command_line.split()
    for token in reversed(tokens):
        if token.startswith("-"):
            continue
        return token.strip("'\"")
    return ""


def _set_event_shape(result: Dict[str, Any], *, category: str, action: str, event_type: str) -> None:
    result["event.category"] = category
    result["event.action"] = action
    result["event.type"] = event_type


def _apply_audit_key_shape(result: Dict[str, Any], audit_key: str) -> None:
    normalized_key = _normalize_audit_key(audit_key)
    shape = AUDIT_KEY_SHAPES.get(normalized_key)
    if not shape:
        return
    current_type = _clean_value(result.get("event.type", ""))
    should_override = (
        not current_type
        or current_type.startswith("audit_")
        or current_type
        in {
            "linux_download_utility",
            "linux_network_tool",
            "linux_packet_capture",
            "linux_system_recon",
        }
    )
    if not should_override and shape[2] != current_type:
        return
    _set_event_shape(result, category=shape[0], action=shape[1], event_type=shape[2])


def _classify_file_path_event(result: Dict[str, Any], path_value: str) -> None:
    path_lower = _clean_value(path_value).lower()
    if not path_lower:
        return
    if path_lower.endswith(".ssh/authorized_keys"):
        _set_event_shape(result, category="persistence", action="file_modify", event_type="linux_authorized_keys_modified")
    elif path_lower == "/etc/sudoers" or path_lower.startswith("/etc/sudoers.d/"):
        _set_event_shape(result, category="privilege", action="sudoers_modify", event_type="linux_sudoers_modified")
    elif path_lower in {"/etc/passwd", "/etc/shadow"}:
        _set_event_shape(result, category="credential", action="file_modify", event_type="linux_passwd_shadow_access")
    elif path_lower.startswith("/etc/cron") or path_lower.endswith("/crontab") or path_lower.startswith("/var/spool/cron"):
        _set_event_shape(result, category="persistence", action="scheduled_task_modify", event_type="linux_cron_modified")
    elif path_lower.startswith("/etc/systemd/system") or path_lower.startswith("/usr/lib/systemd/system") or path_lower.startswith("/lib/systemd/system"):
        _set_event_shape(result, category="persistence", action="service_unit_modify", event_type="linux_systemd_unit_modified")
    elif path_lower == "/etc/ld.so.preload":
        _set_event_shape(result, category="defense_evasion", action="preload_modify", event_type="linux_ld_preload_modified")
    elif path_lower.startswith("/etc/audit/"):
        _set_event_shape(result, category="defense_evasion", action="audit_config_change", event_type="linux_audit_config_changed")
    elif path_lower.startswith("/etc/ufw") or path_lower.startswith("/etc/firewalld"):
        _set_event_shape(result, category="defense_evasion", action="firewall_modify", event_type="linux_firewall_modified")


def _classify_execve_activity(result: Dict[str, Any]) -> None:
    command_line = _clean_value(result.get("process.command_line", ""))
    command_lower = command_line.lower()
    executable_path = _clean_value(result.get("process.executable", "") or result.get("process.name", "")).lower()
    executable = _basename(executable_path)
    target_user = _extract_target_user(command_line)
    if target_user and not result.get("user.target.name"):
        result["user.target.name"] = target_user

    if executable in {"useradd", "adduser"}:
        _set_event_shape(result, category="identity", action="account_create", event_type="linux_user_created")
    elif executable in {"userdel", "deluser"}:
        _set_event_shape(result, category="identity", action="account_delete", event_type="linux_user_deleted")
    elif executable == "usermod":
        if any(group in command_lower for group in (" sudo", " wheel", "-g sudo", "-g wheel", "-ag sudo", "-ag wheel")):
            _set_event_shape(result, category="privilege", action="group_modify", event_type="linux_user_added_to_admin_group")
        else:
            _set_event_shape(result, category="identity", action="account_modify", event_type="linux_user_modified")
    elif executable == "passwd":
        _set_event_shape(result, category="credential", action="password_change", event_type="linux_password_changed")
    elif executable in {"crontab", "at"} or "/etc/cron" in command_lower:
        _set_event_shape(result, category="persistence", action="scheduled_task_modify", event_type="linux_cron_modified")
    elif executable == "systemctl":
        if " enable " in f" {command_lower} ":
            _set_event_shape(result, category="persistence", action="service_enable", event_type="linux_systemd_service_enabled")
        elif " disable " in f" {command_lower} ":
            _set_event_shape(result, category="defense_evasion", action="service_disable", event_type="linux_systemd_service_disabled")
        elif " start " in f" {command_lower} " or " restart " in f" {command_lower} ":
            _set_event_shape(result, category="execution", action="service_start", event_type="linux_systemd_service_started")
        elif " stop " in f" {command_lower} ":
            _set_event_shape(result, category="impact", action="service_stop", event_type="linux_systemd_service_stopped")
    elif executable in {"auditctl", "augenrules"} or "audit.rules" in command_lower:
        if " -d" in command_lower or " -D" in command_line:
            _set_event_shape(result, category="defense_evasion", action="audit_rules_clear", event_type="linux_audit_rules_cleared")
        else:
            _set_event_shape(result, category="defense_evasion", action="audit_config_change", event_type="linux_audit_config_changed")
    elif executable in {"iptables", "ufw", "firewall-cmd"} or "firewalld" in command_lower:
        if any(token in command_lower for token in ("disable", "stop", "flush", " -f")):
            _set_event_shape(result, category="defense_evasion", action="firewall_disable", event_type="linux_firewall_disabled")
        else:
            _set_event_shape(result, category="defense_evasion", action="firewall_modify", event_type="linux_firewall_modified")
    elif executable in {"tar", "zip", "gzip", "bzip2", "xz", "7z"}:
        _set_event_shape(result, category="exfiltration", action="archive", event_type="linux_data_compressed")
    elif executable in {"curl", "wget"}:
        _set_event_shape(result, category="command_and_control", action="download", event_type="linux_download_utility")
    elif executable in {"nc", "ncat", "socat"}:
        _set_event_shape(result, category="command_and_control", action="network_tool", event_type="linux_network_tool")
    elif executable in {"dbus-send"}:
        _set_event_shape(result, category="execution", action="dbus_send", event_type="linux_dbus_send")
    elif executable in {"pkexec"}:
        _set_event_shape(result, category="privilege", action="pkexec", event_type="linux_pkexec_execution")
    elif executable in {"tcpdump", "tshark"}:
        _set_event_shape(result, category="discovery", action="sniff", event_type="linux_packet_capture")
    elif executable in {"modprobe", "insmod", "rmmod"}:
        _set_event_shape(result, category="defense_evasion", action="module_modify", event_type="linux_kernel_module_modified")
    elif executable in {"lsmod"}:
        _set_event_shape(result, category="discovery", action="recon", event_type="linux_system_recon")
    elif executable in {"sysctl"}:
        _set_event_shape(result, category="defense_evasion", action="kernel_param_modify", event_type="linux_sysctl_modified")
    elif executable in {"setcap", "setfattr"}:
        _set_event_shape(result, category="privilege", action="capability_modify", event_type="linux_file_capability_modified")
    elif executable == "chmod" and (" u+s" in f" {command_lower} " or " g+s" in f" {command_lower} " or " 4755 " in f" {command_lower} "):
        _set_event_shape(result, category="privilege", action="setuid_modify", event_type="linux_setuid_bit_modified")

    if any(token in command_lower for token in ("bash -i", "/dev/tcp/", "nc -e", "ncat -e", "mkfifo ", "socat exec", "python -c", "perl -e", "php -r")):
        _set_event_shape(result, category="command_and_control", action="reverse_shell", event_type="linux_reverse_shell_possible")
    elif any(token in command_lower for token in ("whoami", "uname", "hostnamectl", "ip a", "ifconfig", "netstat", "ss -", "lsof -i", "cat /etc/passwd", "getent passwd", "last ", "w ", "who ")):
        _set_event_shape(result, category="discovery", action="recon", event_type="linux_system_recon")
    elif executable_path.startswith(("/tmp/", "/var/tmp/", "/dev/shm/")) or re.match(
        r"^\s*(?:/usr/bin/env\s+)?(?:/tmp|/var/tmp|/dev/shm)/",
        command_lower,
    ):
        _set_event_shape(result, category="execution", action="exec_tmp", event_type="linux_exec_from_tmp")
    elif "authorized_keys" in command_lower:
        _set_event_shape(result, category="persistence", action="authorized_keys_modify", event_type="linux_authorized_keys_modified")
    elif any(token in command_lower for token in ("/etc/passwd", "/etc/shadow")):
        _set_event_shape(result, category="credential", action="credential_file_access", event_type="linux_passwd_shadow_access")
    elif "ld.so.preload" in command_lower:
        _set_event_shape(result, category="defense_evasion", action="preload_modify", event_type="linux_ld_preload_modified")


def _parse_auditd(body: str, base: Dict[str, Any]) -> Dict[str, Any]:
    values = _parse_key_values(body)
    inner_msg = values.get("msg", "")
    if "=" in inner_msg:
        _merge_non_empty(values, _parse_key_values(inner_msg))

    event_type_raw = values.get("type", "UNKNOWN").upper()
    outcome = _derive_outcome(values)
    acct = values.get("acct", "")
    addr = values.get("addr", "")
    exe = values.get("exe", "")
    command_hex = values.get("cmd", "")
    proctitle_hex = values.get("proctitle", "")
    audit_key = values.get("key", "")
    file_path = values.get("name", "")
    cwd = values.get("cwd", "")
    audit_id_match = AUDIT_ID_RE.search(body)
    audit_id = _clean_value(audit_id_match.group("audit_id")) if audit_id_match else ""
    record_identity = "\x1f".join(
        (
            _clean_value(base.get("host.name")),
            audit_id,
            event_type_raw,
            _clean_value(values.get("item", "")),
            file_path,
        )
    )
    event_id = f"audit-{hashlib.sha256(record_identity.encode('utf-8')).hexdigest()[:32]}" if audit_id else ""
    command_line = _extract_execve_command(values, _decode_hex(command_hex) or _decode_hex(proctitle_hex))
    process_name = values.get("comm", "") or base.get("process.name", "") or _basename(exe)

    event_category = "audit"
    event_action = "audit"
    event_type = f"audit_{event_type_raw.lower()}"

    if event_type_raw in {"USER_AUTH", "USER_ACCT", "USER_LOGIN"}:
        event_category = "authentication"
        event_action = "authentication" if event_type_raw != "USER_LOGIN" else "login"
        if outcome in {"success", "failure"}:
            event_type = f"audit_{event_type_raw.lower()}_{outcome}"
    elif event_type_raw == "USER_ERR":
        event_category = "authentication"
        event_action = "authentication_failed"
        event_type = "audit_user_err"
    elif event_type_raw in {"USER_START", "USER_END", "CRED_ACQ", "CRED_DISP", "CRED_REFR"}:
        event_category = "session"
        event_action = "session"
        if outcome in {"success", "failure"}:
            event_type = f"audit_{event_type_raw.lower()}_{outcome}"
    elif event_type_raw in {"SERVICE_START", "SERVICE_STOP"}:
        event_category = "service"
        event_action = "service_start" if event_type_raw == "SERVICE_START" else "service_stop"
        event_type = f"audit_{event_type_raw.lower()}"
    elif event_type_raw == "USER_CMD":
        event_category = "privilege"
        event_action = "command"
        event_type = "audit_user_command"
    elif event_type_raw in {"EXECVE", "SYSCALL", "PROCTITLE", "PATH", "CWD"}:
        event_category = "process"
        event_action = "execute"
        if audit_key == "exec_as_root":
            event_category = "privilege"
            event_action = "execute_as_root"
            event_type = "audit_exec_as_root"
        else:
            event_type = f"audit_{event_type_raw.lower()}"

    audit_hostname = values.get("hostname", "")
    if _is_ipv4(audit_hostname) or audit_hostname in {"?", "-"}:
        audit_hostname = ""
    result = {
        "event.provider": "linux.auditd",
        "event.category": event_category,
        "event.action": event_action,
        "event.type": event_type,
        "event.outcome": outcome,
        "event.id": event_id,
        "audit.type": event_type_raw,
        "audit.id": audit_id,
        "audit.key": audit_key,
        "session.id": values.get("ses", ""),
        "user.name": acct,
        "user.id": values.get("uid", ""),
        "user.audit.name": values.get("AUID", "") or values.get("auid", ""),
        "user.target.name": "",
        "source.ip": addr if _is_ipv4(addr) else "",
        "source.port": values.get("src", ""),
        "destination.ip": "",
        "destination.port": values.get("dport", "") or values.get("dest", ""),
        "process.executable": exe,
        "process.name": process_name,
        "process.command_line": command_line,
        "process.working_directory": cwd,
        "process.tty": values.get("terminal", "") or values.get("tty", ""),
        "file.path": file_path,
        "file.mode": values.get("mode", ""),
        "file.type": values.get("nametype", ""),
        "host.name": audit_hostname or base.get("host.name", ""),
    }
    _merge_non_empty(result, _decode_audit_sockaddr(values.get("saddr", "")))
    if event_type_raw == "PATH":
        _classify_file_path_event(result, file_path)
    if event_type_raw in {"EXECVE", "SYSCALL", "PROCTITLE"}:
        _classify_execve_activity(result)
    if result.get("event.type", "").startswith("audit_") and result.get("destination.port") and values.get("syscall") in {"42", "connect"}:
        _set_event_shape(result, category="network", action="connection_attempt", event_type="linux_network_connection")
    _apply_audit_key_shape(result, audit_key)
    result["event.severity"] = _derive_severity("auditd", result["event.type"], outcome, str(base.get("log.level", "info")))
    return result


def _parse_sshd(body: str, base: Dict[str, Any]) -> Dict[str, Any]:
    accepted = SSHD_ACCEPT_RE.search(body)
    if accepted:
        return {
            "event.provider": "linux.sshd",
            "event.category": "authentication",
            "event.action": "authentication_success",
            "event.type": "linux_root_ssh_login" if accepted.group("user") == "root" else "ssh_login_success",
            "event.outcome": "success",
            "event.severity": "high" if accepted.group("user") == "root" else "info",
            "user.name": accepted.group("user"),
            "source.ip": accepted.group("ip"),
            "source.port": accepted.group("port"),
            "destination.port": "22",
            "network.transport": "tcp",
            "auth.method": accepted.group("method").lower(),
        }

    invalid_user = SSHD_INVALID_USER_RE.search(body)
    if invalid_user:
        return {
            "event.provider": "linux.sshd",
            "event.category": "authentication",
            "event.action": "authentication_failed",
            "event.type": "ssh_invalid_user",
            "event.outcome": "failure",
            "event.severity": "medium",
            "user.name": invalid_user.group("user"),
            "source.ip": invalid_user.group("ip"),
            "source.port": invalid_user.group("port"),
            "destination.port": "22",
            "network.transport": "tcp",
            "auth.method": "unknown",
        }

    failed = SSHD_FAIL_RE.search(body)
    if failed:
        return {
            "event.provider": "linux.sshd",
            "event.category": "authentication",
            "event.action": "authentication_failed",
            "event.type": "ssh_login_failure",
            "event.outcome": "failure",
            "event.severity": "medium",
            "user.name": failed.group("user"),
            "source.ip": failed.group("ip"),
            "source.port": failed.group("port"),
            "destination.port": "22",
            "network.transport": "tcp",
            "auth.method": failed.group("method").lower(),
        }

    session = SSHD_SESSION_RE.search(body)
    if session:
        state = session.group("state").lower()
        return {
            "event.provider": "linux.sshd",
            "event.category": "session",
            "event.action": f"session_{state}",
            "event.type": f"ssh_session_{state}",
            "event.outcome": "success",
            "event.severity": "info",
            "user.name": session.group("user"),
        }

    return {
        "event.provider": "linux.sshd",
        "event.category": "authentication",
        "event.type": "ssh_event",
        "event.action": "observe",
        "event.severity": str(base.get("log.level", "info") or "info"),
    }


def _parse_network_endpoint(value: str) -> Dict[str, str]:
    endpoint = _clean_value(value)
    if not endpoint or ":" not in endpoint:
        return {"transport": "", "host": "", "port": ""}
    transport, raw_target = endpoint.split(":", 1)
    target = raw_target.strip()
    host = ""
    port = ""
    if target.startswith("[") and "]" in target:
        bracket_end = target.rfind("]")
        host = target[1:bracket_end]
        if len(target) > bracket_end + 2 and target[bracket_end + 1] == ":":
            port = target[bracket_end + 2 :]
    elif ":" in target:
        host, port = target.rsplit(":", 1)
    else:
        host = target
    return {"transport": transport.lower(), "host": host.strip(), "port": port.strip()}


def _parse_xray_access(body: str, base: Dict[str, Any]) -> Dict[str, Any]:
    match = XRAY_ACCESS_RE.search(body)
    if not match:
        return {
            "event.provider": "vpn.xray",
            "event.category": "network",
            "event.action": "observe",
            "event.type": "vpn_proxy_event",
            "event.severity": str(base.get("log.level", "info") or "info"),
        }
    src = _parse_network_endpoint(match.group("src_endpoint"))
    dst = _parse_network_endpoint(match.group("dst_endpoint"))
    domain = _clean_value(match.group("domain")) or dst.get("host", "")
    source_host = src.get("host", "")
    destination_host = dst.get("host", "")
    return {
        "event.provider": "vpn.xray",
        "event.category": "network",
        "event.action": "proxy_access",
        "event.type": "vpn_proxy_access",
        "event.outcome": "success",
        "event.severity": "info",
        "source.ip": source_host if _is_ipv4(source_host) else "",
        "source.port": src.get("port", ""),
        "destination.ip": destination_host if _is_ipv4(destination_host) else "",
        "destination.port": dst.get("port", ""),
        "network.transport": dst.get("transport", "") or src.get("transport", ""),
        "network.domain": domain,
        "vpn.client_id": _clean_value(match.group("email")),
        "vpn.route": _clean_value(match.group("route")),
        "host.name": base.get("host.name", ""),
    }


def _parse_kernel(body: str, base: Dict[str, Any]) -> Dict[str, Any]:
    ufw = UFW_BLOCK_RE.search(body)
    if ufw:
        return {
            "event.provider": "linux.kernel",
            "event.category": "network",
            "event.action": "firewall_block",
            "event.type": "linux_firewall_blocked",
            "event.outcome": "success",
            "event.severity": "low",
            "source.ip": ufw.group("src"),
            "destination.ip": ufw.group("dst"),
            "source.port": ufw.group("spt") or "",
            "destination.port": ufw.group("dpt") or "",
            "network.transport": (ufw.group("proto") or "").lower(),
        }
    return {
        "event.provider": "linux.kernel",
        "event.category": "system",
        "event.action": "observe",
        "event.type": "linux_kernel_event",
        "event.severity": str(base.get("log.level", "info") or "info"),
    }


def _parse_sudo(body: str, base: Dict[str, Any]) -> Dict[str, Any]:
    command = SUDO_COMMAND_RE.search(body)
    if command:
        target_user = command.group("target").strip()
        severity = "high" if target_user == "root" else "medium"
        return {
            "event.provider": "linux.sudo",
            "event.category": "privilege",
            "event.action": "command",
            "event.type": "sudo_command",
            "event.outcome": "success",
            "event.severity": severity,
            "user.name": command.group("user").strip(),
            "user.target.name": target_user,
            "process.command_line": command.group("command").strip(),
            "process.working_directory": command.group("pwd").strip(),
        }

    session = SUDO_SESSION_RE.search(body)
    if session:
        state = session.group("state").lower()
        return {
            "event.provider": "linux.sudo",
            "event.category": "session",
            "event.action": f"session_{state}",
            "event.type": f"sudo_session_{state}",
            "event.outcome": "success",
            "event.severity": "info",
            "user.target.name": session.group("target"),
        }

    return {
        "event.provider": "linux.sudo",
        "event.category": "privilege",
        "event.type": "sudo_event",
        "event.action": "observe",
        "event.severity": str(base.get("log.level", "info") or "info"),
    }


def _parse_su(body: str, base: Dict[str, Any]) -> Dict[str, Any]:
    session = SU_SESSION_RE.search(body)
    if session:
        state = session.group("state").lower()
        return {
            "event.provider": "linux.su",
            "event.category": "privilege",
            "event.action": f"session_{state}",
            "event.type": f"linux_su_session_{state}",
            "event.outcome": "success",
            "event.severity": "medium",
            "user.name": session.group("user"),
            "user.target.name": session.group("target"),
        }
    return {
        "event.provider": "linux.su",
        "event.category": "privilege",
        "event.action": "observe",
        "event.type": "linux_su_event",
        "event.severity": str(base.get("log.level", "info") or "info"),
    }


def _parse_cron(program: str, body: str, base: Dict[str, Any]) -> Dict[str, Any]:
    command = CRON_CMD_RE.search(body)
    if command:
        return {
            "event.provider": f"linux.{program}",
            "event.category": "persistence",
            "event.action": "scheduled_task_execute",
            "event.type": "linux_cron_command",
            "event.outcome": "success",
            "event.severity": "low",
            "user.name": command.group("user").strip(),
            "process.command_line": command.group("command").strip(),
        }
    return {
        "event.provider": f"linux.{program}",
        "event.category": "persistence",
        "event.action": "observe",
        "event.type": "linux_cron_event",
        "event.severity": str(base.get("log.level", "info") or "info"),
    }


def _parse_account_tools(program: str, body: str, base: Dict[str, Any]) -> Dict[str, Any]:
    if program == "passwd":
        change = PASSWD_CHANGE_RE.search(body)
        return {
            "event.provider": "linux.passwd",
            "event.category": "credential",
            "event.action": "password_change",
            "event.type": "linux_password_changed",
            "event.outcome": "success" if change else "unknown",
            "event.severity": "medium",
            "user.target.name": change.group("user") if change else "",
        }

    if program == "useradd":
        created = USERADD_RE.search(body)
        return {
            "event.provider": "linux.useradd",
            "event.category": "identity",
            "event.action": "account_create",
            "event.type": "linux_user_created",
            "event.outcome": "success" if created else "unknown",
            "event.severity": "medium",
            "user.target.name": created.group("user") if created else "",
        }

    if program == "userdel":
        deleted = USERDEL_RE.search(body)
        return {
            "event.provider": "linux.userdel",
            "event.category": "identity",
            "event.action": "account_delete",
            "event.type": "linux_user_deleted",
            "event.outcome": "success" if deleted else "unknown",
            "event.severity": "medium",
            "user.target.name": deleted.group("user") if deleted else "",
        }

    if program == "usermod":
        modified = USERMOD_RE.search(body)
        event_type = "linux_user_added_to_admin_group" if modified and modified.group("group").lower() in {"sudo", "wheel"} else "linux_user_modified"
        return {
            "event.provider": "linux.usermod",
            "event.category": "privilege" if event_type == "linux_user_added_to_admin_group" else "identity",
            "event.action": "group_modify" if event_type == "linux_user_added_to_admin_group" else "account_modify",
            "event.type": event_type,
            "event.outcome": "success" if modified else "unknown",
            "event.severity": "medium",
            "user.target.name": modified.group("user") if modified else "",
            "group.name": modified.group("group") if modified else "",
        }

    return {
        "event.provider": f"linux.{program}",
        "event.category": "identity",
        "event.action": "observe",
        "event.type": f"linux_{program}_event",
        "event.severity": str(base.get("log.level", "info") or "info"),
    }


def _strip_xml_ns(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _parse_windows_xml_payload(message: str) -> Dict[str, Any]:
    text = _clean_value(message)
    if not text.startswith("<Event"):
        return {}
    try:
        root = ET.fromstring(text)
    except Exception:
        return {}
    payload: Dict[str, Any] = {"Event": {"System": {}, "EventData": {"Data": {}}}}
    system = payload["Event"]["System"]
    event_data = payload["Event"]["EventData"]["Data"]
    for child in root:
        child_name = _strip_xml_ns(child.tag)
        if child_name == "System":
            for node in child:
                node_name = _strip_xml_ns(node.tag)
                if node_name == "Provider":
                    system["Provider"] = {"Name": node.attrib.get("Name", "")}
                else:
                    system[node_name] = _clean_value(node.text) or _clean_value(node.attrib.get("Name"))
        elif child_name == "EventData":
            for node in child:
                if _strip_xml_ns(node.tag) != "Data":
                    continue
                key = _clean_value(node.attrib.get("Name")) or f"field_{len(event_data) + 1}"
                event_data[key] = _clean_value(node.text)
    return payload


def _extract_windows_rendered_block(message: str, header: str) -> str:
    pattern = re.compile(rf"{re.escape(header)}\s*(.*?)(?:\r?\n\r?\n[A-Z][A-Za-z ]+:\s*|\Z)", re.IGNORECASE | re.DOTALL)
    match = pattern.search(message)
    return match.group(1) if match else ""


def _extract_windows_rendered_field(block: str, label: str) -> str:
    match = re.search(rf"^\s*{re.escape(label)}\s*:\s*(.*?)\s*$", block, flags=re.IGNORECASE | re.MULTILINE)
    return _clean_value(match.group(1)) if match else ""


def _parse_windows_rendered_security_message(message: str) -> tuple[str, Dict[str, str]]:
    text = _clean_value(message)
    lowered = text.lower()
    event_id = ""
    for marker, candidate in WINDOWS_RENDERED_EVENT_HINTS:
        if marker in lowered:
            event_id = candidate
            break

    event_data: Dict[str, str] = {}
    target_blocks = (
        _extract_windows_rendered_block(text, "Account For Which Logon Failed:"),
        _extract_windows_rendered_block(text, "New Logon:"),
        _extract_windows_rendered_block(text, "New Account:"),
        _extract_windows_rendered_block(text, "Target Account:"),
        _extract_windows_rendered_block(text, "Member:"),
    )
    for block in target_blocks:
        target = _extract_windows_rendered_field(block, "Account Name")
        if target and target != "-":
            event_data["TargetUserName"] = target
            break

    subject = _extract_windows_rendered_block(text, "Subject:")
    subject_user = _extract_windows_rendered_field(subject, "Account Name")
    if subject_user and subject_user != "-":
        event_data["SubjectUserName"] = subject_user

    for label, key in (
        ("Logon Type", "LogonType"),
        ("Source Network Address", "IpAddress"),
        ("Source Address", "IpAddress"),
        ("Client Address", "IpAddress"),
        ("Source Port", "IpPort"),
        ("Process Name", "ProcessName"),
        ("Service Name", "ServiceName"),
        ("Group Name", "GroupName"),
    ):
        value = _extract_windows_rendered_field(text, label)
        if value and value != "-":
            event_data.setdefault(key, value)

    return event_id, event_data


def _build_windows_event(mapping: Dict[str, Any], base: Dict[str, Any]) -> Dict[str, Any]:
    message = _first_non_empty(mapping, "message", "event.original", "winlog.message", "rendering.message")
    rendered_event_id, rendered_event_data = _parse_windows_rendered_security_message(message)
    event_data = _flatten_prefixed(mapping, "winlog.event_data.")
    payload_event_data = _dotted_get(mapping, "winlog.event_data")
    if isinstance(payload_event_data, dict):
        for key, value in payload_event_data.items():
            text = _clean_value(value)
            if text and str(key) not in event_data:
                event_data[str(key)] = text
    collector_event_data = _dotted_get(mapping, "windows.event_data")
    if isinstance(collector_event_data, dict):
        for key, value in collector_event_data.items():
            text = _clean_value(value)
            if text and str(key) not in event_data:
                event_data[str(key)] = text
    xml_event_data = _dotted_get(mapping, "Event.EventData.Data")
    if isinstance(xml_event_data, dict):
        for key, value in xml_event_data.items():
            text = _clean_value(value)
            if text and str(key) not in event_data:
                event_data[str(key)] = text
    for key, value in rendered_event_data.items():
        if value and key not in event_data:
            event_data[key] = value

    event_id = _first_non_empty(
        mapping,
        "event.code",
        "event.id",
        "event_code",
        "event_id",
        "winlog.event_id",
        "Event.System.EventID",
        "winlog.event.code",
    )
    if not event_id:
        event_id = rendered_event_id
    if not event_id:
        return {}
    channel = _first_non_empty(mapping, "winlog.channel", "Event.System.Channel", "channel").lower()
    provider_name = _first_non_empty(
        mapping,
        "winlog.provider_name",
        "Event.System.Provider.Name",
        "provider_name",
        "provider",
        "event.provider",
    ).lower()
    computer_name = _canonical_host_name(_first_non_empty(mapping, "winlog.computer_name", "host.name", "Event.System.Computer", "computer_name", "log_source", "source"))
    source_ip = _first_non_empty(
        event_data,
        "IpAddress",
        "SourceAddress",
        "SourceIp",
        "SourceNetworkAddress",
        "ClientAddress",
        "RemoteAddress",
    )
    source_port = _first_non_empty(event_data, "IpPort", "SourcePort", "SourceNetworkPort", "ClientPort", "RemotePort")
    destination_port = _first_non_empty(event_data, "DestPort", "DestinationPort", "NetworkInformationDestPort")
    user_name = _first_non_empty(event_data, "TargetUserName", "AccountName", "User", "SubjectUserName", "SubjectAccountName")
    target_user = _first_non_empty(event_data, "TargetUserName", "MemberName", "TargetSid", "SamAccountName")
    process_executable = _first_non_empty(event_data, "NewProcessName", "ProcessName", "Image", "Application", "ParentImage")
    process_command = _first_non_empty(event_data, "CommandLine", "ProcessCommandLine", "ScriptBlockText")
    process_name = _basename(process_executable or _first_non_empty(event_data, "Image", "OriginalFileName", "ProcessName"))
    logon_type = _first_non_empty(event_data, "LogonType")
    service_name = _first_non_empty(event_data, "ServiceName")
    group_name = _first_non_empty(event_data, "GroupName", "TargetSid")

    provider = "windows.sysmon" if "sysmon" in provider_name or "sysmon" in channel else "windows.security"
    if "powershell" in channel or "powershell" in provider_name:
        provider = "windows.powershell"
    elif "firewall" in channel:
        provider = "windows.firewall"
    elif "windows defender" in provider_name or "windows defender" in channel:
        provider = "windows.defender"
    elif "wmi-activity" in channel or "wmi-activity" in provider_name:
        provider = "windows.wmi"
    elif "terminalservices-remoteconnectionmanager" in channel or "terminalservices-localsessionmanager" in channel:
        provider = "windows.rdp"
    elif "taskscheduler" in channel:
        provider = "windows.taskscheduler"
    elif "winrm" in channel:
        provider = "windows.winrm"

    result = {
        "event.provider": provider,
        "event.code": event_id,
        "event.category": "windows",
        "event.action": "observe",
        "event.type": "windows_event",
        "event.outcome": "unknown",
        "event.severity": "info",
        "host.name": computer_name,
        "log_source": computer_name or base.get("source", ""),
        "source.ip": source_ip if _is_ipv4(source_ip) else "",
        "source.port": source_port,
        "destination.port": destination_port,
        "user.name": user_name,
        "user.target.name": target_user if target_user and target_user != user_name else "",
        "process.executable": process_executable,
        "process.name": process_name,
        "process.command_line": process_command,
        "group.name": group_name,
        "service.name": service_name,
        "auth.logon_type": logon_type,
        "event.original": message or base.get("message", ""),
    }

    if provider == "windows.sysmon" and event_id == "1":
        _set_event_shape(result, category="process", action="process_create", event_type="windows_process_create")
        result["event.outcome"] = "success"
    elif provider == "windows.sysmon" and event_id == "3":
        _set_event_shape(result, category="network", action="network_connect", event_type="windows_network_connection")
        result["event.outcome"] = "success"
    elif provider == "windows.sysmon" and event_id == "13":
        _set_event_shape(result, category="persistence", action="registry_set", event_type="windows_registry_value_set")
        result["event.outcome"] = "success"
        result["event.severity"] = "medium"
    elif event_id == "4624":
        _set_event_shape(result, category="authentication", action="authentication_success", event_type="windows_logon_success")
        result["event.outcome"] = "success"
        result["event.severity"] = "high" if user_name.lower() in {"administrator", "admin"} or logon_type == "10" else "info"
    elif event_id == "4625":
        _set_event_shape(result, category="authentication", action="authentication_failed", event_type="windows_logon_failure")
        result["event.outcome"] = "failure"
        result["event.severity"] = "medium"
    elif event_id == "4648":
        _set_event_shape(result, category="authentication", action="explicit_credentials", event_type="windows_explicit_credentials_logon")
        result["event.outcome"] = "success"
        result["event.severity"] = "medium"
    elif event_id == "4672":
        _set_event_shape(result, category="privilege", action="special_privileges_assigned", event_type="windows_special_privileges_assigned")
        result["event.outcome"] = "success"
        result["event.severity"] = "high"
    elif event_id == "4688":
        _set_event_shape(result, category="process", action="process_create", event_type="windows_process_create")
        result["event.outcome"] = "success"
    elif event_id == "4698":
        _set_event_shape(result, category="persistence", action="scheduled_task_create", event_type="windows_scheduled_task_created")
        result["event.outcome"] = "success"
        result["event.severity"] = "high"
    elif provider == "windows.taskscheduler" and event_id == "106":
        _set_event_shape(result, category="persistence", action="scheduled_task_create", event_type="windows_scheduled_task_created")
        result["event.outcome"] = "success"
        result["event.severity"] = "high"
    elif event_id == "4719":
        _set_event_shape(result, category="defense_evasion", action="audit_policy_change", event_type="windows_audit_policy_changed")
        result["event.outcome"] = "success"
        result["event.severity"] = "high"
    elif event_id in {"4720", "624"}:
        _set_event_shape(result, category="identity", action="account_create", event_type="windows_user_created")
        result["event.outcome"] = "success"
        result["event.severity"] = "medium"
    elif event_id in {"4726", "630"}:
        _set_event_shape(result, category="identity", action="account_delete", event_type="windows_user_deleted")
        result["event.outcome"] = "success"
        result["event.severity"] = "medium"
    elif event_id == "4723":
        _set_event_shape(result, category="credential", action="password_change", event_type="windows_password_changed")
        result["event.outcome"] = "success"
        result["event.severity"] = "medium"
    elif event_id == "4724":
        _set_event_shape(result, category="credential", action="password_reset", event_type="windows_password_reset")
        result["event.outcome"] = "success"
        result["event.severity"] = "high"
    elif event_id in {"4728", "4732", "4756"}:
        _set_event_shape(result, category="privilege", action="group_membership_add", event_type="windows_user_added_to_privileged_group")
        result["event.outcome"] = "success"
        result["event.severity"] = "high"
    elif event_id in {"5156", "5157"}:
        _set_event_shape(result, category="network", action="connection_allow" if event_id == "5156" else "connection_block", event_type="windows_firewall_connection")
        result["event.outcome"] = "success" if event_id == "5156" else "failure"
        result["event.severity"] = "low" if event_id == "5156" else "medium"
        result["event.provider"] = "windows.firewall"
    elif event_id == "7045":
        _set_event_shape(result, category="persistence", action="service_install", event_type="windows_service_installed")
        result["event.outcome"] = "success"
        result["event.severity"] = "high"
    elif event_id == "1102":
        _set_event_shape(result, category="defense_evasion", action="audit_log_clear", event_type="windows_audit_log_cleared")
        result["event.outcome"] = "success"
        result["event.severity"] = "high"
    elif provider == "windows.defender" and event_id == "1116":
        _set_event_shape(result, category="malware", action="malware_detected", event_type="windows_defender_malware_detected")
        result["event.outcome"] = "success"
        result["event.severity"] = "high"
    elif provider == "windows.defender" and event_id == "5007":
        _set_event_shape(result, category="defense_evasion", action="defender_configuration_change", event_type="windows_defender_configuration_changed")
        result["event.outcome"] = "success"
        result["event.severity"] = "high"
    elif provider == "windows.rdp" and event_id == "1149":
        _set_event_shape(result, category="authentication", action="rdp_authentication_success", event_type="windows_rdp_auth_success")
        result["event.outcome"] = "success"
        result["event.severity"] = "high" if source_ip and source_ip not in {"127.0.0.1", "::1"} else "medium"
    elif provider == "windows.wmi" and event_id in {"5857", "5858", "5859", "5860", "5861"}:
        message_lower = message.lower()
        client_match = re.search(r"\bClientMachine\s*=\s*([^;]+)", message, re.IGNORECASE)
        client_machine = _clean_value(client_match.group(1)) if client_match else ""
        operation_match = re.search(r"\bOperation\s*=\s*([^;]+)", message, re.IGNORECASE)
        operation = _clean_value(operation_match.group(1)) if operation_match else ""
        local_client = bool(
            client_machine
            and computer_name
            and _canonical_host_name(client_machine).lower() == _canonical_host_name(computer_name).lower()
        )
        persistence_markers = (
            "commandlineeventconsumer",
            "activescripteventconsumer",
            "__filtertoconsumerbinding",
            "__eventfilter",
        )
        execution_markers = (
            "iwbemservices::execmethod",
            "win32_process::create",
            "win32_process.create",
        )
        if event_id == "5861" or any(marker in message_lower for marker in persistence_markers):
            action = "wmi_persistence"
        elif any(marker in message_lower for marker in execution_markers):
            action = "wmi_remote_execution" if not local_client else "wmi_local_execution"
        elif client_machine and not local_client and "iwbemservices::execquery" in message_lower:
            action = "wmi_remote_query"
        else:
            action = "wmi_local_query" if local_client else "wmi_activity"
        _set_event_shape(result, category="execution", action=action, event_type="windows_wmi_activity")
        result["event.outcome"] = "failure" if event_id == "5858" else "success"
        result["event.severity"] = "medium" if event_id == "5858" else "high"
        result["wmi.client_machine"] = client_machine
        result["wmi.operation"] = operation

    command_lower = _clean_value(process_command or message).lower()
    executable_lower = _basename(process_executable)
    if executable_lower in {"powershell.exe", "pwsh.exe"} or "powershell" in command_lower:
        result["event.provider"] = "windows.powershell"
        if POWERSHELL_ENCODED_SWITCH_RE.search(command_lower):
            _set_event_shape(result, category="execution", action="powershell_encoded_command", event_type="windows_powershell_encoded_command")
            result["event.outcome"] = "success"
            result["event.severity"] = "high"
    elif executable_lower in {"rundll32.exe", "regsvr32.exe", "mshta.exe", "wmic.exe"}:
        result["event.severity"] = "medium"

    return result


def _iso_utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_rfc5424_timestamp(value: str) -> str:
    text = _clean_value(value)
    if not text or text == "-":
        return ""
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return ""
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return _iso_utc(parsed)


def _parse_bsd_syslog_timestamp(month: str, day: str, clock: str, host_name: str = "") -> str:
    now = datetime.now(timezone.utc)
    source_timezone = (
        timezone(timedelta(hours=3))
        if _canonical_host_name(host_name) in {"pve", "proxmox", "vpn-host-khanov"}
        else timezone.utc
    )
    candidates: list[datetime] = []
    for year in (now.year - 1, now.year, now.year + 1):
        try:
            candidates.append(
                datetime.strptime(f"{year} {month} {day} {clock}", "%Y %b %d %H:%M:%S").replace(
                    tzinfo=source_timezone
                )
            )
        except ValueError:
            continue
    if not candidates:
        return ""
    return _iso_utc(min(candidates, key=lambda candidate: abs((candidate - now).total_seconds())))


def _parse_systemd_resolved(body: str, base: Dict[str, Any]) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "event.provider": "linux.systemd-resolved",
        "network.protocol": "dns",
    }
    transaction_match = RESOLVED_TRANSACTION_RE.search(body)
    if transaction_match:
        outcome = _clean_value(transaction_match.group("outcome")).lower() or "success"
        _set_event_shape(result, category="network", action="dns_query", event_type="linux_dns_query")
        _merge_non_empty(
            result,
            {
                "dns.question.name": _clean_value(transaction_match.group("query_name")),
                "dns.question.type": _clean_value(transaction_match.group("query_type")).upper(),
                "event.outcome": "success" if outcome == "success" else outcome,
                "event.id": _clean_value(transaction_match.group("transaction_id")),
            },
        )
        result["event.severity"] = "info" if result.get("event.outcome") == "success" else "medium"
        return result

    cache_match = RESOLVED_CACHE_RE.search(body)
    if cache_match:
        _set_event_shape(result, category="network", action="dns_cache", event_type="linux_dns_cache_entry")
        _merge_non_empty(
            result,
            {
                "dns.question.name": _clean_value(cache_match.group("query_name")),
                "dns.question.type": _clean_value(cache_match.group("query_type")).upper(),
                "dns.answers.ttl": _clean_value(cache_match.group("ttl")),
                "event.outcome": "success",
            },
        )
        result["event.severity"] = "info"
        return result

    return result


def _parse_windows_event(raw_event: Dict[str, Any]) -> Dict[str, Any]:
    payload = _json_loads_safe(raw_event.get("message", ""))
    xml_payload = _parse_windows_xml_payload(raw_event.get("message", ""))
    rendered_event_id, _ = _parse_windows_rendered_security_message(raw_event.get("message", ""))
    merged: Dict[str, Any] = dict(raw_event)
    if payload:
        merged.update(payload)
    if xml_payload:
        merged.update(xml_payload)
    if not (
        _first_non_empty(
            merged,
            "winlog.event_id",
            "Event.System.EventID",
            "event.code",
            "event.id",
            "event_code",
            "event_id",
        )
        or any(str(key).startswith("winlog.") for key in merged)
        or isinstance(_dotted_get(merged, "windows.event_data"), dict)
        or bool(rendered_event_id)
    ):
        return {}
    return _build_windows_event(merged, raw_event)


def _parse_vuln_scanner_event(raw_event: Dict[str, Any]) -> Dict[str, Any]:
    provider = _first_non_empty(raw_event, "event.provider", "event_provider").lower()
    device_product = _first_non_empty(raw_event, "device.product", "device_product").lower()
    event_code = _first_non_empty(raw_event, "event.code", "event_code")
    source_type = _clean_value(raw_event.get("source_type")).lower()
    if not (
        provider == "vuln.nmap"
        or device_product == "nmap"
        or (source_type == "http_json" and str(event_code).startswith("nmap-"))
    ):
        return {}
    host_name = _canonical_host_name(
        _first_non_empty(raw_event, "host.name", "host_name", "log_source", "source")
    )
    log_source = host_name or _canonical_host_name(_first_non_empty(raw_event, "log_source", "source"))
    dst_ip = _first_non_empty(raw_event, "destination.ip", "dst_ip", "target_ip")
    dst_port = _first_non_empty(raw_event, "destination.port", "dst_port")
    service_name = _first_non_empty(raw_event, "process.name", "process_name", "service.name", "service_name")
    banner = _first_non_empty(
        raw_event,
        "process.command_line",
        "process_command",
        "process.command",
        "banner",
    )
    message = _first_non_empty(raw_event, "message", "event.original")
    event_action = _first_non_empty(raw_event, "event.action", "event_action") or "observe"
    event_type = _first_non_empty(raw_event, "event.type", "event_type") or "scan_observation"
    severity = (_first_non_empty(raw_event, "severity", "event.severity") or "info").lower()

    result = {
        "event.provider": "vuln.nmap",
        "event.code": event_code,
        "event.category": "vulnerability",
        "event.action": event_action,
        "event.type": event_type,
        "event.outcome": "success",
        "event.severity": severity,
        "host.name": host_name,
        "log_source": log_source,
        "destination.ip": dst_ip if _is_ipv4(dst_ip) else "",
        "destination.port": dst_port,
        "process.name": service_name,
        "process.command_line": banner,
        "event.original": message,
        "device.vendor": _first_non_empty(raw_event, "device.vendor", "device_vendor") or "Nmap",
        "device.product": "nmap",
    }
    if event_action == "summary" or event_type == "scan_summary":
        _set_event_shape(result, category="vulnerability", action="summary", event_type="scan_summary")
        result["event.severity"] = "info"
    else:
        _set_event_shape(result, category="vulnerability", action="finding", event_type="open_port")
        result["event.severity"] = severity if severity in {"low", "medium", "high", "critical"} else "medium"
    return result


def _parse_linux_syslog(raw_event: Dict[str, Any]) -> Dict[str, Any]:
    message = _clean_value(raw_event.get("message"))
    source_ip = _clean_value(raw_event.get("source"))
    match = SYSLOG_RE.match(message)
    match_rfc5424 = SYSLOG_RFC5424_RE.match(message)

    enriched: Dict[str, Any] = {
        "event.original": message,
        "log_source": source_ip,
        "source.ip": source_ip if _is_ipv4(source_ip) else "",
        "event.provider": "linux.syslog",
        "event.category": "syslog",
        "event.type": "syslog",
        "event.action": "observe",
        "event.severity": "info",
    }

    body = message
    program = ""
    if match_rfc5424:
        body = _clean_value(match_rfc5424.group("body"))
        program = _clean_value(match_rfc5424.group("program")).lower()
        pri = int(match_rfc5424.group("pri") or 13)
        severity_code = pri % 8
        level = SYSLOG_LEVEL_MAP.get(severity_code, "info")
        host_name = _canonical_host_name(match_rfc5424.group("host"))
        process_pid = _clean_value(match_rfc5424.group("pid"))
        if process_pid == "-":
            process_pid = ""
        _merge_non_empty(
            enriched,
            {
                "@timestamp": _parse_rfc5424_timestamp(match_rfc5424.group("timestamp")),
                "log.level": level,
                "host.name": host_name,
                "log_source": host_name or source_ip,
                "process.name": "" if program == "-" else program,
                "process.pid": process_pid,
                "event.provider": f"linux.{program}" if program and program != "-" else "linux.syslog",
            },
        )
        enriched["event.severity"] = level
    elif match:
        body = _clean_value(match.group("body"))
        program = _clean_value(match.group("program")).lower()
        pri = int(match.group("pri") or 13)
        severity_code = pri % 8
        level = SYSLOG_LEVEL_MAP.get(severity_code, "info")
        host_name = _canonical_host_name(match.group("host"))
        _merge_non_empty(
            enriched,
            {
                "@timestamp": _parse_bsd_syslog_timestamp(
                    match.group("month"),
                    match.group("day"),
                    match.group("clock"),
                    host_name,
                ),
                "log.level": level,
                "host.name": host_name,
                "log_source": host_name or source_ip,
                "process.name": program,
                "process.pid": _clean_value(match.group("pid")),
                "event.provider": f"linux.{program}" if program else "linux.syslog",
            },
        )
        enriched["event.severity"] = level

    if program == "auditd" or " auditd:" in message.lower():
        return _merge_non_empty(enriched, _parse_auditd(body, enriched))
    if program == "sshd":
        return _merge_non_empty(enriched, _parse_sshd(body, enriched))
    if program in {"xray", "xray-access"}:
        return _merge_non_empty(enriched, _parse_xray_access(body, enriched))
    if program == "sudo":
        return _merge_non_empty(enriched, _parse_sudo(body, enriched))
    if program == "su":
        return _merge_non_empty(enriched, _parse_su(body, enriched))
    if program == "kernel":
        return _merge_non_empty(enriched, _parse_kernel(body, enriched))
    if program in {"cron", "crond"}:
        return _merge_non_empty(enriched, _parse_cron(program, body, enriched))
    if program in {"passwd", "useradd", "userdel", "usermod"}:
        return _merge_non_empty(enriched, _parse_account_tools(program, body, enriched))
    if program == "systemd-resolved":
        return _merge_non_empty(enriched, _parse_systemd_resolved(body, enriched))
    if program == "suricata-eve":
        return _merge_non_empty(enriched, parse_suricata_payload(enriched, body))
    if program == "suricata-fast":
        return _merge_non_empty(enriched, parse_suricata_payload(enriched, body))

    return enriched


def _enrich_raw_event(raw_event: Dict[str, Any]) -> Dict[str, Any]:
    enriched = dict(raw_event)
    source_type = _clean_value(raw_event.get("source_type")).lower()
    security_tool_event = parse_security_tool_event(raw_event)
    vuln_event = _parse_vuln_scanner_event(raw_event)
    windows_event = _parse_windows_event(raw_event)
    if security_tool_event:
        _merge_non_empty(enriched, security_tool_event)
    elif vuln_event:
        _merge_non_empty(enriched, vuln_event)
    elif windows_event:
        _merge_non_empty(enriched, windows_event)
    elif source_type == "syslog" or _clean_value(raw_event.get("message")).startswith("<"):
        _merge_non_empty(enriched, _parse_linux_syslog(raw_event))
    _apply_openclaw_allowlist_tags(enriched)
    _apply_operational_allowlist_tags(enriched)
    return enriched


def load_rules(settings: NormalizerSettings) -> List[NormalizerRule]:
    if _CLICKHOUSE_DRIVER_IMPORT_ERROR is not None:
        raise RuntimeError("clickhouse_driver is required to load normalizer rules") from _CLICKHOUSE_DRIVER_IMPORT_ERROR
    if _JMESPATH_IMPORT_ERROR is not None:
        raise RuntimeError("jmespath is required to load normalizer rules") from _JMESPATH_IMPORT_ERROR
    client = Client(
        host=settings.ch_host,
        port=settings.ch_port,
        user=settings.ch_user,
        password=settings.ch_password,
        database=settings.ch_db,
        send_receive_timeout=settings.ch_timeout_secs,
    )
    rows = client.execute(
        """
        SELECT id, priority, source_type, event_matcher, uem_mapping
        FROM siem.normalizer_rules
        WHERE enabled = 1
        ORDER BY priority ASC, id ASC
        """
    )
    rules: List[NormalizerRule] = []
    for rule_id, priority, source_type, event_matcher, uem_mapping_str in rows:
        try:
            mapping_dict = json.loads(uem_mapping_str)
            if not isinstance(mapping_dict, dict):
                raise ValueError("uem_mapping must be a JSON object")
        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to parse uem_mapping JSON", extra={"extra": {"rule_id": rule_id, "error": str(exc)}})
            continue

        compiled_matcher: Optional[Any] = None
        if event_matcher and str(event_matcher).strip():
            try:
                compiled_matcher = jmespath.compile(event_matcher)
            except Exception as exc:  # noqa: BLE001
                logger.error("Failed to compile normalizer matcher", extra={"extra": {"rule_id": rule_id, "matcher": event_matcher, "error": str(exc)}})
                continue

        compiled_mapping: Dict[str, Any] = {}
        for uem_field, expr in mapping_dict.items():
            try:
                compiled_mapping[uem_field] = jmespath.compile(expr)
            except Exception as exc:  # noqa: BLE001
                logger.error("Failed to compile JMESPath expression in uem_mapping", extra={"extra": {"rule_id": rule_id, "uem_field": uem_field, "expr": expr, "error": str(exc)}})

        rules.append(
            NormalizerRule(
                id=rule_id,
                priority=priority,
                source_type=str(source_type or "").strip(),
                event_matcher_expr=event_matcher,
                compiled_matcher=compiled_matcher,
                compiled_mapping=compiled_mapping,
            )
        )

    logger.info("Loaded normalizer rules", extra={"extra": {"count": len(rules)}})
    return rules


def _source_type_matches(rule: NormalizerRule, raw_event: Dict[str, Any]) -> bool:
    source_type = str(raw_event.get("source_type", "") or "").strip()
    expected = rule.source_type.lower()
    if expected in {"", "*", "generic", "any"}:
        return True
    return source_type.lower() == expected


def _matcher_matches(rule: NormalizerRule, raw_event: Dict[str, Any]) -> bool:
    if rule.compiled_matcher is None:
        return True
    try:
        return bool(rule.compiled_matcher.search(raw_event))
    except Exception as exc:  # noqa: BLE001
        logger.error("Failed to evaluate normalizer matcher", extra={"extra": {"rule_id": rule.id, "matcher": rule.event_matcher_expr, "error": str(exc)}})
        return False


def _build_uem(rule: Optional[NormalizerRule], raw_event: Dict[str, Any]) -> Dict[str, Any]:
    uem: Dict[str, Any] = {}
    compiled_mapping = rule.compiled_mapping if rule else {}

    for uem_field, compiled_expr in compiled_mapping.items():
        try:
            value = compiled_expr.search(raw_event)
        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to apply JMESPath mapping", extra={"extra": {"rule_id": rule.id if rule else "builtin", "uem_field": uem_field, "error": str(exc)}})
            value = None
        if value not in (None, "", [], {}):
            uem[uem_field] = value

    passthrough_keys = {
        "@timestamp",
        "message",
        "severity",
        "log_source",
        "source_type",
        "source",
        "metrics",
        "services",
        "details",
        "tags",
    }
    for key, value in raw_event.items():
        if "." in str(key) or str(key) in passthrough_keys:
            if value not in (None, "", [], {}):
                uem[str(key)] = value

    if "event.provider" not in uem or uem.get("event.provider") in (None, ""):
        uem["event.provider"] = raw_event.get("source_type", "") or ""
    if "event.original" not in uem or uem.get("event.original") in (None, ""):
        uem["event.original"] = raw_event.get("message", "") or str(raw_event)
    if "host.name" not in uem or uem.get("host.name") in (None, ""):
        uem["host.name"] = _canonical_host_name(raw_event.get("source", "") or raw_event.get("log_source", "") or "")
    else:
        uem["host.name"] = _canonical_host_name(str(uem.get("host.name") or ""))
    if "log_source" not in uem or uem.get("log_source") in (None, ""):
        uem["log_source"] = _canonical_host_name(
            raw_event.get("host.name", "") or raw_event.get("source", "") or raw_event.get("log_source", "") or ""
        )
    elif raw_event.get("host.name") and raw_event.get("log_source") == raw_event.get("source"):
        uem["log_source"] = _canonical_host_name(raw_event.get("host.name") or uem.get("log_source"))
    else:
        uem["log_source"] = _canonical_host_name(str(uem.get("log_source") or ""))
    return uem


def apply_rules(rules: List[NormalizerRule], raw_event: Dict[str, Any]) -> Dict[str, Any] | None:
    enriched_event = _enrich_raw_event(raw_event)
    for rule in rules:
        if not _source_type_matches(rule, enriched_event):
            continue
        if not _matcher_matches(rule, enriched_event):
            continue
        return _build_uem(rule, enriched_event)

    if enriched_event.get("event.provider") or enriched_event.get("event.category"):
        return _build_uem(None, enriched_event)
    return None
