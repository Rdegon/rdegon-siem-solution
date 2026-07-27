from __future__ import annotations

import csv
import re
from io import StringIO
from typing import Any, Dict


SYSTEMD_UNIT_RE = re.compile(
    r"\b(?P<unit>[A-Za-z0-9_.:@\\-]+\.(?:service|socket|timer|mount|target|path))\b"
)
MINECRAFT_LINE_RE = re.compile(
    r"\[(?P<clock>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<level>TRACE|DEBUG|INFO|WARN|ERROR|FATAL)\]:\s*(?P<body>.*)",
    re.IGNORECASE,
)
MINECRAFT_JOIN_RE = re.compile(r"^(?P<user>[A-Za-z0-9_]{1,16}) joined the game\b")
MINECRAFT_LEAVE_RE = re.compile(
    r"^(?P<user>[A-Za-z0-9_]{1,16}) (?:left the game|lost connection\b)"
)
MINECRAFT_COMMAND_RE = re.compile(
    r"^(?P<user>[A-Za-z0-9_]{1,16}) issued server command:\s*(?P<command>.+)$"
)
PAM_SESSION_RE = re.compile(
    r"pam_unix\((?P<service>[^:)]+):session\): session "
    r"(?P<state>opened|closed) for user (?P<user>[^\s(]+)",
    re.IGNORECASE,
)
PAM_FAILURE_RE = re.compile(
    r"pam_(?:unix|sss)\((?P<service>[^:)]+):auth\):.*?"
    r"(?:authentication failure|auth failure).*?(?:user=|ruser=)(?P<user>[^\s]+)",
    re.IGNORECASE,
)


def _text(value: Any) -> str:
    return str(value or "").strip()


def _base(
    *,
    provider: str,
    dataset: str,
    category: str,
    event_type: str,
    action: str,
    severity: str = "info",
    outcome: str = "unknown",
) -> Dict[str, Any]:
    return {
        "event.provider": provider,
        "event.dataset": dataset,
        "event.category": category,
        "event.type": event_type,
        "event.action": action,
        "event.severity": severity,
        "event.outcome": outcome,
    }


def parse_opnsense_filterlog(body: str) -> Dict[str, Any]:
    try:
        fields = next(csv.reader(StringIO(_text(body))))
    except (csv.Error, StopIteration):
        return {}
    if len(fields) < 20:
        return {}

    ip_version = _text(fields[8])
    if ip_version == "4":
        protocol_id_index = 15
        protocol_index = 16
        source_ip_index = 18
        destination_ip_index = 19
        source_port_index = 20
        destination_port_index = 21
    elif ip_version == "6" and len(fields) >= 17:
        protocol_index = 12
        protocol_id_index = 13
        source_ip_index = 15
        destination_ip_index = 16
        source_port_index = 17
        destination_port_index = 18
    else:
        return {}

    action = _text(fields[6]).lower()
    blocked = action in {"block", "reject"}
    result = _base(
        provider="opnsense",
        dataset="opnsense.filterlog",
        category="network",
        event_type="firewall_connection_denied" if blocked else "firewall_connection_allowed",
        action="firewall_block" if blocked else "firewall_allow",
        severity="low" if blocked else "info",
        outcome="failure" if blocked else "success",
    )
    result.update(
        {
            "rule.id": _text(fields[0]),
            "rule.uuid": _text(fields[3]),
            "observer.interface.name": _text(fields[4]),
            "event.reason": _text(fields[5]),
            "network.direction": _text(fields[7]).lower(),
            "network.type": f"ipv{ip_version}",
            "network.transport": _text(fields[protocol_index]).lower(),
            "network.iana_number": _text(fields[protocol_id_index]),
            "source.ip": _text(fields[source_ip_index]),
            "destination.ip": _text(fields[destination_ip_index]),
            "source.port": _text(fields[source_port_index]) if len(fields) > source_port_index else "",
            "destination.port": _text(fields[destination_port_index]) if len(fields) > destination_port_index else "",
            "tags": ["source:opnsense", f"firewall:{action or 'unknown'}"],
        }
    )
    return result


def parse_systemd_message(body: str) -> Dict[str, Any]:
    message = _text(body)
    lowered = message.lower()
    unit_match = SYSTEMD_UNIT_RE.search(message)
    unit = unit_match.group("unit") if unit_match else ""

    failure_markers = (
        "failed with result",
        "failed to start",
        "entered failed state",
        "main process exited",
        "start request repeated too quickly",
        "dependency failed for",
    )
    if any(marker in lowered for marker in failure_markers):
        result = _base(
            provider="linux.systemd",
            dataset="linux.systemd",
            category="service",
            event_type="linux_systemd_unit_failed",
            action="service_failure",
            severity="high",
            outcome="failure",
        )
    elif "scheduled restart job" in lowered:
        result = _base(
            provider="linux.systemd",
            dataset="linux.systemd",
            category="service",
            event_type="linux_systemd_restart_scheduled",
            action="service_restart",
            severity="medium",
        )
    elif "deactivated successfully" in lowered:
        result = _base(
            provider="linux.systemd",
            dataset="linux.systemd",
            category="service",
            event_type="linux_systemd_unit_deactivated",
            action="service_deactivate",
            outcome="success",
        )
    elif lowered.startswith(("stopped ", "stopping ")) or ": stopped " in lowered:
        result = _base(
            provider="linux.systemd",
            dataset="linux.systemd",
            category="service",
            event_type="linux_systemd_unit_stopped",
            action="service_stop",
            outcome="success",
        )
    elif lowered.startswith(("started ", "starting ", "finished ")):
        result = _base(
            provider="linux.systemd",
            dataset="linux.systemd",
            category="service",
            event_type="linux_systemd_unit_started",
            action="service_start",
            outcome="success",
        )
    else:
        result = _base(
            provider="linux.systemd",
            dataset="linux.systemd",
            category="service",
            event_type="linux_systemd_event",
            action="service_observe",
        )

    if unit:
        result["service.name"] = unit
        result["service.type"] = unit.rsplit(".", 1)[-1]
    return result


def parse_minecraft_message(body: str) -> Dict[str, Any]:
    message = _text(body).replace("#011", "\t")
    match = MINECRAFT_LINE_RE.search(message)
    level = match.group("level").lower() if match else "info"
    payload = _text(match.group("body")) if match else message
    lowered = payload.lower()

    result = _base(
        provider="minecraft",
        dataset="minecraft.server",
        category="application",
        event_type="minecraft_log",
        action="observe",
        severity={"warn": "low", "error": "medium", "fatal": "high"}.get(level, "info"),
    )
    result["log.level"] = level

    joined = MINECRAFT_JOIN_RE.search(payload)
    left = MINECRAFT_LEAVE_RE.search(payload)
    command = MINECRAFT_COMMAND_RE.search(payload)
    if "server has not responded for" in lowered or "creating thread dump" in lowered:
        result.update(
            {
                "event.category": "availability",
                "event.type": "minecraft_server_hang",
                "event.action": "server_unresponsive",
                "event.severity": "high",
                "event.outcome": "failure",
            }
        )
    elif "failed to save" in lowered or "could not save" in lowered:
        result.update(
            {
                "event.category": "availability",
                "event.type": "minecraft_save_failure",
                "event.action": "world_save",
                "event.severity": "high",
                "event.outcome": "failure",
            }
        )
    elif joined:
        result.update(
            {
                "event.category": "session",
                "event.type": "minecraft_player_join",
                "event.action": "player_join",
                "event.outcome": "success",
                "user.name": joined.group("user"),
            }
        )
    elif left:
        result.update(
            {
                "event.category": "session",
                "event.type": "minecraft_player_leave",
                "event.action": "player_leave",
                "event.outcome": "success",
                "user.name": left.group("user"),
            }
        )
    elif command:
        result.update(
            {
                "event.category": "execution",
                "event.type": "minecraft_player_command",
                "event.action": "command",
                "event.severity": "low",
                "event.outcome": "success",
                "user.name": command.group("user"),
                "process.command_line": command.group("command"),
            }
        )
    elif lowered.startswith("done (") or "for help, type \"help\"" in lowered:
        result.update(
            {
                "event.category": "service",
                "event.type": "minecraft_server_started",
                "event.action": "service_start",
                "event.outcome": "success",
            }
        )
    elif lowered.startswith("stopping server"):
        result.update(
            {
                "event.category": "service",
                "event.type": "minecraft_server_stopped",
                "event.action": "service_stop",
                "event.outcome": "success",
            }
        )
    elif level in {"error", "fatal"}:
        result.update(
            {
                "event.type": "minecraft_error",
                "event.action": "application_error",
                "event.outcome": "failure",
            }
        )
    return result


def parse_pam_message(body: str) -> Dict[str, Any]:
    session = PAM_SESSION_RE.search(body)
    if session:
        state = session.group("state").lower()
        result = _base(
            provider="linux.pam",
            dataset="linux.auth",
            category="session",
            event_type=f"pam_session_{state}",
            action=f"session_{state}",
            outcome="success",
        )
        result.update(
            {
                "user.name": session.group("user"),
                "service.name": session.group("service"),
            }
        )
        return result

    failure = PAM_FAILURE_RE.search(body)
    if failure:
        result = _base(
            provider="linux.pam",
            dataset="linux.auth",
            category="authentication",
            event_type="pam_authentication_failure",
            action="authentication_failed",
            severity="medium",
            outcome="failure",
        )
        result.update(
            {
                "user.name": failure.group("user"),
                "service.name": failure.group("service"),
            }
        )
        return result
    return {}


def parse_oauth2_proxy_message(body: str) -> Dict[str, Any]:
    message = _text(body)
    lowered = message.lower()
    if any(
        marker in lowered
        for marker in (
            "error redeeming code",
            "failed to redeem",
            "oidc discovery failed",
            "unable to redeem",
            "authentication failed",
            "panic:",
            "fatal:",
        )
    ):
        return _base(
            provider="oauth2-proxy",
            dataset="oauth2_proxy.application",
            category="authentication",
            event_type="oauth2_proxy_authentication_failure",
            action="authentication_failed",
            severity="medium",
            outcome="failure",
        )
    if "oauthproxy configured" in lowered or "mapping path" in lowered:
        return _base(
            provider="oauth2-proxy",
            dataset="oauth2_proxy.application",
            category="configuration",
            event_type="oauth2_proxy_configured",
            action="configuration_loaded",
            outcome="success",
        )
    return _base(
        provider="oauth2-proxy",
        dataset="oauth2_proxy.application",
        category="application",
        event_type="oauth2_proxy_log",
        action="observe",
    )
