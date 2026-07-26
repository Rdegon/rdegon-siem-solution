from __future__ import annotations

import ipaddress
import json
import re
from typing import Any, Dict, Iterable


EMPTY_VALUES = (None, "", [], {})


def _text(value: Any) -> str:
    if value in EMPTY_VALUES:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value).strip()


def _dict(value: Any) -> Dict[str, Any]:
    if isinstance(value, dict):
        return value
    text = _text(value)
    if not text or not text.startswith("{"):
        return {}
    try:
        parsed = json.loads(text)
    except (TypeError, ValueError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    text = _text(value)
    if not text or not text.startswith("["):
        return []
    try:
        parsed = json.loads(text)
    except (TypeError, ValueError):
        return []
    return parsed if isinstance(parsed, list) else []


def _first(event: Dict[str, Any], *keys: str) -> Any:
    for key in keys:
        value = event.get(key)
        if value not in EMPTY_VALUES:
            return value
    return ""


def _nested(event: Dict[str, Any], parent: str, *keys: str) -> Any:
    nested = _dict(event.get(parent))
    return _first(nested, *keys)


def _tags(*groups: Iterable[str] | str) -> list[str]:
    result: list[str] = []
    seen: set[str] = set()
    for group in groups:
        values = [group] if isinstance(group, str) else group
        for value in values:
            tag = _text(value)
            if tag and tag not in seen:
                seen.add(tag)
                result.append(tag)
    return result


def _message(event: Dict[str, Any]) -> str:
    existing = _text(_first(event, "event.original", "message", "Message", "output"))
    if existing:
        return existing
    return json.dumps(event, ensure_ascii=True, separators=(",", ":"), default=str)


def _severity(value: Any, *, default: str = "info") -> str:
    normalized = _text(value).lower()
    aliases = {
        "emergency": "critical",
        "alert": "critical",
        "fatal": "critical",
        "critical": "critical",
        "crit": "critical",
        "error": "high",
        "err": "high",
        "high": "high",
        "warning": "medium",
        "warn": "medium",
        "medium": "medium",
        "notice": "low",
        "low": "low",
        "informational": "info",
        "information": "info",
        "info": "info",
        "debug": "info",
        "unknown": default,
    }
    return aliases.get(normalized, normalized or default)


_INTERNAL_NETWORKS = tuple(
    ipaddress.ip_network(value)
    for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)
_SURICATA_FAST_RE = re.compile(
    r"^\S+\s+\[\*\*\]\s+\[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\]\s+"
    r"(?P<signature>.*?)\s+\[\*\*\].*?"
    r"(?:\[Classification:\s*(?P<category>[^\]]+)\]\s+)?"
    r"\[Priority:\s*(?P<priority>\d+)\]\s+"
    r"\{(?P<proto>[^}]+)\}\s+"
    r"(?P<src_ip>\d{1,3}(?:\.\d{1,3}){3})(?::(?P<src_port>\d+))?\s+->\s+"
    r"(?P<dst_ip>\d{1,3}(?:\.\d{1,3}){3})(?::(?P<dst_port>\d+))?"
)


def _network_direction(source_ip: str, destination_ip: str) -> str:
    def is_internal(value: str) -> bool:
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            return False
        return any(address in network for network in _INTERNAL_NETWORKS)

    source_internal = is_internal(source_ip)
    destination_internal = is_internal(destination_ip)
    if source_internal and destination_internal:
        return "internal"
    if source_internal and not destination_internal:
        return "outbound"
    if not source_internal and destination_internal:
        return "inbound"
    return "external"


def _suricata_alert_severity(value: Any) -> str:
    priority = _text(value)
    return {"1": "critical", "2": "high", "3": "medium"}.get(priority, "medium")


def _base(
    event: Dict[str, Any],
    *,
    provider: str,
    dataset: str,
    category: str,
    event_type: str,
    action: str,
    severity: str,
) -> Dict[str, Any]:
    host_name = _text(
        _first(
            event,
            "host.name",
            "hostname",
            "HostName",
            "source",
            "log_source",
            "sensor",
        )
    )
    result: Dict[str, Any] = {
        "event.provider": provider,
        "event.dataset": dataset,
        "event.category": category,
        "event.type": event_type,
        "event.action": action,
        "event.severity": severity,
        "event.original": _message(event),
        "host.name": host_name,
        "log_source": host_name,
        "tags": _tags([f"sensor:{provider}", f"dataset:{dataset}"]),
    }
    timestamp = _text(_first(event, "@timestamp", "timestamp", "Timestamp", "time", "ts"))
    if timestamp:
        result["@timestamp"] = timestamp
    ingested_timestamp = _text(
        _first(event, "event.ingested", "event_ingested", "ingested_at")
    )
    if ingested_timestamp:
        result["event.ingested"] = ingested_timestamp
    evidence_id = _text(_first(event, "evidence.id", "evidence_id", "object_id"))
    evidence_uri = _text(_first(event, "evidence.uri", "evidence_uri", "object_uri"))
    if evidence_id:
        result["evidence.id"] = evidence_id
    if evidence_uri:
        result["evidence.uri"] = evidence_uri
    return result


def parse_suricata_payload(event: Dict[str, Any], payload: Dict[str, Any] | str) -> Dict[str, Any]:
    eve = payload if isinstance(payload, dict) else _dict(payload)
    if not eve:
        fast_match = _SURICATA_FAST_RE.search(_text(payload))
        if not fast_match:
            return {}
        fields = fast_match.groupdict()
        source_ip = _text(fields.get("src_ip"))
        destination_ip = _text(fields.get("dst_ip"))
        priority = _text(fields.get("priority"))
        normalized = _base(
            event,
            provider="suricata",
            dataset="suricata.fast",
            category="intrusion_detection",
            event_type="suricata_alert",
            action="signature_match",
            severity=_suricata_alert_severity(priority),
        )
        normalized.update(
            {
                "event.code": _text(fields.get("sid")),
                "rule.id": _text(fields.get("sid")),
                "rule.name": _text(fields.get("signature")),
                "rule.category": _text(fields.get("category")),
                "suricata.alert.severity": priority,
                "source.ip": source_ip,
                "source.port": _text(fields.get("src_port")),
                "destination.ip": destination_ip,
                "destination.port": _text(fields.get("dst_port")),
                "network.transport": _text(fields.get("proto")).lower(),
                "network.direction": _network_direction(source_ip, destination_ip),
                "event.outcome": "failure",
            }
        )
        normalized["tags"] = _tags(normalized["tags"], ["alert:network", "suricata:fast"])
        return normalized

    event_type = _text(eve.get("event_type")).lower()
    if not event_type:
        return {}
    alert = _dict(eve.get("alert"))
    dns = _dict(eve.get("dns"))
    http = _dict(eve.get("http"))
    tls = _dict(eve.get("tls"))
    file_info = _dict(eve.get("fileinfo"))
    source_ip = _text(_first(eve, "src_ip", "source.ip"))
    destination_ip = _text(_first(eve, "dest_ip", "destination.ip"))
    actions = {
        "alert": "signature_match",
        "dns": "dns_query",
        "flow": "network_connection",
        "http": "http_request",
        "tls": "tls_handshake",
        "fileinfo": "file_observed",
        "anomaly": "protocol_anomaly",
        "stats": "sensor_stats",
    }
    categories = {
        "alert": "intrusion_detection",
        "dns": "network",
        "flow": "network",
        "http": "web",
        "tls": "network",
        "fileinfo": "file",
        "anomaly": "network",
        "stats": "network",
    }
    priority = _text(alert.get("severity"))
    severity = _suricata_alert_severity(priority) if event_type == "alert" else "info"
    normalized = _base(
        event,
        provider="suricata",
        dataset=f"suricata.eve.{event_type}",
        category=categories.get(event_type, "network"),
        event_type=f"suricata_{event_type}",
        action=actions.get(event_type, "network_observation"),
        severity=severity,
    )
    normalized.update(
        {
            "event.id": _text(_first(eve, "event.id", "flow_id", "community_id")),
            "event.code": _text(_first(alert, "signature_id", "gid")),
            "event.outcome": "failure" if event_type == "alert" else "unknown",
            "rule.id": _text(_first(alert, "signature_id", "gid")),
            "rule.name": _text(_first(alert, "signature", "name")),
            "rule.category": _text(_first(alert, "category")),
            "suricata.alert.severity": priority,
            "source.ip": source_ip,
            "source.port": _text(_first(eve, "src_port", "source.port")),
            "destination.ip": destination_ip,
            "destination.port": _text(_first(eve, "dest_port", "destination.port")),
            "network.transport": _text(_first(eve, "proto", "network.transport")).lower(),
            "network.protocol": _text(_first(eve, "app_proto", "network.protocol")).lower(),
            "network.community_id": _text(_first(eve, "community_id")),
            "network.direction": _network_direction(source_ip, destination_ip),
            "dns.question.name": _text(_first(dns, "rrname", "query", "dns.question.name")),
            "dns.question.type": _text(_first(dns, "rrtype", "type", "dns.question.type")),
            "dns.response_code": _text(_first(dns, "rcode", "dns.response_code")),
            "url.domain": _text(_first(http, "hostname", "url.domain") or _first(tls, "sni")),
            "url.path": _text(_first(http, "url", "url.path")),
            "http.request.method": _text(_first(http, "http_method", "method")),
            "http.response.status_code": _text(_first(http, "status", "status_code")),
            "user_agent.original": _text(_first(http, "http_user_agent", "user_agent")),
            "file.name": _text(_first(file_info, "filename", "file.name")),
            "file.sha256": _text(_first(file_info, "sha256", "file.sha256")),
            "file.md5": _text(_first(file_info, "md5", "file.md5")),
        }
    )
    normalized["tags"] = _tags(
        normalized["tags"],
        [f"suricata:{event_type}"],
        ["alert:network"] if event_type == "alert" else [],
    )
    return normalized


def _parse_zeek(event: Dict[str, Any]) -> Dict[str, Any]:
    path = _text(_first(event, "_path", "path", "zeek.path")).lower() or "event"
    dataset = _text(event.get("event.dataset")).lower()
    if dataset.startswith("zeek.") and dataset != "zeek.event":
        path = dataset.split(".", 1)[1]
    elif path == "event":
        sensor_file = _text(event.get("sensor.file")).replace("\\", "/").rsplit("/", 1)[-1]
        if sensor_file.lower().endswith(".log"):
            path = sensor_file.lower().split(".", 1)[0]
    actions = {
        "conn": "network_connection",
        "dns": "dns_query",
        "http": "http_request",
        "ssl": "tls_handshake",
        "notice": "notice",
        "files": "file_observed",
        "weird": "protocol_anomaly",
    }
    categories = {
        "dns": "network",
        "http": "web",
        "ssl": "network",
        "notice": "intrusion_detection",
        "files": "file",
        "weird": "network",
    }
    severity = _severity(_first(event, "severity", "level"), default="info")
    if path in {"notice", "weird"} and severity == "info":
        severity = "medium"
    normalized = _base(
        event,
        provider="zeek",
        dataset=f"zeek.{path}",
        category=categories.get(path, "network"),
        event_type=f"zeek_{path}",
        action=actions.get(path, "network_observation"),
        severity=severity,
    )
    normalized.update(
        {
            # Zeek uid/fuid identifies a connection or file and can occur in many
            # records. Preserve the forwarder's per-record identity for SIEM dedup.
            "event.id": _text(_first(event, "event.id", "event_id", "uid", "fuid")),
            "event.code": _text(_first(event, "note", "event.code")),
            "zeek.uid": _text(_first(event, "uid", "fuid")),
            "source.ip": _text(_first(event, "id.orig_h", "src_ip", "source.ip")),
            "source.port": _text(_first(event, "id.orig_p", "src_port", "source.port")),
            "destination.ip": _text(_first(event, "id.resp_h", "dest_ip", "destination.ip")),
            "destination.port": _text(_first(event, "id.resp_p", "dest_port", "destination.port")),
            "network.transport": _text(_first(event, "proto", "network.transport")).lower(),
            "network.protocol": _text(_first(event, "service", "network.protocol", "qtype_name")).lower(),
            "network.community_id": _text(_first(event, "community_id", "network.community_id")),
            "network.bytes": _text(_first(event, "orig_bytes", "network.bytes")),
            "network.packets": _text(_first(event, "orig_pkts", "network.packets")),
            "dns.question.name": _text(_first(event, "query", "dns.question.name")),
            "dns.question.type": _text(_first(event, "qtype_name", "dns.question.type")),
            "dns.response_code": _text(_first(event, "rcode_name", "dns.response_code")),
            "url.domain": _text(_first(event, "host", "server_name", "url.domain")),
            "url.path": _text(_first(event, "uri", "url.path")),
            "http.request.method": _text(_first(event, "method", "http.request.method")),
            "http.response.status_code": _text(_first(event, "status_code", "http.response.status_code")),
            "user_agent.original": _text(_first(event, "user_agent", "user_agent.original")),
            "rule.name": _text(_first(event, "note", "signature", "rule.name")),
            "file.name": _text(_first(event, "filename", "file.name")),
            "file.sha256": _text(_first(event, "sha256", "file.sha256")),
            "file.md5": _text(_first(event, "md5", "file.md5")),
        }
    )
    normalized["network.direction"] = _network_direction(
        _text(normalized.get("source.ip")),
        _text(normalized.get("destination.ip")),
    )
    conn_state = _text(event.get("conn_state"))
    status_code = _text(event.get("status_code"))
    if conn_state:
        normalized["network.connection.state"] = conn_state
        normalized["event.outcome"] = "success" if conn_state in {"SF", "S1"} else "unknown"
    elif status_code:
        try:
            normalized["event.outcome"] = "failure" if int(status_code) >= 400 else "success"
        except ValueError:
            normalized["event.outcome"] = "unknown"
    answers = _list(event.get("answers"))
    if answers:
        normalized["dns.answers"] = answers
    return normalized


def _parse_falco(event: Dict[str, Any]) -> Dict[str, Any]:
    output_fields = _dict(event.get("output_fields"))
    rule_name = _text(_first(event, "rule", "rule.name"))
    normalized = _base(
        event,
        provider="falco",
        dataset="falco.runtime",
        category="intrusion_detection",
        event_type="falco_runtime_alert",
        action="rule_triggered",
        severity=_severity(_first(event, "priority", "severity"), default="medium"),
    )
    normalized.update(
        {
            "event.code": rule_name,
            "rule.name": rule_name,
            "event.outcome": "unknown",
            "user.name": _text(_first(output_fields, "user.name", "user.loginuid", "user.uid")),
            "process.name": _text(_first(output_fields, "proc.name", "process.name")),
            "process.executable": _text(_first(output_fields, "proc.exepath", "proc.exe", "process.executable")),
            "process.command_line": _text(_first(output_fields, "proc.cmdline", "process.command_line")),
            "container.id": _text(_first(output_fields, "container.id", "container.full_id")),
            "container.name": _text(_first(output_fields, "container.name")),
            "container.image.name": _text(_first(output_fields, "container.image.repository", "container.image")),
            "source.ip": _text(_first(output_fields, "fd.cip", "fd.sip", "source.ip")),
            "source.port": _text(_first(output_fields, "fd.cport", "fd.sport", "source.port")),
            "destination.ip": _text(_first(output_fields, "fd.sip", "fd.rip", "destination.ip")),
            "destination.port": _text(_first(output_fields, "fd.sport", "fd.rport", "destination.port")),
        }
    )
    normalized["tags"] = _tags(normalized["tags"], _list(event.get("tags")), ["alert:runtime"])
    return normalized


def _parse_trivy(event: Dict[str, Any]) -> Dict[str, Any]:
    vulnerability = _dict(event.get("Vulnerability"))
    vuln_id = _text(_first(event, "VulnerabilityID", "vulnerability.id", "vulnerability_id"))
    if not vuln_id:
        vuln_id = _text(_first(vulnerability, "VulnerabilityID", "ID"))
    severity = _severity(
        _first(event, "Severity", "severity", "vulnerability.severity") or _first(vulnerability, "Severity"),
        default="medium",
    )
    target = _text(_first(event, "Target", "target", "resource", "artifact"))
    normalized = _base(
        event,
        provider="trivy",
        dataset="trivy.vulnerability",
        category="vulnerability",
        event_type="vulnerability_finding",
        action="vulnerability_detected",
        severity=severity,
    )
    normalized.update(
        {
            "event.code": vuln_id,
            "vulnerability.id": vuln_id,
            "vulnerability.severity": severity,
            "vulnerability.title": _text(_first(event, "Title", "title") or _first(vulnerability, "Title")),
            "vulnerability.description": _text(
                _first(event, "Description", "description") or _first(vulnerability, "Description")
            ),
            "vulnerability.package.name": _text(_first(event, "PkgName", "package.name")),
            "vulnerability.package.version": _text(_first(event, "InstalledVersion", "package.version")),
            "vulnerability.fixed_version": _text(_first(event, "FixedVersion", "fixed_version")),
            "resource.name": target,
            "resource.type": _text(_first(event, "Type", "Class", "resource.type")),
            "url.original": _text(_first(event, "PrimaryURL", "url")),
            "event.outcome": "failure",
        }
    )
    normalized["tags"] = _tags(normalized["tags"], ["finding:vulnerability", f"severity:{severity}"])
    return normalized


def _parse_velociraptor(event: Dict[str, Any]) -> Dict[str, Any]:
    artifact = _text(_first(event, "artifact", "Artifact", "event.dataset", "query_name"))
    artifact_name = artifact.removeprefix("velociraptor.") or "hunt"
    client_id = _text(_first(event, "client_id", "ClientId", "ClientId__"))
    normalized = _base(
        event,
        provider="velociraptor",
        dataset=f"velociraptor.{artifact_name}",
        category="endpoint",
        event_type="velociraptor_artifact_result",
        action="artifact_collected",
        severity=_severity(_first(event, "severity", "Severity", "Level"), default="info"),
    )
    normalized.update(
        {
            "event.id": _text(_first(event, "event_id", "EventId", "FlowId", "HuntId")),
            "event.code": artifact_name,
            "agent.id": client_id,
            "host.name": _text(_first(event, "hostname", "HostName", "host.name")) or normalized["host.name"],
            "user.name": _text(_first(event, "user", "User", "Username")),
            "process.name": _text(_first(event, "process_name", "Name", "process.name")),
            "process.executable": _text(_first(event, "path", "Exe", "process.executable")),
            "process.command_line": _text(_first(event, "command_line", "CommandLine", "process.command_line")),
            "file.name": _text(_first(event, "file_name", "Name", "file.name")),
            "file.path": _text(_first(event, "file_path", "OSPath", "Path", "file.path")),
            "file.sha256": _text(_first(event, "sha256", "SHA256", "file.sha256")),
            "source.ip": _text(_first(event, "source.ip", "RemoteAddress", "SrcIP")),
            "destination.ip": _text(_first(event, "destination.ip", "LocalAddress", "DestIP")),
            "event.outcome": "success",
        }
    )
    normalized["log_source"] = normalized["host.name"] or client_id
    normalized["tags"] = _tags(normalized["tags"], ["telemetry:endpoint"])
    return normalized


def _parse_misp(event: Dict[str, Any]) -> Dict[str, Any]:
    attribute = _dict(event.get("Attribute"))
    misp_event = _dict(event.get("Event"))
    indicator_type = _text(_first(event, "attribute_type", "type", "indicator.type") or attribute.get("type"))
    indicator = _text(_first(event, "value", "indicator", "threat.indicator") or attribute.get("value"))
    misp_event_id = _text(_first(event, "event_id", "EventId") or misp_event.get("id"))
    attribute_id = _text(attribute.get("uuid") or attribute.get("id"))
    event_id = _text(event.get("event.id"))
    if not event_id:
        event_id = f"misp-{misp_event_id}-attribute-{attribute_id or indicator}"
    threat_level = _text(_first(event, "threat_level_id") or misp_event.get("threat_level_id"))
    orgc = _dict(misp_event.get("Orgc"))
    severity = {"1": "high", "2": "medium", "3": "low", "4": "info"}.get(threat_level, "medium")
    normalized = _base(
        event,
        provider="misp",
        dataset="misp.attribute",
        category="threat_intelligence",
        event_type="threat_indicator",
        action="indicator_published",
        severity=severity,
    )
    normalized.update(
        {
            "event.id": event_id,
            "event.code": indicator_type,
            "threat.indicator.type": indicator_type,
            "threat.indicator.value": indicator,
            "threat.feed.name": _text(_first(event, "feed", "org") or orgc.get("name")) or "misp",
            "threat.confidence": _text(_first(event, "confidence", "threat.confidence")),
            "rule.name": _text(_first(event, "event_info", "info") or misp_event.get("info")),
            "event.outcome": "success",
        }
    )
    normalized["tags"] = _tags(normalized["tags"], ["intel:ioc", f"ioc_type:{indicator_type}"])
    return normalized


def _parse_malware(event: Dict[str, Any]) -> Dict[str, Any]:
    rule_name = _text(_first(event, "rule", "rule.name", "yara_rule", "signature"))
    sha256 = _text(_first(event, "sha256", "file.sha256"))
    verdict = _text(_first(event, "verdict", "classification", "event.outcome")).lower()
    malicious = verdict in {"malicious", "suspicious", "infected", "detected", "match", "failure"}
    severity = _severity(_first(event, "severity", "priority"), default="high" if malicious else "medium")
    normalized = _base(
        event,
        provider=_text(_first(event, "scanner", "event.provider")) or "malware-analysis",
        dataset="malware.static",
        category="malware",
        event_type="malware_analysis_result",
        action="file_scanned",
        severity=severity,
    )
    normalized.update(
        {
            "event.code": rule_name,
            "rule.name": rule_name,
            "file.name": _text(_first(event, "file_name", "name", "file.name")),
            "file.path": _text(_first(event, "file_path", "path", "file.path")),
            "file.sha256": sha256,
            "file.sha1": _text(_first(event, "sha1", "file.sha1")),
            "file.md5": _text(_first(event, "md5", "file.md5")),
            "file.size": _text(_first(event, "size", "file.size")),
            "event.outcome": "failure" if malicious else "success",
        }
    )
    normalized["tags"] = _tags(normalized["tags"], ["analysis:static", f"verdict:{verdict or 'unknown'}"])
    return normalized


def parse_security_tool_event(raw_event: Dict[str, Any]) -> Dict[str, Any]:
    source_type = _text(raw_event.get("source_type")).lower()
    provider = _text(raw_event.get("event.provider")).lower()
    dataset = _text(raw_event.get("event.dataset")).lower()
    collector = _text(_first(raw_event, "collector", "collector_profile", "observer.collector")).lower()
    identity = " ".join((source_type, provider, dataset, collector))

    if "suricata" in identity:
        payload = _first(raw_event, "eve", "payload", "message", "event.original")
        parsed = parse_suricata_payload(raw_event, payload)
        if parsed:
            return parsed
    if "zeek" in identity or "_path" in raw_event:
        return _parse_zeek(raw_event)
    if "falco" in identity or ("output_fields" in raw_event and "rule" in raw_event):
        return _parse_falco(raw_event)
    if "trivy" in identity or "VulnerabilityID" in raw_event:
        return _parse_trivy(raw_event)
    if "velociraptor" in identity or "ClientId" in raw_event or "client_id" in raw_event and "artifact" in raw_event:
        return _parse_velociraptor(raw_event)
    if "misp" in identity or "Attribute" in raw_event and "Event" in raw_event:
        return _parse_misp(raw_event)
    if any(marker in identity for marker in ("yara", "malware", "clamav", "static-analysis")):
        return _parse_malware(raw_event)
    return {}
