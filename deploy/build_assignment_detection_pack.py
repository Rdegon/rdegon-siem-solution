from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Any

import yaml

try:
    from deploy.curated_assignment_rules import curated_batch_sql
except ModuleNotFoundError:  # Direct script execution from deploy/.
    from curated_assignment_rules import curated_batch_sql


ROOT = Path(__file__).resolve().parents[1]
PACK_PATH = ROOT / "correlation_rule_packs" / "siem_detection_pack_v1.json"
REPORT_PATH = ROOT / "correlation_rule_packs" / "siem_detection_pack_v1_report.md"
ACTIVE_SOURCE_IDS_PATH = ROOT / "correlation_rule_packs" / "siem_detection_pack_v1_active_source_ids.txt"
ACTIVE_OVERRIDES_PATH = ROOT / "correlation_rule_packs" / "siem_detection_pack_v1_active_overrides.json"

PACK_ID = "siem-detection-pack-v1"
RULE_ID_BASE = 8000

BATCH_PREFIXES = {"HB", "MET", "BCK"}
SAFE_STREAM_PREFIXES: set[str] = set()
STRUCTURED_STREAM_PREFIXES = {"WIN"}
STREAM_EXPR_OVERRIDE_KEYS = ("expr", "stream_expr", "rule_expr")
GENERATED_SIGMA_PUBLISH_KEYS = ("publish_generated_sigma", "validated_for_stream", "safe_to_publish")
ASSET_GROUPS: dict[str, list[str]] = {
    "proxmox": ["pve"],
    "siem_core": ["104 SIEM-Ingest", "105 SIEM-Processing", "106 SIEM-Storage", "107 SIEM-WEB", "108 SIEM-Transport"],
    "windows": ["101 win-test", "111 WIN-RTX-test"],
    "linux_common": ["all Linux VM/LXC"],
    "public_services": ["120 nextcloud-siem", "121 navidrome-01", "123 pilot-web-01", "126 openclaw-gateway", "130 gamepanel-01"],
    "game": ["100 minecraft-01", "130 gamepanel-01"],
    "vuln": ["122 vuln-mgr-01"],
    "pilot": ["123 pilot-web-01", "124 pilot-db-01", "125 pilot-cache-01"],
    "edge_gateway": ["102 lab-edge-01", "126 openclaw-gateway"],
    "devops": ["Gitea", "GitHub", "GitHub Runner", "CI/CD"],
    "identity": ["Keycloak", "SIEM IAM/SSO"],
}
ALL_ASSET_GROUP_NAMES = tuple(ASSET_GROUPS)
PREFIX_ASSET_GROUPS: dict[str, tuple[str, ...]] = {
    "ALERT": ("siem_core",),
    "AUTH": ("linux_common",),
    "BCK": ("proxmox", "siem_core", "public_services", "pilot", "vuln", "game"),
    "CH": ("siem_core",),
    "CORR": (),
    "DB": ("pilot", "siem_core"),
    "DCK": ("linux_common", "public_services", "pilot", "game", "vuln"),
    "DNS": ("edge_gateway",),
    "EDGE": ("edge_gateway",),
    "GAME": ("game",),
    "GW": ("edge_gateway", "public_services"),
    "HB": ALL_ASSET_GROUP_NAMES,
    "IAM": ("identity",),
    "IDS": ("edge_gateway", "public_services"),
    "ING": ("siem_core",),
    "KFK": ("siem_core",),
    "MC": ("game",),
    "MET": ALL_ASSET_GROUP_NAMES,
    "MONGO": ("siem_core",),
    "NAV": ("public_services",),
    "NC": ("public_services",),
    "PG": ("pilot", "siem_core"),
    "PILOT": ("pilot",),
    "PROC": ("siem_core",),
    "PVE": ("proxmox",),
    "STR": ("siem_core",),
    "SVC": ("linux_common", "siem_core"),
    "SYSLOG": ("siem_core", "linux_common", "edge_gateway"),
    "VAULT": ("identity", "siem_core"),
    "VULN": ("vuln",),
    "WEB": ("siem_core", "public_services"),
    "WIN": ("windows",),
    "WR": ("siem_core",),
}
ASSET_GROUP_MARKERS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("proxmox", ("pve", "proxmox", "pvedaemon", "pveproxy", "pveum", "qm", "pct", "vzdump")),
    ("siem_core", ("104", "105", "106", "107", "108", "siem", "ingest", "processing", "storage", "clickhouse", "kafka", "transport", "writer")),
    ("windows", ("101", "111", "windows", "win-test", "win-rtx", "eventid", "powershell", "defender", "rdp")),
    ("linux_common", ("linux", "lxc", "vm/lxc", "auth.log", "sshd", "sudo", "systemd", "rsyslog")),
    ("public_services", ("120", "121", "123", "126", "130", "nextcloud", "navidrome", "pilot-web", "openclaw", "gamepanel", "public service")),
    ("game", ("100", "130", "minecraft", "pterodactyl", "gamepanel", "game")),
    ("vuln", ("122", "vuln", "openvas", "greenbone", "scanner")),
    ("pilot", ("123", "124", "125", "pilot", "postgres", "redis", "valkey", "cache")),
    ("edge_gateway", ("102", "126", "edge", "gateway", "lab-edge", "opnsense", "openclaw", "suricata", "unbound", "frpc", "firewall")),
    ("devops", ("gitea", "github", "runner", "ci/cd", "cicd", "devops")),
    ("identity", ("keycloak", "iam", "sso", "identity", "mfa", "vault")),
)
BATCH_TERMS = (
    "last_seen",
    "first_seen",
    "baseline",
    "known_",
    "not in known",
    "admin_window",
    "sla",
    "overdue",
    "last_success",
    "planned_offline",
    "coverage",
    "inventory",
    "retention",
    "queue",
    "lag",
    "p95",
    "p99",
    "cpu_usage",
    "memory_usage",
    "disk_usage",
    "eps(",
    "alerts_per_min",
    "no alerts",
    "no events",
    "нет событий",
    "перестал поступать",
    "перестали поступать",
    "нет событий",
    "перестал поступать",
    "перестали поступать",
)
BLOCKED_HINTS = ("if collected", "if enabled", "metadata", "export", "api if collected")

PROVIDERS: dict[str, list[str]] = {
    "ALERT": ["linux.python", "linux.systemd"],
    "AUTH": ["linux.sshd", "linux.sudo", "linux.auditd", "linux.syslog"],
    "CH": ["linux.systemd", "linux.python"],
    "DB": ["linux.systemd", "linux.python"],
    "DCK": ["linux.docker", "linux.systemd"],
    "DNS": ["linux.unbound", "linux.suricata-eve"],
    "EDGE": ["linux.systemd", "linux.suricata-eve", "linux.unbound"],
    "GAME": ["linux.gamepanel-audit", "linux.gamepanel-auth", "linux.gamepanel-nginx-access"],
    "GW": ["linux.frpc", "linux.node", "linux.python"],
    "IAM": ["linux.python", "linux.systemd"],
    "IDS": ["linux.suricata-eve"],
    "ING": ["linux.systemd", "linux.rsyslogd", "linux.python"],
    "KFK": ["linux.systemd", "linux.python"],
    "MC": ["linux.suricata-eve", "linux.kernel", "linux.python"],
    "MONGO": ["linux.systemd", "linux.python"],
    "NAV": ["linux.python", "linux.systemd"],
    "NC": ["linux.python", "linux.systemd"],
    "PG": ["linux.systemd", "linux.python"],
    "PILOT": ["linux.systemd", "linux.pilot-gitea", "linux.python"],
    "PROC": ["linux.systemd", "linux.python"],
    "PVE": ["linux.pvedaemon", "linux.pveproxy", "linux.pvestatd", "linux.proxmox-heartbeat"],
    "STR": ["linux.systemd", "linux.python"],
    "SVC": ["linux.systemd", "linux.syslog"],
    "SYSLOG": ["linux.rsyslogd", "linux.syslog"],
    "VAULT": ["linux.python", "linux.systemd"],
    "VULN": ["linux.python", "linux.systemd"],
    "WEB": ["linux.systemd", "linux.python"],
    "WIN": ["windows.security", "windows.powershell", "windows.defender", "windows.wmi"],
    "WR": ["linux.python", "linux.systemd"],
}

STOPWORDS = {
    "and",
    "or",
    "then",
    "count",
    "same",
    "source",
    "status",
    "event",
    "events",
    "message",
    "contains",
    "changed",
    "change",
    "created",
    "deleted",
    "failed",
    "failure",
    "success",
    "error",
    "errors",
    "threshold",
    "baseline",
    "host",
    "hosts",
    "service",
    "services",
    "logs",
    "log",
    "app",
    "user",
    "users",
    "client",
    "critical",
    "agent",
    "via",
    "not",
    "in",
    "within",
    "for",
    "known",
    "normalization",
    "enabled",
    "engine",
    "correlation",
    "rsyslog",
    "syslog",
    "sshd",
    "sudo",
    "auth.log",
    "auth.log/sshd",
    "auth.log/sudo",
    "windows",
    "eventid",
    "admin_window",
    "known_admin_ips",
}


def _split_markdown_row(line: str) -> list[str]:
    return [cell.strip() for cell in line.strip().strip("|").split("|")]


def parse_assignment(path: Path) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    section = ""
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.startswith("### "):
            section = line[4:].strip()
            continue
        if not line.startswith("|") or set(line.strip()) <= set("|:- "):
            continue
        cells = _split_markdown_row(line)
        if not cells or cells[0] == "ID" or len(cells) < 7:
            continue
        rows.append(
            {
                "section": section,
                "source_id": cells[0],
                "title": cells[1],
                "scope": cells[2],
                "sources": cells[3],
                "logic": cells[4],
                "severity": cells[5].lower(),
                "response": cells[6],
            }
        )
    return rows


def _prefix(source_id: str) -> str:
    return source_id.split("-", 1)[0].upper()


def _ordered_groups(groups: set[str]) -> list[str]:
    return [group for group in ALL_ASSET_GROUP_NAMES if group in groups]


def _contains_asset_marker(haystack: str, marker: str) -> bool:
    if marker.isdigit():
        return re.search(rf"(?<!\d){re.escape(marker)}(?!\d)", haystack) is not None
    return marker in haystack


def _asset_groups(row: dict[str, str]) -> list[str]:
    prefix = _prefix(row["source_id"])
    groups: set[str] = set(PREFIX_ASSET_GROUPS.get(prefix, ()))
    haystack = " ".join(
        [
            row.get("section", ""),
            row.get("source_id", ""),
            row.get("title", ""),
            row.get("scope", ""),
            row.get("sources", ""),
            row.get("logic", ""),
        ]
    ).lower()
    for group, markers in ASSET_GROUP_MARKERS:
        if any(_contains_asset_marker(haystack, marker) for marker in markers):
            groups.add(group)
    if "все" in haystack or "all hosts" in haystack or "all vm" in haystack or "all linux" in haystack:
        groups.update(ALL_ASSET_GROUP_NAMES)
    if not groups:
        groups.add("linux_common")
    return _ordered_groups(groups)


def _asset_group_tags(groups: list[str]) -> list[str]:
    return [f"asset_group.{group}" for group in groups]


def _slug(value: str) -> str:
    slug = re.sub(r"[^a-zA-Z0-9]+", "-", value.lower()).strip("-")
    return slug or "rule"


def _display_title(row: dict[str, str]) -> str:
    source_id = row["source_id"]
    title = row["title"]
    return title if title.startswith(f"{source_id} ") else f"{source_id} {title}"


def _window_s(logic: str) -> int:
    lowered = logic.lower()
    matches = re.findall(r"(\d+)\s*([mh])", lowered)
    if not matches:
        return 300
    value, unit = matches[-1]
    seconds = int(value) * (3600 if unit == "h" else 60)
    return max(60, min(seconds, 86400))


def _threshold(logic: str) -> int:
    lowered = logic.lower()
    for pattern in (
        r"count\s*[>=]+\s*(\d+)",
        r"failed\s*[>=]+\s*(\d+)",
        r"failures\s*[>=]+\s*(\d+)",
        r"login_error\s*[>=]+\s*(\d+)",
        r"restart\s+count\s*[>=]+\s*(\d+)",
    ):
        found = re.search(pattern, lowered)
        if found:
            return max(1, min(int(found.group(1)), 500))
    return 1


def _entity_field(logic: str, source_id: str) -> str:
    lowered = logic.lower()
    if "by src_ip" in lowered or "same src_ip" in lowered or "client_ip" in lowered:
        return "source.ip"
    if "by user" in lowered or "same user" in lowered or "target_user" in lowered:
        return "user.name"
    if "rule_id" in lowered:
        return "rule.id"
    return "host.name"


def _extract_bracket_terms(logic: str) -> list[str]:
    terms: list[str] = []
    for group in re.findall(r"\[([^\]]+)\]", logic):
        for term in re.split(r",|\|", group):
            cleaned = term.strip().strip("'\"")
            if cleaned:
                terms.append(cleaned)
    return terms


def _extract_token_terms(text: str) -> list[str]:
    tokens = re.findall(r"[A-Za-z0-9_./:-]{3,}", text)
    terms: list[str] = []
    for token in tokens:
        lowered = token.lower().strip(".:-_/")
        if not lowered or lowered in STOPWORDS:
            continue
        if lowered.isdigit():
            continue
        terms.append(token.strip())
    return terms


def _event_code_selection(logic: str) -> list[str]:
    codes = re.findall(r"(?:EventID|event_id|event.code)\s*[=:\s]+\s*(\d{3,5})", logic, flags=re.IGNORECASE)
    for raw_group in re.findall(r"(?:EventID|event_id|event.code)\s+in\s+\[([^\]]+)\]", logic, flags=re.IGNORECASE):
        for value in re.findall(r"\d{3,5}", raw_group):
            codes.append(value)
    return sorted(set(codes), key=codes.index)


def _windows_event_type_selection(source_id: str, logic: str) -> list[str]:
    code_map = {
        "4624": "windows_logon_success",
        "4625": "windows_logon_failure",
        "4720": "windows_user_created",
        "4726": "windows_user_deleted",
        "4728": "windows_user_added_to_privileged_group",
        "4732": "windows_user_added_to_privileged_group",
        "4756": "windows_user_added_to_privileged_group",
        "7045": "windows_service_installed",
        "4698": "windows_scheduled_task_created",
        "106": "windows_scheduled_task_created",
        "1102": "windows_audit_log_cleared",
    }
    event_types = [code_map[code] for code in _event_code_selection(logic) if code in code_map]
    if source_id == "WIN-015":
        event_types.append("windows_powershell_encoded_command")
    return sorted(set(event_types), key=event_types.index)


def _windows_provider_selection(logic: str) -> list[str]:
    provider_by_code = {
        "106": "windows.taskscheduler",
    }
    providers = [provider_by_code.get(code, "windows.security") for code in _event_code_selection(logic)]
    lowered = logic.lower()
    if "powershell" in lowered or "-encodedcommand" in lowered or "-enc" in lowered:
        providers.append("windows.powershell")
    if "defender" in lowered or "mpreference" in lowered:
        providers.append("windows.defender")
    if "wmi" in lowered:
        providers.append("windows.wmi")
    return sorted(set(providers or ["windows.security"]), key=providers.index if providers else None)


def _provider_values(row: dict[str, str]) -> list[str]:
    prefix = _prefix(row["source_id"])
    if prefix == "WIN":
        return _windows_provider_selection(row["logic"])

    text = " ".join([row.get("source_id", ""), row.get("title", ""), row.get("sources", ""), row.get("logic", "")]).lower()
    if prefix == "AUTH":
        providers: list[str] = []
        if "sudo" in text or "command=" in text:
            providers.append("linux.sudo")
        if "ssh" in text or "accepted" in text or "failed" in text or "invalid" in text:
            providers.append("linux.sshd")
        if any(term in text for term in ("useradd", "usermod", "passwd", "shadow", "sudoers", "authorized_keys", "cron")):
            providers.append("linux.auditd")
        return sorted(set(providers or PROVIDERS["AUTH"]), key=(providers or PROVIDERS["AUTH"]).index)

    return PROVIDERS.get(prefix) or []


def _linux_event_type_selection(row: dict[str, str]) -> list[str]:
    source_id = row["source_id"]
    prefix = _prefix(source_id)
    if prefix != "AUTH":
        return []

    logic = row["logic"].lower()
    title = row["title"].lower()
    event_types: list[str] = []
    if source_id == "AUTH-001" or ("accepted" in logic and "root" in logic):
        event_types.extend(["linux_root_ssh_login", "ssh_login_success"])
    elif source_id in {"AUTH-002", "AUTH-003"} or "failed password" in logic:
        event_types.append("ssh_login_failure")
    elif "invalid" in logic:
        event_types.append("ssh_invalid_user")
    if "sudo" in logic or "sudo" in title or "command=" in logic:
        event_types.extend(["sudo_command", "sudo_event"])
    if "sudoers" in logic:
        event_types.append("linux_sudoers_modified")
    if "authorized_keys" in logic:
        event_types.append("linux_authorized_keys_modified")
    if "sshd_config" in logic:
        event_types.append("linux_sshd_config_modified")
    return sorted(set(event_types), key=event_types.index)


def _windows_selection(row: dict[str, str]) -> dict[str, Any]:
    logic = row["logic"]
    source_id = row["source_id"]
    selection: dict[str, Any] = {}
    providers = _windows_provider_selection(logic)
    if providers:
        selection["event.provider"] = providers if len(providers) > 1 else providers[0]
    event_codes = _event_code_selection(logic)
    if event_codes:
        selection["event.code"] = event_codes if len(event_codes) > 1 else event_codes[0]
    event_types = _windows_event_type_selection(source_id, logic)
    if event_types:
        selection["event.type"] = event_types if len(event_types) > 1 else event_types[0]
    if source_id in {"WIN-001", "WIN-002"}:
        selection["user.name"] = ["Administrator", "Администратор"]
    if source_id == "WIN-003":
        selection["auth.logon_type"] = "10"
    if source_id == "WIN-015":
        selection["process.command_line|contains"] = ["-enc", "-EncodedCommand"]
    return selection


def _stream_keywords(row: dict[str, str]) -> list[str]:
    logic = row["logic"]
    source_id = row["source_id"]
    terms = _extract_bracket_terms(logic)
    terms.extend(_extract_token_terms(logic))

    lowered = logic.lower()
    if _prefix(source_id) == "AUTH":
        title_lower = row["title"].lower()
        if "успеш" in title_lower:
            terms.extend(["Accepted", "ssh_login_success"])
        if "неуспеш" in title_lower:
            terms.extend(["Failed password", "ssh_login_failure"])
        if "accepted" in lowered or "успеш" in row["title"].lower():
            terms.extend(["Accepted", "ssh_login_success"])
        if "failed" in lowered or "неуспеш" in row["title"].lower():
            terms.extend(["Failed password", "ssh_login_failure"])
        if "invalid" in lowered:
            terms.extend(["Invalid user", "ssh_invalid_user"])
    if _prefix(source_id) == "SVC" or "unit=" in lowered or "systemd" in lowered:
        terms.extend(["stopped", "failed", "entered failed state"])
    if _prefix(source_id) == "IDS":
        terms.extend(["alert", "signature", "suricata"])
    if _prefix(source_id) == "WIN":
        terms.extend(_event_code_selection(logic))

    deduped: list[str] = []
    seen: set[str] = set()
    for term in terms:
        cleaned = term.strip().strip("'\"")
        if not cleaned or len(cleaned) < 3:
            continue
        key = cleaned.lower()
        if key in seen:
            continue
        seen.add(key)
        deduped.append(cleaned)
    return deduped[:10]


def _expr_value(value: str) -> str:
    return str(value or "").replace("\\", "\\\\").replace("'", "").strip()


def _expr_cmp(field: str, op: str, value: str) -> str:
    return f"{field} {op} '{_expr_value(value)}'"


def _expr_or(parts: list[str]) -> str:
    cleaned = [part for part in parts if part]
    if not cleaned:
        return ""
    return cleaned[0] if len(cleaned) == 1 else "(" + " or ".join(cleaned) + ")"


def _expr_and(parts: list[str]) -> str:
    cleaned = [part for part in parts if part]
    if not cleaned:
        return "event.original icontains 'assignment'"
    return cleaned[0] if len(cleaned) == 1 else "(" + " and ".join(cleaned) + ")"


def _stream_provider_expr(row: dict[str, str]) -> str:
    providers = _provider_values(row)
    return _expr_or([_expr_cmp("event.provider", "==", provider) for provider in providers])


def _stream_code_type_expr(row: dict[str, str]) -> str:
    codes = [_expr_cmp("event.code", "==", code) for code in _event_code_selection(row["logic"])]
    types: list[str] = _linux_event_type_selection(row)
    if _prefix(row["source_id"]) == "WIN":
        types = _windows_event_type_selection(row["source_id"], row["logic"])
    return _expr_or([*codes, *[_expr_cmp("event.type", "==", event_type) for event_type in types]])


def _stream_keyword_expr(row: dict[str, str]) -> str:
    terms = [
        term
        for term in _stream_keywords(row)
        if term.lower()
        not in {
            "logs",
            "log",
            "audit",
            "syslog",
            "events",
            "event",
            "status",
            "source",
            "host",
            "user",
            "count",
            "failed",
            "success",
            "critical",
            "agent",
            "via",
            "not",
            "within",
            "known",
            "normalization",
            "enabled",
            "engine",
            "correlation",
            "rsyslog",
            "syslog",
            "sshd",
            "sudo",
            "auth.log",
            "auth.log/sshd",
            "auth.log/sudo",
            "eventid",
            "windows",
            "admin_window",
            "known_admin_ips",
        }
    ]
    return _expr_or([_expr_cmp("event.original", "icontains", term) for term in terms[:8]])


def _stream_asset_scope_expr(groups: list[str]) -> str:
    host_terms: list[str] = []
    for group in groups:
        for host in ASSET_GROUPS.get(group, []):
            normalized = host.lower()
            if normalized == "all linux vm/lxc":
                continue
            for token in re.split(r"[\s,]+", normalized):
                token = token.strip()
                if not token or token.isdigit():
                    continue
                host_terms.append(token)
    deduped = sorted(set(host_terms))
    if not deduped:
        return ""
    return _expr_or(
        [
            _expr_or([_expr_cmp("host.name", "icontains", term), _expr_cmp("log_source", "icontains", term)])
            for term in deduped[:10]
        ]
    )


def _stream_fp_guard_expr(row: dict[str, str]) -> str:
    source_id = row["source_id"]
    prefix = _prefix(source_id)
    guards = ["not tags icontains 'allowlist:'"]
    if prefix in {"AUTH", "IDS", "DNS", "EDGE", "VULN"} or "src_ip" in row["logic"].lower():
        guards.extend(
            [
                "source.ip != '192.168.1.102'",
                "source.ip != '10.20.30.122'",
                "source.ip != '0'",
            ]
        )
    if prefix == "WIN":
        guards.append("not event.original icontains 'RdegonSIEMCollector'")
        guards.append("not event.original icontains 'collector-state.json'")
        if source_id in {"WIN-001", "WIN-003"}:
            guards.append("user.name != 'SYSTEM'")
            guards.append("not user.name icontains '$'")
    if prefix == "DCK":
        guards.append("not event.original icontains 'healthcheck'")
    return _expr_and(guards)


def _compiled_stream_expr(row: dict[str, str], groups: list[str]) -> str:
    source_id = row["source_id"]
    clauses = [_stream_provider_expr(row)]
    code_type = _stream_code_type_expr(row)
    keywords = _stream_keyword_expr(row)
    if code_type:
        clauses.append(code_type)
    if keywords and (not code_type or source_id in {"AUTH-008", "AUTH-009", "AUTH-010", "AUTH-011", "AUTH-012", "AUTH-013"}):
        clauses.append(keywords)
    if not code_type and not keywords:
        clauses.append(_expr_cmp("event.original", "icontains", source_id.split("-", 1)[0]))
    if source_id in {"WIN-001", "WIN-002"}:
        clauses.append(_expr_or([_expr_cmp("user.name", "icontains", "Administrator"), _expr_cmp("user.name", "icontains", "Администратор")]))
    if source_id in {"AUTH-001", "AUTH-002"}:
        clauses.append(_expr_cmp("user.name", "==", "root"))
    if source_id == "WIN-003":
        clauses.append(_expr_cmp("auth.logon_type", "==", "10"))
        clauses.append("source.ip != ''")
        clauses.append("source.ip != '192.168.1.102'")
    if source_id == "WIN-004":
        clauses.append(_expr_or([_expr_cmp("event.type", "==", "windows_rdp_auth_success"), _expr_cmp("auth.logon_type", "==", "10")]))
        clauses.append("source.ip != ''")
        clauses.append("source.ip != '192.168.1.102'")
    if source_id == "WIN-021":
        clauses.append(_expr_cmp("event.type", "==", "windows_logon_failure"))
    asset_scope = _stream_asset_scope_expr(groups)
    if asset_scope and _prefix(source_id) not in {"HB", "MET"}:
        clauses.append(asset_scope)
    clauses.append(_stream_fp_guard_expr(row))
    return _expr_and(clauses)


def _safe_stream_threshold(row: dict[str, str]) -> int:
    threshold = _threshold(row["logic"])
    source_id = row["source_id"]
    prefix = _prefix(source_id)
    if "count" in row["logic"].lower() or ">=" in row["logic"]:
        return max(threshold, 2)
    if prefix in {"WIN"} and source_id in {"WIN-005", "WIN-006", "WIN-007", "WIN-008", "WIN-011", "WIN-012", "WIN-013", "WIN-014", "WIN-019"}:
        return 1
    if prefix in {"PVE", "IAM", "VAULT"} and row["severity"] in {"critical", "high"}:
        return 1
    if prefix in {"AUTH", "IDS", "DNS", "EDGE", "GW"}:
        return max(threshold, 3)
    return max(threshold, 2)


def _sql_quote(value: str) -> str:
    return "'" + str(value or "").replace("'", "''") + "'"


def _sql_keyword_predicate(row: dict[str, str]) -> str:
    if row["source_id"] == "EDGE-005":
        last_seen = (
            "(positionCaseInsensitiveUTF8(toString(message), 'last_seen') > 0 "
            "OR positionCaseInsensitiveUTF8(toString(normalized_json), 'last_seen') > 0)"
        )
        stale_signal = (
            "(positionCaseInsensitiveUTF8(toString(message), '10m') > 0 "
            "OR positionCaseInsensitiveUTF8(toString(normalized_json), '10m') > 0 "
            "OR positionCaseInsensitiveUTF8(toString(message), 'stale') > 0 "
            "OR positionCaseInsensitiveUTF8(toString(normalized_json), 'stale') > 0 "
            "OR positionCaseInsensitiveUTF8(toString(message), 'no logs') > 0 "
            "OR positionCaseInsensitiveUTF8(toString(normalized_json), 'no logs') > 0)"
        )
        return f"({last_seen} AND {stale_signal})"

    terms = _stream_keywords(row)[:8]
    predicates = [
        f"(positionCaseInsensitiveUTF8(toString(message), {_sql_quote(term)}) > 0 OR positionCaseInsensitiveUTF8(toString(normalized_json), {_sql_quote(term)}) > 0)"
        for term in terms
        if term and len(term) >= 3
    ]
    codes = [f"event_code = {_sql_quote(code)}" for code in _event_code_selection(row["logic"])]
    predicates.extend(codes)
    if not predicates:
        predicates.append(f"positionCaseInsensitiveUTF8(toString(message), {_sql_quote(row['source_id'].split('-', 1)[0])}) > 0")
    return "(" + " OR ".join(predicates) + ")"


def _sql_asset_scope(groups: list[str]) -> str:
    terms: list[str] = []
    for group in groups:
        for host in ASSET_GROUPS.get(group, []):
            if host == "all Linux VM/LXC":
                continue
            parts = [part for part in re.split(r"[\s,]+", host.lower()) if part and not part.isdigit()]
            terms.extend(parts)
    terms = sorted(set(terms))
    if not terms:
        return "1"
    source_expr = "lowerUTF8(if(host_name != '' AND host_name != '-', host_name, log_source))"
    return "(" + " OR ".join(f"positionCaseInsensitiveUTF8({source_expr}, {_sql_quote(term)}) > 0" for term in terms[:12]) + ")"


def _sql_provider_predicate(row: dict[str, str]) -> str:
    providers = _provider_values(row)
    if not providers:
        return "1"
    return "(" + " OR ".join(
        f"device_product = {_sql_quote(provider)} OR positionCaseInsensitiveUTF8(toString(log_source), {_sql_quote(provider)}) > 0"
        for provider in providers
    ) + ")"


def _referenced_source_ids(row: dict[str, str], source_id_to_rule_id: dict[str, int]) -> list[str]:
    refs: list[str] = []
    text = " ".join([row.get("logic", ""), row.get("sources", ""), row.get("response", "")]).upper()
    for match in re.finditer(r"\b([A-Z]{2,8})-(\d{3})(?:/(\d{3}))?\b", text):
        prefix, first, second = match.groups()
        for number in (first, second):
            if not number:
                continue
            source_id = f"{prefix}-{number}"
            if source_id != row["source_id"] and source_id in source_id_to_rule_id:
                refs.append(source_id)
    deduped: list[str] = []
    seen: set[str] = set()
    for source_id in refs:
        if source_id in seen:
            continue
        seen.add(source_id)
        deduped.append(source_id)
    return deduped


def _generic_correlation_sql_template(row: dict[str, str], source_id_to_rule_id: dict[str, int]) -> str:
    rule_id = RULE_ID_BASE + int(row.get("_index", "0"))
    title = _display_title(row).replace("'", "''")
    severity = row["severity"].lower()
    refs = _referenced_source_ids(row, source_id_to_rule_id)
    ref_ids = [source_id_to_rule_id[source_id] for source_id in refs]
    if not ref_ids:
        return ""
    required = len(ref_ids) if " then " in f" {row['logic'].lower()} " else max(1, min(len(ref_ids), _threshold(row["logic"])))
    ids_csv = ", ".join(str(rule_id) for rule_id in ref_ids)
    dedupe_window_s = max(int(row.get("_dedupe_window_s") or row.get("_override_window_s") or _window_s(row["logic"])), 60)
    return f"""
INSERT INTO siem.alerts_raw
(ts, alert_id, rule_id, rule_name, severity, ts_first, ts_last, window_s, entity_key, hits, context_json, source, status)
SELECT
    now(),
    generateUUIDv4(),
    {rule_id},
    '{title}',
    '{severity}',
    candidate.corr_ts_first,
    candidate.corr_ts_last,
    {{WINDOW_S}},
    candidate.corr_entity_key,
    candidate.hits,
    candidate.context_json,
    candidate.correlation_source,
    'open'
FROM
(
    SELECT
        if(child.entity_key != '' AND child.entity_key != '-', child.entity_key, child.source) AS corr_entity_key,
        concat('assignment-correlation:', if(child.entity_key != '' AND child.entity_key != '-', child.entity_key, child.source)) AS correlation_source,
        min(child.ts_first) AS corr_ts_first,
        max(child.ts_last) AS corr_ts_last,
        count() AS hits,
        concat(
            '{{"event_type":"assignment_correlation_rule","source_id":"{row["source_id"]}","required":{required},"child_rule_ids":[',
            arrayStringConcat(arrayMap(x -> toString(x), groupUniqArray(child.rule_id)), ','),
            ']}}'
        ) AS context_json,
        uniqExact(child.rule_id) AS matched_rules
    FROM siem.alerts_raw AS child
    WHERE child.ts_last >= now() - INTERVAL {{WINDOW_S}} SECOND
      AND child.rule_id IN ({ids_csv})
      AND lower(child.status) NOT IN ('closed', 'false_positive', 'resolved', 'suppressed')
    GROUP BY corr_entity_key, correlation_source
    HAVING matched_rules >= {required}
) AS candidate
LEFT JOIN
(
    SELECT entity_key
    FROM siem.alerts_raw
    WHERE rule_id = {rule_id}
      AND ts >= now() - INTERVAL {dedupe_window_s} SECOND
      AND lower(status) NOT IN ('closed', 'false_positive', 'resolved', 'suppressed')
    GROUP BY entity_key
) AS existing
ON candidate.corr_entity_key = existing.entity_key
WHERE existing.entity_key = ''
"""


def _normalize_existing_alert_dedupe_guard(sql_template: str) -> str:
    sql = str(sql_template or "")
    existing_end = sql.rfind(") AS existing")
    if existing_end < 0:
        return sql
    existing_start = sql.rfind("LEFT JOIN", 0, existing_end)
    if existing_start < 0:
        return sql
    existing_block = sql[existing_start:existing_end]
    existing_block = re.sub(r"(\bAND\s+)ts_last(\s+>=\s+now\(\)\s+-\s+INTERVAL\b)", r"\1ts\2", existing_block)
    return sql[:existing_start] + existing_block + sql[existing_end:]


def _generic_batch_sql_template(
    row: dict[str, str],
    groups: list[str],
    *,
    status: str,
    source_id_to_rule_id: dict[str, int] | None = None,
) -> str:
    curated_sql = curated_batch_sql(row)
    if curated_sql:
        return curated_sql
    if status == "active_correlation":
        correlation_sql = _generic_correlation_sql_template(row, source_id_to_rule_id or {})
        if correlation_sql:
            return correlation_sql
    rule_id = RULE_ID_BASE + int(row.get("_index", "0"))
    title = _display_title(row).replace("'", "''")
    severity = row["severity"].lower()
    window_s = _window_s(row["logic"])
    threshold = max(int(row.get("_override_threshold") or _threshold(row["logic"])), 1)
    dedupe_window_s = max(int(row.get("_dedupe_window_s") or row.get("_override_window_s") or window_s), window_s, 60)
    source_expr = "if(host_name != '' AND host_name != '-', host_name, log_source)"
    predicate = _sql_keyword_predicate(row)
    provider_predicate = _sql_provider_predicate(row)
    scope = _sql_asset_scope(groups)
    if status == "active_correlation" and " then " in f" {row['logic'].lower()} ":
        threshold = max(threshold, 5)
    return f"""
INSERT INTO siem.alerts_raw
(ts, alert_id, rule_id, rule_name, severity, ts_first, ts_last, window_s, entity_key, hits, context_json, source, status)
SELECT
    now(),
    generateUUIDv4(),
    {rule_id},
    '{title}',
    '{severity}',
    candidate.ts_first,
    candidate.ts_last,
    {{WINDOW_S}},
    candidate.entity_key,
    candidate.hits,
    candidate.context_json,
    candidate.source,
    'open'
FROM
(
    SELECT
        {source_expr} AS entity_key,
        {source_expr} AS source,
        min(ts) AS ts_first,
        max(ts) AS ts_last,
        count() AS hits,
        concat(
            '{{"event_type":"assignment_batch_rule","source_id":"{row["source_id"]}","source":"',
            {source_expr},
            '","hits":', toString(count()), '}}'
        ) AS context_json
    FROM siem.events
    WHERE ts >= now() - INTERVAL {{WINDOW_S}} SECOND
      AND positionCaseInsensitiveUTF8(toString(tags), 'allowlist:') = 0
      AND ({provider_predicate})
      AND ({scope})
      AND ({predicate})
    GROUP BY entity_key
    HAVING hits >= {threshold}
) AS candidate
LEFT JOIN
(
    SELECT entity_key
    FROM siem.alerts_raw
    WHERE rule_id = {rule_id}
      AND ts >= now() - INTERVAL {dedupe_window_s} SECOND
      AND lower(status) NOT IN ('closed', 'false_positive', 'resolved', 'suppressed')
    GROUP BY entity_key
) AS existing
ON candidate.entity_key = existing.entity_key
WHERE existing.entity_key = ''
"""


def _safe_batch_threshold(row: dict[str, str], *, status: str, override: dict[str, Any]) -> int:
    threshold = max(int(override.get("threshold") or _threshold(row["logic"])), 1)
    if status == "active_correlation" and " then " in f" {row['logic'].lower()} ":
        threshold = max(threshold, 5)
    return threshold


def _is_batch_rule(row: dict[str, str]) -> tuple[bool, str]:
    prefix = _prefix(row["source_id"])
    logic = row["logic"].lower()
    sources = row["sources"].lower()
    if prefix == "CORR":
        return True, "requires_correlation_engine"
    if prefix in BATCH_PREFIXES:
        return True, "requires_batch_engine"
    if " then " in f" {logic} ":
        return True, "requires_correlation_engine"
    if any(term in logic for term in BATCH_TERMS):
        return True, "requires_batch_engine"
    if any(term in sources for term in BLOCKED_HINTS):
        return True, "blocked_by_telemetry"
    if prefix not in SAFE_STREAM_PREFIXES:
        return True, "requires_stream_tuning"
    return False, "active"


def _logsource(prefix: str) -> dict[str, str]:
    if prefix == "WIN":
        return {"product": "windows", "service": "security"}
    if prefix in {"IDS", "DNS", "EDGE"}:
        return {"product": "network", "service": "suricata-unbound"}
    if prefix in {"PG", "MONGO", "DB", "CH"}:
        return {"product": "database", "service": prefix.lower()}
    if prefix in {"PVE", "SVC", "AUTH", "DCK", "ING", "KFK", "STR", "WEB"}:
        return {"product": "linux", "service": prefix.lower()}
    return {"product": "siem", "service": prefix.lower()}


def _sigma_yaml(row: dict[str, str]) -> str:
    prefix = _prefix(row["source_id"])
    selection: dict[str, Any] = {}
    if prefix == "WIN":
        selection.update(_windows_selection(row))
    else:
        providers = PROVIDERS.get(prefix) or []
        if providers:
            selection["event.provider"] = providers if len(providers) > 1 else providers[0]
        event_codes = _event_code_selection(row["logic"])
        if event_codes:
            selection["event.code"] = event_codes if len(event_codes) > 1 else event_codes[0]
        keywords = _stream_keywords(row)
        if keywords:
            selection["keywords"] = keywords
    if not selection:
        selection["keywords"] = [row["source_id"]]

    document = {
        "title": _display_title(row),
        "id": f"assignment-{row['source_id'].lower()}",
        "status": "experimental",
        "description": f"Scope: {row['scope']}. Sources: {row['sources']}. Detection logic: {row['logic']}.",
        "logsource": _logsource(prefix),
        "detection": {"selection": selection, "condition": "selection"},
        "level": row["severity"],
        "tags": [
            "assignment.siem_detection_pack_v1",
            f"assignment.source_id.{row['source_id'].lower()}",
            f"assignment.prefix.{prefix.lower()}",
            *_asset_group_tags(list(row.get("asset_groups") or [])),
        ],
    }
    return yaml.safe_dump(document, allow_unicode=True, sort_keys=False)


def _override_stream_expr(override: dict[str, Any]) -> str:
    for key in STREAM_EXPR_OVERRIDE_KEYS:
        value = override.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


def _override_allows_generated_sigma(override: dict[str, Any]) -> bool:
    return any(bool(override.get(key)) for key in GENERATED_SIGMA_PUBLISH_KEYS)


def _sigma_uses_keywords(sigma_yaml: str) -> bool:
    try:
        document = yaml.safe_load(sigma_yaml) or {}
    except yaml.YAMLError:
        return True
    if not isinstance(document, dict):
        return True
    detection = document.get("detection") or {}
    if not isinstance(detection, dict):
        return True
    for key, value in detection.items():
        if key == "condition":
            continue
        if isinstance(value, dict) and "keywords" in value:
            return True
    return False


def _structured_stream_ready(row: dict[str, str], sigma_yaml: str) -> bool:
    if _prefix(row["source_id"]) not in STRUCTURED_STREAM_PREFIXES:
        return False
    return not _sigma_uses_keywords(sigma_yaml)


def build_pack(
    rows: list[dict[str, str]],
    *,
    active_source_ids: set[str] | None = None,
    active_overrides: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    active_source_ids = active_source_ids or set()
    active_overrides = active_overrides or {}
    source_id_to_rule_id = {row["source_id"]: RULE_ID_BASE + index for index, row in enumerate(rows, start=1)}
    stream_rules: list[dict[str, Any]] = []
    batch_rules: list[dict[str, Any]] = []
    for index, row in enumerate(rows, start=1):
        rule_id = RULE_ID_BASE + index
        is_batch, status = _is_batch_rule(row)
        source_id = row["source_id"]
        asset_groups = _asset_groups(row)
        rule_row = {**row, "id": rule_id, "asset_groups": asset_groups, "_index": str(index)}
        override = active_overrides.get(source_id) or {}
        override_expr = _override_stream_expr(override)
        if override.get("threshold") is not None:
            rule_row["_override_threshold"] = str(int(override.get("threshold") or 1))
        if override.get("window_s") is not None:
            rule_row["_override_window_s"] = str(int(override.get("window_s") or 300))
        if override.get("dedupe_window_s") is not None:
            rule_row["_dedupe_window_s"] = str(int(override.get("dedupe_window_s") or 300))
        if override.get("legacy_event_offset_cutoffs"):
            rule_row["legacy_event_offset_cutoffs"] = dict(
                override["legacy_event_offset_cutoffs"]
            )
        sigma_yaml = ""
        if status == "requires_stream_tuning":
            if override_expr:
                is_batch = False
                status = "active"
            elif source_id in active_source_ids and _override_allows_generated_sigma(override):
                sigma_yaml = _sigma_yaml(rule_row)
                if _structured_stream_ready(rule_row, sigma_yaml):
                    is_batch = False
                    status = "active"
            else:
                override_expr = _compiled_stream_expr(rule_row, asset_groups)
                is_batch = False
                status = "active"
        elif status == "blocked_by_telemetry":
            override_expr = override_expr or _compiled_stream_expr(rule_row, asset_groups)
            is_batch = False
            status = "active"
        elif status == "requires_batch_engine":
            status = "active_batch"
        elif status == "requires_correlation_engine":
            status = "active_correlation"
        common = {
            "id": rule_id,
            "source_id": source_id,
            "title": _display_title(row),
            "severity": row["severity"],
            "status": status,
            "asset_groups": asset_groups,
            "scope": row["scope"],
            "sources": row["sources"],
            "detection_logic": row["logic"],
            "operator_action": row["response"],
            "description": f"{row['source_id']}: {row['logic']} Источники: {row['sources']}.",
        }
        if override.get("legacy_event_offset_cutoffs"):
            common["legacy_event_offset_cutoffs"] = dict(
                override["legacy_event_offset_cutoffs"]
            )
        if is_batch:
            if status in {"active_batch", "active_correlation"}:
                common["window_s"] = int(override.get("window_s") or _window_s(row["logic"]))
                common["threshold"] = _safe_batch_threshold(rule_row, status=status, override=override)
                curated_sql = curated_batch_sql(rule_row)
                common["sql_template"] = _normalize_existing_alert_dedupe_guard(
                    str(
                        curated_sql
                        or override.get("sql_template")
                        or _generic_batch_sql_template(
                            rule_row,
                            asset_groups,
                            status=status,
                            source_id_to_rule_id=source_id_to_rule_id,
                        )
                    ).strip()
                )
                if override.get("trusted_admin_ips"):
                    common["trusted_admin_ips"] = list(override["trusted_admin_ips"])
            batch_rules.append(common)
            continue
        stream_rule = {
            **common,
            "window_s": int(override.get("window_s") or _window_s(row["logic"])),
            "threshold": int(override.get("threshold") or _safe_stream_threshold(rule_row)),
            "entity_field": _entity_field(row["logic"], row["source_id"]),
            "suppression_key": "host.name + source.ip + assignment.siem_detection_pack_v1",
        }
        if override_expr:
            stream_rule["source_format"] = "stream-expr"
            stream_rule["expr"] = override_expr
        else:
            stream_rule["source_format"] = "sigma"
            stream_rule["sigma_yaml"] = sigma_yaml or _sigma_yaml(rule_row)
        stream_rules.append(stream_rule)
    return {
        "pack_id": PACK_ID,
        "title": "SIEM asset-grouped detection pack",
        "version": "1.0.0",
        "status": "active",
        "owner": "diploma-siem",
        "asset_groups": ASSET_GROUPS,
        "notes": [
            "Generated from the asset-grouped SIEM detection catalog markdown.",
            "Each rule is mapped to one or more asset_groups and published with asset_group.* tags.",
            "Stream-capable catalog rows are compiled into normalized stream expressions with allowlist and source-scope guards.",
            "Batch and sequence-style catalog rows are compiled into guarded SQL templates for the batch correlation runtime.",
            "active_source_ids remain review metadata; runtime activation is driven by compiled expr/sql_template output.",
            "Every active runtime rule must pass synthetic validation before being kept in production.",
        ],
        "stream_rules": stream_rules,
        "batch_rules": batch_rules,
    }


def write_report(pack: dict[str, Any], path: Path) -> None:
    status_counts: dict[str, int] = {}
    prefix_counts: dict[str, int] = {}
    asset_group_counts: dict[str, int] = {}
    for group in ("stream_rules", "batch_rules"):
        for rule in pack[group]:
            status_counts[rule["status"]] = status_counts.get(rule["status"], 0) + 1
            source_id = str(rule.get("source_id") or "")
            prefix_counts[_prefix(source_id)] = prefix_counts.get(_prefix(source_id), 0) + 1
            for asset_group in list(rule.get("asset_groups") or []):
                asset_group_counts[str(asset_group)] = asset_group_counts.get(str(asset_group), 0) + 1
    lines = [
        "# SIEM detection pack generation report",
        "",
        f"- Pack: `{pack['pack_id']}`",
        f"- Total rules: {len(pack['stream_rules']) + len(pack['batch_rules'])}",
        f"- Active stream rules: {len(pack['stream_rules'])}",
        f"- Batch/correlation SQL rules: {len(pack['batch_rules'])}",
        "",
        "## Status counts",
        "",
    ]
    for status, count in sorted(status_counts.items()):
        lines.append(f"- `{status}`: {count}")
    lines.extend(["", "## Prefix counts", ""])
    for prefix, count in sorted(prefix_counts.items()):
        lines.append(f"- `{prefix}`: {count}")
    lines.extend(["", "## Asset group counts", ""])
    for asset_group, count in sorted(asset_group_counts.items()):
        hosts = ", ".join(list((pack.get("asset_groups") or {}).get(asset_group) or []))
        lines.append(f"- `{asset_group}`: {count} rules; hosts: {hosts}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def _load_active_source_ids(path: Path) -> set[str]:
    if not path.exists():
        return set()
    return {
        line.strip()
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    }


def _load_active_overrides(path: Path) -> dict[str, dict[str, Any]]:
    if not path.exists():
        return {}
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        return {}
    return {
        str(key): dict(value)
        for key, value in payload.items()
        if isinstance(value, dict)
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("assignment", type=Path)
    parser.add_argument("--output", type=Path, default=PACK_PATH)
    parser.add_argument("--report", type=Path, default=REPORT_PATH)
    parser.add_argument("--active-source-ids", type=Path, default=ACTIVE_SOURCE_IDS_PATH)
    parser.add_argument("--active-overrides", type=Path, default=ACTIVE_OVERRIDES_PATH)
    args = parser.parse_args()

    rows = parse_assignment(args.assignment)
    if not rows:
        raise SystemExit(f"No rule rows found in {args.assignment}")
    source_ids = [row["source_id"] for row in rows]
    duplicates = sorted({source_id for source_id in source_ids if source_ids.count(source_id) > 1})
    if duplicates:
        raise SystemExit(f"Duplicate source IDs: {duplicates}")

    active_source_ids = _load_active_source_ids(args.active_source_ids)
    active_overrides = _load_active_overrides(args.active_overrides)
    pack = build_pack(rows, active_source_ids=active_source_ids, active_overrides=active_overrides)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(pack, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    write_report(pack, args.report)
    print(
        json.dumps(
            {
                "output": str(args.output),
                "report": str(args.report),
                "total_rules": len(rows),
                "stream_rules": len(pack["stream_rules"]),
                "batch_rules": len(pack["batch_rules"]),
                "active_source_ids": len(active_source_ids),
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
