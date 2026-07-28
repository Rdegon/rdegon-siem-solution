from __future__ import annotations

import argparse
import json
import os
import re
from dataclasses import dataclass
from typing import Any

import requests
import urllib3


DEFAULT_HOST = "https://192.168.3.103"


@dataclass(frozen=True)
class Alias:
    name: str
    kind: str
    content: str
    description: str


@dataclass(frozen=True)
class Rule:
    interface: str
    sequence: int
    description: str
    source: str
    destination: str
    protocol: str = "any"
    destination_port: str = ""
    destination_not: bool = False


ALIASES = (
    Alias(
        "SOC_INTERNAL_NETS",
        "network",
        "10.20.10.0/24\n10.20.20.0/24\n10.20.30.0/24\n10.20.40.0/24",
        "All routed SOC zones",
    ),
    Alias(
        "SOC_MANAGEMENT_SOURCES",
        "network",
        "192.168.3.81/32\n192.168.3.101/32\n10.10.10.0/24",
        "Operator workstation, Proxmox VPN transit and management VPN",
    ),
    Alias(
        "SOC_EDGE_TRANSIT",
        "host",
        "192.168.3.102",
        "Production reverse proxy and VPN edge",
    ),
    Alias(
        "SIEM_CORE_HOSTS",
        "host",
        "\n".join(
            (
                *(f"10.20.10.{host}" for host in range(104, 109)),
                "10.20.10.127",
                "10.20.10.128",
                "10.20.10.131",
                "10.20.10.132",
                "10.20.10.133",
            )
        ),
        "SIEM core, NDR, DFIR, threat intel, PKI and evidence services",
    ),
    Alias(
        "SOC_LAB_SCANNERS",
        "host",
        "10.20.30.122\n10.20.30.129",
        "Greenbone and static-analysis scanners",
    ),
    Alias(
        "SOC_USER_SERVICES",
        "host",
        "\n".join(
            (
                "10.20.20.100",
                "10.20.20.120",
                "10.20.20.121",
                "10.20.20.130",
                "10.20.30.123",
                "10.20.10.128",
                "10.20.10.131",
                "10.20.10.133",
            )
        ),
        "Services intentionally reachable by users and operators",
    ),
    Alias(
        "SOC_DNS_NTP_PORTS",
        "port",
        "53\n123",
        "DNS and NTP",
    ),
)


RULES = (
    Rule(
        "opt1",
        10,
        "SOC WAN management and VPN to internal zones",
        "SOC_MANAGEMENT_SOURCES",
        "SOC_INTERNAL_NETS",
    ),
    Rule(
        "opt1",
        20,
        "SOC production edge to published internal services",
        "SOC_EDGE_TRANSIT",
        "SOC_INTERNAL_NETS",
    ),
    Rule(
        "opt2",
        10,
        "SOC sec zone trusted infrastructure routing",
        "opt2",
        "any",
    ),
    Rule(
        "opt3",
        10,
        "SOC servers DNS and NTP to firewall",
        "opt3",
        "(self)",
        "TCP/UDP",
        "SOC_DNS_NTP_PORTS",
    ),
    Rule(
        "opt3",
        20,
        "SOC servers telemetry to SIEM core",
        "opt3",
        "SIEM_CORE_HOSTS",
    ),
    Rule(
        "opt3",
        30,
        "SOC servers outbound Internet",
        "opt3",
        "SOC_INTERNAL_NETS",
        destination_not=True,
    ),
    Rule(
        "opt4",
        10,
        "SOC lab scanners to all targets",
        "SOC_LAB_SCANNERS",
        "any",
    ),
    Rule(
        "opt4",
        15,
        "SOC lab DNS and NTP to firewall",
        "opt4",
        "(self)",
        "TCP/UDP",
        "SOC_DNS_NTP_PORTS",
    ),
    Rule(
        "opt4",
        20,
        "SOC lab telemetry to SIEM core",
        "opt4",
        "SIEM_CORE_HOSTS",
    ),
    Rule(
        "opt4",
        30,
        "SOC lab outbound Internet",
        "opt4",
        "SOC_INTERNAL_NETS",
        destination_not=True,
    ),
    Rule(
        "opt5",
        10,
        "SOC users DNS and NTP to firewall",
        "opt5",
        "(self)",
        "TCP/UDP",
        "SOC_DNS_NTP_PORTS",
    ),
    Rule(
        "opt5",
        20,
        "SOC users access to SIEM core",
        "opt5",
        "SIEM_CORE_HOSTS",
    ),
    Rule(
        "opt5",
        30,
        "SOC users access to approved services",
        "opt5",
        "SOC_USER_SERVICES",
    ),
    Rule(
        "opt5",
        40,
        "SOC users outbound Internet",
        "opt5",
        "SOC_INTERNAL_NETS",
        destination_not=True,
    ),
)

SOURCE_NAT_DESCRIPTION = "SOC internal zones outbound via WAN"


class OPNsense:
    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        *,
        verify_tls: bool,
    ) -> None:
        normalized_host = host.strip()
        if "://" not in normalized_host:
            normalized_host = f"https://{normalized_host}"
        self.host = normalized_host.rstrip("/")
        self.username = username
        self.password = password
        self.verify_tls = verify_tls
        self.session = requests.Session()
        self.csrf_name = ""
        self.csrf_token = ""

    def login(self) -> None:
        if not self.verify_tls:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        response = self.session.get(self.host + "/", verify=self.verify_tls, timeout=15)
        response.raise_for_status()
        match = re.search(
            r'<input type="hidden" name="([^"]+)" value="([^"]+)"',
            response.text,
        )
        if not match:
            raise RuntimeError("OPNsense login form did not contain a CSRF token")
        self.csrf_name, self.csrf_token = match.groups()
        response = self.session.post(
            self.host + "/",
            data={
                self.csrf_name: self.csrf_token,
                "usernamefld": self.username,
                "passwordfld": self.password,
                "login": "1",
            },
            verify=self.verify_tls,
            timeout=20,
        )
        response.raise_for_status()
        if "Logout" not in response.text and "/ui/" not in response.url:
            raise RuntimeError("OPNsense authentication failed")

    def get(self, path: str) -> dict[str, Any]:
        response = self.session.get(
            self.host + path,
            verify=self.verify_tls,
            timeout=20,
        )
        response.raise_for_status()
        return response.json()

    def post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        response = self.session.post(
            self.host + path,
            headers={
                "X-CSRFToken": self.csrf_token,
                "Content-Type": "application/json",
            },
            json=payload,
            verify=self.verify_tls,
            timeout=30,
        )
        response.raise_for_status()
        result = response.json()
        if result.get("result") == "failed":
            raise RuntimeError(f"OPNsense rejected {path}: {result}")
        return result


def _alias_payload(alias: Alias) -> dict[str, Any]:
    return {
        "alias": {
            "enabled": "1",
            "name": alias.name,
            "type": alias.kind,
            "proto": "IPv4",
            "interface": "",
            "content": alias.content,
            "description": alias.description,
        }
    }


def _rule_payload(rule: Rule) -> dict[str, Any]:
    return {
        "rule": {
            "enabled": "1",
            "statetype": "keep",
            "state-policy": "",
            "sequence": str(rule.sequence),
            "action": "pass",
            "quick": "1",
            "interfacenot": "0",
            "interface": rule.interface,
            "direction": "in",
            "ipprotocol": "inet",
            "protocol": rule.protocol,
            "icmptype": "",
            "source_net": rule.source,
            "source_not": "0",
            "source_port": "",
            "destination_net": rule.destination,
            "destination_not": "1" if rule.destination_not else "0",
            "destination_port": rule.destination_port,
            "gateway": "",
            "replyto": "",
            "disablereplyto": "1",
            "log": "0",
            "allowopts": "0",
            "nosync": "0",
            "nopfsync": "0",
            "description": rule.description,
        }
    }


def _source_nat_payload() -> dict[str, Any]:
    return {
        "rule": {
            "enabled": "1",
            "nonat": "0",
            "nosync": "0",
            "sequence": "10",
            "interface": "opt1",
            "ipprotocol": "inet",
            "protocol": "any",
            "source_net": "SOC_INTERNAL_NETS",
            "source_not": "0",
            "destination_net": "any",
            "destination_not": "0",
            "log": "0",
            "description": SOURCE_NAT_DESCRIPTION,
        }
    }


def reconcile(client: OPNsense, *, apply: bool) -> dict[str, Any]:
    aliases = {
        row["name"]: row
        for row in client.get("/api/firewall/alias/search_item").get("rows", [])
        if row.get("name")
    }
    rules = {
        row["description"]: row
        for row in client.get("/api/firewall/filter/search_rule").get("rows", [])
        if row.get("description")
    }
    source_nat_settings = client.get("/api/firewall/source_nat/get")
    source_nat_mode = next(
        (
            name
            for name, value in source_nat_settings["filter"]["general"][
                "snat_mode"
            ].items()
            if value.get("selected") == 1
        ),
        "unknown",
    )
    source_nat_rules = client.get("/api/firewall/source_nat/search_rule").get(
        "rows", []
    )
    source_nat_present = any(
        row.get("description") == SOURCE_NAT_DESCRIPTION for row in source_nat_rules
    )
    pending_aliases = [alias for alias in ALIASES if alias.name not in aliases]
    changed_aliases = [
        alias
        for alias in ALIASES
        if alias.name in aliases
        and (
            aliases[alias.name].get("type") != alias.kind
            or aliases[alias.name].get("content", "").splitlines()
            != alias.content.splitlines()
            or aliases[alias.name].get("description") != alias.description
        )
    ]
    pending_rules = [rule for rule in RULES if rule.description not in rules]
    desired_rule_payloads = {
        rule.description: _rule_payload(rule)["rule"] for rule in RULES
    }
    changed_rules = [
        rule
        for rule in RULES
        if rule.description in rules
        and any(
            str(rules[rule.description].get(key, "")) != str(value)
            for key, value in desired_rule_payloads[rule.description].items()
            if key
            in {
                "enabled",
                "sequence",
                "action",
                "interface",
                "direction",
                "ipprotocol",
                "protocol",
                "source_net",
                "source_not",
                "destination_net",
                "destination_not",
                "destination_port",
                "log",
            }
        )
    ]
    desired_source_nat = _source_nat_payload()["rule"]
    changed_source_nat = next(
        (
            row
            for row in source_nat_rules
            if row.get("description") == SOURCE_NAT_DESCRIPTION
            and any(
                str(row.get(key, "")) != str(value)
                for key, value in desired_source_nat.items()
            )
        ),
        None,
    )
    result: dict[str, Any] = {
        "mode": "apply" if apply else "plan",
        "aliases_present": len(ALIASES) - len(pending_aliases),
        "aliases_pending": [alias.name for alias in pending_aliases],
        "aliases_changed": [alias.name for alias in changed_aliases],
        "rules_present": len(RULES) - len(pending_rules),
        "rules_pending": [rule.description for rule in pending_rules],
        "rules_changed": [rule.description for rule in changed_rules],
        "source_nat_mode": source_nat_mode,
        "source_nat_pending": not source_nat_present,
        "source_nat_changed": bool(changed_source_nat),
        "ids": client.get("/api/ids/service/status").get("status"),
        "unbound": client.get("/api/unbound/service/status").get("status"),
    }
    if not apply:
        return result

    for alias in pending_aliases:
        client.post("/api/firewall/alias/add_item/", _alias_payload(alias))
    for alias in changed_aliases:
        client.post(
            f"/api/firewall/alias/set_item/{aliases[alias.name]['uuid']}",
            _alias_payload(alias),
        )
    if pending_aliases or changed_aliases:
        client.post("/api/firewall/alias/reconfigure", {})
    for rule in pending_rules:
        client.post("/api/firewall/filter/add_rule/", _rule_payload(rule))
    for rule in changed_rules:
        client.post(
            f"/api/firewall/filter/set_rule/{rules[rule.description]['uuid']}",
            _rule_payload(rule),
        )
    if pending_rules or changed_rules:
        client.post("/api/firewall/filter/apply", {})
    if source_nat_mode != "hybrid":
        client.post(
            "/api/firewall/source_nat/set",
            {"filter": {"general": {"snat_mode": "hybrid"}}},
        )
    if not source_nat_present:
        client.post(
            "/api/firewall/source_nat/add_rule/",
            _source_nat_payload(),
        )
    if changed_source_nat:
        client.post(
            f"/api/firewall/source_nat/set_rule/{changed_source_nat['uuid']}",
            _source_nat_payload(),
        )
    if (
        source_nat_mode != "hybrid"
        or not source_nat_present
        or changed_source_nat
    ):
        client.post("/api/firewall/source_nat/apply", {})

    result["ids"] = client.get("/api/ids/service/status").get("status")
    result["unbound"] = client.get("/api/unbound/service/status").get("status")
    result["aliases_active"] = len(
        client.get("/api/firewall/alias/search_item").get("rows", [])
    )
    result["rules_active"] = len(
        client.get("/api/firewall/filter/search_rule").get("rows", [])
    )
    return result


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Promote OPNsense to the routed internal SOC NGFW."
    )
    parser.add_argument("--host", default=os.getenv("SIEM_OPNSENSE_HOST", DEFAULT_HOST))
    parser.add_argument("--username", default=os.getenv("SIEM_OPNSENSE_USER"))
    parser.add_argument("--password", default=os.getenv("SIEM_OPNSENSE_ROOT_PASSWORD"))
    parser.add_argument("--verify-tls", action="store_true")
    parser.add_argument("--apply", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not args.username or not args.password:
        raise SystemExit(
            "SIEM_OPNSENSE_USER and SIEM_OPNSENSE_ROOT_PASSWORD are required"
        )
    client = OPNsense(
        args.host,
        args.username,
        args.password,
        verify_tls=args.verify_tls,
    )
    client.login()
    print(json.dumps(reconcile(client, apply=args.apply), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
