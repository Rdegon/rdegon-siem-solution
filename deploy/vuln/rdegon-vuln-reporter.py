#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import socket
import ssl
import subprocess
import sys
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path


BASE_URL = os.getenv("RDEGON_SIEM_BASE_URL", "https://192.168.1.35")
INGEST_URL = os.getenv("RDEGON_SIEM_VULN_INGEST_URL", "https://192.168.1.35:9445/")
TARGETS_FILE = Path(os.getenv("RDEGON_VULN_TARGETS_FILE", "/opt/rdegon-siem-vuln/targets.txt"))
REPORT_DIR = Path(os.getenv("RDEGON_VULN_REPORT_DIR", "/opt/rdegon-siem-vuln/reports"))
NMAP_ARGS = os.getenv("RDEGON_VULN_NMAP_ARGS", "-Pn -sV -T4").split()


def load_targets() -> list[str]:
    if not TARGETS_FILE.exists():
        return []
    rows = []
    for line in TARGETS_FILE.read_text(encoding="utf-8").splitlines():
        value = line.strip()
        if value and not value.startswith("#"):
            rows.append(value)
    return rows


def run_scan(targets: list[str]) -> tuple[str, str]:
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    report_id = datetime.now(timezone.utc).strftime("nmap-%Y%m%d-%H%M%S")
    xml_path = REPORT_DIR / f"{report_id}.xml"
    cmd = ["nmap", *NMAP_ARGS, "-oX", str(xml_path), *targets]
    subprocess.run(cmd, check=True)
    return report_id, xml_path.read_text(encoding="utf-8", errors="ignore")


def parse_findings(xml_text: str) -> list[dict]:
    root = ET.fromstring(xml_text)
    findings: list[dict] = []
    for host in root.findall("host"):
        addr_node = host.find("address")
        if addr_node is None:
            continue
        target_ip = str(addr_node.get("addr") or "").strip()
        for port in host.findall("./ports/port"):
            state_node = port.find("state")
            if state_node is None or state_node.get("state") != "open":
                continue
            service_node = port.find("service")
            port_id = int(port.get("portid") or 0)
            service_name = str((service_node.get("name") if service_node is not None else "") or "")
            product = str((service_node.get("product") if service_node is not None else "") or "")
            version = str((service_node.get("version") if service_node is not None else "") or "")
            banner = " ".join(part for part in [service_name, product, version] if part).strip()
            findings.append(
                {
                    "target_ip": target_ip,
                    "dst_port": port_id,
                    "service_name": service_name,
                    "banner": banner,
                }
            )
    return findings


def severity_for_port(port: int) -> str:
    if port in {22, 80, 443}:
        return "medium"
    if port in {23, 3389, 5900, 8728}:
        return "high"
    return "low"


def build_payloads(report_id: str, findings: list[dict]) -> list[dict]:
    host_name = socket.gethostname().split(".", 1)[0]
    ts = datetime.now(timezone.utc).isoformat()
    targets = sorted({item["target_ip"] for item in findings if item["target_ip"]})
    payloads = [
        {
            "source_type": "http_json",
            "source": host_name,
            "log_source": host_name,
            "host.name": host_name,
            "event.provider": "vuln.nmap",
            "event.category": "vulnerability",
            "event.type": "scan_summary",
            "event.action": "summary",
            "event.code": report_id,
            "event.created": ts,
            "device.vendor": "Nmap",
            "device.product": "nmap",
            "message": f"Nmap scan {report_id} completed against {len(targets)} targets with {len(findings)} findings.",
            "severity": "info",
            "tags": "scanner,vulnerability,nmap",
            "process.command": " ".join(["nmap", *NMAP_ARGS]),
        }
    ]
    for finding in findings:
        port = int(finding["dst_port"] or 0)
        payloads.append(
            {
                "source_type": "http_json",
                "source": host_name,
                "log_source": host_name,
                "host.name": host_name,
                "event.provider": "vuln.nmap",
                "event.category": "vulnerability",
                "event.type": "open_port",
                "event.action": "finding",
                "event.code": report_id,
                "event.created": ts,
                "device.vendor": "Nmap",
                "device.product": "nmap",
                "destination.ip": finding["target_ip"],
                "destination.port": str(port),
                "process.name": finding["service_name"],
                "process.command": finding["banner"],
                "message": f"Open service {finding['service_name'] or 'unknown'} on {finding['target_ip']}:{port}. {finding['banner']}".strip(),
                "severity": severity_for_port(port),
                "tags": "scanner,vulnerability,service-exposure",
            }
        )
    return payloads


def post_payloads(payloads: list[dict]) -> None:
    data = json.dumps(payloads).encode("utf-8")
    request = urllib.request.Request(
        normalize_ingest_url(INGEST_URL),
        data=data,
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    context = ssl._create_unverified_context()
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({}),
        urllib.request.HTTPSHandler(context=context),
    )
    with opener.open(request, timeout=30) as response:
        body = response.read().decode("utf-8", errors="ignore")
        print(body)


def normalize_ingest_url(url: str) -> str:
    value = (url or "").strip()
    if not value:
        return value
    lowered = value.lower()
    if any(f":{port}" in lowered for port in (9440, 9441, 9442, 9443, 9444, 9445, 9446)):
        prefix = value.split("?", 1)[0].split("#", 1)[0]
        if "/" in prefix[8:]:
            base = prefix.split("/", 3)[:3]
            return "/".join(base) + "/"
    return value


def main() -> int:
    targets = load_targets()
    if not targets:
        print("No targets configured", file=sys.stderr)
        return 2
    report_id, xml_text = run_scan(targets)
    findings = parse_findings(xml_text)
    post_payloads(build_payloads(report_id, findings))
    print(f"report_id={report_id} findings={len(findings)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
