from __future__ import annotations

import argparse
import json
import os
import ssl
import subprocess
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _request_json(url: str, password: str) -> dict[str, Any]:
    credentials = __import__("base64").b64encode(f"admin:{password}".encode("utf-8")).decode("ascii")
    request = urllib.request.Request(
        url,
        headers={"Authorization": f"Basic {credentials}", "Accept": "application/json"},
    )
    with urllib.request.urlopen(
        request,
        timeout=30,
        context=ssl._create_unverified_context(),
    ) as response:
        payload = json.load(response)
    return payload if isinstance(payload, dict) else {}


def collect_metrics(
    *,
    opensearch_url: str,
    password_path: Path,
    pcap_dir: Path,
) -> dict[str, Any]:
    password = password_path.read_text(encoding="utf-8").strip()
    cluster = _request_json(f"{opensearch_url}/_cluster/health", password)
    sessions = _request_json(f"{opensearch_url}/arkime_sessions3-*/_count", password)
    pcap_files = [path for path in pcap_dir.rglob("*.pcap*") if path.is_file()]
    services = {}
    for unit in ("opensearch", "arkimecapture", "arkimeviewer"):
        result = subprocess.run(
            ["systemctl", "is-active", unit],
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
        )
        services[unit] = result.stdout.strip() or "unknown"
    healthy = all(value == "active" for value in services.values())
    return {
        "@timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "source_type": "arkime",
        "event.provider": "arkime",
        "event.dataset": "arkime.health",
        "event.action": "health_snapshot",
        "event.outcome": "success" if healthy else "failure",
        "event.severity": "info" if healthy else "high",
        "host.name": "soc-ndr-01",
        "service.name": "arkime",
        "service.state": "active" if healthy else "degraded",
        "arkime.sessions": int(sessions.get("count") or 0),
        "arkime.pcap.files": len(pcap_files),
        "arkime.pcap.bytes": sum(path.stat().st_size for path in pcap_files),
        "opensearch.status": str(cluster.get("status") or "unknown"),
        "opensearch.nodes": int(cluster.get("number_of_nodes") or 0),
        "services": services,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Export Arkime health metrics to SIEM JSONL.")
    parser.add_argument("--opensearch-url", default="https://127.0.0.1:9200")
    parser.add_argument("--password-path", default="/etc/opensearch/admin-password")
    parser.add_argument("--pcap-dir", default="/srv/arkime-pcap")
    parser.add_argument("--output-path", default="/var/log/siem/arkime-health.jsonl")
    args = parser.parse_args()
    document = collect_metrics(
        opensearch_url=args.opensearch_url,
        password_path=Path(args.password_path),
        pcap_dir=Path(args.pcap_dir),
    )
    output_path = Path(args.output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(document, ensure_ascii=True, separators=(",", ":")) + "\n")
        handle.flush()
        os.fsync(handle.fileno())
    output_path.chmod(0o640)
    print(json.dumps({"events": 1, "healthy": document["event.outcome"] == "success"}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
