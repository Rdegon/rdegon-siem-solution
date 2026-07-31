from __future__ import annotations

import argparse
import json
import shlex
import sys
from pathlib import Path

try:
    from deploy.soc_foundation_provision import Proxmox
except ModuleNotFoundError:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from soc_foundation_provision import Proxmox


VMID = 107
REMOTE_ROOT = "/opt/siem/siem-solution"
WEB_PYTHON = "/opt/siem/venv-web/bin/python"


def _smoke_command() -> str:
    script = r'''
import json
import os
import sys
from pathlib import Path

for raw_line in Path("/etc/siem/web.env").read_text(encoding="utf-8").splitlines():
    line = raw_line.strip()
    if not line or line.startswith("#") or "=" not in raw_line:
        continue
    key, value = raw_line.split("=", 1)
    os.environ.setdefault(key.strip(), value)

sys.path.insert(0, "/opt/siem/siem-solution/services/web")

from app.control_plane_report_ops import generate_report_run, list_report_runs, list_report_templates
from app.control_plane_source_policy_ops import evaluate_source_policies, list_source_policies
from app.host_runtime_runtime import fetch_host_runtime_overview
from app.query.sources import fetch_source_inventory
from app.routes.console_router_registry import build_console_router
from app.security_services_runtime import get_security_service

templates = list_report_templates()
runs = list_report_runs(limit=20)
if os.getenv("SIEM_UI_SMOKE_GENERATE_REPORT") == "1" and not runs:
    generate_report_run("soc-shift-summary", actor="ui-functional-wave")
    runs = list_report_runs(limit=20)
policies = list_source_policies()
sources = fetch_source_inventory(limit=500, hours=24)
evaluated = evaluate_source_policies([dict(item) for item in sources], policies=policies)
runtime = fetch_host_runtime_overview(hours=24, limit=5)
vpn = get_security_service("vpn")
routes = {route.path for route in build_console_router().routes}
required_routes = {
    "/api/reporting/templates",
    "/api/reporting/runs",
    "/api/sources/policies",
    "/api/security-services/{service_id}",
}
dist = Path("/opt/siem/siem-solution/services/web/frontend-react/dist")
assets = list((dist / "assets").glob("*")) if (dist / "assets").exists() else []

result = {
    "report_templates": len(templates),
    "report_runs": len(runs),
    "latest_report": {
        "status": (runs[0] if runs else {}).get("status"),
        "record_count": (runs[0] if runs else {}).get("record_count"),
        "section_count": (runs[0] if runs else {}).get("section_count"),
        "errors": len((runs[0] if runs else {}).get("errors") or []),
    },
    "source_policies": len(policies),
    "source_policy_violations": sum(int(item.get("violation_count") or 0) for item in evaluated),
    "sources": len(sources),
    "runtime_targets": len(runtime.get("targets") or []),
    "runtime_policy": {
        "version": (runtime.get("policy") or {}).get("version"),
        "loaded": (runtime.get("policy") or {}).get("loaded"),
        "signals": len((runtime.get("policy") or {}).get("event_overrides") or {}),
    },
    "vpn": {
        "service_id": (vpn.get("service") or {}).get("service_id"),
        "state": (vpn.get("telemetry") or {}).get("integration_state"),
        "events_1h": (vpn.get("telemetry") or {}).get("events_1h"),
    },
    "required_routes_present": required_routes.issubset(routes),
    "frontend": {
        "index": (dist / "index.html").exists(),
        "asset_files": len(assets),
    },
}
print(json.dumps(result, ensure_ascii=True))
'''
    return (
        "set -euo pipefail; "
        f"cd {shlex.quote(REMOTE_ROOT)}; "
        f"{shlex.quote(WEB_PYTHON)} - <<'PY'\n{script}\nPY"
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--generate-initial-report", action="store_true")
    args = parser.parse_args()
    with Proxmox() as pve:
        command = _smoke_command()
        if args.generate_initial_report:
            command = f"export SIEM_UI_SMOKE_GENERATE_REPORT=1; {command}"
        payload = json.loads(pve.guest_exec(VMID, command, timeout=300))
        services = pve.guest_exec(
            VMID,
            "systemctl is-active siem-web nginx siem-report-scheduler.timer",
            timeout=30,
        ).strip().splitlines()
        health = pve.guest_exec(
            VMID,
            "curl -kfsS --max-time 10 https://127.0.0.1/healthz",
            timeout=30,
        ).strip()
    payload["services"] = services
    payload["health"] = json.loads(health)
    print(json.dumps(payload, indent=2, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
