from __future__ import annotations

import base64
import json
import shlex
import sys
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

try:
    from deploy.soc_foundation_provision import Proxmox
except ModuleNotFoundError:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from soc_foundation_provision import Proxmox


ROOT = Path(__file__).resolve().parents[1]
VMID = 107
REMOTE_ROOT = "/opt/siem/siem-solution"
WEB_PYTHON = "/opt/siem/venv-web/bin/python"

RELEASE_FILES = (
    "correlation_rule_packs/linux_activity_v1.json",
    "deploy/homelab_watchdog.py",
    "deploy/close_confirmed_runtime_false_positives.py",
    "deploy/curated_assignment_rules.py",
    "deploy/publish_targeted_rule_calibration.py",
    "services/web/app/health_surfaces.py",
    "services/web/app/inventory_catalog.py",
    "services/web/app/runtime_humanization.py",
    "services/web/app/security_services_runtime.py",
    "correlation_rule_packs/siem_detection_pack_v1.json",
    "correlation_rule_packs/windows_activity_v1.json",
    "frontend-react/src/shell/App.tsx",
    "frontend-react/src/shell/humanize.ts",
    "frontend-react/src/shell/pages/SecurityServicePage.tsx",
    "correlation_rule_packs/security_services_v1.json",
    "deploy/publish_operational_rule_packs.py",
)


def _remote_path(relative: str) -> str:
    if relative.startswith("frontend-react/"):
        return str(
            PurePosixPath(REMOTE_ROOT)
            / "services/web/frontend-react"
            / relative.removeprefix("frontend-react/")
        )
    return str(PurePosixPath(REMOTE_ROOT) / relative)


def _push_file(
    pve: Proxmox,
    relative: str,
    *,
    backup_root: str,
) -> None:
    source = ROOT / relative
    destination = _remote_path(relative)
    encoded = base64.b64encode(source.read_bytes()).decode("ascii")
    temp = f"/tmp/siem-vm4-release-{source.name}.b64"
    backup = str(
        PurePosixPath(backup_root)
        / destination.removeprefix("/").replace("/", "__")
    )
    pve.guest_exec(
        VMID,
        f"install -d -m 0750 {shlex.quote(backup_root)} "
        f"{shlex.quote(str(PurePosixPath(destination).parent))}; "
        f"if [ -f {shlex.quote(destination)} ]; then "
        f"cp -a {shlex.quote(destination)} {shlex.quote(backup)}; fi; "
        f": > {shlex.quote(temp)}",
    )
    for offset in range(0, len(encoded), 32_000):
        chunk = encoded[offset : offset + 32_000]
        pve.guest_exec(
            VMID,
            f"printf %s {shlex.quote(chunk)} >> {shlex.quote(temp)}",
        )
    pve.guest_exec(
        VMID,
        f"base64 -d {shlex.quote(temp)} > {shlex.quote(destination)}; "
        f"rm -f {shlex.quote(temp)}; "
        f"chmod 0644 {shlex.quote(destination)}; "
        f"chown rdegon:rdegon {shlex.quote(destination)}",
    )


def _publish_rules_command() -> str:
    return f"""
set -euo pipefail
cd {shlex.quote(REMOTE_ROOT)}
{shlex.quote(WEB_PYTHON)} - <<'PY'
import os
import runpy
from pathlib import Path
for raw_line in Path("/etc/siem/web.env").read_text(encoding="utf-8").splitlines():
    line = raw_line.strip()
    if not line or line.startswith("#") or "=" not in raw_line:
        continue
    key, value = raw_line.split("=", 1)
    if key.strip():
        os.environ.setdefault(key.strip(), value)
runpy.run_path("deploy/publish_operational_rule_packs.py", run_name="__main__")
PY
"""


def _publish_targeted_rules_command() -> str:
    return f"""
set -euo pipefail
cd {shlex.quote(REMOTE_ROOT)}
{shlex.quote(WEB_PYTHON)} - <<'PY'
import os
import runpy
from pathlib import Path
for raw_line in Path("/etc/siem/web.env").read_text(encoding="utf-8").splitlines():
    line = raw_line.strip()
    if not line or line.startswith("#") or "=" not in raw_line:
        continue
    key, value = raw_line.split("=", 1)
    if key.strip():
        os.environ.setdefault(key.strip(), value)
runpy.run_path("deploy/publish_targeted_rule_calibration.py", run_name="__main__")
PY
"""


def main() -> int:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup_root = f"/var/backups/siem/vm4-qga-release-{stamp}"
    with Proxmox() as pve:
        for relative in RELEASE_FILES:
            _push_file(pve, relative, backup_root=backup_root)
        compile_output = pve.guest_exec(
            VMID,
            f"{shlex.quote(WEB_PYTHON)} -m py_compile "
            f"{shlex.quote(_remote_path('deploy/homelab_watchdog.py'))} "
            f"{shlex.quote(_remote_path('deploy/close_confirmed_runtime_false_positives.py'))} "
            f"{shlex.quote(_remote_path('deploy/curated_assignment_rules.py'))} "
            f"{shlex.quote(_remote_path('deploy/publish_targeted_rule_calibration.py'))} "
            f"{shlex.quote(_remote_path('services/web/app/health_surfaces.py'))} "
            f"{shlex.quote(_remote_path('services/web/app/inventory_catalog.py'))} "
            f"{shlex.quote(_remote_path('services/web/app/runtime_humanization.py'))} "
            f"{shlex.quote(_remote_path('services/web/app/security_services_runtime.py'))} "
            f"{shlex.quote(_remote_path('deploy/publish_operational_rule_packs.py'))}",
            timeout=180,
        )
        build_output = pve.guest_exec(
            VMID,
            "set -euo pipefail; "
            f"chmod o+x {shlex.quote(REMOTE_ROOT)}; "
            f"cd {shlex.quote(REMOTE_ROOT + '/services/web/frontend-react')}; "
            "runuser -u rdegon -- npm run build",
            timeout=600,
        )
        publish_output = pve.guest_exec(
            VMID,
            _publish_rules_command(),
            timeout=600,
        )
        targeted_publish_output = pve.guest_exec(
            VMID,
            _publish_targeted_rules_command(),
            timeout=900,
        )
        state_output = pve.guest_exec(
            VMID,
            "set -euo pipefail; "
            "rm -f /opt/siem/runtime-docs/health_surface_cache.json "
            "/opt/siem/runtime-docs/health_overview_cache.json; "
            "systemctl restart siem-web; "
            "systemctl is-active --quiet siem-web nginx siem-keycloak siem-vault; "
            "for attempt in $(seq 1 30); do "
            "curl -kfsS --max-time 5 https://127.0.0.1/healthz >/dev/null && break; "
            "sleep 1; "
            "done; "
            "curl -kfsS --max-time 5 https://127.0.0.1/healthz >/dev/null; "
            "systemctl is-active siem-web nginx siem-keycloak siem-vault",
            timeout=240,
        )
    result = {
        "vmid": VMID,
        "files": len(RELEASE_FILES),
        "backup": backup_root,
        "compile": compile_output.strip() or "ok",
        "frontend": build_output.strip().splitlines()[-1:] or ["ok"],
        "rules": json.loads(publish_output.strip()),
        "targeted_rules": json.loads(targeted_publish_output.strip()),
        "services": state_output.strip().splitlines(),
    }
    print(json.dumps(result, indent=2, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
