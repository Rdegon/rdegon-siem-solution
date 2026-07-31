from __future__ import annotations

import json
import os
import shlex
import subprocess
from datetime import datetime, timezone
from pathlib import Path

try:
    from deploy.vm4_qga_release_deploy import (
        REMOTE_ROOT,
        VMID,
        WEB_PYTHON,
        Proxmox,
        _push_file,
        _remote_path,
    )
except ModuleNotFoundError:
    from vm4_qga_release_deploy import (  # type: ignore[no-redef]
        REMOTE_ROOT,
        VMID,
        WEB_PYTHON,
        Proxmox,
        _push_file,
        _remote_path,
    )


ROOT = Path(__file__).resolve().parents[1]


def _tree_files(relative_root: str) -> tuple[str, ...]:
    root = ROOT / relative_root
    return tuple(
        path.relative_to(ROOT).as_posix()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    )


BACKEND_AND_RUNTIME_FILES = (
    "services/web/app/deps.py",
    "services/web/app/security.py",
    "services/web/app/control_plane_access_ops.py",
    "services/web/app/control_plane_report_ops.py",
    "services/web/app/control_plane_source_policy_ops.py",
    "services/web/app/host_runtime_runtime.py",
    "services/web/app/security_services_runtime.py",
    "services/web/app/routes/console_assets_routes.py",
    "services/web/app/routes/alerts.py",
    "services/web/app/routes/console_reporting_routes.py",
    "services/web/app/routes/console_router_registry.py",
    "services/web/app/routes/console_source_policy_routes.py",
    "services/web/maintenance/report_scheduler.py",
    "deploy/systemd/siem-report-scheduler.service",
    "deploy/systemd/siem-report-scheduler.timer",
)
FRONTEND_BUILD_FILES = (
    "frontend-react/build.cjs",
    "frontend-react/package.json",
    "frontend-react/package-lock.json",
    "frontend-react/tsconfig.json",
)
RELEASE_FILES = tuple(
    dict.fromkeys(
        (
            *BACKEND_AND_RUNTIME_FILES,
            *FRONTEND_BUILD_FILES,
            *_tree_files("frontend-react/src"),
            *_tree_files("frontend-react/public"),
        )
    )
)

BACKEND_FILES = tuple(
    path for path in RELEASE_FILES if path.startswith("services/web/") and path.endswith(".py")
)


def main() -> int:
    build_env = dict(os.environ)
    build_env["SIEM_SHELL_SOURCEMAP"] = "false"
    local_build = subprocess.run(
        ["npm.cmd" if os.name == "nt" else "npm", "run", "build"],
        cwd=ROOT / "frontend-react",
        check=True,
        capture_output=True,
        env=build_env,
        text=True,
        shell=False,
    )
    release_files = tuple(dict.fromkeys((*RELEASE_FILES, *_tree_files("frontend-react/dist"))))
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup_root = f"/var/backups/siem/vm4-ui-functional-wave-{stamp}"
    with Proxmox() as pve:
        for relative in release_files:
            _push_file(pve, relative, backup_root=backup_root)
        compile_output = pve.guest_exec(
            VMID,
            f"{shlex.quote(WEB_PYTHON)} -m py_compile "
            + " ".join(shlex.quote(_remote_path(path)) for path in BACKEND_FILES),
            timeout=180,
        )
        state_output = pve.guest_exec(
            VMID,
            "set -euo pipefail; "
            f"install -m 0644 {shlex.quote(_remote_path('deploy/systemd/siem-report-scheduler.service'))} /etc/systemd/system/siem-report-scheduler.service; "
            f"install -m 0644 {shlex.quote(_remote_path('deploy/systemd/siem-report-scheduler.timer'))} /etc/systemd/system/siem-report-scheduler.timer; "
            "systemctl daemon-reload; "
            "systemctl enable --now siem-report-scheduler.timer; "
            "systemctl start siem-report-scheduler.service; "
            "systemctl restart siem-web; "
            "systemctl is-active --quiet siem-web nginx siem-report-scheduler.timer; "
            "for attempt in $(seq 1 30); do "
            "curl -kfsS --max-time 5 https://127.0.0.1/healthz >/dev/null && break; "
            "sleep 1; "
            "done; "
            "curl -kfsS --max-time 5 https://127.0.0.1/healthz >/dev/null; "
            "systemctl is-active siem-web nginx siem-report-scheduler.timer",
            timeout=240,
        )
    print(
        json.dumps(
            {
                "vmid": VMID,
                "files": len(release_files),
                "backup": backup_root,
                "compile": compile_output.strip() or "ok",
                "frontend": local_build.stdout.strip().splitlines()[-1:] or ["ok"],
                "services": state_output.strip().splitlines(),
            },
            indent=2,
            ensure_ascii=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
