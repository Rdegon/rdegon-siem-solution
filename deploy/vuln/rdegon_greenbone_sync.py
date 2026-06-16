#!/usr/bin/env python3
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import importlib.util
import json
from pathlib import Path
import sys
import types
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
APP_ROOT = ROOT if (ROOT / "config.py").exists() else ROOT / "services" / "web" / "app"
PACKAGE = "rdegon_greenbone_sync_pkg"


def _load_module(name: str):
    if PACKAGE not in sys.modules:
        package = types.ModuleType(PACKAGE)
        package.__path__ = [str(APP_ROOT)]
        sys.modules[PACKAGE] = package
    full_name = f"{PACKAGE}.{name}"
    if full_name in sys.modules:
        return sys.modules[full_name]
    spec = importlib.util.spec_from_file_location(full_name, APP_ROOT / f"{name}.py")
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load runtime module {name} from {APP_ROOT}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[full_name] = module
    spec.loader.exec_module(module)
    return module


CONFIG = _load_module("config").CONFIG
_greenbone = _load_module("vuln_greenbone")
_runtime = _load_module("vuln_runtime")
_store = _load_module("vuln_store")

greenbone_is_configured = _greenbone.greenbone_is_configured
probe_greenbone = _greenbone.probe_greenbone
vulnerability_runtime_state_path = _runtime.vulnerability_runtime_state_path
write_vulnerability_runtime_state = _runtime.write_vulnerability_runtime_state
import_greenbone_reports = _store.import_greenbone_reports
sync_vulnerability_targets = _store.sync_vulnerability_targets


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run Greenbone target sync and report import for Rdegon SIEM.")
    parser.add_argument("--sync-limit", type=int, default=500)
    parser.add_argument("--import-limit", type=int, default=20)
    parser.add_argument("--skip-target-sync", action="store_true")
    parser.add_argument("--skip-report-import", action="store_true")
    parser.add_argument("--probe-only", action="store_true")
    parser.add_argument("--state-file", default="")
    return parser


def _state_path(raw_path: str) -> Path:
    return Path(raw_path).expanduser() if str(raw_path or "").strip() else vulnerability_runtime_state_path()


def run_greenbone_cycle(
    *,
    sync_limit: int,
    import_limit: int,
    skip_target_sync: bool,
    skip_report_import: bool,
    probe_only: bool,
    state_path: Path,
) -> dict[str, Any]:
    started_at = datetime.now(timezone.utc).isoformat()
    result: dict[str, Any] = {
        "status": "ok",
        "started_at": started_at,
        "greenbone": {
            "enabled": greenbone_is_configured(),
            "host": str(CONFIG.greenbone.host or ""),
            "port": int(CONFIG.greenbone.port or 0),
            "web_base_url": str(CONFIG.greenbone.web_base_url or ""),
        },
        "probe": {},
        "target_sync": {"status": "skipped"},
        "report_import": {"status": "skipped"},
    }
    try:
        if not greenbone_is_configured():
            raise RuntimeError("Greenbone integration is not configured on this node")
        result["probe"] = probe_greenbone()
        if not probe_only and not skip_target_sync:
            result["target_sync"] = sync_vulnerability_targets(limit=max(1, int(sync_limit)))
        if not probe_only and not skip_report_import:
            result["report_import"] = import_greenbone_reports(limit=max(1, int(import_limit)))
    except Exception as exc:  # noqa: BLE001
        result["status"] = "error"
        result["error"] = str(exc)
        raise
    finally:
        result["finished_at"] = datetime.now(timezone.utc).isoformat()
        write_vulnerability_runtime_state(result, state_path)
    return result


def main() -> int:
    args = _parser().parse_args()
    state_path = _state_path(args.state_file)
    result = run_greenbone_cycle(
        sync_limit=args.sync_limit,
        import_limit=args.import_limit,
        skip_target_sync=bool(args.skip_target_sync),
        skip_report_import=bool(args.skip_report_import),
        probe_only=bool(args.probe_only),
        state_path=state_path,
    )
    print(json.dumps(result, ensure_ascii=True, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
