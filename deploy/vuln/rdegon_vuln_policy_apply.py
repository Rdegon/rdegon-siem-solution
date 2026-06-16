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
PACKAGE = "rdegon_vuln_policy_apply_pkg"


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


# Import control-plane first so its late case-op bindings settle before maturity runtime loads.
_load_module("enterprise_control_plane")
_maturity = _load_module("vuln_maturity_runtime")
_runtime = _load_module("vuln_runtime")

apply_vulnerability_incident_policies = _maturity.apply_vulnerability_incident_policies
vulnerability_policy_state_path = _runtime.vulnerability_policy_state_path
write_vulnerability_runtime_state = _runtime.write_vulnerability_runtime_state


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Apply scheduled vulnerability incident policies for Rdegon SIEM.")
    parser.add_argument("--days", type=int, default=30)
    parser.add_argument("--limit", type=int, default=50)
    parser.add_argument("--actor", default="systemd-timer")
    parser.add_argument("--state-file", default="")
    return parser


def _state_path(raw_path: str) -> Path:
    return Path(raw_path).expanduser() if str(raw_path or "").strip() else vulnerability_policy_state_path()


def run_policy_cycle(*, days: int, limit: int, actor: str, state_path: Path) -> dict[str, Any]:
    result: dict[str, Any] = {
        "status": "ok",
        "started_at": datetime.now(timezone.utc).isoformat(),
        "days": max(1, int(days)),
        "limit": max(1, int(limit)),
        "actor": str(actor or "systemd-timer"),
    }
    try:
        result["apply"] = apply_vulnerability_incident_policies(
            actor=result["actor"],
            days=result["days"],
            limit=result["limit"],
        )
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
    result = run_policy_cycle(
        days=args.days,
        limit=args.limit,
        actor=args.actor,
        state_path=_state_path(args.state_file),
    )
    print(json.dumps(result, ensure_ascii=True, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
