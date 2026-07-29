from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


def _load_runtime_env() -> None:
    env_path = Path("/etc/siem/web.env")
    if not env_path.exists():
        return
    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in raw_line:
            continue
        key, value = raw_line.split("=", 1)
        os.environ.setdefault(key.strip(), value)


_load_runtime_env()

from deploy.publish_assignment_detection_pack import _publish_stream_rule  # noqa: E402
from deploy.publish_operational_rule_packs import (  # noqa: E402
    _build_stream_rule,
    _insert_detection_rules,
    _insert_stream_rules,
)
from deploy.runtime_imports import import_app_module  # noqa: E402

deps = import_app_module("deps")

ASSIGNMENT_RULE_IDS = {8067, 8305, 8355}
WINDOWS_RULE_IDS = {2604}
TARGET_RULE_IDS = ASSIGNMENT_RULE_IDS | WINDOWS_RULE_IDS


def _load_pack(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _load_rules() -> list[dict[str, Any]]:
    assignment = _load_pack(ROOT / "correlation_rule_packs" / "siem_detection_pack_v1.json")
    windows = _load_pack(ROOT / "correlation_rule_packs" / "windows_activity_v1.json")
    rules: dict[int, dict[str, Any]] = {}
    for item in assignment.get("stream_rules") or []:
        rule_id = int(item.get("id") or 0)
        if rule_id in ASSIGNMENT_RULE_IDS:
            rule = _publish_stream_rule(item, pack_id=str(assignment.get("pack_id") or "siem_detection_pack_v1"))
            if rule:
                rules[rule_id] = rule
    for item in windows.get("stream_rules") or []:
        rule_id = int(item.get("id") or 0)
        if rule_id in WINDOWS_RULE_IDS:
            rule = _build_stream_rule(item, pack_id=str(windows.get("pack_id") or "windows_activity_v1"))
            if rule:
                rules[rule_id] = rule
    missing = sorted(TARGET_RULE_IDS - set(rules))
    if missing:
        raise RuntimeError(f"Missing calibrated rules: {missing}")
    for rule_id, rule in rules.items():
        if not str(rule.get("expr") or "").strip():
            raise RuntimeError(f"Calibrated rule {rule_id} has an empty expression")
    return [rules[rule_id] for rule_id in sorted(rules)]


def main() -> int:
    rules = _load_rules()
    rule_ids = ",".join(str(rule_id) for rule_id in sorted(TARGET_RULE_IDS))
    deps.ensure_detection_support_tables()
    client = deps.get_ch_client()
    for table_name in (deps.DETECTION_RULE_TABLE, "siem.correlation_rules_stream"):
        client.command(
            f"DELETE FROM {table_name} WHERE id IN ({rule_ids}) "
            "SETTINGS lightweight_deletes_sync=2"
        )
    _insert_detection_rules(rules)
    _insert_stream_rules(rules)
    print(json.dumps({"published": True, "rule_ids": sorted(TARGET_RULE_IDS)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
