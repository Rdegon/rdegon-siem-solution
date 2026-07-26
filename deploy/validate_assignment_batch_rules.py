from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

PACK_PATH = ROOT / "correlation_rule_packs" / "siem_detection_pack_v1.json"


def validate_batch_rules(client: Any, payload: dict[str, Any]) -> list[dict[str, Any]]:
    failures: list[dict[str, Any]] = []
    for item in payload.get("batch_rules") or []:
        if not isinstance(item, dict):
            continue
        sql = str(item.get("sql_template") or "").strip().rstrip(";")
        if not sql:
            continue
        window_s = max(60, int(item.get("window_s") or 300))
        rendered = sql.replace("{WINDOW_S}", str(window_s))
        try:
            client.command(f"EXPLAIN SYNTAX {rendered}")
        except Exception as exc:  # noqa: BLE001
            failures.append(
                {
                    "rule_id": int(item.get("id") or 0),
                    "source_id": str(item.get("source_id") or ""),
                    "error": f"{type(exc).__name__}: {exc}",
                }
            )
    return failures


def main() -> int:
    from deploy.runtime_imports import import_app_module

    deps = import_app_module("deps")
    payload = json.loads(PACK_PATH.read_text(encoding="utf-8"))
    failures = validate_batch_rules(deps.get_ch_client(), payload)
    print(
        json.dumps(
            {
                "batch_rules": len(payload.get("batch_rules") or []),
                "failures": failures,
                "failure_count": len(failures),
            },
            ensure_ascii=False,
        )
    )
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
