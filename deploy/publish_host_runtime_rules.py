from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP_ROOT = ROOT / "services" / "web"
for candidate in (str(APP_ROOT), str(ROOT)):
    if candidate not in sys.path:
        sys.path.insert(0, candidate)

from app import deps  # type: ignore[import-not-found]  # noqa: E402


PACK_PATH = ROOT / "correlation_rule_packs" / "host_runtime_observability_v1.json"


def main() -> int:
    payload = json.loads(PACK_PATH.read_text(encoding="utf-8"))
    deps.ensure_detection_support_tables()
    published = 0
    for item in payload.get("stream_rules") or []:
        if str(item.get("status") or "").lower() not in {"active", "publish_ready_after_host_metrics"}:
            continue
        rule = deps.convert_sigma_to_stream_rule(
            str(item.get("sigma_yaml") or ""),
            threshold=max(1, int(item.get("threshold") or 1)),
            window_s=max(60, int(item.get("window_s") or 300)),
            entity_field=str(item.get("entity_field") or "host.name"),
            rule_id=int(item.get("id") or 0),
        )
        rule["author"] = "host-runtime-wave"
        rule["description"] = str(item.get("description") or rule.get("description") or "")
        rule["level"] = str(item.get("severity") or rule.get("level") or "medium").lower()
        rule["enabled"] = 1
        deps.get_ch_client().command(f"ALTER TABLE {deps.DETECTION_RULE_TABLE} DELETE WHERE id = {int(rule['id'])}")
        deps.get_ch_client().command(f"ALTER TABLE siem.correlation_rules_stream DELETE WHERE id = {int(rule['id'])}")
        deps._insert_detection_rule_rows([rule], sync_stream=True)  # type: ignore[attr-defined]
        published += 1
    print(f"published_rules={published}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
