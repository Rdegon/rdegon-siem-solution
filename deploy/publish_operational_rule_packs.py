from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from deploy.runtime_imports import import_app_module  # noqa: E402

deps = import_app_module("deps")


PACK_FILES = (
    "host_runtime_observability_v1.json",
    "fleet_observability_v1.json",
    "openclaw_behavior_v1.json",
    "vuln_coverage_v1.json",
    "pilot_services_v1.json",
    "windows_activity_v1.json",
    "linux_activity_v1.json",
    "identity_access_v1.json",
    "gitea_activity_v1.json",
    "navidrome_activity_v1.json",
    "scanner_runtime_v1.json",
    "source_coverage_v1.json",
    "diploma_core_stream_v1.json",
    "siem_detection_pack_v1.json",
)
PACK_DIR = ROOT / "correlation_rule_packs"


def _direct_stream_rule(item: dict[str, object], *, pack_id: str) -> dict[str, Any]:
    rule_id = int(item.get("id") or 0)
    title = str(item.get("title") or f"{pack_id} rule {rule_id}").strip()
    scenario = str(item.get("scenario") or "").strip()
    tags = [
        f"pack.{pack_id}",
        "source.stream_expr",
    ]
    if scenario:
        tags.append(f"scenario.{scenario.lower().replace(' ', '_')}")
    return {
        "id": rule_id,
        "title": title,
        "sigma_id": f"{pack_id}-{rule_id}",
        "status": str(item.get("status") or "active"),
        "level": str(item.get("severity") or "medium").lower(),
        "source_format": "stream-expr",
        "logsource_product": "",
        "logsource_service": "",
        "logsource_category": "",
        "sigma_yaml": "",
        "expr": str(item.get("expr") or "").strip(),
        "entity_field": str(item.get("entity_field") or "host.name"),
        "window_s": max(60, int(item.get("window_s") or 300)),
        "threshold": max(1, int(item.get("threshold") or 1)),
        "verification_query": "",
        "tags": ",".join(tags),
        "description": str(item.get("description") or item.get("operator_action") or ""),
        "enabled": 1,
        "author": f"operational-pack:{pack_id}",
    }


def _build_stream_rule(item: dict[str, object], *, pack_id: str) -> dict[str, Any] | None:
    if str(item.get("status") or "").lower() not in {"active", "publish_ready_after_host_metrics"}:
        return None
    sigma_yaml = str(item.get("sigma_yaml") or "").strip()
    if sigma_yaml:
        rule = deps.convert_sigma_to_stream_rule(
            sigma_yaml,
            threshold=max(1, int(item.get("threshold") or 1)),
            window_s=max(60, int(item.get("window_s") or 300)),
            entity_field=str(item.get("entity_field") or "host.name"),
            rule_id=int(item.get("id") or 0),
        )
        rule["author"] = f"operational-pack:{pack_id}"
        rule["description"] = str(item.get("description") or item.get("operator_action") or rule.get("description") or "")
        rule["level"] = str(item.get("severity") or rule.get("level") or "medium").lower()
        rule["enabled"] = 1
    else:
        if not str(item.get("expr") or "").strip():
            return None
        rule = _direct_stream_rule(item, pack_id=pack_id)
    return rule


def _existing_rule_ids(rule_ids: set[int]) -> tuple[set[int], set[int]]:
    if not rule_ids:
        return set(), set()
    ids = sorted({int(rule_id) for rule_id in rule_ids if int(rule_id or 0) > 0})
    catalog_ids = deps._query_existing_rule_ids(deps.DETECTION_RULE_TABLE, ids)  # type: ignore[attr-defined]
    stream_ids = deps._query_existing_rule_ids("siem.correlation_rules_stream", ids)  # type: ignore[attr-defined]
    return catalog_ids, stream_ids


def _insert_detection_rules(rules: list[dict[str, Any]]) -> None:
    if not rules:
        return
    deps._insert_detection_rule_rows(rules, sync_stream=False)  # type: ignore[attr-defined]


def _insert_stream_rules(rules: list[dict[str, Any]]) -> None:
    if not rules:
        return
    deps.get_ch_client().insert(
        "siem.correlation_rules_stream",
        [
            [
                int(rule["id"]),
                rule["title"],
                rule["description"] or f"Sigma-derived rule for {rule['title']}",
                1,
                rule["level"],
                "threshold",
                int(rule["window_s"]),
                int(rule["threshold"]),
                rule["expr"],
                rule["entity_field"],
            ]
            for rule in rules
        ],
        column_names=[
            "id",
            "name",
            "description",
            "enabled",
            "severity",
            "pattern",
            "window_s",
            "threshold",
            "expr",
            "entity_field",
        ],
    )


def main() -> int:
    deps.ensure_detection_support_tables()
    published = 0
    pack_results: list[dict[str, object]] = []
    for pack_name in PACK_FILES:
        pack_path = PACK_DIR / pack_name
        if not pack_path.exists():
            continue
        payload = json.loads(pack_path.read_text(encoding="utf-8"))
        pack_id = str(payload.get("pack_id") or pack_name)
        rule_ids = {
            int(item.get("id") or 0)
            for item in payload.get("stream_rules") or []
            if isinstance(item, dict) and int(item.get("id") or 0) > 0
        }
        catalog_ids, stream_ids = _existing_rule_ids(rule_ids)
        pack_rules: list[dict[str, Any]] = []
        for item in payload.get("stream_rules") or []:
            if not isinstance(item, dict):
                continue
            rule = _build_stream_rule(item, pack_id=pack_id)
            if rule:
                pack_rules.append(rule)
        catalog_missing = [rule for rule in pack_rules if int(rule["id"]) not in catalog_ids]
        stream_missing = [rule for rule in pack_rules if int(rule["id"]) not in stream_ids]
        _insert_detection_rules(catalog_missing)
        _insert_stream_rules(stream_missing)
        published += len(stream_missing)
        pack_results.append(
            {
                "pack_id": pack_id,
                "published_rules": len(stream_missing),
                "catalog_rules_added": len(catalog_missing),
                "present_rules": len(pack_rules) - len(stream_missing),
            }
        )
    print(json.dumps({"published_rules": published, "packs": pack_results}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
