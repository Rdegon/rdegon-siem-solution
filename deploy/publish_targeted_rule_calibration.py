from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) in sys.path:
    sys.path.remove(str(ROOT))
sys.path.insert(0, str(ROOT))

if "--dry-run" in sys.argv:
    os.environ.setdefault("SIEM_CH_HOST", "127.0.0.1")
    os.environ.setdefault("SIEM_CH_USER", "default")
    os.environ.setdefault("SIEM_CH_PASSWORD", "dry-run")
    os.environ.setdefault("SIEM_ADMIN_DEFAULT_PASSWORD", "dry-run")
    os.environ.setdefault("SIEM_JWT_SECRET", "dry-run")

from services.filter.filter_core import parse_expr  # noqa: E402

from deploy.publish_assignment_detection_pack import (  # noqa: E402
    _ensure_batch_rule_table,
    _publish_batch_rule,
    _publish_stream_rule,
)
from deploy.publish_batch_rules import _split_sql_statements  # noqa: E402
from deploy.publish_operational_rule_packs import (  # noqa: E402
    PACK_DIR,
    PACK_FILES,
    _build_stream_rule,
    _insert_detection_rules,
    _insert_stream_rules,
)
from deploy.runtime_imports import import_app_module  # noqa: E402

deps = import_app_module("deps")


TARGET_STREAM_RULE_IDS = {
    2617,
    2704,
    2706,
    2709,
    2711,
    2715,
    2716,
    2717,
    2726,
    8036,
    8047,
    8077,
    8081,
    8083,
    8084,
    8090,
    8096,
    8097,
    8098,
    8103,
    8111,
    8121,
    8267,
    8279,
    8283,
    8297,
    8329,
    9005,
    9006,
    9007,
}
TARGET_ASSIGNMENT_BATCH_RULE_IDS = {
    8001,
    8002,
    8006,
    8011,
    8012,
    8065,
    8221,
    8425,
    8429,
}
TARGET_SQL_BATCH_RULE_IDS = {4001, 4002}
ASSIGNMENT_PACK_NAME = "siem_detection_pack_v1.json"
MULTI_HOST_BATCH_SEED = ROOT / "sql" / "13_batch_corr_seed.sql"


def _ids_sql(rule_ids: set[int]) -> str:
    return ",".join(str(rule_id) for rule_id in sorted(rule_ids))


def _load_targets() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    stream_rules: dict[int, dict[str, Any]] = {}
    assignment_batch_rules: dict[int, dict[str, Any]] = {}
    for pack_name in PACK_FILES:
        path = PACK_DIR / pack_name
        if not path.exists():
            continue
        payload = json.loads(path.read_text(encoding="utf-8"))
        pack_id = str(payload.get("pack_id") or pack_name)
        for item in payload.get("stream_rules") or []:
            if not isinstance(item, dict):
                continue
            rule_id = int(item.get("id") or 0)
            if rule_id not in TARGET_STREAM_RULE_IDS:
                continue
            if pack_name == ASSIGNMENT_PACK_NAME:
                rule = _publish_stream_rule(item, pack_id=pack_id)
            else:
                rule = _build_stream_rule(item, pack_id=pack_id)
            if rule:
                try:
                    parse_expr(str(rule.get("expr") or ""))
                except ValueError as exc:
                    raise ValueError(
                        f"Invalid expression for rule {rule_id} in {pack_name}: {exc}"
                    ) from exc
                stream_rules[rule_id] = rule
        if pack_name == ASSIGNMENT_PACK_NAME:
            for item in payload.get("batch_rules") or []:
                if not isinstance(item, dict):
                    continue
                rule_id = int(item.get("id") or 0)
                if rule_id in TARGET_ASSIGNMENT_BATCH_RULE_IDS:
                    assignment_batch_rules[rule_id] = item

    missing_stream = sorted(TARGET_STREAM_RULE_IDS - set(stream_rules))
    missing_batch = sorted(TARGET_ASSIGNMENT_BATCH_RULE_IDS - set(assignment_batch_rules))
    if missing_stream or missing_batch:
        raise RuntimeError(
            f"Missing targeted rules: stream={missing_stream}, assignment_batch={missing_batch}"
        )
    return (
        [stream_rules[rule_id] for rule_id in sorted(stream_rules)],
        [assignment_batch_rules[rule_id] for rule_id in sorted(assignment_batch_rules)],
    )


def _delete_exact(table_name: str, rule_ids: set[int]) -> None:
    deps.get_ch_client().command(
        f"DELETE FROM {table_name} WHERE id IN ({_ids_sql(rule_ids)}) "
        "SETTINGS lightweight_deletes_sync=2"
    )


def _publish_assignment_batch(items: list[dict[str, Any]]) -> None:
    rows = [_publish_batch_rule(item) for item in items]
    deps.get_ch_client().insert(
        "siem.correlation_rules_batch",
        [list(row) for row in rows],
        column_names=[
            "id",
            "name",
            "description",
            "enabled",
            "severity",
            "window_s",
            "sql_template",
        ],
    )


def _publish_sql_batch_seed() -> int:
    statements = _split_sql_statements(MULTI_HOST_BATCH_SEED.read_text(encoding="utf-8"))
    executed = 0
    for statement in statements:
        delete_match = re.fullmatch(
            r"ALTER\s+TABLE\s+([A-Za-z0-9_.]+)\s+DELETE\s+WHERE\s+(.+)",
            statement,
            flags=re.IGNORECASE | re.DOTALL,
        )
        if delete_match:
            table_name, condition = delete_match.groups()
            statement = (
                f"DELETE FROM {table_name} WHERE {condition} "
                "SETTINGS lightweight_deletes_sync=2"
            )
        deps.get_ch_client().command(statement)
        executed += 1
    return executed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate and publish only the explicitly calibrated SIEM rule IDs."
    )
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args(argv)

    stream_rules, assignment_batch_rules = _load_targets()
    if args.dry_run:
        print(
            json.dumps(
                {
                    "validated": True,
                    "stream_rule_ids": sorted(TARGET_STREAM_RULE_IDS),
                    "assignment_batch_rule_ids": sorted(TARGET_ASSIGNMENT_BATCH_RULE_IDS),
                    "sql_batch_rule_ids": sorted(TARGET_SQL_BATCH_RULE_IDS),
                },
                ensure_ascii=False,
            )
        )
        return 0

    deps.ensure_detection_support_tables()
    _ensure_batch_rule_table()
    _delete_exact(deps.DETECTION_RULE_TABLE, TARGET_STREAM_RULE_IDS)
    _delete_exact("siem.correlation_rules_stream", TARGET_STREAM_RULE_IDS)
    _insert_detection_rules(stream_rules)
    _insert_stream_rules(stream_rules)

    _delete_exact("siem.correlation_rules_batch", TARGET_ASSIGNMENT_BATCH_RULE_IDS)
    _publish_assignment_batch(assignment_batch_rules)
    seed_statements = _publish_sql_batch_seed()
    print(
        json.dumps(
            {
                "published": True,
                "stream_rules": len(stream_rules),
                "assignment_batch_rules": len(assignment_batch_rules),
                "sql_batch_rule_ids": sorted(TARGET_SQL_BATCH_RULE_IDS),
                "sql_seed_statements": seed_statements,
            },
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
