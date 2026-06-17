from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from deploy.runtime_imports import import_app_module  # noqa: E402

deps = import_app_module("deps")

from deploy.publish_operational_rule_packs import (  # noqa: E402
    PACK_DIR,
    PACK_FILES,
    _build_stream_rule,
    _insert_detection_rules,
    _insert_stream_rules,
)
from deploy.publish_batch_rules import (  # noqa: E402
    BATCH_SQL_FILES,
    _ensure_batch_rule_table,
    _split_sql_statements,
)


REPUBLISH_STREAM_RULE_IDS = {
    2108,
    2202,
    2303,
    2304,
    2604,
    2605,
    2607,
    2611,
    2612,
    2616,
    2618,
    2701,
    2702,
    2703,
    2706,
    2708,
    2711,
    2726,
}
RETIRE_STREAM_RULE_IDS = {
    1001,
    1002,
    1003,
    1004,
    1005,
    1006,
    1007,
    1008,
    1009,
    1010,
    1011,
    1012,
    1013,
    1014,
    1017,
    1018,
    1019,
    1020,
    1021,
    1023,
    1024,
    1026,
    1027,
    1028,
    1029,
    2000,
    2302,
    2723,
}
REFRESH_BATCH_RULE_IDS = {4001, 4002, 4003, 4004, 4005}
RETIRE_OPEN_ALERT_RULE_IDS = {
    *REPUBLISH_STREAM_RULE_IDS,
    *RETIRE_STREAM_RULE_IDS,
    2104,
    8012,
    8018,
    8019,
    8025,
    8027,
    8029,
    8036,
    8045,
    8046,
    8047,
    8050,
    8065,
    8067,
    8070,
    8071,
    8072,
    8073,
    8074,
    8075,
    8081,
    8083,
    8084,
    8085,
    8086,
    8090,
    8091,
    8092,
    8093,
    8126,
    8129,
    8134,
    8138,
    8145,
    8213,
    8221,
    8222,
    8223,
    8224,
    8225,
    8226,
    8227,
    8228,
    8230,
    8233,
    8234,
    8253,
    8258,
    8260,
    8261,
    8263,
    8270,
    8279,
    8283,
    8285,
    8287,
    8288,
    8295,
    8297,
    8298,
    8299,
    8294,
    8301,
    8302,
    8303,
    8304,
    8305,
    8286,
    8308,
    8328,
    8330,
    8325,
    8331,
    8332,
    8333,
    8335,
    8336,
    8338,
    8339,
    8341,
    8343,
    8344,
    8340,
    8355,
    8359,
    8360,
    8361,
    8363,
    8366,
    8369,
    8373,
    8375,
    8379,
    8377,
    8388,
    8389,
    8390,
    8391,
    8418,
    8419,
    8420,
    8425,
    8426,
    8427,
    8429,
    8431,
    8432,
    8438,
    8440,
    8441,
    8442,
    8457,
    8481,
    2501,
    2615,
    2617,
    8001,
    8006,
    8007,
    8008,
    8009,
    8011,
    8012,
    8013,
    8014,
    8015,
    8016,
    8017,
    8018,
    8019,
    8020,
    8099,
    8113,
    2705,
    2709,
    2710,
    2711,
    2714,
    2704,
    2706,
    2715,
    2716,
    2717,
    2718,
    2719,
    2720,
    2721,
    2912,
    4001,
    4002,
    4003,
    4004,
    4005,
    8465,
    8487,
    9003,
    9006,
}
TERMINAL_ALERT_STATUSES = ("closed", "false_positive", "resolved", "suppressed")


def _id_list(rule_ids: set[int]) -> str:
    return ",".join(str(rule_id) for rule_id in sorted(rule_ids))


def _load_target_stream_rules() -> list[dict[str, Any]]:
    found: dict[int, dict[str, Any]] = {}
    for pack_name in PACK_FILES:
        pack_path = PACK_DIR / pack_name
        if not pack_path.exists():
            continue
        payload = json.loads(pack_path.read_text(encoding="utf-8"))
        pack_id = str(payload.get("pack_id") or pack_name)
        for item in payload.get("stream_rules") or []:
            if not isinstance(item, dict):
                continue
            rule_id = int(item.get("id") or 0)
            if rule_id not in REPUBLISH_STREAM_RULE_IDS:
                continue
            rule = _build_stream_rule(item, pack_id=pack_id)
            if rule:
                found[rule_id] = rule
    missing = sorted(REPUBLISH_STREAM_RULE_IDS - set(found))
    if missing:
        raise RuntimeError(f"Target rules not found or not publishable: {missing}")
    return [found[rule_id] for rule_id in sorted(found)]


def _delete_runtime_rules(rule_ids: set[int]) -> None:
    if not rule_ids:
        return
    ids = _id_list(rule_ids)
    deps.get_ch_client().command(
        f"ALTER TABLE {deps.DETECTION_RULE_TABLE} DELETE WHERE id IN ({ids}) SETTINGS mutations_sync = 1"
    )
    deps.get_ch_client().command(
        f"ALTER TABLE siem.correlation_rules_stream DELETE WHERE id IN ({ids}) SETTINGS mutations_sync = 1"
    )


def _refresh_batch_rules() -> int:
    _ensure_batch_rule_table()
    executed = 0
    for sql_file in BATCH_SQL_FILES:
        payload = sql_file.read_text(encoding="utf-8")
        for statement in _split_sql_statements(payload):
            if statement.upper().startswith("ALTER TABLE") and " DELETE " in statement.upper() and "SETTINGS" not in statement.upper():
                statement = f"{statement} SETTINGS mutations_sync = 1"
            deps.get_ch_client().command(statement)
            executed += 1
    return executed


def _retire_open_alerts(rule_ids: set[int]) -> dict[str, int]:
    if not rule_ids:
        return {}
    deps.ensure_incident_workflow_support()
    ids = _id_list(rule_ids)
    terminal = ",".join(f"'{status}'" for status in TERMINAL_ALERT_STATUSES)
    counts: dict[str, int] = {}
    for table_name in ("siem.alerts_raw", "siem.alerts_agg"):
        result = deps.get_ch_client().query(
            f"""
            SELECT count()
            FROM {table_name}
            WHERE rule_id IN ({ids})
              AND lower(status) NOT IN ({terminal})
            """
        ).result_rows
        counts[table_name] = int(result[0][0]) if result and result[0] else 0
        deps.get_ch_client().command(
            f"""
            ALTER TABLE {table_name}
            UPDATE
                status = 'false_positive',
                assignee = 'system-fp-remediation',
                updated_ts = now()
            WHERE rule_id IN ({ids})
              AND lower(status) NOT IN ({terminal})
            SETTINGS mutations_sync = 0
            """
        )
    return counts


def _open_alert_count(rule_ids: set[int]) -> int:
    if not rule_ids:
        return 0
    ids = _id_list(rule_ids)
    terminal = ",".join(f"'{status}'" for status in TERMINAL_ALERT_STATUSES)
    result = deps.get_ch_client().query(
        f"""
        SELECT count()
        FROM siem.alerts_raw
        WHERE rule_id IN ({ids})
          AND lower(status) NOT IN ({terminal})
        """
    ).result_rows
    return int(result[0][0]) if result and result[0] else 0


def _wait_for_alert_retire(rule_ids: set[int], *, timeout_seconds: float = 60.0) -> int:
    deadline = time.monotonic() + timeout_seconds
    remaining = _open_alert_count(rule_ids)
    while remaining and time.monotonic() < deadline:
        time.sleep(2.0)
        remaining = _open_alert_count(rule_ids)
    return remaining


def main() -> int:
    deps.ensure_detection_support_tables()
    target_rules = _load_target_stream_rules()
    batch_refresh_statements = _refresh_batch_rules()
    _delete_runtime_rules(REPUBLISH_STREAM_RULE_IDS | RETIRE_STREAM_RULE_IDS)
    _insert_detection_rules(target_rules)
    _insert_stream_rules(target_rules)
    retired_alerts = _retire_open_alerts(RETIRE_OPEN_ALERT_RULE_IDS)
    remaining_open_alerts = _wait_for_alert_retire(RETIRE_OPEN_ALERT_RULE_IDS)
    stream_ids = deps._query_existing_rule_ids("siem.correlation_rules_stream", sorted(REPUBLISH_STREAM_RULE_IDS))  # type: ignore[attr-defined]
    print(
        json.dumps(
            {
                "republished_stream_rules": sorted(REPUBLISH_STREAM_RULE_IDS),
                "retired_stream_rules": sorted(RETIRE_STREAM_RULE_IDS),
                "refreshed_batch_rules": sorted(REFRESH_BATCH_RULE_IDS),
                "batch_refresh_statements": batch_refresh_statements,
                "retired_open_alerts": retired_alerts,
                "remaining_open_alerts": remaining_open_alerts,
                "published_stream_ids_present": sorted(stream_ids),
            },
            ensure_ascii=False,
        )
    )
    return 0 if remaining_open_alerts == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())
