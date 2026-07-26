from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

_publish_timeout = int(os.getenv("SIEM_FILTER_RULE_PUBLISH_TIMEOUT_SECONDS", "300"))
_configured_ch_timeout = int(os.getenv("SIEM_CH_SEND_RECEIVE_TIMEOUT_SECONDS", "20"))
os.environ["SIEM_CH_SEND_RECEIVE_TIMEOUT_SECONDS"] = str(
    max(_publish_timeout, _configured_ch_timeout)
)

from deploy.runtime_imports import import_app_module  # noqa: E402

deps = import_app_module("deps")


FILTER_RULES_SQL = ROOT / "sql" / "12_filter_rule_seed.sql"
FILTER_RULE_MUTATION_TIMEOUT_SECONDS = _publish_timeout
FILTER_RULE_IDS = tuple(range(3001, 3017))


def _ensure_filter_rule_table() -> None:
    deps.get_ch_client().command(
        """
        CREATE TABLE IF NOT EXISTS siem.filter_rules
        (
            id UInt32,
            name String,
            description String,
            priority UInt32,
            expr String,
            action LowCardinality(String),
            tags Array(String),
            enabled UInt8,
            created_ts DateTime DEFAULT now(),
            updated_ts DateTime DEFAULT now()
        )
        ENGINE = MergeTree
        ORDER BY (priority, id)
        """
    )


def _split_sql_statements(payload: str) -> list[str]:
    statements: list[str] = []
    current: list[str] = []
    in_string = False
    i = 0
    while i < len(payload):
        char = payload[i]
        current.append(char)
        if char == "'":
            if i + 1 < len(payload) and payload[i + 1] == "'":
                current.append(payload[i + 1])
                i += 2
                continue
            in_string = not in_string
        elif char == ";" and not in_string:
            statement = "".join(current).strip()
            if statement:
                statements.append(statement[:-1].strip())
            current = []
        i += 1
    tail = "".join(current).strip()
    if tail:
        statements.append(tail)
    return [statement for statement in statements if statement]


def _wait_for_filter_rule_deletion(timeout_seconds: int) -> None:
    deadline = time.monotonic() + timeout_seconds
    rule_ids = ", ".join(str(rule_id) for rule_id in FILTER_RULE_IDS)
    while True:
        remaining = int(
            deps.get_ch_client()
            .query(
                f"""
                SELECT count()
                FROM siem.filter_rules
                WHERE id IN ({rule_ids})
                """
            )
            .result_rows[0][0]
        )
        if remaining == 0:
            return
        if time.monotonic() >= deadline:
            raise TimeoutError(
                f"Timed out waiting for deletion of {remaining} filter rule row(s)"
            )
        time.sleep(1)


def main() -> int:
    _ensure_filter_rule_table()
    payload = FILTER_RULES_SQL.read_text(encoding="utf-8")
    statements = _split_sql_statements(payload)
    executed = 0
    for statement in statements:
        is_delete = statement.lstrip().upper().startswith(
            "ALTER TABLE SIEM.FILTER_RULES DELETE"
        )
        if is_delete:
            deps.get_ch_client().command(
                statement,
                settings={"mutations_sync": 0},
            )
            _wait_for_filter_rule_deletion(FILTER_RULE_MUTATION_TIMEOUT_SECONDS)
        else:
            deps.get_ch_client().command(statement)
        executed += 1
    count = int(
        deps.get_ch_client()
        .query("SELECT count() FROM siem.filter_rules WHERE enabled = 1")
        .result_rows[0][0]
    )
    print(json.dumps({"executed": executed, "enabled_filter_rules": count}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
