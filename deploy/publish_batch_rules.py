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


BATCH_SQL_FILES = (
    ROOT / "sql_13_batch_corr_seed.sql",
    ROOT / "sql_15_batch_corr_soc_seed.sql",
)


def _ensure_batch_rule_table() -> None:
    deps.get_ch_client().command(
        """
        CREATE TABLE IF NOT EXISTS siem.correlation_rules_batch
        (
            id UInt32,
            name String,
            description String,
            enabled UInt8,
            severity LowCardinality(String),
            window_s UInt32,
            sql_template String,
            created_ts DateTime DEFAULT now(),
            updated_ts DateTime DEFAULT now()
        )
        ENGINE = MergeTree
        ORDER BY id
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


def main() -> int:
    _ensure_batch_rule_table()
    executed = 0
    for sql_file in BATCH_SQL_FILES:
        payload = sql_file.read_text(encoding="utf-8")
        for statement in _split_sql_statements(payload):
            if statement.upper().startswith("ALTER TABLE") and " DELETE " in statement.upper() and "SETTINGS" not in statement.upper():
                statement = f"{statement} SETTINGS mutations_sync = 0"
            deps.get_ch_client().command(statement)
            executed += 1
    count = int(
        deps.get_ch_client()
        .query("SELECT count() FROM siem.correlation_rules_batch WHERE enabled = 1")
        .result_rows[0][0]
    )
    print(json.dumps({"executed": executed, "enabled_batch_rules": count}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
