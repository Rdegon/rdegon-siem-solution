from __future__ import annotations

import json
from pathlib import Path

from services.filter.filter_core import parse_expr


ROOT = Path(__file__).resolve().parents[1]


def test_all_diploma_core_stream_expressions_compile() -> None:
    pack = json.loads(
        (ROOT / "correlation_rule_packs" / "diploma_core_stream_v1.json").read_text(encoding="utf-8")
    )

    for rule in pack["stream_rules"]:
        assert parse_expr(str(rule["expr"])) is not None, f"rule {rule['id']} did not compile"
