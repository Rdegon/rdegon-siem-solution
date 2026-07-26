from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class _Result:
    def __init__(self, value: int) -> None:
        self.result_rows = [[value]]


class _Client:
    def __init__(self, pending: list[int]) -> None:
        self.pending = pending

    def query(self, _query: str) -> _Result:
        return _Result(self.pending.pop(0))


def _load_module(client: _Client):
    fake_deps = types.SimpleNamespace(get_ch_client=lambda: client)
    fake_runtime_imports = types.ModuleType("deploy.runtime_imports")
    fake_runtime_imports.import_app_module = lambda _name: fake_deps
    original = sys.modules.get("deploy.runtime_imports")
    sys.modules["deploy.runtime_imports"] = fake_runtime_imports
    try:
        spec = importlib.util.spec_from_file_location(
            "publish_filter_rules_under_test",
            ROOT / "deploy" / "publish_filter_rules.py",
        )
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        if original is None:
            sys.modules.pop("deploy.runtime_imports", None)
        else:
            sys.modules["deploy.runtime_imports"] = original


def test_wait_for_filter_rule_deletion_polls_until_done(monkeypatch) -> None:
    module = _load_module(_Client([2, 1, 0]))
    monkeypatch.setattr(module.time, "sleep", lambda _seconds: None)

    module._wait_for_filter_rule_deletion(5)


def test_wait_for_filter_rule_deletion_times_out(monkeypatch) -> None:
    module = _load_module(_Client([1, 1]))
    ticks = iter([0.0, 2.0])
    monkeypatch.setattr(module.time, "monotonic", lambda: next(ticks))
    monkeypatch.setattr(module.time, "sleep", lambda _seconds: None)

    try:
        module._wait_for_filter_rule_deletion(1)
    except TimeoutError as exc:
        assert "filter rule row" in str(exc)
    else:
        raise AssertionError("expected filter rule mutation timeout")


def test_approved_scanner_filter_keeps_ids_telemetry_searchable() -> None:
    payload = (ROOT / "sql" / "12_filter_rule_seed.sql").read_text(encoding="utf-8")

    assert (
        "tags contains ''allowlist:siem_approved_scanner'' "
        "and event.type == ''windows_logon_failure''"
    ) in payload
