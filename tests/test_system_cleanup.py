from __future__ import annotations

import os

os.environ.setdefault("SIEM_CH_HOST", "127.0.0.1")
os.environ.setdefault("SIEM_CH_USER", "default")
os.environ.setdefault("SIEM_CH_PASSWORD", "test-clickhouse-password")
os.environ.setdefault("SIEM_ADMIN_DEFAULT_PASSWORD", "test-admin-password")
os.environ.setdefault("SIEM_JWT_SECRET", "test-jwt-secret")

from deploy import system_cleanup


class _Result:
    def __init__(self, rows):
        self.result_rows = rows


class _Client:
    def __init__(self, *, pending: bool = False):
        self.pending = pending
        self.commands: list[str] = []

    def query(self, query: str, parameters=None):
        if "system.columns" in query:
            return _Result([("ts",), ("message",), ("normalized_json",)])
        if "system.mutations" in query:
            return _Result([(1 if self.pending else 0,)])
        raise AssertionError(query)

    def command(self, command: str):
        self.commands.append(command)


def test_high_volume_cleanup_is_time_bounded(monkeypatch) -> None:
    monkeypatch.setenv("SIEM_SYSTEM_CLEANUP_LOOKBACK_DAYS", "5")
    client = _Client()

    result = system_cleanup._cleanup_clickhouse_table(
        client,
        "siem.events",
        ("message", "normalized_json"),
        time_column="ts",
    )

    assert result == "bounded schema-aware marker cleanup"
    assert "ts >= now() - toIntervalDay(5)" in client.commands[0]
    assert "mutations_sync = 0" in client.commands[0]


def test_cleanup_does_not_stack_mutations() -> None:
    client = _Client(pending=True)

    result = system_cleanup._cleanup_clickhouse_table(
        client,
        "siem.events",
        ("message",),
        time_column="ts",
    )

    assert result == "deferred: pending mutation"
    assert client.commands == []
