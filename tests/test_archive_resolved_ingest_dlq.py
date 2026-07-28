from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from deploy.archive_resolved_ingest_dlq import (
    DLQ_REPLAY_HASH_KEY,
    DLQ_STREAM_KEY,
    INGEST_METRICS_HASH_KEY,
    DlqSnapshot,
    archive_resolved_dlq,
    validate_snapshot,
)


def _create_runtime_database(path: Path, *, last_dlq_ts: str) -> None:
    conn = sqlite3.connect(path)
    try:
        conn.executescript(
            """
            CREATE TABLE hashes (
                key TEXT NOT NULL,
                field TEXT NOT NULL,
                value TEXT NOT NULL,
                PRIMARY KEY (key, field)
            );
            CREATE TABLE streams (
                stream_key TEXT NOT NULL,
                seq INTEGER NOT NULL,
                id TEXT NOT NULL,
                fields_json TEXT NOT NULL,
                PRIMARY KEY (stream_key, seq),
                UNIQUE (stream_key, id)
            );
            """
        )
        conn.executemany(
            "INSERT INTO hashes (key, field, value) VALUES (?, ?, ?)",
            (
                (INGEST_METRICS_HASH_KEY, "dlq_total", "1"),
                (INGEST_METRICS_HASH_KEY, "resolved_dlq_total", "1"),
                (INGEST_METRICS_HASH_KEY, "last_dlq_ts", last_dlq_ts),
                (DLQ_REPLAY_HASH_KEY, "1-1", '{"status":"success"}'),
                ("siem:ingest:sources", "host-a", '{"status":"healthy"}'),
            ),
        )
        conn.execute(
            "INSERT INTO streams (stream_key, seq, id, fields_json) VALUES (?, ?, ?, ?)",
            (
                DLQ_STREAM_KEY,
                1,
                "1-1",
                json.dumps({"ingest_ts": last_dlq_ts, "reason": "historical"}),
            ),
        )
        conn.commit()
    finally:
        conn.close()


def test_archive_preserves_non_dlq_state_and_creates_recovery_copy(tmp_path: Path) -> None:
    now = datetime(2026, 7, 28, 12, tzinfo=timezone.utc)
    database = tmp_path / "ingest-runtime.db"
    archives = tmp_path / "archives"
    _create_runtime_database(database, last_dlq_ts="2026-07-25T00:00:00Z")

    result = archive_resolved_dlq(
        database,
        archive_directory=archives,
        execute=True,
        minimum_age=timedelta(hours=24),
        retention=timedelta(days=7),
        now=now,
    )

    assert result["changed"] is True
    assert result["archived_stream_rows"] == 1
    assert result["archived_replay_rows"] == 1
    assert result["after"]["stream_rows"] == 0
    assert result["after"]["replay_rows"] == 0
    assert Path(result["archive"]).is_file()
    conn = sqlite3.connect(database)
    try:
        assert conn.execute(
            "SELECT value FROM hashes WHERE key = ? AND field = 'dlq_total'",
            (INGEST_METRICS_HASH_KEY,),
        ).fetchone()[0] == "0"
        assert conn.execute(
            "SELECT value FROM hashes WHERE key = 'siem:ingest:sources' AND field = 'host-a'"
        ).fetchone()[0] == '{"status":"healthy"}'
    finally:
        conn.close()


def test_archive_refuses_outstanding_or_recent_state() -> None:
    now = datetime(2026, 7, 28, 12, tzinfo=timezone.utc)
    with pytest.raises(RuntimeError, match="outstanding"):
        validate_snapshot(
            DlqSnapshot(2, 1, 2, 1, 2, "2026-07-25T00:00:00Z", ""),
            now=now,
            minimum_age=timedelta(hours=24),
        )
    with pytest.raises(RuntimeError, match="recent"):
        validate_snapshot(
            DlqSnapshot(1, 1, 1, 1, 1, "2026-07-28T11:30:00Z", ""),
            now=now,
            minimum_age=timedelta(hours=24),
        )
