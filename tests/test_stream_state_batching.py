from __future__ import annotations

import sqlite3

from services.stream_state import SQLiteStreamState


def test_threshold_state_can_commit_once_per_transport_batch(tmp_path) -> None:
    state_path = tmp_path / "runtime-state.db"
    state = SQLiteStreamState(str(state_path))
    reader = sqlite3.connect(str(state_path))
    try:
        state.append_event(9007, "203.0.113.20", "event", "topic:0:1", 100.0, commit=False)
        state.trim_events(9007, "203.0.113.20", "event", 0.0, commit=False)

        assert reader.execute("SELECT count(*) FROM threshold_events").fetchone()[0] == 0

        state.flush()

        assert reader.execute("SELECT count(*) FROM threshold_events").fetchone()[0] == 1
    finally:
        reader.close()
        state.close()
