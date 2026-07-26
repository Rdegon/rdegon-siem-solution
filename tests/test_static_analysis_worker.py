from __future__ import annotations

import argparse
import json
from pathlib import Path

from services.security_analysis import static_worker


def test_process_once_moves_file_and_writes_event(tmp_path: Path, monkeypatch) -> None:
    inbox = tmp_path / "inbox"
    quarantine = tmp_path / "quarantine"
    rules = tmp_path / "rules"
    output = tmp_path / "result.jsonl"
    inbox.mkdir()
    rules.mkdir()
    sample = inbox / "sample.bin"
    sample.write_bytes(b"static sample")

    monkeypatch.setattr(
        static_worker,
        "analyze_file",
        lambda path, **_: {
            "file.sha256": "a" * 64,
            "file.path": str(path),
            "verdict": "clean",
        },
    )
    args = argparse.Namespace(
        inbox=str(inbox),
        quarantine=str(quarantine),
        rules=str(rules),
        output=str(output),
        timeout=1,
        limit=20,
    )

    assert static_worker.process_once(args) == 1
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["file.sha256"] == "a" * 64
    assert payload["file.quarantine_path"].endswith("a" * 64 + ".bin")
    assert not sample.exists()
