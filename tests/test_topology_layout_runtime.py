from __future__ import annotations

import os
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

os.environ.setdefault("SIEM_CH_HOST", "127.0.0.1")
os.environ.setdefault("SIEM_CH_USER", "default")
os.environ.setdefault("SIEM_CH_PASSWORD", "test")
os.environ.setdefault("SIEM_JWT_SECRET", "test-secret")
os.environ.setdefault("SIEM_ADMIN_DEFAULT_PASSWORD", "test-password")
os.environ.setdefault("SIEM_CONTENT_STORE_BACKEND", "filesystem")

from services.web.app import topology_layout_runtime


def test_save_and_load_topology_layout_from_filesystem() -> None:
    with TemporaryDirectory() as directory, patch.dict(
        "os.environ",
        {"SIEM_TOPOLOGY_LAYOUT_DIR": directory},
    ), patch.object(
        topology_layout_runtime,
        "upsert_content_document",
        return_value=False,
    ), patch.object(
        topology_layout_runtime,
        "get_content_document",
        return_value=None,
    ), patch.object(
        topology_layout_runtime,
        "append_audit_event",
    ):
        saved = topology_layout_runtime.save_topology_layout(
            {
                "workspace": "network",
                "positions": {
                    "source:new-game-source": {
                        "x": 120.125,
                        "y": 240.875,
                        "segment": "servers-games",
                    }
                },
            },
            actor="operator",
        )
        loaded = topology_layout_runtime.get_topology_layout("network")

    assert saved["storage_backend"] == "filesystem"
    assert saved["node_count"] == 1
    assert loaded["positions"]["source:new-game-source"] == {
        "x": 120.12,
        "y": 240.88,
        "segment": "servers-games",
    }
    assert not Path(directory).exists()


def test_layout_sanitizer_rejects_oversized_payload() -> None:
    positions = {
        f"node:{index}": {"x": index, "y": index, "segment": "sec"}
        for index in range(601)
    }
    try:
        topology_layout_runtime._sanitize_positions(positions)
    except ValueError as exc:
        assert "600" in str(exc)
    else:
        raise AssertionError("Oversized topology layout was accepted")
