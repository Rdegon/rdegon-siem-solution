from __future__ import annotations

import json
import time
from pathlib import Path
from unittest.mock import patch

from services.web.app.query import assets, sources
from services.web.app.query.stale_cache import load_snapshot, save_snapshot


def test_snapshot_round_trip(tmp_path: Path) -> None:
    path = tmp_path / "inventory.json"
    save_snapshot(path, "24", [{"source_name": "siem-web", "events": 5}])

    snapshot = load_snapshot(path, "24", max_stale_seconds=60)

    assert snapshot is not None
    assert snapshot[1] == [{"source_name": "siem-web", "events": 5}]


def test_source_inventory_snapshot_is_reused_across_limits(tmp_path: Path) -> None:
    calls: list[tuple[int, int]] = []

    class FakeDeps:
        @staticmethod
        def fetch_source_inventory(*, limit: int, hours: int):
            calls.append((limit, hours))
            return [
                {"source_name": f"source-{index}", "events": 10 - index}
                for index in range(10)
            ]

    sources._CACHE.clear()
    with (
        patch.object(sources, "INVENTORY_CACHE_FILE", tmp_path / "sources.json"),
        patch("services.web.app.query.sources.deps_module", return_value=FakeDeps),
    ):
        assert len(sources.fetch_source_inventory(limit=8, hours=24)) == 8
        assert len(sources.fetch_source_inventory(limit=3, hours=24)) == 3

    assert calls == [(1000, 24)]


def test_stale_source_snapshot_returns_without_synchronous_refresh(
    tmp_path: Path,
) -> None:
    path = tmp_path / "sources.json"
    path.write_text(
        json.dumps(
            {
                "24": {
                    "updated_ts": time.time() - 600,
                    "items": [{"source_name": "cached-source", "events": 4}],
                }
            }
        ),
        encoding="utf-8",
    )
    sources._CACHE.clear()

    with (
        patch.object(sources, "INVENTORY_CACHE_FILE", path),
        patch.object(sources, "INVENTORY_CACHE_TTL_SECONDS", 30),
        patch(
            "services.web.app.query.sources.refresh_in_background",
            return_value=True,
        ) as refresh,
    ):
        rows = sources.fetch_source_inventory(limit=20, hours=24)

    assert rows == [{"source_name": "cached-source", "events": 4}]
    refresh.assert_called_once()


def test_asset_inventory_snapshot_is_reused_across_limits(tmp_path: Path) -> None:
    calls: list[tuple[int, int]] = []

    class FakeDeps:
        @staticmethod
        def fetch_assets(*, limit: int, hours: int):
            calls.append((limit, hours))
            return [
                {"asset": f"asset-{index}", "events": 10 - index}
                for index in range(10)
            ]

    assets._CACHE.clear()
    with (
        patch.object(assets, "INVENTORY_CACHE_FILE", tmp_path / "assets.json"),
        patch("services.web.app.query.assets.deps_module", return_value=FakeDeps),
    ):
        assert len(assets.fetch_assets(limit=7, hours=24)) == 7
        assert len(assets.fetch_assets(limit=2, hours=24)) == 2

    assert calls == [(500, 24)]
