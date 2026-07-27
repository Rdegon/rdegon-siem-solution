from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from unittest.mock import patch

from services.web.app.stale_runtime_cache import StaleRuntimeCache


def test_runtime_cache_round_trip(tmp_path: Path) -> None:
    cache = StaleRuntimeCache(
        tmp_path / "runtime.json",
        ttl_seconds=60,
    )

    cache.put("health", {"status": "healthy"})

    assert cache.get("health") == ({"status": "healthy"}, False)


def test_runtime_cache_returns_stale_and_schedules_refresh(
    tmp_path: Path,
) -> None:
    path = tmp_path / "runtime.json"
    path.write_text(
        json.dumps(
            {
                "dashboard": {
                    "updated_ts": time.time() - 120,
                    "payload": {"events": 10},
                }
            }
        ),
        encoding="utf-8",
    )
    cache = StaleRuntimeCache(
        path,
        ttl_seconds=30,
        max_stale_seconds=600,
    )

    with patch.object(cache, "schedule", return_value=True) as schedule:
        payload = asyncio.run(
            cache.get_or_refresh(
                "dashboard",
                lambda: {"events": 20},
            )
        )

    assert payload == {"events": 10}
    schedule.assert_called_once()


def test_runtime_cache_loads_cold_value_off_event_loop(tmp_path: Path) -> None:
    cache = StaleRuntimeCache(
        tmp_path / "runtime.json",
        ttl_seconds=60,
    )

    payload = asyncio.run(
        cache.get_or_refresh(
            "topology",
            lambda: {"nodes": 4},
        )
    )

    assert payload == {"nodes": 4}
    assert cache.get("topology") == ({"nodes": 4}, False)
