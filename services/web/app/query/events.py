from __future__ import annotations

from typing import Any

from .shared import deps_module


def fetch_event_rows(*args: Any, **kwargs: Any) -> Any:
    return deps_module().fetch_event_rows(*args, **kwargs)
