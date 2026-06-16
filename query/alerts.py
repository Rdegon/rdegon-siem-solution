from __future__ import annotations

from typing import Any

from .shared import deps_module


def fetch_alerts_agg(*args: Any, **kwargs: Any) -> Any:
    return deps_module().fetch_alerts_agg(*args, **kwargs)


def fetch_alerts_raw(*args: Any, **kwargs: Any) -> Any:
    return deps_module().fetch_alerts_raw(*args, **kwargs)


def fetch_alert_history(*args: Any, **kwargs: Any) -> Any:
    return deps_module().fetch_alert_history(*args, **kwargs)
