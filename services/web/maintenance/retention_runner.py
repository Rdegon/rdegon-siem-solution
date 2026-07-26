from __future__ import annotations

import sys
from pathlib import Path

CURRENT_FILE = Path(__file__).resolve()
BASE_DIR = next((parent for parent in CURRENT_FILE.parents if (parent / "services").is_dir()), CURRENT_FILE.parent)
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

try:
    from services.web.app.config import CONFIG
    from services.web.app.deps import enforce_event_retention
except ModuleNotFoundError:
    WEB_DIR = CURRENT_FILE.parents[1]
    if str(WEB_DIR) not in sys.path:
        sys.path.insert(0, str(WEB_DIR))
    from app.config import CONFIG  # type: ignore[no-redef]
    from app.deps import enforce_event_retention  # type: ignore[no-redef]


def main() -> None:
    result = enforce_event_retention(CONFIG.hot_retention_hours, CONFIG.cold_retention_days)
    print(result)


if __name__ == "__main__":
    main()
