from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent
IMPORT_ROOTS = (
    ROOT / "services" / "web",
    ROOT / "services" / "web" / "app",
    ROOT / "services" / "web" / "app" / "routes",
    ROOT / "services" / "writer",
    ROOT / "services" / "stream_corr",
    ROOT / "services" / "filter",
    ROOT / "services" / "normalizer",
)


def _prepend_existing(path: Path) -> None:
    text = str(path)
    if path.exists() and text not in sys.path:
        sys.path.insert(0, text)


for import_root in reversed(IMPORT_ROOTS):
    _prepend_existing(import_root)
