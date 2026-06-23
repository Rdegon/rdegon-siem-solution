from __future__ import annotations

import sys
import types
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
IMPORT_ROOTS = (
    ROOT,
    ROOT / "services" / "web",
    ROOT / "services" / "web" / "app",
    ROOT / "services" / "web" / "app" / "routes",
    ROOT / "services" / "writer",
    ROOT / "services" / "stream_corr",
    ROOT / "services" / "filter",
    ROOT / "services" / "normalizer",
)

for import_root in reversed(IMPORT_ROOTS):
    text = str(import_root)
    if import_root.exists() and text not in sys.path:
        sys.path.insert(0, text)

APP_ROOT = ROOT / "services" / "web" / "app"

if "app" not in sys.modules:
    app_module = types.ModuleType("app")
    app_module.__path__ = [str(APP_ROOT)]  # type: ignore[attr-defined]
    app_module.__file__ = str(APP_ROOT / "__init__.py")
    sys.modules["app"] = app_module

if "repo_testpkg" not in sys.modules:
    repo_testpkg = types.ModuleType("repo_testpkg")
    repo_testpkg.__path__ = [str(APP_ROOT)]  # type: ignore[attr-defined]
    repo_testpkg.__file__ = str(APP_ROOT / "__init__.py")
    sys.modules["repo_testpkg"] = repo_testpkg
