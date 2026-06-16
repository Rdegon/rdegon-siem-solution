from __future__ import annotations

import importlib
import sys
import types
from pathlib import Path
from types import ModuleType


ROOT = Path(__file__).resolve().parents[1]
APP_ROOT = ROOT / "services" / "web"


def _ensure_path(path: Path) -> None:
    text = str(path)
    if text not in sys.path:
        sys.path.insert(0, text)


def _install_flat_app_package() -> None:
    package = types.ModuleType("app")
    package.__file__ = str(ROOT / "__init__.py")
    package.__path__ = [str(ROOT)]  # type: ignore[attr-defined]
    sys.modules["app"] = package


def import_app_module(name: str) -> ModuleType:
    """Import an app module from either deployed layout or flat clean checkout."""

    legacy_module = sys.modules.get(name)
    if isinstance(legacy_module, ModuleType):
        return legacy_module

    _ensure_path(APP_ROOT)
    _ensure_path(ROOT)
    module_name = f"app.{name}"
    try:
        return importlib.import_module(module_name)
    except ModuleNotFoundError as first_error:
        if not (ROOT / f"{name}.py").exists():
            raise first_error
        for loaded in list(sys.modules):
            if loaded == "app" or loaded.startswith("app."):
                sys.modules.pop(loaded, None)
        _install_flat_app_package()
        return importlib.import_module(module_name)
