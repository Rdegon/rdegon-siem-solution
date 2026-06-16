from __future__ import annotations

import os
from pathlib import Path


DEFAULT_ENV_FILE = Path("/etc/siem/web.env")


def parse_env_file(path: str | Path) -> dict[str, str]:
    env: dict[str, str] = {}
    for raw_line in Path(path).read_text(encoding="utf-8").splitlines():
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#") or "=" not in raw_line:
            continue
        key, value = raw_line.split("=", 1)
        key = key.strip()
        if key:
            env[key] = value
    return env


def load_env_file(path: str | Path, *, override: bool = False) -> dict[str, str]:
    loaded = parse_env_file(path)
    for key, value in loaded.items():
        if override or key not in os.environ:
            os.environ[key] = value
    return loaded


def maybe_load_runtime_env() -> dict[str, str]:
    configured = str(os.getenv("SIEM_ENV_FILE", "") or "").strip()
    path = Path(configured) if configured else DEFAULT_ENV_FILE
    if not path.exists():
        return {}
    try:
        return load_env_file(path)
    except OSError:
        return {}
