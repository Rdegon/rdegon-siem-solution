#!/usr/bin/env python3
"""Exec the configured Xray binary without systemd executable-path expansion."""

from __future__ import annotations

import os
from pathlib import Path


def main() -> None:
    binary = Path(os.getenv("XUI_BRIDGE_XRAY_BINARY") or "")
    config = Path("/run/siem-xui-vless-bridge/config.json")
    if not binary.is_absolute() or not binary.is_file() or not os.access(binary, os.X_OK):
        raise RuntimeError("Configured Xray binary is not an executable absolute path")
    if not config.is_file() or config.is_symlink():
        raise RuntimeError("Rendered Xray bridge configuration is missing or unsafe")
    os.execv(str(binary), [str(binary), "run", "-config", str(config)])


if __name__ == "__main__":
    main()
