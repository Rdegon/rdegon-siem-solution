#!/usr/bin/env python3
"""Refresh ClamAV signatures without invalidating a usable local database."""

from __future__ import annotations

import glob
import os
import subprocess
import sys


DATABASE_GLOBS = (
    "/var/lib/clamav/*.cvd",
    "/var/lib/clamav/*.cld",
    "/var/lib/clamav/*.hdb",
    "/var/lib/clamav/*.ndb",
)


def usable_database_paths() -> list[str]:
    paths: set[str] = set()
    for pattern in DATABASE_GLOBS:
        for path in glob.glob(pattern):
            try:
                if os.path.getsize(path) > 0:
                    paths.add(path)
            except OSError:
                continue
    return sorted(paths)


def main() -> int:
    before = usable_database_paths()
    try:
        result = subprocess.run(
            ["/usr/bin/freshclam", "--stdout"],
            check=False,
            text=True,
            timeout=900,
        )
    except subprocess.TimeoutExpired:
        result = None

    after = usable_database_paths()
    if result is not None and result.returncode == 0:
        subprocess.run(
            ["/usr/bin/systemctl", "try-reload-or-restart", "clamav-daemon.service"],
            check=False,
            timeout=120,
        )
        return 0

    if after or before:
        reason = "timeout" if result is None else f"exit={result.returncode}"
        print(
            f"ClamAV update deferred ({reason}); retaining "
            f"{len(after or before)} usable local signature file(s).",
            file=sys.stderr,
        )
        return 0

    print("ClamAV update failed and no usable signature database exists.", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
