from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MAX_TRACKED_FILE_BYTES = 5 * 1024 * 1024

FORBIDDEN_PATH_PARTS = {
    "__pycache__",
    ".pytest_cache",
    "node_modules",
    "dist",
    "build",
    "coverage",
    "htmlcov",
    ".mypy_cache",
    ".ruff_cache",
}

FORBIDDEN_SUFFIXES = {
    ".pyc",
    ".pyo",
    ".log",
    ".tmp",
    ".db",
    ".sqlite",
    ".sqlite3",
    ".zip",
    ".tar",
    ".gz",
    ".7z",
    ".pfx",
    ".p12",
    ".pem",
    ".key",
}

FORBIDDEN_BASENAMES = {
    ".env",
    "vault-token",
}

SECRET_PATTERNS = [
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\bghp_[A-Za-z0-9_]{30,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{30,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
]


def _git_list_candidate_files() -> list[str]:
    result = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=True,
    )
    return [line.strip() for line in result.stdout.splitlines() if line.strip()]


def _is_forbidden_path(path: str) -> str | None:
    parts = set(Path(path).parts)
    if parts & FORBIDDEN_PATH_PARTS:
        return "forbidden generated/cache directory"
    name = Path(path).name
    lowered = name.lower()
    if lowered in FORBIDDEN_BASENAMES or lowered.startswith(".env."):
        return "forbidden environment or token file"
    if Path(path).suffix.lower() in FORBIDDEN_SUFFIXES:
        return "forbidden generated/binary/secret suffix"
    if path.startswith("artifacts_") or "/artifacts_" in path.replace("\\", "/"):
        return "forbidden artifacts path"
    return None


def _scan_content(path: Path) -> str | None:
    try:
        payload = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return None
    for pattern in SECRET_PATTERNS:
        if pattern.search(payload):
            return f"suspicious secret pattern: {pattern.pattern}"
    return None


def main() -> int:
    errors: list[str] = []
    for rel_path in _git_list_candidate_files():
        reason = _is_forbidden_path(rel_path)
        if reason:
            errors.append(f"{rel_path}: {reason}")
            continue
        path = ROOT / rel_path
        if path.exists() and path.stat().st_size > MAX_TRACKED_FILE_BYTES:
            errors.append(f"{rel_path}: tracked file exceeds {MAX_TRACKED_FILE_BYTES} bytes")
        content_reason = _scan_content(path)
        if content_reason:
            errors.append(f"{rel_path}: {content_reason}")

    if errors:
        print("Repository hygiene check failed:", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    print("Repository hygiene check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
