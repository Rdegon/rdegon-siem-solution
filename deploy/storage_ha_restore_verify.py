from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path

from deploy.env_file_runtime import maybe_load_runtime_env

maybe_load_runtime_env()


REQUIRED_BINARIES = (
    "clickhouse-client",
    "pg_isready",
    "pg_basebackup",
    "mongosh",
    "mongodump",
    "mongorestore",
)


def build_restore_verification(*, backup_root: Path | None = None) -> dict[str, object]:
    resolved_root = Path(backup_root or "/tmp").resolve()
    binaries = {name: bool(shutil.which(name)) for name in REQUIRED_BINARIES}
    artifacts = [
        str(path)
        for path in sorted(resolved_root.glob("siem-*backup-*"))
        if path.exists()
    ]
    return {
        "backup_root": str(resolved_root),
        "binaries": binaries,
        "all_binaries_present": all(binaries.values()),
        "artifacts_detected": artifacts[:50],
        "artifacts_total": len(artifacts),
        "restore_ready": all(binaries.values()) and bool(artifacts),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify storage restore prerequisites")
    parser.add_argument("--backup-root", default="/tmp")
    args = parser.parse_args()
    result = build_restore_verification(backup_root=Path(args.backup_root))
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
