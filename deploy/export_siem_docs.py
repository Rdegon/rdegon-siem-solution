from __future__ import annotations

import argparse
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
SOURCE_DOCS = ROOT / "docs"
TRANSFER_ROOT = ROOT.parent
DEFAULT_TARGET_ROOT = TRANSFER_ROOT / "siem_docs"
OPERATOR_BUNDLE = TRANSFER_ROOT / "access" / "operator_docs" / "OPERATOR_ACCESS_BUNDLE.md"


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _copy_docs_tree(*, source_docs: Path, target_root: Path) -> list[dict[str, str]]:
    exported: list[dict[str, str]] = []
    docs_root = target_root / "system_docs"
    for path in sorted(source_docs.rglob("*")):
        relative_path = path.relative_to(source_docs)
        target_path = docs_root / relative_path
        if path.is_dir():
            target_path.mkdir(parents=True, exist_ok=True)
            continue
        target_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(path, target_path)
        exported.append(
            {
                "name": str(relative_path).replace("\\", "/"),
                "source": str(path),
                "target": str(target_path),
            }
        )
    return exported


def _write_readme(*, target_root: Path, exported_docs: list[dict[str, str]], source_docs: Path) -> None:
    lines = [
        "# SIEM Documentation Export",
        "",
        "Machine-local export of the current SIEM documentation set.",
        "",
        f"- exported_at: `{_now_iso()}`",
        f"- source_repo: `{ROOT}`",
        f"- docs_source: `{source_docs}`",
        f"- exported_to: `{target_root}`",
        f"- exported_docs: `{len(exported_docs)}`",
        "",
        "## Structure",
        "",
        "- `system_docs/` - engineering docs and runbooks from the repository",
        "- `operator_bundle/` - duplicated operator access bundle for manual support",
        "- `manifest.json` - export inventory",
        "",
        "## Primary entry points",
        "",
        "- `system_docs/README.md`",
        "- `system_docs/architecture.md`",
        "- `system_docs/configuration.md`",
        "- `system_docs/debugging.md`",
        "- `operator_bundle/OPERATOR_ACCESS_BUNDLE.md`",
        "",
    ]
    (target_root / "README.md").write_text("\n".join(lines), encoding="utf-8")


def export_siem_docs(*, target_root: Path | None = None, source_docs: Path = SOURCE_DOCS, operator_bundle: Path = OPERATOR_BUNDLE) -> dict[str, Any]:
    resolved_target = Path(target_root or DEFAULT_TARGET_ROOT).resolve()
    if resolved_target.exists():
        shutil.rmtree(resolved_target)
    (resolved_target / "system_docs").mkdir(parents=True, exist_ok=True)
    (resolved_target / "operator_bundle").mkdir(parents=True, exist_ok=True)

    exported_docs = _copy_docs_tree(source_docs=source_docs, target_root=resolved_target)
    operator_bundle_copied = False
    if operator_bundle.exists():
        shutil.copy2(operator_bundle, resolved_target / "operator_bundle" / operator_bundle.name)
        operator_bundle_copied = True

    manifest = {
        "generated_ts": _now_iso(),
        "source_repo": str(ROOT),
        "docs_source": str(source_docs),
        "target_root": str(resolved_target),
        "operator_bundle": str(operator_bundle),
        "operator_bundle_copied": operator_bundle_copied,
        "files": exported_docs,
    }
    (resolved_target / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    _write_readme(target_root=resolved_target, exported_docs=exported_docs, source_docs=source_docs)
    return {
        "target_root": str(resolved_target),
        "docs_exported": len(exported_docs),
        "operator_bundle": operator_bundle_copied,
        "manifest": manifest,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Export SIEM docs into a clean local folder.")
    parser.add_argument("--target-root", default=str(DEFAULT_TARGET_ROOT), help="Target directory for the docs export")
    args = parser.parse_args(argv)
    result = export_siem_docs(target_root=Path(args.target_root))
    print(json.dumps({key: value for key, value in result.items() if key != "manifest"}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
