from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
TRANSFER_ROOT = ROOT.parent
DEFAULT_TARGET_ROOT = TRANSFER_ROOT / "siem_project_bundle"
DEFAULT_DOCS_ROOT = DEFAULT_TARGET_ROOT / "siem_docs"
OPERATOR_BUNDLE = TRANSFER_ROOT / "access" / "operator_docs" / "OPERATOR_ACCESS_BUNDLE.md"

try:
    from .export_siem_docs import export_siem_docs
except ImportError:  # pragma: no cover - local script fallback
    from export_siem_docs import export_siem_docs  # type: ignore[no-redef]


def _tracked_files(project_root: Path) -> list[str]:
    completed = subprocess.run(
        ["git", "-C", str(project_root), "ls-files", "-z"],
        capture_output=True,
        check=True,
    )
    raw = completed.stdout.decode("utf-8", errors="replace")
    return [item for item in raw.split("\x00") if item.strip()]


def _copy_project_tree(*, project_root: Path, target_root: Path, tracked_files: list[str]) -> list[str]:
    copied: list[str] = []
    for relative_path in tracked_files:
        source_path = project_root / relative_path
        if not source_path.exists() or not source_path.is_file():
            continue
        destination_path = target_root / "project" / relative_path
        destination_path.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source_path, destination_path)
        copied.append(relative_path.replace("\\", "/"))
    return copied


def _write_bundle_readme(*, target_root: Path, copied_files: list[str], docs_result: dict[str, Any], binary_built: bool) -> None:
    lines = [
        "# SIEM Project Bundle",
        "",
        "Curated export of the backend project, local documentation set, and operator tooling.",
        "",
        f"- project_root: `{ROOT}`",
        f"- exported_files: `{len(copied_files)}`",
        f"- docs_exported: `{docs_result.get('docs_exported', 0)}`",
        f"- operator_binary_built: `{str(binary_built).lower()}`",
        "",
        "## Structure",
        "",
        "- `project/` - clean tracked project files copied from the repository",
        "- `siem_docs/` - exported documentation and operator bundle",
        "- `operator_bundle/` - duplicated operator access bundle",
        "- `bin/` - built operator binary and helper launcher",
        "- `manifest.json` - export inventory",
        "",
        "## Primary entry points",
        "",
        "- `project/docs/README.md`",
        "- `siem_docs/README.md`",
        "- `bin/siem-operator.exe`",
        "",
    ]
    (target_root / "README.md").write_text("\n".join(lines), encoding="utf-8")


def _build_operator_binary(*, project_root: Path, output_dir: Path) -> dict[str, Any]:
    script_path = project_root / "deploy" / "build_siem_operator_binary.py"
    completed = subprocess.run(
        [
            sys.executable,
            str(script_path),
            "--output-dir",
            str(output_dir),
            "--repo-root",
            str(project_root),
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    payload = completed.stdout.strip().splitlines()[-1] if completed.stdout.strip() else "{}"
    try:
        return json.loads(payload)
    except json.JSONDecodeError:
        return {"raw_stdout": completed.stdout, "raw_stderr": completed.stderr}


def export_clean_project_bundle(
    *,
    target_root: Path | None = None,
    project_root: Path = ROOT,
    docs_root: Path | None = None,
    build_binary: bool = False,
) -> dict[str, Any]:
    resolved_target = Path(target_root or DEFAULT_TARGET_ROOT).resolve()
    resolved_docs = Path(docs_root or (resolved_target / "siem_docs")).resolve()
    if resolved_target.exists():
        shutil.rmtree(resolved_target)
    (resolved_target / "project").mkdir(parents=True, exist_ok=True)
    (resolved_target / "bin").mkdir(parents=True, exist_ok=True)
    (resolved_target / "operator_bundle").mkdir(parents=True, exist_ok=True)

    tracked_files = _tracked_files(project_root)
    copied_files = _copy_project_tree(project_root=project_root, target_root=resolved_target, tracked_files=tracked_files)
    docs_result = export_siem_docs(target_root=resolved_docs)

    operator_bundle_copied = False
    if OPERATOR_BUNDLE.exists():
        shutil.copy2(OPERATOR_BUNDLE, resolved_target / "operator_bundle" / OPERATOR_BUNDLE.name)
        operator_bundle_copied = True

    binary_result: dict[str, Any] = {"built": False}
    if build_binary:
        binary_result = _build_operator_binary(project_root=project_root, output_dir=resolved_target / "bin")

    manifest = {
        "project_root": str(project_root),
        "target_root": str(resolved_target),
        "docs_root": str(resolved_docs),
        "tracked_files_total": len(tracked_files),
        "copied_files_total": len(copied_files),
        "operator_bundle_copied": operator_bundle_copied,
        "binary": binary_result,
    }
    (resolved_target / "manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    _write_bundle_readme(
        target_root=resolved_target,
        copied_files=copied_files,
        docs_result=docs_result,
        binary_built=bool(binary_result.get("built")),
    )
    return {
        "target_root": str(resolved_target),
        "docs_root": str(resolved_docs),
        "copied_files_total": len(copied_files),
        "operator_bundle_copied": operator_bundle_copied,
        "binary": binary_result,
        "manifest": manifest,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Export a clean SIEM project bundle with docs and optional operator binary.")
    parser.add_argument("--target-root", default=str(DEFAULT_TARGET_ROOT), help="Target directory for the clean bundle")
    parser.add_argument("--docs-root", default="", help="Optional docs export target; defaults to <target-root>/siem_docs")
    parser.add_argument("--build-binary", action="store_true", help="Build the operator binary into the bundle bin directory")
    args = parser.parse_args(argv)
    result = export_clean_project_bundle(
        target_root=Path(args.target_root),
        docs_root=Path(args.docs_root) if str(args.docs_root).strip() else None,
        build_binary=bool(args.build_binary),
    )
    print(json.dumps({key: value for key, value in result.items() if key != "manifest"}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
