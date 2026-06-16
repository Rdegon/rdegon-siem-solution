from __future__ import annotations

import argparse
import json
import subprocess
import sys
import venv
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT_DIR = ROOT.parent / "siem_project_bundle" / "bin"
DEFAULT_VENV_DIR = ROOT / ".build" / "siem-operator-venv"
DEFAULT_WORK_DIR = ROOT / ".build" / "pyinstaller-work"
DEFAULT_SPEC_DIR = ROOT / ".build" / "pyinstaller-spec"
HIDDEN_IMPORTS = (
    "app.control_plane_access_ops",
    "app.control_plane_response_ops",
    "app.deps",
    "app.enterprise_control_plane",
    "control_plane_access_ops",
    "control_plane_response_ops",
    "deploy.export_clean_project_bundle",
    "deploy.distribution_toolkit",
    "deploy.distributed_eps_benchmark",
    "deploy.export_siem_docs",
    "deploy.storage_ha_drill",
    "deploy.storage_ha_restore_verify",
    "deploy.system_cleanup",
    "enterprise_control_plane",
)


def _python_in_venv(venv_dir: Path) -> Path:
    if sys.platform.startswith("win"):
        return venv_dir / "Scripts" / "python.exe"
    return venv_dir / "bin" / "python"


def _ensure_venv(venv_dir: Path) -> Path:
    python_path = _python_in_venv(venv_dir)
    if not python_path.exists():
        venv.EnvBuilder(with_pip=True).create(str(venv_dir))
    return python_path


def _run(command: list[str]) -> None:
    subprocess.run(command, check=True)


def build_operator_binary(
    *,
    repo_root: Path = ROOT,
    output_dir: Path = DEFAULT_OUTPUT_DIR,
    venv_dir: Path = DEFAULT_VENV_DIR,
) -> dict[str, str | bool]:
    repo_root = repo_root.resolve()
    output_dir = output_dir.resolve()
    venv_dir = venv_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    DEFAULT_WORK_DIR.mkdir(parents=True, exist_ok=True)
    DEFAULT_SPEC_DIR.mkdir(parents=True, exist_ok=True)
    cli_path = repo_root / "tools" / "siem_operator_cli.py"
    python_path = _ensure_venv(venv_dir)
    _run([str(python_path), "-m", "pip", "install", "--upgrade", "pip", "pyinstaller"])
    command = [
        str(python_path),
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--clean",
        "--onefile",
        "--name",
        "siem-operator",
        "--distpath",
        str(output_dir),
        "--workpath",
        str(DEFAULT_WORK_DIR),
        "--specpath",
        str(DEFAULT_SPEC_DIR),
        "--paths",
        str(repo_root),
        "--paths",
        str(repo_root / "services" / "web" / "app"),
    ]
    for hidden_import in HIDDEN_IMPORTS:
        command.extend(["--hidden-import", hidden_import])
    command.append(str(cli_path))
    _run(command)
    binary_path = output_dir / ("siem-operator.exe" if sys.platform.startswith("win") else "siem-operator")
    return {
        "built": binary_path.exists(),
        "binary_path": str(binary_path),
        "output_dir": str(output_dir),
        "venv_dir": str(venv_dir),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Build the SIEM operator binary.")
    parser.add_argument("--repo-root", default=str(ROOT), help="Repo root to build from")
    parser.add_argument("--output-dir", default=str(DEFAULT_OUTPUT_DIR), help="Output directory for the binary")
    parser.add_argument("--venv-dir", default=str(DEFAULT_VENV_DIR), help="Build venv directory")
    args = parser.parse_args(argv)
    result = build_operator_binary(
        repo_root=Path(args.repo_root),
        output_dir=Path(args.output_dir),
        venv_dir=Path(args.venv_dir),
    )
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
