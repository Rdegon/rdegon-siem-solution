from __future__ import annotations

import importlib
import json
import os
import shlex
import sys
import time
import types
from pathlib import Path

try:
    import paramiko
except ModuleNotFoundError:  # pragma: no cover - optional for local-only invocation
    paramiko = None  # type: ignore[assignment]

ROOT = Path(__file__).resolve().parents[1]
DEPLOY_ROOT = Path(__file__).resolve().parent
SOURCE_DOCS = ROOT / "docs"
TRANSFER_ROOT = ROOT.parent
OPERATOR_BUNDLE = TRANSFER_ROOT / "access" / "operator_docs" / "OPERATOR_ACCESS_BUNDLE.md"
APP_ROOT = ROOT / "services" / "web"
DEFAULT_REMOTE_ROOT = "/opt/siem/siem-solution"
DEFAULT_REMOTE_PYTHON = "/opt/siem/venv-web/bin/python"
DEFAULT_REMOTE_ENV_FILE = "/etc/siem/web.env"

for candidate in (str(DEPLOY_ROOT), str(APP_ROOT), str(ROOT)):
    if candidate not in sys.path:
        sys.path.insert(0, candidate)

from env_file_runtime import maybe_load_runtime_env  # noqa: E402

maybe_load_runtime_env()


def _doc_name(relative_path: Path) -> str:
    safe_name = str(relative_path).replace("\\", "/").strip("/")
    return safe_name.replace("/", "__")


def _connect_client(host: str, user: str, password: str, *, attempts: int = 5, delay_seconds: float = 3.0) -> "paramiko.SSHClient":
    if paramiko is None:
        raise RuntimeError("paramiko is required for remote runtime docs publishing")
    last_error: Exception | None = None
    for attempt in range(1, attempts + 1):
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                host,
                username=user,
                password=password,
                timeout=20,
                banner_timeout=20,
                auth_timeout=20,
                look_for_keys=False,
                allow_agent=False,
            )
            return client
        except Exception as exc:  # noqa: BLE001
            last_error = exc
            client.close()
            if attempt == attempts:
                break
            print(f"ssh connect attempt {attempt}/{attempts} failed: {exc}", file=sys.stderr)
            time.sleep(delay_seconds)
    raise RuntimeError(f"Unable to connect to {host} after {attempts} attempts: {last_error}")


def _run_remote_command(
    client: "paramiko.SSHClient",
    command: str,
    *,
    sudo_password: str = "",
    use_sudo: bool = False,
) -> tuple[int, str, str]:
    wrapped = f"sudo -S -p '' bash -lc {shlex.quote(command)}" if use_sudo else command
    stdin, stdout, stderr = client.exec_command(wrapped, get_pty=use_sudo)
    if use_sudo:
        stdin.write(f"{sudo_password}\n")
        stdin.flush()
    out = stdout.read().decode("utf-8", errors="replace")
    err = stderr.read().decode("utf-8", errors="replace")
    code = stdout.channel.recv_exit_status()
    return code, out, err


def _import_local_deps():
    try:
        from app import deps as deps_module  # type: ignore[import-not-found]

        return deps_module
    except Exception as first_error:  # noqa: BLE001
        if not (ROOT / "deps.py").exists():
            raise RuntimeError(f"Unable to import runtime deps via app package: {first_error}") from first_error
        sys.modules.pop("app.deps", None)
        package = sys.modules.get("app")
        if package is None or not getattr(package, "__path__", None):
            package = types.ModuleType("app")
            package.__path__ = [str(ROOT)]  # type: ignore[attr-defined]
            sys.modules["app"] = package
        try:
            return importlib.import_module("app.deps")
        except Exception as second_error:  # noqa: BLE001
            raise RuntimeError(
                f"Unable to import runtime deps locally via app package ({first_error}) or synthetic package ({second_error})"
            ) from second_error


def _publish_local_docs() -> dict[str, object]:
    deps = _import_local_deps()
    published: list[str] = []
    for path in sorted(SOURCE_DOCS.rglob("*.md")):
        relative_path = path.relative_to(SOURCE_DOCS)
        deps.save_runtime_doc(_doc_name(relative_path), path.read_text(encoding="utf-8"))
        published.append(str(relative_path).replace("\\", "/"))
    if OPERATOR_BUNDLE.exists():
        deps.save_runtime_doc("operator_access_bundle.md", OPERATOR_BUNDLE.read_text(encoding="utf-8"))
        published.append("operator_access_bundle.md")
    return {"published_docs": len(published), "items": published, "mode": "local"}


def _extract_json_payload(text: str) -> dict[str, object]:
    for raw_line in reversed(text.splitlines()):
        line = raw_line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            return payload
    raise RuntimeError(f"Remote runtime docs publish did not return a JSON payload: {text.strip() or '<empty>'}")


def _publish_remote_docs() -> dict[str, object]:
    host = str(os.getenv("SIEM_VM4_HOST", "")).strip()
    user = str(os.getenv("SIEM_VM4_USER", "")).strip()
    password = str(os.getenv("SIEM_VM4_PASSWORD", "")).strip()
    remote_root = str(os.getenv("SIEM_VM4_BASE_DIR", DEFAULT_REMOTE_ROOT)).strip() or DEFAULT_REMOTE_ROOT
    remote_python = str(os.getenv("SIEM_VM4_WEB_PYTHON", DEFAULT_REMOTE_PYTHON)).strip() or DEFAULT_REMOTE_PYTHON
    remote_env_file = str(os.getenv("SIEM_VM4_WEB_ENV_PATH", DEFAULT_REMOTE_ENV_FILE)).strip() or DEFAULT_REMOTE_ENV_FILE
    if not host or not user or not password:
        raise RuntimeError("Missing SIEM_VM4_HOST/SIEM_VM4_USER/SIEM_VM4_PASSWORD for remote runtime docs publishing")
    client = _connect_client(host, user, password)
    try:
        command = (
            f"cd {shlex.quote(remote_root)} && "
            f"set -a && source {shlex.quote(remote_env_file)} && set +a && "
            "SIEM_PUBLISH_RUNTIME_DOCS_FORCE_LOCAL=1 "
            f"{shlex.quote(remote_python)} deploy/publish_runtime_docs.py"
        )
        code, out, err = _run_remote_command(client, command, sudo_password=password, use_sudo=True)
    finally:
        client.close()
    if err.strip():
        print(err.rstrip(), file=sys.stderr)
    if code != 0:
        raise RuntimeError(f"Remote runtime docs publish failed with exit code {code}")
    payload = _extract_json_payload(out)
    payload["mode"] = "remote"
    payload["remote_host"] = host
    return payload


def main() -> int:
    force_local = str(os.getenv("SIEM_PUBLISH_RUNTIME_DOCS_FORCE_LOCAL", "")).strip() in {"1", "true", "TRUE", "yes", "on"}
    try:
        payload = _publish_local_docs()
    except Exception as exc:  # noqa: BLE001
        if force_local:
            raise
        if not all(str(os.getenv(name, "")).strip() for name in ("SIEM_VM4_HOST", "SIEM_VM4_USER", "SIEM_VM4_PASSWORD")):
            raise
        print(f"local runtime docs publish unavailable, retrying on VM4: {exc}", file=sys.stderr)
        payload = _publish_remote_docs()
    print(json.dumps(payload, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
