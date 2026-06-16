from __future__ import annotations

import argparse
import json
import os
import subprocess
from pathlib import Path
from typing import Any

try:
    from .export_clean_project_bundle import export_clean_project_bundle
except ImportError:  # pragma: no cover - local script fallback
    from export_clean_project_bundle import export_clean_project_bundle  # type: ignore[no-redef]


ROOT = Path(__file__).resolve().parents[1]
PLAYGROUND_ROOT = ROOT.parent
DEFAULT_TOOLKIT_ROOT = PLAYGROUND_ROOT / "siem_distribution_toolkit"
DEFAULT_REMOTE_ROOT = "/opt/siem/siem-solution"
DEFAULT_HOSTS = (
    {
        "id": "vm1",
        "title": "SIEM-Ingest",
        "role": "ingest",
        "address": "192.168.1.35",
        "services": ["siem-ingest", "nginx"],
        "env_files": ["/etc/siem/ingest.env"],
        "cert_paths": ["/etc/siem/tls/ingest"],
    },
    {
        "id": "vm2",
        "title": "SIEM-Processing",
        "role": "processing",
        "address": "192.168.1.37",
        "services": ["siem-normalizer", "siem-normalizer@2", "siem-filter", "siem-filter@2"],
        "env_files": ["/etc/siem/processing.env"],
        "cert_paths": ["/etc/siem/tls/transport"],
    },
    {
        "id": "vm3",
        "title": "SIEM-Storage",
        "role": "storage",
        "address": "192.168.1.38",
        "services": ["clickhouse-server", "siem-writer", "siem-writer@2", "siem-stream-corr", "siem-batch-corr", "siem-alert-agg"],
        "env_files": ["/etc/siem/storage.env", "/etc/siem/storage-ha.env"],
        "cert_paths": ["/etc/siem/tls/storage"],
    },
    {
        "id": "vm4",
        "title": "SIEM-Web",
        "role": "control-plane",
        "address": "192.168.1.39",
        "services": ["siem-web", "nginx", "openvpn-client@home-gateway", "siem-jump-tunnels"],
        "env_files": ["/etc/siem/web.env", "/etc/siem/host-runtime-monitor.env"],
        "cert_paths": ["/etc/siem/tls/web"],
    },
    {
        "id": "vm5",
        "title": "SIEM-Transport",
        "role": "transport",
        "address": "192.168.1.40",
        "services": ["siem-kafka", "siem-normalizer@1", "siem-normalizer@2", "siem-filter@1", "siem-filter@2"],
        "env_files": ["/etc/siem/transport.env", "/etc/siem/storage-standby.env"],
        "cert_paths": ["/etc/siem/tls/kafka", "/etc/siem/tls/mongo"],
    },
)


def _git_text(project_root: Path, *args: str) -> str:
    try:
        completed = subprocess.run(
            ["git", "-C", str(project_root), *args],
            capture_output=True,
            text=True,
            check=True,
        )
    except Exception:  # noqa: BLE001
        return ""
    return str(completed.stdout or "").strip()


def resolve_project_version(project_root: Path = ROOT) -> dict[str, str]:
    sha = _git_text(project_root, "rev-parse", "HEAD")
    short_sha = _git_text(project_root, "rev-parse", "--short", "HEAD")
    describe = _git_text(project_root, "describe", "--always", "--dirty")
    return {
        "git_sha": sha,
        "git_short_sha": short_sha or (sha[:7] if sha else ""),
        "git_describe": describe or short_sha or sha[:7],
    }


def build_topology_manifest(*, env: dict[str, str] | None = None, project_root: Path = ROOT) -> dict[str, Any]:
    env_map = dict(os.environ if env is None else env)
    version = resolve_project_version(project_root)
    transport_backend = str(env_map.get("SIEM_TRANSPORT_BACKEND") or "kafka").strip().lower() or "kafka"
    topology = {
        "version": version,
        "transport_backend": transport_backend,
        "transport_bootstrap_servers": [item.strip() for item in str(env_map.get("SIEM_KAFKA_BOOTSTRAP_SERVERS") or "192.168.1.35:9092,192.168.1.37:9092,192.168.1.40:9092").split(",") if item.strip()],
        "control_plane_backend": str(env_map.get("SIEM_CONTROL_PLANE_BACKEND") or "postgres"),
        "content_store_backend": str(env_map.get("SIEM_CONTENT_STORE_BACKEND") or "mongo"),
        "stream_state_backend": str(env_map.get("SIEM_STREAM_STATE_BACKEND") or "sqlite"),
        "storage": {
            "clickhouse_hosts": [item.strip() for item in str(env_map.get("SIEM_CH_HOSTS") or "192.168.1.38:8123,192.168.1.40:8123").split(",") if item.strip()],
            "postgres_dsn_present": bool(str(env_map.get("SIEM_CONTROL_PLANE_PG_DSN") or "").strip()),
            "mongo_uri_present": bool(str(env_map.get("SIEM_MONGO_URI") or "").strip()),
        },
        "hosts": list(DEFAULT_HOSTS),
    }
    return topology


def build_upgrade_plan(*, project_root: Path = ROOT, target_version: str = "current", env: dict[str, str] | None = None) -> dict[str, Any]:
    topology = build_topology_manifest(env=env, project_root=project_root)
    current = dict(topology["version"])
    return {
        "current_version": current,
        "target_version": str(target_version or "current"),
        "topology_roles": [item["role"] for item in topology["hosts"]],
        "ordered_steps": [
            {"id": "backup", "title": "Create storage and control-plane backups", "required": True},
            {"id": "vm5", "title": "Validate transport/standby node readiness", "required": True},
            {"id": "vm1", "title": "Upgrade ingest edge and revalidate TLS/certs", "required": True},
            {"id": "vm2_vm5", "title": "Upgrade processing nodes and verify consumer lag returns to zero", "required": True},
            {"id": "vm3", "title": "Upgrade storage services and verify ClickHouse/SQLite health", "required": True},
            {"id": "vm4", "title": "Upgrade control plane and verify Postgres/Mongo/health surfaces", "required": True},
            {"id": "post_checks", "title": "Run CI/CD deploy smoke, host runtime checks, and restore verification", "required": True},
        ],
    }


def render_env_templates(*, topology: dict[str, Any]) -> dict[str, str]:
    transport_backend = str(topology.get("transport_backend") or "kafka")
    bootstrap_servers = ",".join(topology.get("transport_bootstrap_servers") or [])
    clickhouse_hosts = ",".join(dict(topology.get("storage") or {}).get("clickhouse_hosts") or [])
    return {
        "transport.env.sample": "\n".join(
            [
                f"SIEM_TRANSPORT_BACKEND={transport_backend}",
                f"SIEM_KAFKA_BOOTSTRAP_SERVERS={bootstrap_servers}",
                "SIEM_KAFKA_SECURITY_PROTOCOL=SASL_SSL",
                "SIEM_KAFKA_SASL_USERNAME=<set-me>",
                "SIEM_KAFKA_SASL_PASSWORD=<set-me>",
                "SIEM_KAFKA_SSL_CAFILE=/etc/siem/tls/kafka/ca.pem",
                "",
            ]
        ),
        "web.env.sample": "\n".join(
            [
                "SIEM_CONTROL_PLANE_BACKEND=postgres",
                "SIEM_CONTROL_PLANE_PG_DSN=host=<pg-primary>,<pg-standby> port=5432,5432 dbname=siem user=siem password=<set-me> target_session_attrs=read-write connect_timeout=2",
                "SIEM_CONTENT_STORE_BACKEND=mongo",
                "SIEM_MONGO_URI=mongodb://siem:<set-me>@<mongo-primary>:27017,<mongo-secondary1>:27017,<mongo-secondary2>:27017/siem_content?authSource=siem_content&replicaSet=siem-rs",
                "SIEM_MONGO_DB=siem_content",
                "SIEM_STREAM_STATE_BACKEND=sqlite",
                "SIEM_STREAM_STATE_SQLITE_PATH=/var/lib/siem-stream-corr/runtime-state.db",
                "",
            ]
        ),
        "storage.env.sample": "\n".join(
            [
                f"SIEM_CH_HOSTS={clickhouse_hosts}",
                "SIEM_CH_HOST=<primary-host>",
                "SIEM_CH_PORT=8123",
                "SIEM_CH_USER=siem",
                "SIEM_CH_PASSWORD=<set-me>",
                "SIEM_CH_DB=siem",
                "",
            ]
        ),
        "certs.README.md": "\n".join(
            [
                "# Certificate Layout",
                "",
                "- kafka: `/etc/siem/tls/kafka`",
                "- mongo: `/etc/siem/tls/mongo`",
                "- web: `/etc/siem/tls/web`",
                "- ingest: `/etc/siem/tls/ingest`",
                "- storage: `/etc/siem/tls/storage`",
                "",
                "Place environment-specific CA, cert, and key files here before bootstrap.",
                "",
            ]
        ),
        "secrets.README.md": "\n".join(
            [
                "# Secret Handoff",
                "",
                "The toolkit intentionally ships only placeholders and topology metadata.",
                "",
                "Populate customer-specific secrets before running bootstrap or upgrade steps.",
                "",
            ]
        ),
    }


def render_linux_bootstrap_script(*, topology: dict[str, Any]) -> str:
    version = dict(topology.get("version") or {})
    return "\n".join(
        [
            "#!/usr/bin/env bash",
            "set -euo pipefail",
            "",
            f"REMOTE_ROOT=\"${{SIEM_REMOTE_ROOT:-{DEFAULT_REMOTE_ROOT}}}\"",
            "mkdir -p \"$REMOTE_ROOT\" /etc/siem /var/lib/siem",
            "if command -v apt-get >/dev/null 2>&1; then",
            "  sudo apt-get update -y",
            "  sudo apt-get install -y python3 python3-venv rsync jq curl",
            "fi",
            "echo \"Bootstrap skeleton ready\"",
            f"echo \"Expected project version: {version.get('git_describe') or version.get('git_short_sha') or 'unknown'}\"",
            "",
        ]
    )


def render_windows_launcher(binary_name: str = "siem-operator.exe") -> dict[str, str]:
    return {
        "siem-operator.cmd": "\n".join(
            [
                "@echo off",
                "setlocal",
                "set TOOL_DIR=%~dp0",
                f"\"%TOOL_DIR%{binary_name}\" --repo-root \"%TOOL_DIR%..\\project\" %*",
                "",
            ]
        ),
        "siem-operator.ps1": "\n".join(
            [
                "$toolDir = Split-Path -Parent $MyInvocation.MyCommand.Path",
                "$repoRoot = Join-Path (Split-Path -Parent $toolDir) 'project'",
                f"& (Join-Path $toolDir '{binary_name}') --repo-root $repoRoot @Args",
                "",
            ]
        ),
        "siem-operator.sh": "\n".join(
            [
                "#!/usr/bin/env bash",
                "set -euo pipefail",
                "TOOL_DIR=\"$(cd \"$(dirname \"$0\")\" && pwd)\"",
                "REPO_ROOT=\"$(cd \"$TOOL_DIR/..\" && pwd)/project\"",
                f"\"$TOOL_DIR/{binary_name}\" --repo-root \"$REPO_ROOT\" \"$@\"",
                "",
            ]
        ),
    }


def export_distribution_toolkit(
    *,
    target_root: Path | None = None,
    project_root: Path = ROOT,
    build_binary: bool = True,
    env: dict[str, str] | None = None,
) -> dict[str, Any]:
    resolved_target = Path(target_root or DEFAULT_TOOLKIT_ROOT).resolve()
    bundle_result = export_clean_project_bundle(target_root=resolved_target, project_root=project_root, build_binary=build_binary)
    (resolved_target / "bin").mkdir(parents=True, exist_ok=True)
    topology = build_topology_manifest(env=env, project_root=project_root)
    distribution_root = resolved_target / "distribution"
    env_root = distribution_root / "env-templates"
    bootstrap_root = distribution_root / "bootstrap"
    docs_root = distribution_root / "docs"
    certs_root = distribution_root / "certs"
    secrets_root = distribution_root / "secrets"
    for path in (distribution_root, env_root, bootstrap_root, docs_root, certs_root, secrets_root):
        path.mkdir(parents=True, exist_ok=True)

    env_templates = render_env_templates(topology=topology)
    for filename, content in env_templates.items():
        if filename.endswith(".md"):
            target_dir = certs_root if filename.startswith("certs.") else secrets_root
            target_path = target_dir / filename.split(".", 1)[1]
        else:
            target_path = env_root / filename
        target_path.write_text(content, encoding="utf-8")

    version = dict(topology.get("version") or {})
    upgrade_plan = build_upgrade_plan(project_root=project_root, target_version=version.get("git_describe") or "current", env=env)
    (distribution_root / "topology.json").write_text(json.dumps(topology, ensure_ascii=False, indent=2), encoding="utf-8")
    (distribution_root / "upgrade-plan.json").write_text(json.dumps(upgrade_plan, ensure_ascii=False, indent=2), encoding="utf-8")
    (bootstrap_root / "bootstrap-linux.sh").write_text(render_linux_bootstrap_script(topology=topology), encoding="utf-8")
    for filename, content in render_windows_launcher(binary_name="siem-operator.exe").items():
        target = resolved_target / "bin" / filename if filename.startswith("siem-operator.") else bootstrap_root / filename
        target.write_text(content, encoding="utf-8")

    (docs_root / "README.md").write_text(
        "\n".join(
            [
                "# Distribution Toolkit",
                "",
                "This package contains a clean project export, operator binary, topology manifest, env templates, and bootstrap helpers.",
                "",
                "Use `bin/siem-operator.exe` or the launcher wrappers to manage lifecycle operations.",
                "",
            ]
        ),
        encoding="utf-8",
    )
    return {
        "target_root": str(resolved_target),
        "distribution_root": str(distribution_root),
        "bundle": bundle_result,
        "topology": topology,
        "upgrade_plan": upgrade_plan,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Export the SIEM distribution toolkit")
    parser.add_argument("--target-root", default=str(DEFAULT_TOOLKIT_ROOT))
    parser.add_argument("--build-binary", action="store_true")
    args = parser.parse_args(argv)
    result = export_distribution_toolkit(target_root=Path(args.target_root), build_binary=bool(args.build_binary))
    print(json.dumps(result, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
