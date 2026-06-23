from __future__ import annotations

import argparse
import importlib
import json
import os
import sys
import types
from pathlib import Path
from typing import Any


def _is_repo_root(path: Path) -> bool:
    return (path / "services" / "web" / "main.py").exists() and (path / "deploy").exists() and (path / "docs").exists()


def _resolve_repo_root(explicit: str = "") -> Path:
    candidates = []
    if str(explicit).strip():
        candidates.append(Path(explicit).resolve())
    env_root = str(os.getenv("SIEM_REPO_ROOT", "") or "").strip()
    if env_root:
        candidates.append(Path(env_root).resolve())
    cwd = Path.cwd().resolve()
    candidates.extend((cwd, cwd / "project"))
    script_path = Path(sys.argv[0]).resolve()
    candidates.extend((script_path.parent, script_path.parent.parent, script_path.parent.parent / "project"))
    for candidate in candidates:
        if _is_repo_root(candidate):
            return candidate
    raise SystemExit("Unable to resolve SIEM repo root. Use --repo-root or run the tool from the project root.")


def _bootstrap_repo_paths(repo_root: Path) -> None:
    candidates = (repo_root / "services" / "web", repo_root / "services" / "web" / "app", repo_root)
    for candidate in candidates:
        text = str(candidate)
        if text not in sys.path:
            sys.path.insert(0, text)
    if "app" not in sys.modules:
        app_root = repo_root / "services" / "web" / "app"
        app_module = types.ModuleType("app")
        app_module.__path__ = [str(app_root)]  # type: ignore[attr-defined]
        app_module.__file__ = str(app_root / "__init__.py")
        sys.modules["app"] = app_module


def _access_module():
    try:
        return importlib.import_module("app.control_plane_access_ops")
    except Exception:  # noqa: BLE001
        return importlib.import_module("control_plane_access_ops")


def _response_module():
    try:
        return importlib.import_module("app.control_plane_response_ops")
    except Exception:  # noqa: BLE001
        return importlib.import_module("control_plane_response_ops")


def _docs_module():
    return importlib.import_module("deploy.export_siem_docs")


def _bundle_module():
    return importlib.import_module("deploy.export_clean_project_bundle")


def _cleanup_module():
    return importlib.import_module("deploy.system_cleanup")


def _distribution_module():
    return importlib.import_module("deploy.distribution_toolkit")


def _storage_ha_drill_module():
    return importlib.import_module("deploy.storage_ha_drill")


def _storage_ha_restore_module():
    return importlib.import_module("deploy.storage_ha_restore_verify")


def _distributed_eps_module():
    return importlib.import_module("deploy.distributed_eps_benchmark")


def _deps_module():
    return importlib.import_module("app.deps")


def _operator_bundle_path(repo_root: Path) -> Path:
    return repo_root.parent / "product-docs" / "OPERATOR_ACCESS_BUNDLE.md"


def _print(payload: Any) -> int:
    print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


def _cmd_permissions(args: argparse.Namespace) -> int:
    return _print(_access_module().get_permission_inventory())


def _cmd_users_list(args: argparse.Namespace) -> int:
    return _print({"items": _access_module().list_local_users(include_disabled=bool(args.include_disabled))})


def _cmd_users_create(args: argparse.Namespace) -> int:
    payload = {
        "username": args.username,
        "password": args.password,
        "role": args.role,
        "permissions": list(args.permission or []),
        "permission_bundles": list(args.permission_bundle or []),
        "enabled": not bool(args.disabled),
    }
    return _print(_access_module().save_local_user(payload, actor=str(args.actor)))


def _cmd_users_set_password(args: argparse.Namespace) -> int:
    return _print(_access_module().set_local_user_password(args.username, new_password=args.password, actor=str(args.actor)))


def _cmd_users_delete(args: argparse.Namespace) -> int:
    return _print(_access_module().delete_local_user(args.username, actor=str(args.actor)))


def _cmd_service_accounts_list(args: argparse.Namespace) -> int:
    return _print({"items": _access_module().list_service_accounts()})


def _cmd_service_accounts_create(args: argparse.Namespace) -> int:
    payload = {
        "name": args.name,
        "description": str(args.description or ""),
        "permissions": list(args.permission or []),
        "permission_bundles": list(args.permission_bundle or []),
        "enabled": not bool(args.disabled),
        "tags": list(args.tag or []),
    }
    return _print(_access_module().save_service_account(payload, actor=str(args.actor)))


def _cmd_service_accounts_delete(args: argparse.Namespace) -> int:
    return _print(_access_module().delete_service_account(args.service_account_id, actor=str(args.actor)))


def _cmd_service_accounts_issue_token(args: argparse.Namespace) -> int:
    return _print(
        _access_module().issue_service_account_token(
            args.service_account_id,
            title=str(args.title or ""),
            actor=str(args.actor),
            expires_days=int(args.expires_days),
        )
    )


def _cmd_service_accounts_revoke_token(args: argparse.Namespace) -> int:
    return _print(_access_module().revoke_service_account_token(args.service_account_id, args.token_id, actor=str(args.actor)))


def _cmd_response_overview(args: argparse.Namespace) -> int:
    module = _response_module()
    return _print(
        {
            "actions": module.list_response_actions(),
            "executions": module.list_response_executions(limit=int(args.limit)),
            "dlq": module.list_response_dlq(limit=int(args.limit)),
        }
    )


def _cmd_response_execute(args: argparse.Namespace) -> int:
    payload = json.loads(str(args.payload_json or "{}"))
    return _print(
        _response_module().execute_response_action(
            args.action_id,
            actor=str(args.actor),
            payload=payload,
            dry_run=bool(args.dry_run),
        )
    )


def _cmd_response_approve(args: argparse.Namespace) -> int:
    return _print(_response_module().approve_response_execution(args.execution_id, actor=str(args.actor)))


def _cmd_response_retry(args: argparse.Namespace) -> int:
    return _print(_response_module().retry_response_execution(args.execution_id, actor=str(args.actor)))


def _cmd_response_replay_dlq(args: argparse.Namespace) -> int:
    return _print(_response_module().replay_response_dlq(args.dlq_id, actor=str(args.actor)))


def _cmd_response_analytics(args: argparse.Namespace) -> int:
    return _print(_response_module().get_response_analytics(limit=int(args.limit)))


def _cmd_docs_export(args: argparse.Namespace, repo_root: Path) -> int:
    target_root = Path(args.target_root).resolve() if str(args.target_root).strip() else repo_root.parent / "siem_docs"
    return _print(_docs_module().export_siem_docs(target_root=target_root))


def _cmd_docs_publish_runtime(args: argparse.Namespace, repo_root: Path) -> int:
    deps = _deps_module()
    docs_root = repo_root / "docs"
    published: list[str] = []
    for path in sorted(docs_root.rglob("*.md")):
        relative_path = path.relative_to(docs_root)
        name = str(relative_path).replace("\\", "/").replace("/", "__")
        deps.save_runtime_doc(name, path.read_text(encoding="utf-8"))
        published.append(str(relative_path).replace("\\", "/"))
    operator_bundle = _operator_bundle_path(repo_root)
    if operator_bundle.exists():
        deps.save_runtime_doc("operator_access_bundle.md", operator_bundle.read_text(encoding="utf-8"))
        published.append("operator_access_bundle.md")
    return _print({"published_docs": len(published), "items": published})


def _cmd_cleanup_smoke(args: argparse.Namespace) -> int:
    module = _cleanup_module()
    return _print(
        {
            "control_plane_removed": module._cleanup_control_plane(),
            "builder_drafts_removed": module._cleanup_builder_drafts(),
            "clickhouse_cleanup": module._cleanup_clickhouse(),
        }
    )


def _cmd_vuln_maturity(args: argparse.Namespace) -> int:
    try:
        module = importlib.import_module("app.vuln_maturity_runtime")
    except Exception:  # noqa: BLE001
        module = importlib.import_module("vuln_maturity_runtime")
    return _print(module.build_vulnerability_maturity_status(days=int(args.days), limit=int(args.limit)))


def _cmd_vuln_apply_policies(args: argparse.Namespace) -> int:
    try:
        module = importlib.import_module("app.vuln_maturity_runtime")
    except Exception:  # noqa: BLE001
        module = importlib.import_module("vuln_maturity_runtime")
    return _print(module.apply_vulnerability_incident_policies(actor=str(args.actor), days=int(args.days), limit=int(args.limit)))


def _cmd_bundle_export_clean(args: argparse.Namespace, repo_root: Path) -> int:
    target_root = Path(args.target_root).resolve() if str(args.target_root).strip() else repo_root.parent / "siem_project_bundle"
    return _print(
        _bundle_module().export_clean_project_bundle(
            target_root=target_root,
            project_root=repo_root,
            build_binary=bool(args.build_binary),
        )
    )


def _cmd_distribution_export(args: argparse.Namespace, repo_root: Path) -> int:
    target_root = Path(args.target_root).resolve() if str(args.target_root).strip() else repo_root.parent / "siem_distribution_toolkit"
    return _print(
        _distribution_module().export_distribution_toolkit(
            target_root=target_root,
            project_root=repo_root,
            build_binary=bool(args.build_binary),
        )
    )


def _cmd_distribution_topology(args: argparse.Namespace, repo_root: Path) -> int:
    return _print(_distribution_module().build_topology_manifest(project_root=repo_root))


def _cmd_distribution_upgrade_plan(args: argparse.Namespace, repo_root: Path) -> int:
    return _print(_distribution_module().build_upgrade_plan(project_root=repo_root, target_version=str(args.target_version or "current")))


def _cmd_storage_ha_drill(args: argparse.Namespace) -> int:
    module = _storage_ha_drill_module()
    try:
        status = module.build_storage_ha_status(
            platform_status=_deps_module().fetch_platform_status(),
            control_plane_status=importlib.import_module("app.enterprise_control_plane").control_plane_storage_status(),
            content_status=importlib.import_module("app.content_runtime").content_storage_status(),
        )
    except Exception:  # noqa: BLE001
        status = module.build_storage_ha_status(
            platform_status=importlib.import_module("deps").fetch_platform_status(),
            control_plane_status=importlib.import_module("enterprise_control_plane").control_plane_storage_status(),
            content_status=importlib.import_module("content_runtime").content_storage_status(),
        )
    return _print(module.build_storage_ha_drill_report(status))


def _cmd_storage_ha_restore_verify(args: argparse.Namespace) -> int:
    return _print(_storage_ha_restore_module().build_restore_verification(backup_root=Path(args.backup_root)))


def _cmd_performance_distributed_eps(args: argparse.Namespace) -> int:
    argv: list[str] = []
    if str(args.ingest_url or "").strip():
        argv.extend(["--ingest-url", str(args.ingest_url).strip()])
    if int(args.duration_sec or 0) > 0:
        argv.extend(["--duration-sec", str(int(args.duration_sec))])
    if int(args.batch_size or 0) > 0:
        argv.extend(["--batch-size", str(int(args.batch_size))])
    if str(args.stages or "").strip():
        argv.extend(["--stages", str(args.stages).strip()])
    return _distributed_eps_module().main(argv)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="SIEM operator CLI")
    parser.add_argument("--repo-root", default="", help="Project root. Defaults to cwd or bundle-local project/")
    subparsers = parser.add_subparsers(dest="command", required=True)

    permissions_parser = subparsers.add_parser("permissions", help="Permission inventory")
    permissions_parser.set_defaults(handler=_cmd_permissions)

    users_parser = subparsers.add_parser("users", help="Local user management")
    users_subparsers = users_parser.add_subparsers(dest="users_command", required=True)
    users_list = users_subparsers.add_parser("list", help="List local users")
    users_list.add_argument("--include-disabled", action="store_true")
    users_list.set_defaults(handler=_cmd_users_list)
    users_create = users_subparsers.add_parser("create", help="Create or update a local user")
    users_create.add_argument("--username", required=True)
    users_create.add_argument("--password", required=True)
    users_create.add_argument("--role", default="viewer")
    users_create.add_argument("--permission", action="append", default=[])
    users_create.add_argument("--permission-bundle", action="append", default=[])
    users_create.add_argument("--disabled", action="store_true")
    users_create.add_argument("--actor", default="siem-operator")
    users_create.set_defaults(handler=_cmd_users_create)
    users_password = users_subparsers.add_parser("set-password", help="Rotate a local user password")
    users_password.add_argument("--username", required=True)
    users_password.add_argument("--password", required=True)
    users_password.add_argument("--actor", default="siem-operator")
    users_password.set_defaults(handler=_cmd_users_set_password)
    users_delete = users_subparsers.add_parser("delete", help="Delete a local user")
    users_delete.add_argument("--username", required=True)
    users_delete.add_argument("--actor", default="siem-operator")
    users_delete.set_defaults(handler=_cmd_users_delete)

    service_accounts_parser = subparsers.add_parser("service-accounts", help="Service account management")
    service_accounts_subparsers = service_accounts_parser.add_subparsers(dest="service_accounts_command", required=True)
    service_accounts_list = service_accounts_subparsers.add_parser("list", help="List service accounts")
    service_accounts_list.set_defaults(handler=_cmd_service_accounts_list)
    service_accounts_create = service_accounts_subparsers.add_parser("create", help="Create or update a service account")
    service_accounts_create.add_argument("--name", required=True)
    service_accounts_create.add_argument("--description", default="")
    service_accounts_create.add_argument("--permission", action="append", default=[])
    service_accounts_create.add_argument("--permission-bundle", action="append", default=[])
    service_accounts_create.add_argument("--tag", action="append", default=[])
    service_accounts_create.add_argument("--disabled", action="store_true")
    service_accounts_create.add_argument("--actor", default="siem-operator")
    service_accounts_create.set_defaults(handler=_cmd_service_accounts_create)
    service_accounts_delete = service_accounts_subparsers.add_parser("delete", help="Delete a service account")
    service_accounts_delete.add_argument("--service-account-id", required=True)
    service_accounts_delete.add_argument("--actor", default="siem-operator")
    service_accounts_delete.set_defaults(handler=_cmd_service_accounts_delete)
    service_accounts_issue = service_accounts_subparsers.add_parser("issue-token", help="Issue a service account token")
    service_accounts_issue.add_argument("--service-account-id", required=True)
    service_accounts_issue.add_argument("--title", default="")
    service_accounts_issue.add_argument("--expires-days", type=int, default=90)
    service_accounts_issue.add_argument("--actor", default="siem-operator")
    service_accounts_issue.set_defaults(handler=_cmd_service_accounts_issue_token)
    service_accounts_revoke = service_accounts_subparsers.add_parser("revoke-token", help="Revoke a service account token")
    service_accounts_revoke.add_argument("--service-account-id", required=True)
    service_accounts_revoke.add_argument("--token-id", required=True)
    service_accounts_revoke.add_argument("--actor", default="siem-operator")
    service_accounts_revoke.set_defaults(handler=_cmd_service_accounts_revoke_token)

    response_parser = subparsers.add_parser("response", help="Response / SOAR operations")
    response_subparsers = response_parser.add_subparsers(dest="response_command", required=True)
    response_overview = response_subparsers.add_parser("overview", help="List response actions, executions, and DLQ")
    response_overview.add_argument("--limit", type=int, default=50)
    response_overview.set_defaults(handler=_cmd_response_overview)
    response_execute = response_subparsers.add_parser("execute", help="Execute a response action")
    response_execute.add_argument("--action-id", required=True)
    response_execute.add_argument("--payload-json", default="{}")
    response_execute.add_argument("--dry-run", action="store_true")
    response_execute.add_argument("--actor", default="siem-operator")
    response_execute.set_defaults(handler=_cmd_response_execute)
    response_approve = response_subparsers.add_parser("approve", help="Approve a pending execution")
    response_approve.add_argument("--execution-id", required=True)
    response_approve.add_argument("--actor", default="siem-operator")
    response_approve.set_defaults(handler=_cmd_response_approve)
    response_retry = response_subparsers.add_parser("retry", help="Retry an execution")
    response_retry.add_argument("--execution-id", required=True)
    response_retry.add_argument("--actor", default="siem-operator")
    response_retry.set_defaults(handler=_cmd_response_retry)
    response_replay = response_subparsers.add_parser("replay-dlq", help="Replay a response DLQ entry")
    response_replay.add_argument("--dlq-id", required=True)
    response_replay.add_argument("--actor", default="siem-operator")
    response_replay.set_defaults(handler=_cmd_response_replay_dlq)
    response_analytics = response_subparsers.add_parser("analytics", help="Response execution analytics")
    response_analytics.add_argument("--limit", type=int, default=200)
    response_analytics.set_defaults(handler=_cmd_response_analytics)

    docs_parser = subparsers.add_parser("docs", help="Docs export and publish")
    docs_subparsers = docs_parser.add_subparsers(dest="docs_command", required=True)
    docs_export = docs_subparsers.add_parser("export", help="Export docs to a clean local folder")
    docs_export.add_argument("--target-root", default="")
    docs_export.set_defaults(handler=_cmd_docs_export)
    docs_publish = docs_subparsers.add_parser("publish-runtime", help="Publish docs into runtime content store")
    docs_publish.set_defaults(handler=_cmd_docs_publish_runtime)

    cleanup_parser = subparsers.add_parser("cleanup", help="System cleanup helpers")
    cleanup_subparsers = cleanup_parser.add_subparsers(dest="cleanup_command", required=True)
    cleanup_smoke = cleanup_subparsers.add_parser("smoke", help="Remove smoke/test residue")
    cleanup_smoke.set_defaults(handler=_cmd_cleanup_smoke)

    bundle_parser = subparsers.add_parser("bundle", help="Clean project bundle export")
    bundle_subparsers = bundle_parser.add_subparsers(dest="bundle_command", required=True)
    bundle_export = bundle_subparsers.add_parser("export-clean", help="Export a clean project bundle")
    bundle_export.add_argument("--target-root", default="")
    bundle_export.add_argument("--build-binary", action="store_true")
    bundle_export.set_defaults(handler=_cmd_bundle_export_clean)

    distribution_parser = subparsers.add_parser("distribution", help="Customer deployment/distribution helpers")
    distribution_subparsers = distribution_parser.add_subparsers(dest="distribution_command", required=True)
    distribution_export = distribution_subparsers.add_parser("export", help="Export a full deployment toolkit")
    distribution_export.add_argument("--target-root", default="")
    distribution_export.add_argument("--build-binary", action="store_true")
    distribution_export.set_defaults(handler=_cmd_distribution_export)
    distribution_topology = distribution_subparsers.add_parser("topology", help="Render the current topology manifest")
    distribution_topology.set_defaults(handler=_cmd_distribution_topology)
    distribution_upgrade = distribution_subparsers.add_parser("upgrade-plan", help="Render a version upgrade plan")
    distribution_upgrade.add_argument("--target-version", default="current")
    distribution_upgrade.set_defaults(handler=_cmd_distribution_upgrade_plan)

    storage_ha_parser = subparsers.add_parser("storage-ha", help="Storage HA drill and restore verification")
    storage_ha_subparsers = storage_ha_parser.add_subparsers(dest="storage_ha_command", required=True)
    storage_ha_drill = storage_ha_subparsers.add_parser("drill", help="Build a failover/switchover readiness report")
    storage_ha_drill.set_defaults(handler=_cmd_storage_ha_drill)
    storage_ha_restore = storage_ha_subparsers.add_parser("restore-verify", help="Verify restore prerequisites")
    storage_ha_restore.add_argument("--backup-root", default="/tmp")
    storage_ha_restore.set_defaults(handler=_cmd_storage_ha_restore_verify)

    performance_parser = subparsers.add_parser("performance", help="Performance and capacity tools")
    performance_subparsers = performance_parser.add_subparsers(dest="performance_command", required=True)
    perf_eps = performance_subparsers.add_parser("distributed-eps", help="Run the distributed EPS benchmark")
    perf_eps.add_argument("--ingest-url", default="")
    perf_eps.add_argument("--duration-sec", type=int, default=0)
    perf_eps.add_argument("--batch-size", type=int, default=0)
    perf_eps.add_argument("--stages", default="")
    perf_eps.set_defaults(handler=_cmd_performance_distributed_eps)

    vuln_parser = subparsers.add_parser("vuln", help="Vulnerability maturity and policy tools")
    vuln_subparsers = vuln_parser.add_subparsers(dest="vuln_command", required=True)
    vuln_maturity = vuln_subparsers.add_parser("maturity", help="Build vulnerability maturity status")
    vuln_maturity.add_argument("--days", type=int, default=30)
    vuln_maturity.add_argument("--limit", type=int, default=200)
    vuln_maturity.set_defaults(handler=_cmd_vuln_maturity)
    vuln_apply = vuln_subparsers.add_parser("apply-policies", help="Apply critical vulnerability incident policies")
    vuln_apply.add_argument("--days", type=int, default=30)
    vuln_apply.add_argument("--limit", type=int, default=50)
    vuln_apply.add_argument("--actor", default="siem-operator")
    vuln_apply.set_defaults(handler=_cmd_vuln_apply_policies)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    repo_root = _resolve_repo_root(str(args.repo_root or ""))
    _bootstrap_repo_paths(repo_root)
    handler = getattr(args, "handler", None)
    if handler is None:
        parser.error("No command handler selected")
    if handler in {
        _cmd_docs_export,
        _cmd_docs_publish_runtime,
        _cmd_bundle_export_clean,
        _cmd_distribution_export,
        _cmd_distribution_topology,
        _cmd_distribution_upgrade_plan,
    }:
        return handler(args, repo_root)
    return handler(args)


if __name__ == "__main__":
    raise SystemExit(main())
