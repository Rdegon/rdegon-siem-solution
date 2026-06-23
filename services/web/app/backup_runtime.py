from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping


def _env_value(env: Mapping[str, str], name: str, default: str) -> str:
    return str(env.get(name, default) or default).strip()


def _bool_env(env: Mapping[str, str], name: str, default: bool = False) -> bool:
    raw = str(env.get(name, "1" if default else "0") or "").strip().lower()
    return raw in {"1", "true", "yes", "on"}


def _local_node_aliases(env: Mapping[str, str]) -> set[str]:
    values = {
        str(env.get("SIEM_BACKUP_LOCAL_NODE") or "").strip().lower(),
        str(env.get("SIEM_NODE_NAME") or "").strip().lower(),
        str(env.get("HOSTNAME") or "").strip().lower(),
        "localhost",
        "127.0.0.1",
        "::1",
    }
    return {value for value in values if value}


def _node_is_local(env: Mapping[str, str], node: str) -> bool:
    return str(node or "").strip().lower() in _local_node_aliases(env)


def _path_state(path_value: str, *, check_local: bool) -> dict[str, Any]:
    path = Path(path_value)
    if not check_local:
        return {
            "path": str(path),
            "path_exists": None,
            "parent_exists": None,
            "check_local": False,
        }
    return {
        "path": str(path),
        "path_exists": path.exists(),
        "parent_exists": path.parent.exists(),
        "check_local": True,
    }


def _stream_state_source_state(stream_state_status: Mapping[str, Any], env: Mapping[str, str]) -> dict[str, Any]:
    sqlite_source_path = str(stream_state_status.get("sqlite_path") or "").strip()
    source_node = str(
        stream_state_status.get("sqlite_node")
        or env.get("SIEM_STREAM_STATE_SQLITE_NODE")
        or "vm3"
    ).strip() or "vm3"
    source_check_local = _bool_env(
        env,
        "SIEM_STREAM_STATE_SQLITE_SOURCE_CHECK_LOCAL",
        default=_node_is_local(env, source_node),
    )
    runtime_exists = bool(
        stream_state_status.get("sqlite_exists")
        or stream_state_status.get("healthy")
        or stream_state_status.get("last_offset_ts")
        or stream_state_status.get("stored_offsets_total")
    )
    local_exists = bool(sqlite_source_path and Path(sqlite_source_path).exists()) if source_check_local else None
    return {
        "sqlite_path": sqlite_source_path,
        "sqlite_source_node": source_node,
        "sqlite_source_check_local": source_check_local,
        "sqlite_source_exists": bool(local_exists if source_check_local else runtime_exists),
    }


def backup_runtime_status(
    *,
    control_plane_status: Mapping[str, Any],
    content_status: Mapping[str, Any],
    stream_state_status: Mapping[str, Any],
    platform_status: Mapping[str, Any],
    env: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    env_map = env or os.environ
    postgres_backup_dir = _env_value(env_map, "SIEM_CONTROL_PLANE_PG_BACKUP_DIR", "/var/backups/siem-postgres")
    mongo_backup_dir = _env_value(env_map, "SIEM_MONGO_BACKUP_DIR", "/var/backups/siem-mongo")
    sqlite_backup_dir = _env_value(env_map, "SIEM_STREAM_STATE_BACKUP_DIR", "/var/backups/siem-stream-state")
    clickhouse_backup_dir = _env_value(env_map, "SIEM_CLICKHOUSE_BACKUP_DIR", "/var/backups/siem-clickhouse")
    clickhouse_check_local = _bool_env(env_map, "SIEM_CLICKHOUSE_BACKUP_CHECK_LOCAL", default=False)
    sqlite_backup_node = _env_value(env_map, "SIEM_STREAM_STATE_BACKUP_NODE", "vm3")
    sqlite_backup_check_local = _bool_env(
        env_map,
        "SIEM_STREAM_STATE_BACKUP_CHECK_LOCAL",
        default=_node_is_local(env_map, sqlite_backup_node),
    )

    control_plane_active = str(control_plane_status.get("backend") or "") == "postgres"
    content_active = str(content_status.get("backend") or "") == "mongo"
    sqlite_active = str(stream_state_status.get("backend") or "") == "sqlite"
    clickhouse_active = bool(platform_status.get("clickhouse_ok", False))

    control_plane_target = {
        "node": "vm4",
        "backend": str(control_plane_status.get("backend") or ""),
        "requested_backend": str(control_plane_status.get("requested_backend") or ""),
        "required": control_plane_active,
        **_path_state(postgres_backup_dir, check_local=True),
    }
    control_plane_target["prepared"] = (not control_plane_active) or bool(
        control_plane_target["path_exists"] or control_plane_target["parent_exists"]
    )

    content_target = {
        "node": "vm4",
        "backend": str(content_status.get("backend") or ""),
        "requested_backend": str(content_status.get("requested_backend") or ""),
        "required": content_active,
        **_path_state(mongo_backup_dir, check_local=True),
    }
    content_target["prepared"] = (not content_active) or bool(content_target["path_exists"] or content_target["parent_exists"])

    sqlite_source = _stream_state_source_state(stream_state_status, env_map)
    sqlite_target = {
        "node": "vm3",
        "backend": str(stream_state_status.get("backend") or ""),
        **sqlite_source,
        "backup_node": sqlite_backup_node,
        "required": sqlite_active,
        **_path_state(sqlite_backup_dir, check_local=sqlite_backup_check_local),
    }
    sqlite_target["prepared"] = (not sqlite_active) or bool(
        sqlite_target["sqlite_source_exists"]
        and (
            bool(sqlite_target["path_exists"] or sqlite_target["parent_exists"])
            if sqlite_backup_check_local
            else bool(sqlite_backup_dir)
        )
    )
    sqlite_target["check_local"] = sqlite_backup_check_local

    clickhouse_target = {
        "node": "vm3",
        "backend": "clickhouse",
        "required": clickhouse_active,
        **_path_state(clickhouse_backup_dir, check_local=clickhouse_check_local),
    }
    clickhouse_target["prepared"] = (not clickhouse_active) or (
        bool(clickhouse_target["path_exists"] or clickhouse_target["parent_exists"])
        if clickhouse_check_local
        else bool(clickhouse_backup_dir)
    )
    clickhouse_target["check_local"] = clickhouse_check_local

    targets = {
        "control_plane_postgres": control_plane_target,
        "content_store_mongo": content_target,
        "stream_state_sqlite": sqlite_target,
        "clickhouse_storage": clickhouse_target,
    }

    issues: list[str] = []
    for key, target in targets.items():
        if target.get("required") and not target.get("prepared"):
            issues.append(f"{key} backup path is not prepared")

    return {
        "generated_ts": datetime.now(tz=timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "healthy": not issues,
        "issues": issues,
        "targets": targets,
    }
