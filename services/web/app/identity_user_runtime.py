from __future__ import annotations

import threading
from typing import Any

try:
    from . import keycloak_admin_runtime as keycloak
    from .control_plane_access_ops import delete_access_grant, list_access_grants, save_access_grant
except ImportError:  # pragma: no cover - local test fallback
    import keycloak_admin_runtime as keycloak  # type: ignore[no-redef]
    from control_plane_access_ops import delete_access_grant, list_access_grants, save_access_grant  # type: ignore[no-redef]


_MUTATION_LOCK = threading.RLock()
_SIEM_ROLES = {"admin", "analyst", "viewer"}


class IdentityUserConflict(keycloak.KeycloakMutationConflict):
    """A managed identity operation would remove required platform access."""


def _string(value: Any) -> str:
    return str(value or "").strip()


def _siem_grants() -> list[dict[str, Any]]:
    return [
        dict(item)
        for item in list_access_grants(principal_kind="keycloak_user", include_disabled=True)
        if _string(item.get("system_id")) == "siem"
    ]


def _grant_for(username: str, grants: list[dict[str, Any]] | None = None) -> dict[str, Any] | None:
    safe_username = _string(username).casefold()
    return next(
        (
            item
            for item in (grants if grants is not None else _siem_grants())
            if _string(item.get("principal_id")).casefold() == safe_username
        ),
        None,
    )


def _enrich(item: dict[str, Any], grant: dict[str, Any] | None = None) -> dict[str, Any]:
    payload = dict(item)
    resolved_grant = grant if grant is not None else _grant_for(_string(payload.get("username")))
    payload.update(
        {
            "management_backend": "keycloak",
            "siem_grant_id": _string((resolved_grant or {}).get("id")),
            "siem_role": _string((resolved_grant or {}).get("role")),
            "siem_access_enabled": bool((resolved_grant or {}).get("enabled", False)) if resolved_grant else False,
            "siem_sections": list((resolved_grant or {}).get("sections") or []),
        }
    )
    return payload


def _validated_siem_role(payload: dict[str, Any], *, required: bool = False) -> str:
    role = _string(payload.get("siem_role")).lower()
    if required and not role:
        raise ValueError("siem_role is required")
    if role and role not in _SIEM_ROLES:
        raise ValueError(f"Unsupported SIEM role: {role}")
    return role


def _active_platform_admins() -> set[str]:
    users = {str(item.get("username") or "").casefold(): item for item in keycloak.list_users(limit=500)}
    return {
        _string(grant.get("principal_id")).casefold()
        for grant in _siem_grants()
        if _string(grant.get("role")).lower() == "admin"
        and bool(grant.get("enabled", True))
        and bool(users.get(_string(grant.get("principal_id")).casefold(), {}).get("enabled", False))
    }


def _ensure_platform_admin_safety(
    current: dict[str, Any],
    *,
    actor: str,
    deleting: bool = False,
    disabling: bool = False,
    demoting: bool = False,
) -> None:
    username = _string(current.get("username"))
    if (deleting or disabling or demoting) and username.casefold() == _string(actor).casefold():
        raise IdentityUserConflict("The currently authenticated user cannot be deleted, disabled, or demoted")
    if (
        bool(current.get("enabled", True))
        and _string(current.get("siem_role")).lower() == "admin"
        and bool(current.get("siem_access_enabled", False))
        and (deleting or disabling or demoting)
        and len(_active_platform_admins()) <= 1
    ):
        raise IdentityUserConflict("The last enabled Sentinel administrator cannot be deleted, disabled, or demoted")


def list_users(*, search: str = "", limit: int = 200) -> list[dict[str, Any]]:
    grants = _siem_grants()
    grant_index = {_string(item.get("principal_id")).casefold(): item for item in grants}
    return [
        _enrich(dict(item), grant_index.get(_string(item.get("username")).casefold()))
        for item in keycloak.list_users(search=search, limit=limit)
    ]


def get_user(user_id: str) -> dict[str, Any]:
    return _enrich(keycloak.get_user(user_id))


def create_user(payload: dict[str, Any], *, actor: str) -> dict[str, Any]:
    role = _validated_siem_role(payload)
    created = keycloak.create_user(payload, actor=actor)
    if role:
        try:
            save_access_grant(
                {
                    "principal_kind": "keycloak_user",
                    "principal_id": _string(created.get("username")),
                    "system_id": "siem",
                    "role": role,
                    "sections": list(payload.get("siem_sections") or []),
                    "enabled": bool(payload.get("enabled", True)),
                },
                actor=actor,
            )
        except Exception as exc:
            # The user must not survive as an unmanaged partial result.
            try:
                keycloak._delete_user_unchecked(_string(created.get("id")))  # noqa: SLF001
                for grant in list_access_grants(
                    principal_kind="keycloak_user",
                    principal_id=_string(created.get("username")),
                    include_disabled=True,
                ):
                    delete_access_grant(_string(grant.get("id")), actor=actor)
            except Exception as cleanup_exc:
                raise RuntimeError(f"User provisioning failed and compensating cleanup failed: {cleanup_exc}") from exc
            raise
    return get_user(_string(created.get("id")))


def update_user(user_id: str, payload: dict[str, Any], *, actor: str) -> dict[str, Any]:
    with _MUTATION_LOCK:
        current = get_user(user_id)
        if "username" in payload and _string(payload.get("username")) != _string(current.get("username")):
            raise ValueError("Changing a managed Keycloak username is not supported")
        desired_enabled = bool(payload.get("enabled")) if "enabled" in payload else bool(current.get("enabled", True))
        desired_role = _validated_siem_role(payload) if "siem_role" in payload else _string(current.get("siem_role")).lower()
        _ensure_platform_admin_safety(
            current,
            actor=actor,
            disabling=bool(current.get("enabled", True)) and not desired_enabled,
            demoting=_string(current.get("siem_role")).lower() == "admin" and desired_role != "admin",
        )
        updated = keycloak.update_user(user_id, payload, actor=actor)
        grant_id = _string(current.get("siem_grant_id"))
        if desired_role:
            try:
                save_access_grant(
                    {
                        "principal_kind": "keycloak_user",
                        "principal_id": _string(current.get("username")),
                        "system_id": "siem",
                        "role": desired_role,
                        "sections": list(payload.get("siem_sections") if "siem_sections" in payload else current.get("siem_sections") or []),
                        "enabled": desired_enabled,
                    },
                    actor=actor,
                    grant_id=grant_id,
                )
            except Exception as exc:
                rollback = {
                    "email": current.get("email"),
                    "first_name": current.get("first_name"),
                    "last_name": current.get("last_name"),
                    "enabled": current.get("enabled", True),
                    "email_verified": current.get("email_verified", False),
                    "attributes": current.get("attributes") or {},
                    "roles": [_string(item.get("name")) for item in list(current.get("roles") or [])],
                }
                try:
                    keycloak.update_user(user_id, rollback, actor=actor)
                    if grant_id:
                        save_access_grant(
                            {
                                "principal_kind": "keycloak_user",
                                "principal_id": _string(current.get("username")),
                                "system_id": "siem",
                                "role": _string(current.get("siem_role")),
                                "sections": list(current.get("siem_sections") or []),
                                "enabled": bool(current.get("siem_access_enabled", True)),
                            },
                            actor=actor,
                            grant_id=grant_id,
                        )
                except Exception as rollback_exc:
                    raise RuntimeError(f"SIEM grant update failed and Keycloak rollback failed: {rollback_exc}") from exc
                raise
        return _enrich(updated)


def set_user_password(user_id: str, payload: dict[str, Any], *, actor: str) -> dict[str, Any]:
    keycloak.set_user_password(user_id, payload, actor=actor)
    return get_user(user_id)


def set_user_groups(user_id: str, payload: dict[str, Any], *, actor: str) -> dict[str, Any]:
    keycloak.set_user_groups(user_id, payload, actor=actor)
    return get_user(user_id)


def set_user_roles(user_id: str, payload: dict[str, Any], *, actor: str) -> dict[str, Any]:
    keycloak.set_user_roles(user_id, payload, actor=actor)
    return get_user(user_id)


def delete_user(user_id: str, *, actor: str) -> dict[str, Any]:
    with _MUTATION_LOCK:
        current = get_user(user_id)
        _ensure_platform_admin_safety(current, actor=actor, deleting=True)
        deleted = keycloak.delete_user(user_id, actor=actor)
        for grant in list_access_grants(
            principal_kind="keycloak_user",
            principal_id=_string(current.get("username")),
            include_disabled=True,
        ):
            delete_access_grant(_string(grant.get("id")), actor=actor)
        return {**deleted, "deleted_grants": True, "management_backend": "keycloak"}
