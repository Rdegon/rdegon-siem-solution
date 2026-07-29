from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import os
import re
from typing import Any

import requests

from .control_plane_governance_runtime import append_audit_event
from .secret_runtime import resolve_secret_value


_UUID_RE = re.compile(r"^[0-9a-fA-F-]{36}$")
_SID_RE = re.compile(r"^\d+(?:,\d+)*$")
_MANAGED_DESCRIPTION_RE = re.compile(r"^(SOC|SIEM)\s", re.IGNORECASE)
_ALLOWED_INTERFACES = {"lan", "opt1", "opt2", "opt3", "opt4", "opt5"}
_ALLOWED_ACTIONS = {"pass", "block", "reject"}
_ALLOWED_PROTOCOLS = {"any", "TCP", "UDP", "TCP/UDP", "ICMP"}


def _env_bool(name: str, default: bool) -> bool:
    value = str(os.getenv(name, "") or "").strip().lower()
    return default if not value else value in {"1", "true", "yes", "on"}


def _selected(value: Any, default: str = "") -> str:
    if not isinstance(value, dict):
        return str(value or default)
    for key, item in value.items():
        if isinstance(item, dict) and int(item.get("selected") or 0) == 1:
            return str(key)
    return default


def _clean_text(value: Any, *, max_length: int = 255) -> str:
    return str(value or "").strip()[:max_length]


@dataclass(frozen=True)
class OPNsenseConfig:
    base_url: str
    api_key: str
    api_secret: str
    username: str
    password: str
    verify_tls: bool
    timeout_seconds: int
    ca_file: str = ""

    @property
    def configured(self) -> bool:
        return bool((self.api_key and self.api_secret) or (self.username and self.password))

    @property
    def auth_mode(self) -> str:
        return "api_key" if self.api_key and self.api_secret else "web_session"

    @property
    def requests_verify(self) -> bool | str:
        if not self.verify_tls:
            return False
        return self.ca_file or True


def load_opnsense_config() -> OPNsenseConfig:
    base_url = str(os.getenv("SIEM_OPNSENSE_HOST", "https://192.168.3.103") or "").strip()
    if "://" not in base_url:
        base_url = f"https://{base_url}"
    api_key, _, _ = resolve_secret_value("SIEM_OPNSENSE_API_KEY")
    api_secret, _, _ = resolve_secret_value("SIEM_OPNSENSE_API_SECRET")
    password, _, _ = resolve_secret_value("SIEM_OPNSENSE_ROOT_PASSWORD")
    return OPNsenseConfig(
        base_url=base_url.rstrip("/"),
        api_key=api_key,
        api_secret=api_secret,
        username=str(os.getenv("SIEM_OPNSENSE_USER", "") or "").strip(),
        password=password,
        verify_tls=_env_bool("SIEM_OPNSENSE_VERIFY_TLS", False),
        timeout_seconds=max(3, min(int(os.getenv("SIEM_OPNSENSE_TIMEOUT_SECONDS", "15") or "15"), 60)),
        ca_file=str(os.getenv("SIEM_OPNSENSE_CA_FILE", "") or "").strip(),
    )


class OPNsenseClient:
    def __init__(
        self,
        config: OPNsenseConfig | None = None,
        *,
        session: requests.Session | None = None,
    ) -> None:
        self.config = config or load_opnsense_config()
        self.session = session or requests.Session()
        self._logged_in = False
        self._csrf_name = ""
        self._csrf_token = ""

    def _login(self) -> None:
        if self._logged_in or self.config.auth_mode == "api_key":
            return
        response = self.session.get(
            f"{self.config.base_url}/",
            verify=self.config.requests_verify,
            timeout=self.config.timeout_seconds,
        )
        response.raise_for_status()
        match = re.search(r'<input type="hidden" name="([^"]+)" value="([^"]+)"', response.text)
        if not match:
            raise RuntimeError("OPNsense login page did not expose a CSRF token")
        self._csrf_name, self._csrf_token = match.groups()
        response = self.session.post(
            f"{self.config.base_url}/",
            data={
                self._csrf_name: self._csrf_token,
                "usernamefld": self.config.username,
                "passwordfld": self.config.password,
                "login": "1",
            },
            verify=self.config.requests_verify,
            timeout=self.config.timeout_seconds,
        )
        response.raise_for_status()
        if "Logout" not in response.text and "/ui/" not in response.url:
            raise RuntimeError("OPNsense authentication failed")
        self._logged_in = True

    def request(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
        *,
        timeout_seconds: int | None = None,
    ) -> dict[str, Any]:
        if not self.config.configured:
            raise RuntimeError("OPNsense API credentials are not configured")
        self._login()
        headers = {"Accept": "application/json"}
        auth = None
        if self.config.auth_mode == "api_key":
            auth = (self.config.api_key, self.config.api_secret)
        elif method.upper() == "POST":
            headers["X-CSRFToken"] = self._csrf_token
        response = self.session.request(
            method.upper(),
            f"{self.config.base_url}{path}",
            json=payload if method.upper() == "POST" else None,
            headers=headers,
            auth=auth,
            verify=self.config.requests_verify,
            timeout=timeout_seconds or self.config.timeout_seconds,
        )
        response.raise_for_status()
        body = response.json()
        if isinstance(body, dict):
            result_state = str(body.get("result") or "").lower()
            status_state = str(body.get("status") or "").lower()
            if result_state in {"failed", "error"} or status_state in {"failed", "error"}:
                raise RuntimeError(f"OPNsense rejected {path}: {body}")
        return dict(body or {})

    def get(self, path: str) -> dict[str, Any]:
        return self.request("GET", path)

    def post(
        self,
        path: str,
        payload: dict[str, Any] | None = None,
        *,
        timeout_seconds: int | None = None,
    ) -> dict[str, Any]:
        return self.request(
            "POST",
            path,
            payload or {},
            timeout_seconds=timeout_seconds,
        )


def _firewall_rows(client: OPNsenseClient) -> list[dict[str, Any]]:
    rows = list(client.get("/api/firewall/filter/search_rule").get("rows") or [])
    result: list[dict[str, Any]] = []
    for raw in rows:
        row = dict(raw or {})
        description = _clean_text(row.get("description"))
        result.append(
            {
                "uuid": _clean_text(row.get("uuid"), max_length=40),
                "description": description,
                "enabled": str(row.get("enabled") or "0") == "1",
                "managed": bool(_MANAGED_DESCRIPTION_RE.match(description)),
                "legacy": bool(row.get("legacy")),
                "automatic": bool(row.get("is_automatic")),
                "action": _clean_text(row.get("action") or row.get("%action")),
                "interface": _clean_text(row.get("interface")),
                "direction": _clean_text(row.get("direction")),
                "protocol": _clean_text(row.get("protocol") or row.get("%protocol")),
                "source": _clean_text(row.get("source_net")),
                "source_port": _clean_text(row.get("source_port")),
                "destination": _clean_text(row.get("destination_net")),
                "destination_port": _clean_text(row.get("destination_port")),
                "log": str(row.get("log") or "0") == "1",
                "sort_order": row.get("sort_order"),
            }
        )
    return result


def _firewall_aliases(client: OPNsenseClient) -> list[dict[str, Any]]:
    rows = list(client.get("/api/firewall/alias/search_item").get("rows") or [])
    return [
        {
            "uuid": _clean_text(row.get("uuid"), max_length=40),
            "name": _clean_text(row.get("name")),
            "type": _clean_text(row.get("type")),
            "enabled": str(row.get("enabled") or "0") == "1",
            "description": _clean_text(row.get("description")),
            "content": str(row.get("content") or "")[:4000],
            "current_items": int(row.get("current_items") or 0),
            "last_updated": _clean_text(row.get("last_updated")),
        }
        for row in rows
        if isinstance(row, dict)
    ]


def _ids_state(client: OPNsenseClient, search: str) -> dict[str, Any]:
    query = {
        "current": 1,
        "rowCount": 100,
        "sort": {"timestamp": "desc"},
        "searchPhrase": _clean_text(search),
    }
    alerts = client.post("/api/ids/service/query_alerts", query)
    rulesets = client.get("/api/ids/settings/list_rulesets")
    return {
        "status": client.get("/api/ids/service/status").get("status"),
        "alerts_total": int(alerts.get("total") or 0),
        "alerts": [dict(row or {}) for row in list(alerts.get("rows") or [])[:100]],
        "rulesets_total": int(rulesets.get("total") or 0),
        "rulesets": [
            {
                "filename": _clean_text(row.get("filename")),
                "description": _clean_text(row.get("description")),
                "enabled": str(row.get("enabled") or "0") == "1",
                "modified_local": bool(row.get("modified_local")),
                "documentation_url": _clean_text(row.get("documentation_url"), max_length=500),
            }
            for row in list(rulesets.get("rows") or [])
            if isinstance(row, dict)
        ],
    }


def get_opnsense_control_state(
    service_id: str,
    *,
    search: str = "",
    client: OPNsenseClient | None = None,
) -> dict[str, Any]:
    normalized = str(service_id or "").strip().lower()
    if normalized not in {"ngfw", "ips"}:
        raise KeyError(normalized)
    runtime_client = client or OPNsenseClient()
    config = runtime_client.config
    base = {
        "service_id": normalized,
        "generated_at": datetime.now(tz=timezone.utc).isoformat(),
        "configured": config.configured,
        "auth_mode": config.auth_mode if config.configured else "none",
        "verify_tls": config.verify_tls,
        "device_url": config.base_url,
    }
    if not config.configured:
        return {**base, "available": False, "error": "OPNsense control credentials are not configured"}
    try:
        if normalized == "ngfw":
            rules = _firewall_rows(runtime_client)
            aliases = _firewall_aliases(runtime_client)
            return {
                **base,
                "available": True,
                "firewall": {
                    "rules_total": len(rules),
                    "managed_rules": sum(1 for row in rules if row["managed"]),
                    "enabled_rules": sum(1 for row in rules if row["enabled"]),
                    "rules": rules,
                    "aliases_total": len(aliases),
                    "aliases": aliases,
                },
                "system": runtime_client.get("/api/core/system/status"),
            }
        return {**base, "available": True, "ids": _ids_state(runtime_client, search)}
    except Exception as exc:  # noqa: BLE001
        return {**base, "available": False, "error": str(exc)[:600]}


def _require_uuid(value: Any) -> str:
    uuid = _clean_text(value, max_length=40)
    if not _UUID_RE.match(uuid):
        raise ValueError("A valid OPNsense rule UUID is required")
    return uuid


def _find_rule(client: OPNsenseClient, uuid: str) -> dict[str, Any]:
    rule = next((row for row in _firewall_rows(client) if row["uuid"] == uuid), None)
    if not rule:
        raise ValueError(f"Firewall rule not found: {uuid}")
    return rule


def _require_managed_rule(rule: dict[str, Any]) -> None:
    if not rule.get("managed"):
        raise ValueError("Only rules with an SOC or SIEM description can be changed from SIEM")
    if rule.get("legacy") or rule.get("automatic"):
        raise ValueError("Legacy and automatic firewall rules cannot be changed from SIEM")


def _firewall_signature(rows: list[dict[str, Any]]) -> tuple[tuple[Any, ...], ...]:
    return tuple(
        sorted(
            (
                row.get("uuid"),
                row.get("description"),
                row.get("enabled"),
                row.get("action"),
                row.get("interface"),
                row.get("protocol"),
                row.get("source"),
                row.get("source_port"),
                row.get("destination"),
                row.get("destination_port"),
                row.get("log"),
            )
            for row in rows
        )
    )


def _firewall_backups(client: OPNsenseClient) -> list[str]:
    items = client.get("/api/core/backup/backups/this").get("items") or []
    return [
        _clean_text(item.get("id"), max_length=180)
        for item in items
        if isinstance(item, dict) and _clean_text(item.get("id"), max_length=180)
    ]


def _rollback_firewall(
    client: OPNsenseClient,
    backup_id: str,
    baseline_signature: tuple[tuple[Any, ...], ...],
) -> None:
    response = client.post(f"/api/core/backup/revert_backup/{urllib_quote(backup_id)}")
    if str(response.get("status") or "").lower() != "reverted":
        raise RuntimeError(f"OPNsense could not restore firewall backup {backup_id}")
    client.post("/api/firewall/filter/apply")
    restored = _firewall_signature(_firewall_rows(client))
    if restored != baseline_signature:
        raise RuntimeError("OPNsense restored a backup, but the firewall policy does not match the pre-change state")


def _firewall_savepoint(client: OPNsenseClient) -> str:
    try:
        response = client.post("/api/firewall/filter/savepoint")
    except Exception:  # noqa: BLE001
        return ""
    return _clean_text(response.get("revision"), max_length=180)


def _revert_firewall_savepoint(
    client: OPNsenseClient,
    revision: str,
    baseline_signature: tuple[tuple[Any, ...], ...],
) -> None:
    client.post(f"/api/firewall/filter/revert/{urllib_quote(revision)}")
    client.post("/api/firewall/filter/apply")
    if _firewall_signature(_firewall_rows(client)) != baseline_signature:
        raise RuntimeError("OPNsense reverted the savepoint, but the firewall policy does not match the pre-change state")


def _rule_payload(payload: dict[str, Any]) -> dict[str, Any]:
    description = _clean_text(payload.get("description"))
    if not _MANAGED_DESCRIPTION_RE.match(description):
        description = f"SIEM {description}".strip()
    if len(description) < 6:
        raise ValueError("A descriptive firewall rule name is required")
    interface = _clean_text(payload.get("interface"))
    action = _clean_text(payload.get("action") or "block").lower()
    protocol_raw = _clean_text(payload.get("protocol") or "any")
    protocol = next((item for item in _ALLOWED_PROTOCOLS if item.lower() == protocol_raw.lower()), "")
    source = _clean_text(payload.get("source") or "any")
    destination = _clean_text(payload.get("destination") or "any")
    if interface not in _ALLOWED_INTERFACES:
        raise ValueError(f"Unsupported firewall interface: {interface}")
    if action not in _ALLOWED_ACTIONS:
        raise ValueError(f"Unsupported firewall action: {action}")
    if not protocol:
        raise ValueError(f"Unsupported firewall protocol: {protocol_raw}")
    if not source or not destination:
        raise ValueError("Source and destination are required")
    return {
        "rule": {
            "enabled": "1" if bool(payload.get("enabled", True)) else "0",
            "statetype": "keep",
            "sequence": str(max(1, min(int(payload.get("sequence") or 100), 999999))),
            "action": action,
            "quick": "1",
            "interface": interface,
            "direction": "in",
            "ipprotocol": "inet",
            "protocol": protocol,
            "source_net": source,
            "source_not": "1" if bool(payload.get("source_not")) else "0",
            "source_port": _clean_text(payload.get("source_port")),
            "destination_net": destination,
            "destination_not": "1" if bool(payload.get("destination_not")) else "0",
            "destination_port": _clean_text(payload.get("destination_port")),
            "gateway": "",
            "disablereplyto": "1",
            "log": "1" if bool(payload.get("log", True)) else "0",
            "description": description,
        }
    }


def mutate_firewall(
    operation: str,
    payload: dict[str, Any],
    *,
    actor: str,
    client: OPNsenseClient | None = None,
) -> dict[str, Any]:
    runtime_client = client or OPNsenseClient()
    action = str(operation or "").strip().lower()
    if action not in {"create", "update", "toggle", "delete"}:
        raise ValueError(f"Unsupported firewall operation: {action}")
    rollback_backup = ""
    rollback_revision = ""
    object_id = _clean_text(payload.get("uuid")) or "new"
    baseline_rules: list[dict[str, Any]] = []
    baseline_signature: tuple[tuple[Any, ...], ...] = ()
    mutation_started = False
    try:
        baseline_rules = _firewall_rows(runtime_client)
        baseline_signature = _firewall_signature(baseline_rules)
        backup_ids_before = set(_firewall_backups(runtime_client))
        if action == "create":
            body = _rule_payload(payload)
            expected_description = body["rule"]["description"]
            if any(row["description"] == expected_description for row in baseline_rules):
                raise ValueError("A firewall rule with this description already exists")
            rollback_revision = _firewall_savepoint(runtime_client)
            response = runtime_client.post("/api/firewall/filter/add_rule", body)
            mutation_started = True
            object_id = _clean_text(response.get("uuid"), max_length=40) or object_id
            expected_description = body["rule"]["description"]
        else:
            uuid = _require_uuid(payload.get("uuid"))
            current = next((row for row in baseline_rules if row["uuid"] == uuid), None)
            if not current:
                raise ValueError(f"Firewall rule not found: {uuid}")
            _require_managed_rule(current)
            expected_description = current["description"]
            if action == "update":
                body = _rule_payload(payload)
                rollback_revision = _firewall_savepoint(runtime_client)
                runtime_client.post(f"/api/firewall/filter/set_rule/{uuid}", body)
                mutation_started = True
                expected_description = body["rule"]["description"]
            elif action == "toggle":
                desired = bool(payload.get("enabled"))
                if bool(current.get("enabled")) != desired:
                    rollback_revision = _firewall_savepoint(runtime_client)
                    runtime_client.post(
                        f"/api/firewall/filter/toggle_rule/{uuid}/{1 if desired else 0}"
                    )
                    mutation_started = True
            else:
                if _clean_text(payload.get("confirm")) != current["description"]:
                    raise ValueError("Rule description confirmation does not match")
                rollback_revision = _firewall_savepoint(runtime_client)
                runtime_client.post(f"/api/firewall/filter/del_rule/{uuid}")
                mutation_started = True
        if mutation_started:
            backups_after = _firewall_backups(runtime_client)
            rollback_backup = next(
                (backup_id for backup_id in backups_after if backup_id not in backup_ids_before),
                "",
            )
            if not rollback_revision and not rollback_backup:
                raise RuntimeError(
                    "OPNsense saved the change without exposing a rollback savepoint or backup; "
                    "the firewall policy was not applied"
                )
            apply_path = (
                f"/api/firewall/filter/apply/{urllib_quote(rollback_revision)}"
                if rollback_revision
                else "/api/firewall/filter/apply"
            )
            runtime_client.post(apply_path)
        rules_after = _firewall_rows(runtime_client)
        if action == "delete":
            verified = all(row["uuid"] != object_id for row in rules_after)
        elif action == "toggle":
            verified = any(
                row["uuid"] == object_id and row["enabled"] == bool(payload.get("enabled"))
                for row in rules_after
            )
        else:
            verified = any(
                row["description"] == expected_description
                and (object_id == "new" or row["uuid"] == object_id)
                for row in rules_after
            )
        if not verified:
            raise RuntimeError("Firewall mutation could not be verified")
        if mutation_started and rollback_revision:
            runtime_client.post(
                f"/api/firewall/filter/cancel_rollback/{urllib_quote(rollback_revision)}"
            )
        result = {
            "status": "applied",
            "operation": action,
            "rollback_backup": rollback_backup,
            "rollback_revision": rollback_revision,
            "verified": True,
            "rules_total": len(rules_after),
            "object_id": object_id,
        }
        append_audit_event(
            actor=actor,
            action=f"opnsense.firewall.{action}",
            object_type="opnsense_firewall_rule",
            object_id=object_id,
            summary=f"OPNsense firewall rule {action} completed",
            details=result,
        )
        return result
    except Exception as exc:
        rollback_error = ""
        if mutation_started and rollback_revision and baseline_signature:
            try:
                _revert_firewall_savepoint(
                    runtime_client,
                    rollback_revision,
                    baseline_signature,
                )
            except Exception as rollback_exc:  # noqa: BLE001
                rollback_error = str(rollback_exc)[:600]
        elif mutation_started and rollback_backup and baseline_signature:
            try:
                _rollback_firewall(runtime_client, rollback_backup, baseline_signature)
            except Exception as rollback_exc:  # noqa: BLE001
                rollback_error = str(rollback_exc)[:600]
        append_audit_event(
            actor=actor,
            action=f"opnsense.firewall.{action}.failed",
            object_type="opnsense_firewall_rule",
            object_id=object_id,
            summary=f"OPNsense firewall rule {action} failed",
            details={
                "error": str(exc)[:600],
                "rollback_backup": rollback_backup,
                "rollback_revision": rollback_revision,
                "rollback_error": rollback_error,
            },
        )
        if rollback_error:
            raise RuntimeError(f"{exc}; automatic rollback also failed: {rollback_error}") from exc
        raise


def mutate_ids(
    operation: str,
    payload: dict[str, Any],
    *,
    actor: str,
    client: OPNsenseClient | None = None,
) -> dict[str, Any]:
    runtime_client = client or OPNsenseClient()
    action = str(operation or "").strip().lower()
    object_id = ""
    try:
        if action == "toggle_rule":
            object_id = _clean_text(payload.get("sid"))
            if not _SID_RE.match(object_id):
                raise ValueError("A numeric Suricata SID is required")
            desired = payload.get("enabled")
            suffix = "" if desired is None else f"/{1 if bool(desired) else 0}"
            runtime_client.post(f"/api/ids/settings/toggle_rule/{object_id}{suffix}")
            runtime_client.post("/api/ids/service/reload_rules", timeout_seconds=120)
        elif action == "toggle_ruleset":
            object_id = _clean_text(payload.get("filename"))
            available = {
                row["filename"]: row
                for row in _ids_state(runtime_client, "")["rulesets"]
            }
            current = available.get(object_id)
            if current is None:
                raise ValueError(f"Unknown Suricata ruleset: {object_id}")
            desired = (
                bool(payload.get("enabled"))
                if "enabled" in payload
                else not bool(current.get("enabled"))
            )
            runtime_client.post(
                f"/api/ids/settings/toggle_ruleset/{urllib_quote(object_id)}/{1 if desired else 0}"
            )
            runtime_client.post("/api/ids/service/reload_rules", timeout_seconds=120)
            refreshed = {
                row["filename"]: row
                for row in _ids_state(runtime_client, "")["rulesets"]
            }.get(object_id)
            if refreshed is None or bool(refreshed.get("enabled")) != desired:
                runtime_client.post(
                    f"/api/ids/settings/toggle_ruleset/{urllib_quote(object_id)}/{1 if bool(current.get('enabled')) else 0}"
                )
                runtime_client.post("/api/ids/service/reload_rules", timeout_seconds=120)
                raise RuntimeError(
                    f"Suricata ruleset {object_id} did not reach the requested state"
                )
        elif action in {"reload", "update"}:
            object_id = action
            endpoint = "reload_rules" if action == "reload" else "update_rules"
            timeout_seconds = 120 if action == "reload" else 300
            runtime_client.post(
                f"/api/ids/service/{endpoint}",
                timeout_seconds=timeout_seconds,
            )
        else:
            raise ValueError(f"Unsupported IDS operation: {action}")
        status = runtime_client.get("/api/ids/service/status").get("status")
        if str(status or "").lower() != "running":
            raise RuntimeError(f"Suricata operation completed, but service status is {status or 'unknown'}")
        result = {
            "status": "applied",
            "operation": action,
            "object_id": object_id,
            "service_status": status,
            "verified": True,
        }
        if action == "toggle_ruleset":
            result["object_enabled"] = desired
        append_audit_event(
            actor=actor,
            action=f"opnsense.ids.{action}",
            object_type="opnsense_ids",
            object_id=object_id,
            summary=f"OPNsense IDS operation {action} completed",
            details=result,
        )
        return result
    except Exception as exc:
        append_audit_event(
            actor=actor,
            action=f"opnsense.ids.{action}.failed",
            object_type="opnsense_ids",
            object_id=object_id,
            summary=f"OPNsense IDS operation {action} failed",
            details={"error": str(exc)[:600]},
        )
        raise


def urllib_quote(value: str) -> str:
    from urllib.parse import quote

    return quote(value, safe="")
