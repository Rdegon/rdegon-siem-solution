from __future__ import annotations

import ipaddress
from typing import Any

try:
    from .inventory_catalog import SOURCE_ALIAS_OVERRIDES
except ImportError:  # pragma: no cover - local test fallback
    from inventory_catalog import SOURCE_ALIAS_OVERRIDES  # type: ignore[no-redef]


def _string(value: Any) -> str:
    return str(value or "").strip()


def _normalize_hostname(value: Any) -> str:
    return _string(value).lower()


def _short_hostname(value: Any) -> str:
    hostname = _normalize_hostname(value)
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        return hostname
    return hostname.split(".", 1)[0] if hostname else ""


def _normalize_token(value: Any) -> str:
    return "".join(ch.lower() for ch in _string(value) if ch.isalnum())


def _csv_items(value: Any) -> list[str]:
    if isinstance(value, str):
        raw = value.split(",")
    elif isinstance(value, (list, tuple, set)):
        raw = list(value)
    else:
        raw = []
    items: list[str] = []
    seen: set[str] = set()
    for item in raw:
        text = _string(item)
        if not text:
            continue
        key = text.lower()
        if key in seen:
            continue
        seen.add(key)
        items.append(text)
    return items


def _add_alias(store: dict[str, list[dict[str, Any]]], alias: str, asset: dict[str, Any], *, basis: str, confidence: float) -> None:
    text = _string(alias)
    if not text:
        return
    store.setdefault(text, []).append({"asset": dict(asset), "basis": basis, "confidence": confidence})


def _asset_aliases(asset: dict[str, Any], source_inventory: list[dict[str, Any]] | None = None) -> list[tuple[str, str, float]]:
    aliases: list[tuple[str, str, float]] = []
    asset_id = _string(asset.get("asset_id"))
    hostname = _normalize_hostname(asset.get("hostname"))
    ip_value = _string(asset.get("ip"))
    if asset_id:
        aliases.append((asset_id, "asset_id", 1.0))
    if hostname:
        aliases.append((hostname, "hostname", 0.99))
        aliases.append((_short_hostname(hostname), "hostname_short", 0.95))
    if ip_value:
        aliases.append((ip_value, "ip", 0.99))
        override = _string(SOURCE_ALIAS_OVERRIDES.get(ip_value))
        if override:
            aliases.append((override, "ip_override", 0.96))
            aliases.append((_short_hostname(override), "ip_override_short", 0.94))
    for field in ("aliases", "source_aliases", "connected_sources", "dns_names"):
        for item in _csv_items(asset.get(field)):
            aliases.append((_normalize_hostname(item), field, 0.9))
            aliases.append((_short_hostname(item), f"{field}_short", 0.86))
    for item in _csv_items(asset.get("tags")):
        if "." in item or "-" in item:
            aliases.append((_normalize_hostname(item), "tag", 0.72))
    if source_inventory:
        related = [
            row
            for row in source_inventory
            if _string(row.get("cmdb_asset_id")) == asset_id
            or _normalize_hostname(row.get("source_name")) == hostname
            or _string(row.get("ip")) == ip_value
        ]
        for row in related:
            source_name = _normalize_hostname(row.get("source_name"))
            if source_name:
                aliases.append((source_name, "source_inventory", 0.9))
                aliases.append((_short_hostname(source_name), "source_inventory_short", 0.88))
            for value in row.get("aliases") or []:
                aliases.append((_normalize_hostname(value), "source_alias", 0.84))
                aliases.append((_short_hostname(value), "source_alias_short", 0.82))
    return aliases


def build_asset_lookup(assets: list[dict[str, Any]], source_inventory: list[dict[str, Any]] | None = None) -> dict[str, list[dict[str, Any]]]:
    lookup: dict[str, list[dict[str, Any]]] = {}
    for asset in assets:
        for alias, basis, confidence in _asset_aliases(asset, source_inventory):
            _add_alias(lookup, alias, asset, basis=basis, confidence=confidence)
            _add_alias(lookup, _normalize_token(alias), asset, basis=f"{basis}_token", confidence=max(confidence - 0.04, 0.5))
    return lookup


def _asset_index_value(assets: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    index: dict[str, dict[str, Any]] = {}
    for asset in assets:
        for alias, _, _ in _asset_aliases(asset):
            if not alias:
                continue
            index.setdefault(alias.lower(), dict(asset))
            index.setdefault(_normalize_token(alias), dict(asset))
    return index


def _finding_candidates(item: dict[str, Any]) -> list[tuple[str, str, float]]:
    values: list[tuple[str, str, float]] = []
    for key, basis, confidence in (
        ("asset_id", "asset_id", 1.0),
        ("host_name", "host_name", 0.98),
        ("dst_ip", "dst_ip", 0.99),
        ("target", "target", 0.92),
        ("target_name", "target_name", 0.9),
        ("target_hostname", "target_hostname", 0.9),
        ("fqdn", "fqdn", 0.95),
    ):
        value = _string(item.get(key))
        if not value:
            continue
        values.append((value, basis, confidence))
        values.append((_normalize_hostname(value), f"{basis}_normalized", max(confidence - 0.02, 0.5)))
        values.append((_short_hostname(value), f"{basis}_short", max(confidence - 0.05, 0.5)))
        values.append((_normalize_token(value), f"{basis}_token", max(confidence - 0.08, 0.45)))
    return [(value, basis, confidence) for value, basis, confidence in values if value]


def _override_match(
    item: dict[str, Any],
    overrides: list[dict[str, Any]] | None,
    assets: list[dict[str, Any]] | None,
) -> dict[str, Any] | None:
    if not overrides or not assets:
        return None
    candidates = {_string(binding_target_label(item)).lower()}
    candidates.update(candidate.lower() for candidate, _, _ in _finding_candidates(item))
    tokenized = {_normalize_token(value) for value in candidates if value}
    asset_index = _asset_index_value(list(assets))
    for override in overrides:
        if not bool(override.get("enabled", True)):
            continue
        scope = _string(override.get("scope") or "all").lower() or "all"
        if scope not in {"all", "vulnerability"}:
            continue
        override_tokens = {
            _string(override.get("target")).lower(),
            _string(override.get("hostname")).lower(),
            _string(override.get("ip")).lower(),
            *[_string(item).lower() for item in (override.get("aliases") or []) if _string(item)],
        }
        override_tokens = {value for value in override_tokens if value}
        override_tokenized = {_normalize_token(value) for value in override_tokens}
        if not ((candidates & override_tokens) or (tokenized & override_tokenized)):
            continue
        preferred_keys = [
            _string(override.get("asset_id")),
            _string(override.get("hostname")),
            _string(override.get("ip")),
            *[_string(item) for item in (override.get("aliases") or []) if _string(item)],
            _string(override.get("target")),
        ]
        asset = None
        for key in preferred_keys:
            if not key:
                continue
            asset = asset_index.get(key.lower()) or asset_index.get(_normalize_token(key))
            if asset:
                break
        if asset:
            return {
                "asset": dict(asset),
                "basis": f"override:{_string(override.get('target') or override.get('id'))}",
                "confidence": 1.0,
                "candidate": _string(binding_target_label(item)),
                "override_id": _string(override.get("id")),
            }
    return None


def match_finding_asset(
    item: dict[str, Any],
    lookup: dict[str, list[dict[str, Any]]],
    *,
    overrides: list[dict[str, Any]] | None = None,
    assets: list[dict[str, Any]] | None = None,
) -> dict[str, Any] | None:
    override_match = _override_match(item, overrides, assets)
    if override_match is not None:
        return override_match
    best: dict[str, Any] | None = None
    for candidate, finding_basis, finding_confidence in _finding_candidates(item):
        for match in lookup.get(candidate, []):
            score = round(float(match.get("confidence") or 0) * float(finding_confidence), 4)
            proposal = {
                "asset": dict(match.get("asset") or {}),
                "basis": f"{finding_basis}->{_string(match.get('basis'))}",
                "confidence": score,
                "candidate": candidate,
            }
            if best is None or float(proposal["confidence"]) > float(best.get("confidence") or 0):
                best = proposal
    return best


def binding_target_label(item: dict[str, Any]) -> str:
    return _string(item.get("host_name")) or _string(item.get("dst_ip")) or _string(item.get("target_name")) or "unknown-target"


def is_ip_address(value: Any) -> bool:
    text = _string(value)
    if not text:
        return False
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return False
    return True
