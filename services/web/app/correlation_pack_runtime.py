from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _resolve_pack_dir() -> Path:
    here = Path(__file__).resolve()
    candidates = [here.parent / "correlation_rule_packs"]
    candidates.extend(parent / "correlation_rule_packs" for parent in here.parents)
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return candidates[0]


PACK_DIR = _resolve_pack_dir()


def _deps():
    try:
        from . import deps as deps_module
    except ImportError:  # pragma: no cover - local test fallback
        import deps as deps_module  # type: ignore[no-redef]
    return deps_module


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _string(value: Any) -> str:
    return str(value or "").strip()


def _safe_slug(value: str) -> str:
    safe = "".join(ch.lower() if ch.isalnum() else "-" for ch in _string(value))
    while "--" in safe:
        safe = safe.replace("--", "-")
    return safe.strip("-")


def _pack_file_name(pack_id: str) -> str:
    return f"{_safe_slug(pack_id).replace('-', '_')}.json"


def _pack_path(pack_id: str) -> Path:
    return PACK_DIR / _pack_file_name(pack_id)


def _load_pack(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"Pack payload must be an object: {path.name}")
    payload["_file_name"] = path.name
    payload["_path"] = str(path)
    return payload


def _rule_view(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": int(item.get("id") or 0),
        "title": _string(item.get("title")),
        "severity": _string(item.get("severity") or "medium").lower() or "medium",
        "window_s": max(60, int(item.get("window_s") or 300)),
        "threshold": max(1, int(item.get("threshold") or 1)),
        "entity_field": _string(item.get("entity_field") or "host.name") or "host.name",
        "suppression_key": _string(item.get("suppression_key")),
        "status": _string(item.get("status") or "draft").lower() or "draft",
        "operator_action": _string(item.get("operator_action")),
        "sigma_yaml": _string(item.get("sigma_yaml")),
        "expr": _string(item.get("expr")),
    }


def _pack_view(payload: dict[str, Any]) -> dict[str, Any]:
    stream_rules = [
        _rule_view(dict(item))
        for item in list(payload.get("stream_rules") or [])
        if isinstance(item, dict)
    ]
    batch_rules = [
        {
            "id": int(item.get("id") or 0),
            "title": _string(item.get("title")),
            "severity": _string(item.get("severity") or "medium").lower() or "medium",
            "status": _string(item.get("status") or "draft").lower() or "draft",
            "description": _string(item.get("description")),
        }
        for item in list(payload.get("batch_rules") or [])
        if isinstance(item, dict)
    ]
    return {
        "pack_id": _string(payload.get("pack_id")),
        "title": _string(payload.get("title")),
        "version": _string(payload.get("version") or "1.0.0") or "1.0.0",
        "status": _string(payload.get("status") or "draft").lower() or "draft",
        "owner": _string(payload.get("owner") or "platform-release") or "platform-release",
        "notes": [_string(item) for item in list(payload.get("notes") or []) if _string(item)],
        "stream_rules": stream_rules,
        "batch_rules": batch_rules,
        "rule_count": len(stream_rules) + len(batch_rules),
        "active_stream_rules": sum(1 for item in stream_rules if item["status"] in {"active", "publish_ready_after_host_metrics"}),
        "file_name": _string(payload.get("_file_name")),
        "updated_ts": _now_iso(),
    }


def _validate_pack_payload(payload: dict[str, Any]) -> tuple[dict[str, Any], list[str], list[str]]:
    errors: list[str] = []
    warnings: list[str] = []
    normalized = {
        "pack_id": _safe_slug(_string(payload.get("pack_id"))),
        "title": _string(payload.get("title")),
        "version": _string(payload.get("version") or "1.0.0") or "1.0.0",
        "status": _string(payload.get("status") or "draft").lower() or "draft",
        "owner": _string(payload.get("owner") or "platform-release") or "platform-release",
        "notes": [_string(item) for item in list(payload.get("notes") or []) if _string(item)],
        "stream_rules": [],
        "batch_rules": [],
    }
    if not normalized["pack_id"]:
        errors.append("pack_id is required")
    if not normalized["title"]:
        errors.append("title is required")
    seen_rule_ids: set[int] = set()
    for index, raw_rule in enumerate(list(payload.get("stream_rules") or []), start=1):
        if not isinstance(raw_rule, dict):
            errors.append(f"stream_rules[{index}] must be an object")
            continue
        try:
            rule = _rule_view(dict(raw_rule))
        except Exception as exc:  # noqa: BLE001
            errors.append(f"stream_rules[{index}] invalid: {exc}")
            continue
        if rule["id"] <= 0:
            errors.append(f"stream_rules[{index}] id must be > 0")
        elif rule["id"] in seen_rule_ids:
            errors.append(f"stream_rules[{index}] duplicate id {rule['id']}")
        else:
            seen_rule_ids.add(rule["id"])
        if not rule["title"]:
            errors.append(f"stream_rules[{index}] title is required")
        if not rule["sigma_yaml"] and not rule["expr"]:
            errors.append(f"stream_rules[{index}] sigma_yaml or expr is required")
        if not rule["suppression_key"]:
            warnings.append(f"stream_rules[{index}] suppression_key is empty")
        if not rule["operator_action"]:
            warnings.append(f"stream_rules[{index}] operator_action is empty")
        normalized["stream_rules"].append(rule)
    for index, raw_rule in enumerate(list(payload.get("batch_rules") or []), start=1):
        if not isinstance(raw_rule, dict):
            errors.append(f"batch_rules[{index}] must be an object")
            continue
        rule_id = int(raw_rule.get("id") or 0)
        title = _string(raw_rule.get("title"))
        if rule_id <= 0:
            errors.append(f"batch_rules[{index}] id must be > 0")
        if not title:
            errors.append(f"batch_rules[{index}] title is required")
        normalized["batch_rules"].append(
            {
                "id": rule_id,
                "title": title,
                "severity": _string(raw_rule.get("severity") or "medium").lower() or "medium",
                "status": _string(raw_rule.get("status") or "draft").lower() or "draft",
                "description": _string(raw_rule.get("description")),
            }
        )
    return normalized, errors, warnings


def list_correlation_packs() -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    for path in sorted(PACK_DIR.glob("*.json")):
        try:
            items.append(_pack_view(_load_pack(path)))
        except Exception:  # noqa: BLE001
            continue
    return items


def get_correlation_pack(pack_id: str) -> dict[str, Any]:
    safe_pack_id = _safe_slug(pack_id)
    if not safe_pack_id:
        raise ValueError("pack_id is required")
    for path in PACK_DIR.glob("*.json"):
        payload = _load_pack(path)
        if _string(payload.get("pack_id")) == safe_pack_id or path.stem == safe_pack_id.replace("-", "_"):
            return _pack_view(payload)
    raise ValueError(f"Unknown correlation pack: {pack_id}")


def save_correlation_pack(payload: dict[str, Any], *, actor: str = "web") -> dict[str, Any]:
    normalized, errors, warnings = _validate_pack_payload(dict(payload or {}))
    if errors:
        raise ValueError("; ".join(errors))
    PACK_DIR.mkdir(parents=True, exist_ok=True)
    path = _pack_path(str(normalized.get("pack_id") or ""))
    path.write_text(json.dumps(normalized, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    result = _pack_view(_load_pack(path))
    result["validation"] = {"valid": True, "errors": [], "warnings": warnings}
    result["saved_by"] = actor
    return result


def validate_correlation_pack(pack_id: str = "", payload: dict[str, Any] | None = None) -> dict[str, Any]:
    if payload is None:
        pack = get_correlation_pack(pack_id)
        payload = {
            "pack_id": pack.get("pack_id"),
            "title": pack.get("title"),
            "version": pack.get("version"),
            "status": pack.get("status"),
            "owner": pack.get("owner"),
            "notes": pack.get("notes"),
            "stream_rules": pack.get("stream_rules"),
            "batch_rules": pack.get("batch_rules"),
        }
    normalized, errors, warnings = _validate_pack_payload(dict(payload or {}))
    return {
        "valid": not errors,
        "errors": errors,
        "warnings": warnings,
        "summary": {
            "pack_id": normalized.get("pack_id"),
            "rule_count": len(list(normalized.get("stream_rules") or [])) + len(list(normalized.get("batch_rules") or [])),
            "active_stream_rules": sum(
                1
                for item in list(normalized.get("stream_rules") or [])
                if str(item.get("status") or "").lower() in {"active", "publish_ready_after_host_metrics"}
            ),
        },
    }


def _direct_stream_rule(rule: dict[str, Any], *, pack_id: str) -> dict[str, Any]:
    return {
        "id": int(rule["id"]),
        "title": rule["title"],
        "sigma_id": f"{pack_id}-{int(rule['id'])}",
        "status": rule["status"],
        "level": rule["severity"],
        "source_format": "stream-expr",
        "logsource_product": "",
        "logsource_service": "",
        "logsource_category": "",
        "sigma_yaml": "",
        "expr": rule["expr"],
        "entity_field": rule["entity_field"],
        "window_s": int(rule["window_s"]),
        "threshold": int(rule["threshold"]),
        "verification_query": "",
        "tags": f"pack.{pack_id},source.stream_expr",
        "description": rule["operator_action"],
        "enabled": 1,
        "author": f"operational-pack:{pack_id}",
    }


def test_correlation_pack(pack_id: str, *, payload: dict[str, Any] | None = None) -> dict[str, Any]:
    if payload is None:
        pack = get_correlation_pack(pack_id)
        payload = {
            "pack_id": pack.get("pack_id"),
            "title": pack.get("title"),
            "version": pack.get("version"),
            "status": pack.get("status"),
            "owner": pack.get("owner"),
            "notes": pack.get("notes"),
            "stream_rules": pack.get("stream_rules"),
            "batch_rules": pack.get("batch_rules"),
        }
    validation = validate_correlation_pack(payload=payload)
    if not bool(validation.get("valid")):
        return {
            "status": "validation_failed",
            "validation": validation,
            "items": [],
        }
    deps = _deps()
    items: list[dict[str, Any]] = []
    for raw_rule in list(payload.get("stream_rules") or []):
        if not isinstance(raw_rule, dict):
            continue
        rule = _rule_view(dict(raw_rule))
        compiled: dict[str, Any] | None = None
        compile_error = ""
        try:
            if rule["sigma_yaml"]:
                compiled = dict(
                    deps.convert_sigma_to_stream_rule(
                        rule["sigma_yaml"],
                        threshold=rule["threshold"],
                        window_s=rule["window_s"],
                        entity_field=rule["entity_field"],
                        rule_id=rule["id"],
                    )
                )
            else:
                compiled = _direct_stream_rule(rule, pack_id=str(payload.get("pack_id") or pack_id or "custom-pack"))
        except Exception as exc:  # noqa: BLE001
            compile_error = str(exc)
        runtime_test: dict[str, Any] | None = None
        if not compile_error:
            try:
                runtime_test = dict(deps.test_detection_rule(rule["id"]))
            except Exception:  # noqa: BLE001
                runtime_test = None
        items.append(
            {
                "rule_id": rule["id"],
                "title": rule["title"],
                "status": "compiled" if not compile_error else "compile_failed",
                "compile_error": compile_error,
                "compiled_stream_rule": compiled or {},
                "runtime_test": runtime_test or {},
            }
        )
    return {
        "status": "ok" if all(item["status"] == "compiled" for item in items) else "degraded",
        "validation": validation,
        "items": items,
    }


def publish_correlation_pack(pack_id: str) -> dict[str, Any]:
    pack = get_correlation_pack(pack_id)
    validation = validate_correlation_pack(payload=pack)
    if not bool(validation.get("valid")):
        raise ValueError("; ".join(validation.get("errors") or ["pack validation failed"]))
    deps = _deps()
    deps.ensure_detection_support_tables()
    published = 0
    published_rules: list[int] = []
    for raw_rule in list(pack.get("stream_rules") or []):
        if not isinstance(raw_rule, dict):
            continue
        rule = _rule_view(dict(raw_rule))
        deps.get_ch_client().command(f"ALTER TABLE {deps.DETECTION_RULE_TABLE} DELETE WHERE id = {int(rule['id'])}")
        deps.get_ch_client().command(f"ALTER TABLE siem.correlation_rules_stream DELETE WHERE id = {int(rule['id'])}")
    for raw_rule in list(pack.get("stream_rules") or []):
        if not isinstance(raw_rule, dict):
            continue
        rule = _rule_view(dict(raw_rule))
        if rule["status"] not in {"active", "publish_ready_after_host_metrics"}:
            continue
        if rule["sigma_yaml"]:
            converted = dict(
                deps.convert_sigma_to_stream_rule(
                    rule["sigma_yaml"],
                    threshold=rule["threshold"],
                    window_s=rule["window_s"],
                    entity_field=rule["entity_field"],
                    rule_id=rule["id"],
                )
            )
            converted["author"] = f"operational-pack:{pack['pack_id']}"
            converted["description"] = rule["operator_action"] or converted.get("description") or ""
            converted["level"] = rule["severity"]
            converted["enabled"] = 1
        else:
            converted = _direct_stream_rule(rule, pack_id=str(pack["pack_id"]))
        deps.get_ch_client().command(f"ALTER TABLE {deps.DETECTION_RULE_TABLE} DELETE WHERE id = {int(converted['id'])}")
        deps.get_ch_client().command(f"ALTER TABLE siem.correlation_rules_stream DELETE WHERE id = {int(converted['id'])}")
        deps._insert_detection_rule_rows([converted], sync_stream=True)  # type: ignore[attr-defined]
        published += 1
        published_rules.append(int(converted["id"]))
    return {
        "status": "published",
        "pack_id": pack["pack_id"],
        "published_rules": published,
        "rule_ids": published_rules,
        "published_ts": _now_iso(),
    }
