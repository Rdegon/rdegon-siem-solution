from __future__ import annotations

import base64
import json
import re
import shlex
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

from .clickhouse_runtime import get_clickhouse_client


MAX_RANGE_HOURS = 24 * 31
MAX_PAGE_SIZE = 250
MAX_FILTERS = 24
MAX_EXPERT_LENGTH = 2_000
MAX_FACET_VALUES = 30
SAVED_SEARCH_TABLE = "siem.hunting_saved_searches"

_WINDOWS = {
    "15m": timedelta(minutes=15),
    "1h": timedelta(hours=1),
    "6h": timedelta(hours=6),
    "24h": timedelta(hours=24),
    "72h": timedelta(hours=72),
    "7d": timedelta(days=7),
    "30d": timedelta(days=30),
}
_SOURCE_TABLES = {
    "hot": "siem.events",
    "cold": "siem.events_cold",
    "stream": "siem.events_stream",
}
_COLLECTOR_PROFILE_EXPR = (
    "coalesce("
    "nullIf(JSONExtractString(normalized_json, 'collector_profile'), ''), "
    "nullIf(JSONExtractString(normalized_json, 'collector', 'profile'), ''), "
    "nullIf(log_source, ''), 'unknown')"
)
_PUBLIC_FIELDS = {
    "ts": "ts",
    "event_id": "event_id",
    "event_code": "event_code",
    "source_type": "coalesce(nullIf(device_product, ''), nullIf(log_source, ''), 'unknown')",
    "source": "log_source",
    "log_source": "log_source",
    "collector_profile": _COLLECTOR_PROFILE_EXPR,
    "category": "category",
    "subcategory": "subcategory",
    "severity": "lower(severity)",
    "host": "coalesce(nullIf(host_name, ''), nullIf(asset_id, ''), nullIf(log_source, ''), 'unknown')",
    "host_name": "host_name",
    "asset_id": "asset_id",
    "src_ip": "toString(src_ip)",
    "dst_ip": "toString(dst_ip)",
    "src_port": "toString(src_port)",
    "dst_port": "toString(dst_port)",
    "user_name": "user_name",
    "target_user": "target_user",
    "event_action": "event_action",
    "event_outcome": "event_outcome",
    "process_name": "process_name",
    "process_executable": "process_executable",
    "process_command": "process_command",
    "message": "message",
}
_FILTER_OPERATORS = {"eq", "neq", "contains", "not_contains", "in", "not_in", "exists", "gt", "gte", "lt", "lte"}
_FACETS = ("source_type", "source", "collector_profile", "category", "severity", "host")
_TEXT_SEARCH = ("message", "log_source", "host_name", "user_name", "target_user", "process_name", "process_command", "event_code")
_DETAIL_NORMALIZED_KEYS = {
    "event.kind",
    "event.module",
    "event.provider",
    "event.type",
    "network.protocol",
    "http.request.method",
    "http.response.status_code",
    "url.domain",
    "url.path",
    "dns.question.name",
    "file.name",
    "file.hash.sha256",
    "process.parent.name",
    "service.name",
}
_SAFE_ID_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,127}$")


class HuntingValidationError(ValueError):
    pass


class HuntingNotFoundError(LookupError):
    pass


def _client():
    return get_clickhouse_client()


def _as_utc(value: Any, *, label: str) -> datetime:
    text = str(value or "").strip()
    if not text:
        raise HuntingValidationError(f"{label} is required")
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise HuntingValidationError(f"{label} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _bounded_range(payload: dict[str, Any]) -> tuple[datetime, datetime]:
    now = datetime.now(timezone.utc)
    if payload.get("from_ts") or payload.get("to_ts"):
        start = _as_utc(payload.get("from_ts"), label="from_ts")
        end = _as_utc(payload.get("to_ts"), label="to_ts")
    else:
        window = str(payload.get("window") or "24h")
        delta = _WINDOWS.get(window)
        if delta is None:
            raise HuntingValidationError(f"Unsupported window: {window}")
        end = now
        start = end - delta
    if end <= start:
        raise HuntingValidationError("to_ts must be after from_ts")
    if end - start > timedelta(hours=MAX_RANGE_HOURS):
        raise HuntingValidationError(f"Time range cannot exceed {MAX_RANGE_HOURS} hours")
    if end > now + timedelta(minutes=5):
        raise HuntingValidationError("to_ts cannot be in the future")
    return start, end


def _query_parameters(result: Any) -> list[dict[str, Any]]:
    if hasattr(result, "named_results"):
        return [dict(row) for row in result.named_results()]
    return []


def available_event_sources(*, client=None) -> dict[str, Any]:
    ch = client or _client()
    rows = _query_parameters(
        ch.query(
            """
            SELECT database, name
            FROM system.tables
            WHERE (database, name) IN (
                ('siem', 'events'),
                ('siem', 'events_cold'),
                ('siem', 'events_stream')
            )
            """
        )
    )
    existing = {f"{row.get('database')}.{row.get('name')}" for row in rows}
    items = []
    labels = {"hot": "Оперативное хранилище", "cold": "Архив событий", "stream": "Поток событий"}
    for source_id, table in _SOURCE_TABLES.items():
        if table in existing:
            items.append({"id": source_id, "label": labels[source_id], "table": table, "available": True})
    return {
        "items": items,
        "default": "hot" if "siem.events" in existing else (items[0]["id"] if items else ""),
        "facets": list(_FACETS),
        "max_range_hours": MAX_RANGE_HOURS,
        "max_page_size": MAX_PAGE_SIZE,
    }


def _validate_source(source: Any, *, client=None) -> str:
    source_id = str(source or "hot").strip().lower()
    capabilities = available_event_sources(client=client)
    allowed = {str(item["id"]) for item in capabilities["items"]}
    if source_id not in allowed:
        raise HuntingValidationError(f"Event source is not available: {source_id}")
    return source_id


def _parameter(params: dict[str, Any], value: Any, type_name: str = "String") -> str:
    key = f"p{len(params)}"
    params[key] = value
    return f"%({key})s"


def _field(name: Any) -> str:
    field_name = str(name or "").strip()
    if field_name not in _PUBLIC_FIELDS:
        raise HuntingValidationError(f"Unsupported event field: {field_name}")
    return _PUBLIC_FIELDS[field_name]


def _compile_filter(item: dict[str, Any], params: dict[str, Any]) -> str:
    expression = _field(item.get("field"))
    operator = str(item.get("operator") or "eq").strip().lower()
    if operator not in _FILTER_OPERATORS:
        raise HuntingValidationError(f"Unsupported filter operator: {operator}")
    raw_values = item.get("values") if "values" in item else item.get("value")
    values = raw_values if isinstance(raw_values, list) else [raw_values]
    values = [str(value) for value in values if value is not None and str(value) != ""]
    if operator == "exists":
        expected = str(item.get("value", "true")).lower() not in {"false", "0", "no"}
        return f"length(toString({expression})) {'>' if expected else '='} 0"
    if not values:
        raise HuntingValidationError(f"Filter {item.get('field')} requires a value")
    if operator in {"in", "not_in"}:
        if len(values) > 50:
            raise HuntingValidationError("A filter cannot contain more than 50 values")
        placeholders = ", ".join(_parameter(params, value) for value in values)
        return f"toString({expression}) {'NOT IN' if operator == 'not_in' else 'IN'} ({placeholders})"
    placeholder = _parameter(params, values[0])
    if operator == "eq":
        return f"toString({expression}) = {placeholder}"
    if operator == "neq":
        return f"toString({expression}) != {placeholder}"
    if operator == "contains":
        return f"positionCaseInsensitiveUTF8(toString({expression}), {placeholder}) > 0"
    if operator == "not_contains":
        return f"positionCaseInsensitiveUTF8(toString({expression}), {placeholder}) = 0"
    symbols = {"gt": ">", "gte": ">=", "lt": "<", "lte": "<="}
    return f"toString({expression}) {symbols[operator]} {placeholder}"


def _search_term(value: str, params: dict[str, Any]) -> str:
    placeholder = _parameter(params, value)
    haystack = ", ".join(f"toString({_PUBLIC_FIELDS[field]})" for field in _TEXT_SEARCH)
    return f"positionCaseInsensitiveUTF8(concatWithSeparator(' ', {haystack}), {placeholder}) > 0"


def _expert_tokens(query: str) -> list[str]:
    if len(query) > MAX_EXPERT_LENGTH:
        raise HuntingValidationError(f"Expert query cannot exceed {MAX_EXPERT_LENGTH} characters")
    lexer = shlex.shlex(query, posix=True, punctuation_chars="()")
    lexer.whitespace_split = True
    lexer.commenters = ""
    return list(lexer)


def _expert_clause(token: str, params: dict[str, Any]) -> str:
    for marker, operator in (("!=", "neq"), (">=", "gte"), ("<=", "lte"), (":", "eq"), ("=", "eq"), (">", "gt"), ("<", "lt")):
        if marker in token:
            field_name, value = token.split(marker, 1)
            if field_name in _PUBLIC_FIELDS and value:
                chosen = "contains" if marker == ":" and "*" in value else operator
                return _compile_filter(
                    {"field": field_name, "operator": chosen, "value": value.replace("*", "")},
                    params,
                )
    if re.search(r"\b(select|insert|alter|drop|system|union)\b", token, re.IGNORECASE):
        raise HuntingValidationError("SQL is not accepted by the expert query editor")
    return _search_term(token, params)


def _compile_expert(query: Any, params: dict[str, Any]) -> str:
    text = str(query or "").strip()
    if not text:
        return "1"
    tokens = _expert_tokens(text)
    if len(tokens) > 64:
        raise HuntingValidationError("Expert query contains too many terms")
    output: list[str] = []
    expect_clause = True
    depth = 0
    for token in tokens:
        upper = token.upper()
        if token == "(":
            if not expect_clause:
                raise HuntingValidationError("Missing boolean operator before '('")
            output.append("(")
            depth += 1
            continue
        if token == ")":
            if expect_clause or depth <= 0:
                raise HuntingValidationError("Unexpected ')'")
            output.append(")")
            depth -= 1
            expect_clause = False
            continue
        if upper in {"AND", "OR"}:
            if expect_clause:
                raise HuntingValidationError(f"Unexpected boolean operator: {upper}")
            output.append(upper)
            expect_clause = True
            continue
        if upper == "NOT":
            if not expect_clause:
                raise HuntingValidationError("Missing boolean operator before NOT")
            output.append("NOT")
            continue
        if not expect_clause:
            output.append("AND")
        output.append(f"({_expert_clause(token, params)})")
        expect_clause = False
    if expect_clause or depth:
        raise HuntingValidationError("Incomplete expert query")
    return " ".join(output)


def _decode_cursor(value: Any) -> tuple[str, str] | None:
    raw = str(value or "").strip()
    if not raw:
        return None
    try:
        payload = json.loads(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)).decode("utf-8"))
        ts = _iso(_as_utc(payload.get("ts"), label="cursor.ts"))
        stable_id = str(payload.get("id") or "")
    except Exception as exc:  # noqa: BLE001
        raise HuntingValidationError("Invalid pagination cursor") from exc
    if not stable_id or len(stable_id) > 256:
        raise HuntingValidationError("Invalid pagination cursor")
    return ts, stable_id


def _encode_cursor(row: dict[str, Any]) -> str:
    payload = json.dumps({"v": 1, "ts": row["ts"], "id": row["stable_id"]}, separators=(",", ":"))
    return base64.urlsafe_b64encode(payload.encode("utf-8")).decode("ascii").rstrip("=")


def _select_columns() -> str:
    return f"""
        ts,
        if(length(event_id) > 0, event_id, hex(MD5(concat(toString(ts), log_source, message)))) AS stable_id,
        event_id, event_code,
        coalesce(nullIf(device_product, ''), nullIf(log_source, ''), 'unknown') AS source_type,
        log_source AS source, log_source, '' AS observer_collector,
        {_COLLECTOR_PROFILE_EXPR} AS collector_profile,
        category, subcategory, lower(severity) AS severity,
        coalesce(nullIf(host_name, ''), nullIf(asset_id, ''), nullIf(log_source, ''), 'unknown') AS host,
        host_name, asset_id, src_ip, dst_ip, src_port, dst_port,
        user_name, target_user, event_action, event_outcome,
        process_name, process_executable, process_command, message
    """


def _serialize(value: Any) -> Any:
    if isinstance(value, datetime):
        return _iso(value)
    if isinstance(value, (list, tuple)):
        return [_serialize(item) for item in value]
    if isinstance(value, dict):
        return {str(key): _serialize(item) for key, item in value.items()}
    return value


def _base_where(
    payload: dict[str, Any],
    *,
    source_id: str,
    start: datetime,
    end: datetime,
    params: dict[str, Any],
) -> list[str]:
    clauses = [
        f"ts >= parseDateTime64BestEffort({_parameter(params, _iso(start))})",
        f"ts < parseDateTime64BestEffort({_parameter(params, _iso(end))})",
    ]
    filters = payload.get("filters") or []
    if not isinstance(filters, list):
        raise HuntingValidationError("filters must be an array")
    if len(filters) > MAX_FILTERS:
        raise HuntingValidationError(f"No more than {MAX_FILTERS} filters are allowed")
    for item in filters:
        if not isinstance(item, dict):
            raise HuntingValidationError("Each filter must be an object")
        clauses.append(_compile_filter(item, params))
    clauses.append(_compile_expert(payload.get("expert_query"), params))
    return clauses


def query_events(payload: dict[str, Any], *, tenant_id: str, client=None) -> dict[str, Any]:
    if tenant_id != "main":
        raise HuntingValidationError("Only the production tenant 'main' is available")
    ch = client or _client()
    source_id = _validate_source(payload.get("source"), client=ch)
    start, end = _bounded_range(payload)
    limit = max(1, min(int(payload.get("limit") or 100), MAX_PAGE_SIZE))
    offset = max(0, int(payload.get("offset") or 0))
    if offset > 100_000:
        raise HuntingValidationError("Offset cannot exceed 100000; use the cursor for deep pagination")
    cursor = _decode_cursor(payload.get("cursor"))
    if cursor and offset:
        raise HuntingValidationError("Use either cursor or offset pagination, not both")
    params: dict[str, Any] = {}
    clauses = _base_where(payload, source_id=source_id, start=start, end=end, params=params)
    count_clauses = list(clauses)
    if cursor:
        cursor_ts, cursor_id = cursor
        ts_param = _parameter(params, cursor_ts)
        id_param = _parameter(params, cursor_id)
        stable_expr = "if(length(event_id) > 0, event_id, hex(MD5(concat(toString(ts), log_source, message))))"
        parsed_ts = f"parseDateTime64BestEffort({ts_param})"
        clauses.append(f"(ts < {parsed_ts} OR (ts = {parsed_ts} AND {stable_expr} < {id_param}))")
    table = _SOURCE_TABLES[source_id]
    sql = f"""
        SELECT {_select_columns()}
        FROM {table}
        WHERE {' AND '.join(f'({item})' for item in clauses)}
        ORDER BY ts DESC, stable_id DESC
        LIMIT {limit + 1}
        {f'OFFSET {offset}' if offset else ''}
    """
    rows = [_serialize(row) for row in _query_parameters(ch.query(sql, parameters=params))]
    has_more = len(rows) > limit
    page_rows = rows[:limit]
    next_cursor = _encode_cursor(page_rows[-1]) if has_more and page_rows else ""
    count = None
    if bool(payload.get("include_count")):
        count_sql = f"SELECT count() AS total FROM {table} WHERE {' AND '.join(f'({item})' for item in count_clauses)}"
        count_param_names = {name for clause in count_clauses for name in re.findall(r"%\((p\d+)\)s", clause)}
        count_rows = _query_parameters(ch.query(count_sql, parameters={name: params[name] for name in count_param_names}))
        count = int(count_rows[0].get("total") or 0) if count_rows else 0
    return {
        "rows": page_rows,
        "row_count": len(page_rows),
        "total_count": count,
        "total_count_is_estimate": count is None,
        "source": source_id,
        "from_ts": _iso(start),
        "to_ts": _iso(end),
        "limit": limit,
        "offset": offset,
        "cursor": str(payload.get("cursor") or ""),
        "next_cursor": next_cursor,
        "has_more": has_more,
        "pagination": "cursor" if cursor or payload.get("pagination") == "cursor" else "offset",
    }


def query_facets(payload: dict[str, Any], *, tenant_id: str, client=None) -> dict[str, Any]:
    if tenant_id != "main":
        raise HuntingValidationError("Only the production tenant 'main' is available")
    ch = client or _client()
    source_id = _validate_source(payload.get("source"), client=ch)
    start, end = _bounded_range(payload)
    params: dict[str, Any] = {}
    clauses = _base_where(payload, source_id=source_id, start=start, end=end, params=params)
    table = _SOURCE_TABLES[source_id]
    where = " AND ".join(f"({item})" for item in clauses)
    facet_tuples = ", ".join(
        f"tuple('{facet}', toString({_PUBLIC_FIELDS[facet]}))"
        for facet in _FACETS
    )
    facet_sql = f"""
        SELECT tupleElement(facet, 1) AS facet_name, tupleElement(facet, 2) AS value, count() AS count
        FROM {table}
        ARRAY JOIN [{facet_tuples}] AS facet
        WHERE {where}
        GROUP BY facet_name, value
        ORDER BY facet_name ASC, count DESC, value ASC
        LIMIT {MAX_FACET_VALUES} BY facet_name
    """
    result: dict[str, list[dict[str, Any]]] = {facet: [] for facet in _FACETS}
    for row in _query_parameters(ch.query(facet_sql, parameters=params)):
        facet_name = str(row.get("facet_name") or "")
        if facet_name in result:
            result[facet_name].append(
                {"value": str(row.get("value") or "unknown"), "count": int(row.get("count") or 0)}
            )
    return {"facets": result, "source": source_id, "from_ts": _iso(start), "to_ts": _iso(end)}


def event_detail(event_id: str, *, event_ts: str, source: str, tenant_id: str, client=None) -> dict[str, Any]:
    if tenant_id != "main":
        raise HuntingValidationError("Only the production tenant 'main' is available")
    if not event_id or len(event_id) > 256:
        raise HuntingValidationError("event_id is required")
    ch = client or _client()
    source_id = _validate_source(source, client=ch)
    table = _SOURCE_TABLES[source_id]
    parsed_event_ts = _as_utc(event_ts, label="event_ts")
    params = {"event_id": event_id, "event_ts": _iso(parsed_event_ts)}
    stable_expr = "if(length(event_id) > 0, event_id, hex(MD5(concat(toString(ts), log_source, message))))"
    sql = f"""
        SELECT {_select_columns()}, normalized_json
        FROM {table}
        WHERE {stable_expr} = %(event_id)s
          AND ts >= parseDateTime64BestEffort(%(event_ts)s) - INTERVAL 1 SECOND
          AND ts <= parseDateTime64BestEffort(%(event_ts)s) + INTERVAL 1 SECOND
        ORDER BY ts DESC
        LIMIT 1
    """
    rows = _query_parameters(ch.query(sql, parameters=params))
    if not rows:
        raise HuntingNotFoundError(f"Event not found: {event_id}")
    raw = dict(rows[0])
    normalized_raw = raw.pop("normalized_json", "")
    normalized: dict[str, Any] = {}
    try:
        parsed = normalized_raw if isinstance(normalized_raw, dict) else json.loads(str(normalized_raw or "{}"))
        if isinstance(parsed, dict):
            normalized = {key: _serialize(parsed[key]) for key in _DETAIL_NORMALIZED_KEYS if key in parsed}
    except (TypeError, ValueError, json.JSONDecodeError):
        normalized = {}
    event = _serialize(raw)
    return {
        "event": event,
        "sections": {
            "identity": {key: event.get(key) for key in ("event_id", "event_code", "ts", "severity", "category", "subcategory")},
            "source": {key: event.get(key) for key in ("source_type", "source", "collector_profile", "host", "asset_id")},
            "network": {key: event.get(key) for key in ("src_ip", "src_port", "dst_ip", "dst_port")},
            "principal": {key: event.get(key) for key in ("user_name", "target_user")},
            "process": {key: event.get(key) for key in ("process_name", "process_executable", "process_command")},
            "normalized": normalized,
        },
        "raw_json_available": False,
        "source": source_id,
    }


def _ensure_saved_search_table(client=None) -> None:
    ch = client or _client()
    ch.command(
        f"""
        CREATE TABLE IF NOT EXISTS {SAVED_SEARCH_TABLE}
        (
            tenant_id LowCardinality(String),
            owner String,
            search_id String,
            name String,
            description String,
            specification_json String,
            deleted UInt8 DEFAULT 0,
            revision UInt64,
            updated_at DateTime64(3, 'UTC')
        )
        ENGINE = ReplacingMergeTree(revision)
        ORDER BY (tenant_id, owner, search_id)
        """
    )


def _saved_search_rows(*, tenant_id: str, owner: str, client=None) -> list[dict[str, Any]]:
    ch = client or _client()
    _ensure_saved_search_table(ch)
    rows = _query_parameters(
        ch.query(
            f"""
            SELECT search_id, name, description, specification_json, revision, updated_at
            FROM {SAVED_SEARCH_TABLE} FINAL
            WHERE tenant_id = %(tenant_id)s AND owner = %(owner)s AND deleted = 0
            ORDER BY name ASC, search_id ASC
            """,
            parameters={"tenant_id": tenant_id, "owner": owner},
        )
    )
    result = []
    for row in rows:
        try:
            specification = json.loads(str(row.get("specification_json") or "{}"))
        except json.JSONDecodeError:
            specification = {}
        result.append(
            {
                "id": str(row.get("search_id") or ""),
                "name": str(row.get("name") or ""),
                "description": str(row.get("description") or ""),
                "specification": specification if isinstance(specification, dict) else {},
                "tenant_id": tenant_id,
                "owner": owner,
                "revision": int(row.get("revision") or 0),
                "updated_at": _serialize(row.get("updated_at")),
            }
        )
    return result


def list_saved_searches(*, tenant_id: str, owner: str, client=None) -> dict[str, Any]:
    return {"items": _saved_search_rows(tenant_id=tenant_id, owner=owner, client=client), "tenant_id": tenant_id, "owner": owner}


def _validate_search_specification(value: Any, *, client=None) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise HuntingValidationError("specification must be an object")
    start, end = _bounded_range(dict(value))
    source_id = _validate_source(value.get("source"), client=client)
    params: dict[str, Any] = {}
    _base_where(dict(value), source_id=source_id, start=start, end=end, params=params)
    return {
        "source": source_id,
        "window": str(value.get("window") or "24h"),
        "from_ts": str(value.get("from_ts") or ""),
        "to_ts": str(value.get("to_ts") or ""),
        "filters": list(value.get("filters") or []),
        "expert_query": str(value.get("expert_query") or ""),
        "limit": max(1, min(int(value.get("limit") or 100), MAX_PAGE_SIZE)),
    }


def save_saved_search(payload: dict[str, Any], *, tenant_id: str, owner: str, client=None) -> dict[str, Any]:
    ch = client or _client()
    _ensure_saved_search_table(ch)
    name = str(payload.get("name") or "").strip()
    if not name or len(name) > 160:
        raise HuntingValidationError("name is required and cannot exceed 160 characters")
    search_id = str(payload.get("id") or uuid.uuid4().hex).strip()
    if not _SAFE_ID_RE.fullmatch(search_id):
        raise HuntingValidationError("Invalid saved search id")
    existing = {item["id"]: item for item in _saved_search_rows(tenant_id=tenant_id, owner=owner, client=ch)}.get(search_id)
    requested_revision = payload.get("revision")
    if existing and requested_revision is not None and int(requested_revision) != int(existing["revision"]):
        raise HuntingValidationError("Saved search revision conflict")
    specification = _validate_search_specification(payload.get("specification") or {}, client=ch)
    revision = int(existing["revision"] if existing else 0) + 1
    now = datetime.now(timezone.utc)
    ch.insert(
        SAVED_SEARCH_TABLE,
        [[tenant_id, owner, search_id, name, str(payload.get("description") or "")[:1000], json.dumps(specification, ensure_ascii=False), 0, revision, now]],
        column_names=["tenant_id", "owner", "search_id", "name", "description", "specification_json", "deleted", "revision", "updated_at"],
    )
    return {
        "id": search_id,
        "name": name,
        "description": str(payload.get("description") or "")[:1000],
        "specification": specification,
        "tenant_id": tenant_id,
        "owner": owner,
        "revision": revision,
        "updated_at": _iso(now),
    }


def delete_saved_search(search_id: str, *, tenant_id: str, owner: str, client=None) -> dict[str, Any]:
    ch = client or _client()
    existing = {item["id"]: item for item in _saved_search_rows(tenant_id=tenant_id, owner=owner, client=ch)}.get(search_id)
    if not existing:
        raise HuntingNotFoundError(f"Saved search not found: {search_id}")
    revision = int(existing["revision"]) + 1
    now = datetime.now(timezone.utc)
    ch.insert(
        SAVED_SEARCH_TABLE,
        [[tenant_id, owner, search_id, existing["name"], existing["description"], json.dumps(existing["specification"], ensure_ascii=False), 1, revision, now]],
        column_names=["tenant_id", "owner", "search_id", "name", "description", "specification_json", "deleted", "revision", "updated_at"],
    )
    return {"status": "deleted", "id": search_id, "revision": revision}
