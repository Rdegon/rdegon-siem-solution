from __future__ import annotations

import base64
import html
import importlib
import json
import os
import re
import threading
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Any

try:
    from .enterprise_control_plane import load_control_plane_rows, save_control_plane_rows
except ImportError:  # pragma: no cover - local test fallback
    from enterprise_control_plane import load_control_plane_rows, save_control_plane_rows  # type: ignore[no-redef]

try:
    from .inventory_catalog import SOURCE_ALIAS_OVERRIDES
except ImportError:  # pragma: no cover - local test fallback
    from inventory_catalog import SOURCE_ALIAS_OVERRIDES  # type: ignore[no-redef]

try:
    from .proxmox_fleet_runtime import list_proxmox_fleet_inventory
except ImportError:  # pragma: no cover - local test fallback
    from proxmox_fleet_runtime import list_proxmox_fleet_inventory  # type: ignore[no-redef]

try:
    from .proxmox_guest_ops import guest_exec, proxmox_guest_exec_configured
except ImportError:  # pragma: no cover - local test fallback
    from proxmox_guest_ops import guest_exec, proxmox_guest_exec_configured  # type: ignore[no-redef]

try:
    from .runtime_humanization import canonicalize_source_name, humanize_source_name, humanize_technical_value
except ImportError:  # pragma: no cover - local test fallback
    from runtime_humanization import canonicalize_source_name, humanize_source_name, humanize_technical_value  # type: ignore[no-redef]

try:
    from .deploy.env_file_runtime import maybe_load_runtime_env
except ImportError:  # pragma: no cover - runtime fallback
    try:
        from deploy.env_file_runtime import maybe_load_runtime_env  # type: ignore[no-redef]
    except ImportError:  # pragma: no cover - test fallback
        def maybe_load_runtime_env() -> dict[str, str]:
            return {}


INCIDENT_AI_COLLECTION = "incident_ai_assessments"
_OPENCLAW_VMID = 126
_OPENCLAW_GUEST_TYPE = "qemu"
_SEARCH_PROXY_ENV = ("SIEM_OPENCLAW_PROXY_URL", "SIEM_TELEGRAM_PROXY_URL")
_SEARCH_USER_AGENT = "Mozilla/5.0 (compatible; RdegonSIEM/2026.07; +https://192.168.3.102)"
_ASSESSMENT_LOCK = threading.Lock()
_RUNNING_ASSESSMENTS: set[str] = set()


def _now_iso() -> str:
    return datetime.now(tz=timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _load_rows() -> list[dict[str, Any]]:
    rows = load_control_plane_rows(INCIDENT_AI_COLLECTION, list)
    return rows if isinstance(rows, list) else []


def _save_rows(rows: list[dict[str, Any]]) -> None:
    save_control_plane_rows(INCIDENT_AI_COLLECTION, rows)


def _incident_key(view: str, record_id: str) -> str:
    return f"{'raw' if view == 'raw' else 'agg'}:{str(record_id or '').strip()}"


def _deps_module() -> Any:
    maybe_load_runtime_env()
    errors: list[str] = []
    candidates: list[tuple[str, str | None]] = [
        (".deps", __package__),
        ("app.deps", None),
        ("services.web.app.deps", None),
        ("deps", None),
    ]
    for module_name, package_name in candidates:
        try:
            if package_name is None:
                return importlib.import_module(module_name)
            return importlib.import_module(module_name, package_name)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{module_name}: {exc}")
    raise RuntimeError(f"Unable to load deps module for incident AI runtime: {' | '.join(errors)}")


def _list_incidents(view: str) -> list[dict[str, Any]]:
    deps_module = _deps_module()
    if view == "raw":
        return deps_module.fetch_alerts_raw(limit=5000)
    return deps_module.fetch_alerts_agg(limit=5000)


def _get_incident_row(view: str, record_id: str) -> dict[str, Any]:
    key_name = "alert_id" if view == "raw" else "agg_id"
    safe_record_id = str(record_id or "").strip()
    rows = _list_incidents(view)
    selected = next((row for row in rows if str(row.get(key_name) or "").strip() == safe_record_id), None)
    if not isinstance(selected, dict):
        raise ValueError(f"Incident not found: {record_id}")
    return selected


def _event_count(row: dict[str, Any]) -> int:
    for key in ("raw_hits_total", "raw_alerts_total", "count_alerts", "hits", "count", "events_count"):
        value = row.get(key)
        try:
            if value is None or value == "":
                continue
            return int(value)
        except Exception:  # noqa: BLE001
            continue
    return 0


def _context_blob(row: dict[str, Any]) -> dict[str, Any]:
    context = row.get("context")
    if isinstance(context, dict):
        return dict(context)
    samples = row.get("samples")
    if isinstance(samples, list):
        for item in samples:
            if isinstance(item, dict):
                return dict(item)
    return {}


def _display_title(row: dict[str, Any]) -> str:
    return str(
        row.get("title")
        or row.get("summary")
        or row.get("rule_name")
        or row.get("message")
        or row.get("agg_id")
        or row.get("alert_id")
        or "Инцидент"
    ).strip()


def _humanize_label(value: Any) -> str:
    raw = str(value or "").strip()
    if not raw:
        return ""
    return humanize_source_name(raw, lang="ru", technical_suffix=True) or humanize_technical_value(raw, lang="ru") or raw


def _candidate_host_tokens(row: dict[str, Any]) -> list[str]:
    context = _context_blob(row)
    cluster = dict(row.get("cluster") or {})
    values: list[Any] = [
        row.get("source"),
        row.get("source_summary"),
        row.get("entity_key"),
        context.get("host_name"),
        context.get("source"),
        context.get("log_source"),
        context.get("observer_collector"),
        context.get("src_ip"),
        context.get("dst_ip"),
    ]
    for key in ("sources", "assets", "actors", "iocs"):
        blob = cluster.get(key) or row.get(key)
        if isinstance(blob, list):
            values.extend(blob)
    tokens: list[str] = []
    for value in values:
        text = str(value or "").strip()
        if not text:
            continue
        tokens.append(text)
        canonical = canonicalize_source_name(text)
        if canonical and canonical != text:
            tokens.append(canonical)
    return list(dict.fromkeys(tokens))


def _inventory_index() -> dict[str, dict[str, Any]]:
    index: dict[str, dict[str, Any]] = {}
    try:
        fleet_payload = list_proxmox_fleet_inventory()
    except Exception:  # noqa: BLE001
        fleet_payload = []
    if isinstance(fleet_payload, dict):
        items = list(fleet_payload.get("items") or [])
    elif isinstance(fleet_payload, list):
        items = list(fleet_payload)
    else:
        items = []
    for item in items:
        if not isinstance(item, dict):
            continue
        for key in ("name", "source_name", "hostname", "ip", "vmid"):
            value = str(item.get(key) or "").strip()
            if not value:
                continue
            index[value.lower()] = item
            canonical = canonicalize_source_name(value).lower()
            if canonical:
                index[canonical] = item
    for alias, canonical in SOURCE_ALIAS_OVERRIDES.items():
        if alias.lower() in index:
            index[canonical.lower()] = index[alias.lower()]
    return index


def _incident_hosts(row: dict[str, Any]) -> list[dict[str, Any]]:
    index = _inventory_index()
    matched: list[dict[str, Any]] = []
    seen: set[str] = set()
    for token in _candidate_host_tokens(row):
        candidate = index.get(str(token or "").strip().lower())
        if not isinstance(candidate, dict):
            continue
        host_key = str(candidate.get("name") or candidate.get("source_name") or candidate.get("ip") or "").strip().lower()
        if not host_key or host_key in seen:
            continue
        seen.add(host_key)
        supported_actions = ["snapshot"]
        if str(candidate.get("os_family") or "").lower() == "linux":
            supported_actions.append("refresh_telemetry")
        matched.append(
            {
                "name": str(candidate.get("name") or ""),
                "source_name": str(candidate.get("source_name") or ""),
                "label": _humanize_label(candidate.get("name") or candidate.get("source_name")),
                "ip": str(candidate.get("ip") or ""),
                "vmid": int(candidate.get("vmid") or 0),
                "guest_type": str(candidate.get("guest_type") or ""),
                "os_family": str(candidate.get("os_family") or ""),
                "role": str(candidate.get("role") or ""),
                "business_service": str(candidate.get("business_service") or ""),
                "state": str(candidate.get("state") or ""),
                "supported_actions": supported_actions,
            }
        )
    return matched


def _search_proxy_url() -> str:
    maybe_load_runtime_env()
    for env_name in _SEARCH_PROXY_ENV:
        value = str(os.getenv(env_name, "") or "").strip()
        if value:
            return value
    return ""


def _urlopen(url: str, *, timeout: int = 8) -> str:
    handlers: list[Any] = []
    proxy_url = _search_proxy_url()
    if proxy_url:
        handlers.append(urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url}))
    opener = urllib.request.build_opener(*handlers)
    request = urllib.request.Request(url, headers={"User-Agent": _SEARCH_USER_AGENT, "Accept-Language": "en-US,en;q=0.8,ru;q=0.7"})
    with opener.open(request, timeout=timeout) as response:
        return response.read().decode("utf-8", errors="replace")


def _search_bing(query: str) -> list[dict[str, str]]:
    url = f"https://www.bing.com/search?format=rss&q={urllib.parse.quote(query)}"
    body = _urlopen(url)
    root = ET.fromstring(body)
    items: list[dict[str, str]] = []
    for node in root.findall(".//item")[:3]:
        items.append(
            {
                "engine": "bing",
                "title": html.unescape(str(node.findtext("title") or "").strip()),
                "url": str(node.findtext("link") or "").strip(),
                "snippet": html.unescape(str(node.findtext("description") or "").strip()),
            }
        )
    return [item for item in items if item["title"] and item["url"]]


def _search_duckduckgo(query: str) -> list[dict[str, str]]:
    url = f"https://lite.duckduckgo.com/lite/?q={urllib.parse.quote(query)}"
    body = _urlopen(url)
    matches = re.findall(r'<a[^>]+href="([^"]+)"[^>]*>(.*?)</a>', body, flags=re.IGNORECASE | re.DOTALL)
    items: list[dict[str, str]] = []
    for href, title_html in matches:
        title = re.sub(r"<[^>]+>", "", title_html)
        title = html.unescape(title).strip()
        if not title or href.startswith("/"):
            continue
        items.append({"engine": "duckduckgo", "title": title, "url": html.unescape(href), "snippet": ""})
        if len(items) >= 3:
            break
    return items


def _search_queries(row: dict[str, Any]) -> list[str]:
    cluster = dict(row.get("cluster") or {})
    queries: list[str] = []
    base_title = _display_title(row)
    primary_actor = next((str(item).strip() for item in (cluster.get("actors") or []) if str(item).strip()), "")
    primary_ioc = next((str(item).strip() for item in (cluster.get("iocs") or []) if str(item).strip()), "")
    sources = [str(item).strip() for item in (cluster.get("sources") or []) if str(item).strip()]
    if base_title:
        queries.append(base_title)
    if base_title and primary_actor:
        queries.append(f"{base_title} {primary_actor}")
    if base_title and primary_ioc:
        queries.append(f"{base_title} {primary_ioc}")
    if base_title and sources:
        queries.append(f"{base_title} {sources[0]}")
    return list(dict.fromkeys(query for query in queries if query))[:3]


def _search_context(row: dict[str, Any]) -> dict[str, Any]:
    queries = _search_queries(row)
    results: list[dict[str, str]] = []
    errors: list[str] = []
    seen_urls: set[str] = set()
    for query in queries:
        for engine_fn in (_search_bing, _search_duckduckgo):
            try:
                engine_results = engine_fn(query)
            except Exception as exc:  # noqa: BLE001
                engine_name = getattr(engine_fn, "__name__", engine_fn.__class__.__name__)
                errors.append(f"{engine_name}:{exc}")
                if not results and len(errors) >= 2:
                    return {"queries": queries, "results": [], "errors": errors[:4], "proxy_url": _search_proxy_url()}
                continue
            for item in engine_results:
                url = str(item.get("url") or "").strip()
                if not url or url in seen_urls:
                    continue
                seen_urls.add(url)
                results.append({"query": query, **item})
    return {"queries": queries, "results": results[:8], "errors": errors[:4], "proxy_url": _search_proxy_url()}


def _extract_json_block(text: str) -> dict[str, Any] | None:
    safe_text = str(text or "").strip()
    if not safe_text:
        return None
    decoder = json.JSONDecoder()
    for start in range(len(safe_text)):
        if safe_text[start] not in "{[":
            continue
        try:
            obj, _ = decoder.raw_decode(safe_text[start:])
            if isinstance(obj, dict):
                return obj
        except Exception:  # noqa: BLE001
            continue
    return None


def _extract_openclaw_assistant_text(body: dict[str, Any], *, _seen: set[int] | None = None) -> str:
    if not isinstance(body, dict):
        return ""
    if _seen is None:
        _seen = set()
    identity = id(body)
    if identity in _seen:
        return ""
    _seen.add(identity)

    messages = body.get("messages") or []
    for item in reversed(messages):
        if not isinstance(item, dict):
            continue
        if str(item.get("role") or "").lower() != "assistant":
            continue
        text = str(item.get("content") or "").strip()
        if text:
            return text

    payloads = body.get("payloads") or []
    text_parts: list[str] = []
    for item in payloads:
        if not isinstance(item, dict):
            continue
        text = str(item.get("text") or "").strip()
        if text:
            text_parts.append(text)
    if text_parts:
        return "\n".join(text_parts).strip()

    result = body.get("result")
    if isinstance(result, dict):
        return _extract_openclaw_assistant_text(result, _seen=_seen)
    return ""


def _ensure_openclaw_search_tools() -> dict[str, Any]:
    if not proxmox_guest_exec_configured():
        return {"status": "unavailable", "message": "Proxmox guest-exec is not configured"}
    script = """
python3 - <<'PY'
import json
from pathlib import Path
path = Path('/home/openclaw/.openclaw/openclaw.json')
data = json.loads(path.read_text(encoding='utf-8'))
changed = False
root_tools = data.setdefault('tools', {})
root_deny = [str(item) for item in (root_tools.get('deny') or [])]
if 'web_search' in root_deny:
    root_tools['deny'] = [item for item in root_deny if item != 'web_search']
    changed = True
root_allow = [str(item) for item in (root_tools.get('allow') or [])]
for tool in ('browser', 'web_fetch', 'web_search'):
    if tool not in root_allow:
        root_allow.append(tool)
        changed = True
root_tools['allow'] = root_allow
for agent in data.get('agents', {}).get('list', []):
    if str(agent.get('id') or '') not in {'main', 'research'}:
        continue
    tools = agent.setdefault('tools', {})
    deny = [str(item) for item in (tools.get('deny') or []) if str(item) not in {'web_search', 'browser'}]
    if deny != list(tools.get('deny') or []):
        changed = True
    tools['deny'] = deny
    allow = [str(item) for item in (tools.get('allow') or [])]
    for tool in ('browser', 'web_fetch', 'web_search'):
        if tool not in allow:
            allow.append(tool)
            changed = True
    tools['allow'] = allow
    sandbox = ((tools.get('sandbox') or {}).get('tools') or {})
    sandbox_allow = [str(item) for item in (sandbox.get('allow') or [])]
    for tool in ('browser', 'web_fetch', 'web_search'):
        if tool not in sandbox_allow:
            sandbox_allow.append(tool)
            changed = True
    sandbox['allow'] = sandbox_allow
    sandbox['deny'] = [str(item) for item in (sandbox.get('deny') or []) if str(item) not in {'web_search', 'browser'}]
    tools.setdefault('sandbox', {})['tools'] = sandbox
if changed:
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2) + '\\n', encoding='utf-8')
print(json.dumps({'changed': changed}, ensure_ascii=True))
PY
systemctl restart openclaw-gateway.service >/dev/null 2>&1 || true
"""
    output = guest_exec(_OPENCLAW_VMID, _OPENCLAW_GUEST_TYPE, script, timeout=300).strip()
    payload = _extract_json_block(output) or {}
    return {"status": "ok", **payload}


def _openclaw_prompt_bundle(view: str, record_id: str, row: dict[str, Any], history: list[dict[str, Any]], hosts: list[dict[str, Any]], search_blob: dict[str, Any]) -> dict[str, Any]:
    cluster = dict(row.get("cluster") or {})
    context = _context_blob(row)
    return {
        "incident": {
            "ref": _incident_key(view, record_id),
            "title": _display_title(row),
            "severity": str(row.get("severity_agg") or row.get("severity") or "medium"),
            "status": str(row.get("status") or "new"),
            "assignee": str(row.get("assignee") or ""),
            "events": _event_count(row),
            "entity": str(row.get("entity_key") or ""),
            "summary": str(row.get("summary") or row.get("message") or row.get("rule_name") or "").strip(),
            "sources": [str(item).strip() for item in (cluster.get("sources") or []) if str(item).strip()],
            "actors": [str(item).strip() for item in (cluster.get("actors") or []) if str(item).strip()],
            "assets": [str(item).strip() for item in (cluster.get("assets") or []) if str(item).strip()],
            "iocs": [str(item).strip() for item in (cluster.get("iocs") or []) if str(item).strip()],
            "campaigns": [str(item).strip() for item in (cluster.get("campaigns") or []) if str(item).strip()],
            "context": context,
            "history": history[-12:],
        },
        "humanized": {
            "title": _display_title(row),
            "source_labels": [_humanize_label(item) for item in (cluster.get("sources") or []) if str(item or "").strip()],
            "asset_labels": [_humanize_label(item) for item in (cluster.get("assets") or []) if str(item or "").strip()],
            "ioc_labels": [_humanize_label(item) for item in (cluster.get("iocs") or []) if str(item or "").strip()],
        },
        "hosts": hosts,
        "search": search_blob,
    }


def _openclaw_python_script(prompt_b64: str) -> str:
    return "\n".join(
        [
            "import base64, json, subprocess",
            f"prompt=base64.b64decode('{prompt_b64}').decode('utf-8')",
            "proc=subprocess.run(['sudo','-u','openclaw','-H','env','HOME=/home/openclaw','openclaw','agent','--agent','research','--message',prompt,'--json','--local'],capture_output=True,text=True,timeout=300)",
            "assistant=''",
            "body={}",
            "errors=[]",
            "try:",
            "    body=json.loads(proc.stdout or '{}')",
            "except Exception as exc:",
            "    errors.append(str(exc))",
            "messages=body.get('messages') or []",
            "assistant=next((str(item.get('content') or '') for item in reversed(messages) if str(item.get('role') or '').lower()=='assistant' and str(item.get('content') or '').strip()), '')",
            "print(json.dumps({'returncode':proc.returncode,'assistant':assistant,'stdout':proc.stdout[-12000:],'stderr':proc.stderr[-2000:],'errors':errors}, ensure_ascii=True))",
        ]
    )


def _run_openclaw_analysis(bundle: dict[str, Any]) -> dict[str, Any]:
    if not proxmox_guest_exec_configured():
        raise RuntimeError("OpenClaw bridge is not configured")
    _ensure_openclaw_search_tools()
    prompt = (
        "Ты SOC-аналитик и помощник по расследованию инцидентов. "
        "Верни ТОЛЬКО JSON без markdown и без пояснений. "
        "Схема ответа: "
        '{"score":0,"confidence":"low|medium|high","summary":"","status_suggestion":"new|assigned|in_progress|closed","assignee_hint":"","why_it_matters":[],"recommended_actions":[],"machine_actions":[],"ioc_summary":[],"search_findings":[],"notes":[]}. '
        "Пиши по-русски. score от 0 до 100. "
        "recommended_actions — шаги для аналитика. "
        "machine_actions — только безопасные действия из набора collect_snapshot и refresh_telemetry. "
        "search_findings — короткие выводы по внешнему интернет-контексту. "
        "Если данных мало, явно скажи об этом в summary и confidence."
        "\n\nКонтекст инцидента:\n"
        + json.dumps(bundle, ensure_ascii=False)
    )
    prompt_b64 = base64.b64encode(prompt.encode("utf-8")).decode("ascii")
    python_one_liner = _openclaw_python_script(prompt_b64)
    output = guest_exec(
        _OPENCLAW_VMID,
        _OPENCLAW_GUEST_TYPE,
        "python3 -c " + json.dumps(python_one_liner),
        timeout=360,
    ).strip()
    payload = _extract_json_block(output) or {}
    assistant_text = str(payload.get("assistant") or "").strip()
    if not assistant_text:
        assistant_text = _extract_openclaw_assistant_text(_extract_json_block(str(payload.get("stdout") or "")) or {})
    if int(payload.get("returncode") or 0) != 0:
        raise RuntimeError(f"OpenClaw returned non-zero status: {payload.get('stderr') or payload.get('stdout') or payload}")
    parsed = _extract_json_block(assistant_text)
    if not isinstance(parsed, dict):
        parsed = {
            "score": 35,
            "confidence": "low",
            "summary": assistant_text or "OpenClaw не смог вернуть структурированный JSON, сохранён сырой ответ.",
            "status_suggestion": "in_progress",
            "assignee_hint": "",
            "why_it_matters": [],
            "recommended_actions": [],
            "machine_actions": [],
            "ioc_summary": [],
            "search_findings": [],
            "notes": [],
        }
    return {
        "model_output": parsed,
        "assistant_text": assistant_text,
        "stderr": str(payload.get("stderr") or ""),
        "stdout_sample": str(payload.get("stdout") or "")[-3000:],
    }


def _fallback_incident_ai_assessment(bundle: dict[str, Any], *, error_message: str = "") -> dict[str, Any]:
    incident = dict(bundle.get("incident") or {})
    context = dict(incident.get("context") or {})
    hosts = list(bundle.get("hosts") or [])
    title = str(incident.get("title") or "").strip()
    title_lower = title.lower()
    campaigns = {str(item or "").strip().lower() for item in (incident.get("campaigns") or []) if str(item or "").strip()}
    source_blob = " ".join(str(item or "") for item in (incident.get("sources") or []))
    host_blob = " ".join(str(item.get("name") or "") for item in hosts if isinstance(item, dict))
    combined = " ".join(
        [
            title_lower,
            source_blob.lower(),
            host_blob.lower(),
            str(context.get("host_name") or "").lower(),
            str(context.get("source") or "").lower(),
            str(context.get("process_command") or "").lower(),
            str(context.get("target_user") or "").lower(),
        ]
    )
    notes: list[str] = []
    if error_message:
        notes.append(f"Внешний AI-разбор недоступен, использована локальная эвристика: {error_message[:240]}")
    summary = "Нужна ручная проверка: внешний AI-разбор не завершился, вывод построен по локальному контексту инцидента."
    score = 45
    confidence = "low"
    status_suggestion = "in_progress"
    why_it_matters = ["Внешний AI-разбор был недоступен, поэтому это предварительная оценка по уже собранным данным."]
    recommended_actions = ["Открыть карточку инцидента и сверить последние события, статус узла и историю срабатываний."]
    machine_actions: list[str] = []

    is_openclaw = "openclaw" in combined
    if is_openclaw and (
        "reconnaissance" in campaigns
        or "linux_dns_query" in campaigns
        or "audit_execve" in campaigns
        or "syslog" in campaigns
        or "privilege_escalation" in campaigns
        or "sudo_command" in campaigns
        or "audit_user_command" in campaigns
        or "linux system recon burst" in title_lower
    ):
        summary = (
            "Похоже на служебную исследовательскую активность OpenClaw на шлюзе, а не на подтверждённую атаку. "
            "Кластер совпадает с уже подтверждёнными ложноположительными срабатываниями."
        )
        score = 12
        confidence = "medium"
        status_suggestion = "closed"
        why_it_matters = [
            "События приходят с узла OpenClaw и совпадают с разрешёнными research/proxy-паттернами.",
            "После remediation новые однотипные алерты почти прекратились, в очереди в основном исторический backlog.",
        ]
        recommended_actions = [
            "Проверить, что на OpenClaw не было новых сервисных ошибок и всплесков вне ожидаемого окна.",
            "Если поток новых событий тихий, закрыть инцидент как false_positive с пометкой OpenClaw expected activity.",
        ]
        machine_actions = ["refresh_telemetry"]
    elif "host_load_pressure" in campaigns and any(
        str(item.get("name") or "").strip().lower() in {"nextcloud-siem", "navidrome-01"} for item in hosts if isinstance(item, dict)
    ):
        summary = (
            "Похоже на историческое шумовое срабатывание по нагрузке на прикладном узле. "
            "После ужесточения host-runtime правил такие события больше не должны эскалироваться как полноценный инцидент."
        )
        score = 18
        confidence = "medium"
        status_suggestion = "closed"
        why_it_matters = [
            "Узел не относится к core transport/storage/control-plane ролям, для которых такие алерты считаются критичными.",
            "Текущая волна таких инцидентов выглядит как backlog до remediation, а не как новая деградация.",
        ]
        recommended_actions = [
            "Подтвердить, что на хосте нет failed services и swap pressure.",
            "При чистом runtime закрыть как false_positive и наблюдать только через host-runtime.",
        ]
        machine_actions = ["refresh_telemetry"]
    elif (
        ("linux sudo to root" in title_lower or "privilege_escalation" in campaigns)
        and "systemctl is-active siem-" in combined
        and any(
            str(item.get("name") or "").strip().lower() in {"siem-ingest", "siem-processing", "siem-storage", "siem-web", "siem-standby-transport"}
            for item in hosts
            if isinstance(item, dict)
        )
    ):
        summary = (
            "Похоже на служебную операторскую проверку состояния SIEM-сервисов через sudo/systemctl, "
            "а не на подтверждённое повышение привилегий."
        )
        score = 14
        confidence = "medium"
        status_suggestion = "closed"
        why_it_matters = [
            "Команда совпадает с регулярным operational health-check по SIEM-сервисам.",
            "После allowlist-фикса такие sudo-проверки больше не должны поднимать новый инцидент.",
        ]
        recommended_actions = [
            "Проверить, что в кластере нет других root-команд помимо service-status checks.",
            "Если дополнительных действий нет, закрыть карточку как false_positive с пометкой operational sudo.",
        ]
    elif "host_service_flapping" in campaigns:
        summary = "Есть признак нестабильности сервисов на узле. Это не выглядит как явный фолс без дополнительной проверки."
        score = 58
        confidence = "medium"
        status_suggestion = "in_progress"
        why_it_matters = ["Нужна проверка реальных рестартов и failed services на affected host."]
        recommended_actions = [
            "Снять snapshot состояния узла и проверить systemd/journal.",
            "Сравнить события с maintenance window и недавними rollout-окнами.",
        ]
        machine_actions = ["collect_snapshot", "refresh_telemetry"]
    elif "network_intrusion" in campaigns:
        summary = "Есть признаки внешнего сетевого зондирования. Нужна ручная верификация, это не подтверждённый фолс."
        score = 72
        confidence = "medium"
        status_suggestion = "in_progress"
        why_it_matters = ["Кампания network_intrusion требует проверки сетевого контекста и охвата по нескольким узлам."]
        recommended_actions = [
            "Сверить источник, порты, повторяемость и affected assets.",
            "Проверить, связано ли это с внешним сканированием или исследовательской активностью собственной инфраструктуры.",
        ]
        machine_actions = ["collect_snapshot"]

    return {
        "score": score,
        "confidence": confidence,
        "summary": summary,
        "status_suggestion": status_suggestion,
        "assignee_hint": "soc-tier1" if score >= 50 else "system-fp-remediation",
        "why_it_matters": why_it_matters,
        "recommended_actions": recommended_actions,
        "machine_actions": machine_actions,
        "ioc_summary": [],
        "search_findings": [],
        "notes": notes,
    }


def get_incident_ai_assessment(view: str, record_id: str) -> dict[str, Any]:
    safe_key = _incident_key(view, record_id)
    rows = _load_rows()
    selected = next((row for row in rows if str(row.get("incident_ref") or "") == safe_key), None)
    return dict(selected or {})


def _replace_assessment(record: dict[str, Any]) -> dict[str, Any]:
    with _ASSESSMENT_LOCK:
        rows = [row for row in _load_rows() if str(row.get("incident_ref") or "") != str(record.get("incident_ref") or "")]
        rows.append(record)
        rows.sort(key=lambda item: str(item.get("generated_ts") or item.get("requested_ts") or ""), reverse=True)
        _save_rows(rows[:500])
        return record


def _mark_assessment_running(incident_ref: str) -> bool:
    with _ASSESSMENT_LOCK:
        if incident_ref in _RUNNING_ASSESSMENTS:
            return False
        _RUNNING_ASSESSMENTS.add(incident_ref)
        return True


def _clear_assessment_running(incident_ref: str) -> None:
    with _ASSESSMENT_LOCK:
        _RUNNING_ASSESSMENTS.discard(incident_ref)


def _generate_incident_ai_assessment_sync(
    view: str,
    record_id: str,
    *,
    requested_by: str = "",
    timezone_name: str = "Europe/Moscow",
) -> dict[str, Any]:
    safe_view = "raw" if view == "raw" else "agg"
    row = _get_incident_row(safe_view, record_id)
    history = _deps_module().fetch_alert_history(safe_view, record_id)
    hosts = _incident_hosts(row)
    search_blob = _search_context(row)
    bundle = _openclaw_prompt_bundle(safe_view, record_id, row, history, hosts, search_blob)
    fallback_used = False
    try:
        model_result = _run_openclaw_analysis(bundle)
    except Exception as exc:  # noqa: BLE001
        fallback_used = True
        model_result = {
            "model_output": _fallback_incident_ai_assessment(bundle, error_message=str(exc)),
            "assistant_text": "",
            "stderr": str(exc),
            "stdout_sample": "",
        }
    return {
        "incident_ref": _incident_key(safe_view, record_id),
        "view": safe_view,
        "record_id": str(record_id or "").strip(),
        "status": "ready",
        "generated_ts": _now_iso(),
        "requested_by": str(requested_by or "").strip(),
        "timezone": str(timezone_name or "Europe/Moscow"),
        "incident_title": _display_title(row),
        "search": search_blob,
        "hosts": hosts,
        "assessment": model_result.get("model_output") or {},
        "assistant_text": str(model_result.get("assistant_text") or ""),
        "stderr": str(model_result.get("stderr") or ""),
        "stdout_sample": str(model_result.get("stdout_sample") or ""),
        "fallback_used": fallback_used,
        "error": "",
    }


def _build_pending_assessment(
    view: str,
    record_id: str,
    *,
    requested_by: str = "",
    timezone_name: str = "Europe/Moscow",
) -> dict[str, Any]:
    safe_view = "raw" if view == "raw" else "agg"
    row = _get_incident_row(safe_view, record_id)
    existing = get_incident_ai_assessment(safe_view, record_id)
    existing_assessment = dict(existing.get("assessment") or {}) if isinstance(existing, dict) else {}
    if not existing_assessment:
        existing_assessment = {
            "summary": "AI-разбор поставлен в очередь и скоро появится в карточке инцидента.",
            "status_suggestion": str(row.get("status") or "new"),
            "assignee_hint": str(row.get("assignee") or "").strip() or "system",
        }
    else:
        existing_assessment["summary"] = "AI-разбор обновляется. Пока показываю последнюю доступную версию."
    return {
        "incident_ref": _incident_key(safe_view, record_id),
        "view": safe_view,
        "record_id": str(record_id or "").strip(),
        "status": "pending",
        "requested_ts": _now_iso(),
        "generated_ts": str(existing.get("generated_ts") or ""),
        "requested_by": str(requested_by or "").strip(),
        "timezone": str(timezone_name or "Europe/Moscow"),
        "incident_title": _display_title(row),
        "search": existing.get("search") or {},
        "hosts": existing.get("hosts") or _incident_hosts(row),
        "assessment": existing_assessment,
        "assistant_text": str(existing.get("assistant_text") or ""),
        "stderr": "",
        "stdout_sample": str(existing.get("stdout_sample") or ""),
        "error": "",
    }


def _build_error_assessment(
    view: str,
    record_id: str,
    *,
    requested_by: str = "",
    timezone_name: str = "Europe/Moscow",
    error_message: str,
) -> dict[str, Any]:
    safe_view = "raw" if view == "raw" else "agg"
    row = _get_incident_row(safe_view, record_id)
    existing = get_incident_ai_assessment(safe_view, record_id)
    existing_assessment = dict(existing.get("assessment") or {}) if isinstance(existing, dict) else {}
    existing_assessment["summary"] = "AI-разбор не завершился. Проверьте OpenClaw и доступ к внешнему поиску."
    return {
        "incident_ref": _incident_key(safe_view, record_id),
        "view": safe_view,
        "record_id": str(record_id or "").strip(),
        "status": "error",
        "requested_ts": str(existing.get("requested_ts") or _now_iso()),
        "generated_ts": _now_iso(),
        "requested_by": str(requested_by or "").strip(),
        "timezone": str(timezone_name or "Europe/Moscow"),
        "incident_title": _display_title(row),
        "search": existing.get("search") or {},
        "hosts": existing.get("hosts") or _incident_hosts(row),
        "assessment": existing_assessment,
        "assistant_text": str(existing.get("assistant_text") or ""),
        "stderr": str(existing.get("stderr") or ""),
        "stdout_sample": str(existing.get("stdout_sample") or ""),
        "error": str(error_message or "").strip(),
    }


def _queue_incident_ai_worker(view: str, record_id: str, *, requested_by: str = "", timezone_name: str = "Europe/Moscow") -> None:
    incident_ref = _incident_key(view, record_id)
    try:
        result = _generate_incident_ai_assessment_sync(view, record_id, requested_by=requested_by, timezone_name=timezone_name)
        previous = get_incident_ai_assessment(view, record_id)
        if isinstance(previous, dict) and previous.get("requested_ts"):
            result["requested_ts"] = str(previous.get("requested_ts") or "")
        _replace_assessment(result)
    except Exception as exc:  # noqa: BLE001
        _replace_assessment(
            _build_error_assessment(
                view,
                record_id,
                requested_by=requested_by,
                timezone_name=timezone_name,
                error_message=str(exc),
            )
        )
    finally:
        _clear_assessment_running(incident_ref)


def queue_incident_ai_assessment(view: str, record_id: str, *, requested_by: str = "", timezone_name: str = "Europe/Moscow") -> dict[str, Any]:
    safe_view = "raw" if view == "raw" else "agg"
    incident_ref = _incident_key(safe_view, record_id)
    existing = get_incident_ai_assessment(safe_view, record_id)
    if isinstance(existing, dict) and str(existing.get("status") or "").strip().lower() == "pending" and incident_ref in _RUNNING_ASSESSMENTS:
        return existing
    pending = _build_pending_assessment(safe_view, record_id, requested_by=requested_by, timezone_name=timezone_name)
    _replace_assessment(pending)
    if _mark_assessment_running(incident_ref):
        threading.Thread(
            target=_queue_incident_ai_worker,
            args=(safe_view, record_id),
            kwargs={"requested_by": requested_by, "timezone_name": timezone_name},
            name=f"incident-ai-{incident_ref}",
        ).start()
    return pending


def generate_incident_ai_assessment(view: str, record_id: str, *, requested_by: str = "", timezone_name: str = "Europe/Moscow") -> dict[str, Any]:
    return queue_incident_ai_assessment(view, record_id, requested_by=requested_by, timezone_name=timezone_name)


def _linux_snapshot_command() -> str:
    return (
        "echo '=== host ===' && hostnamectl 2>/dev/null || hostname && "
        "echo '=== uptime ===' && uptime && "
        "echo '=== running ===' && systemctl is-system-running || true && "
        "echo '=== failed units ===' && systemctl --failed --no-pager --plain | head -n 25 || true && "
        "echo '=== recent warnings ===' && journalctl -n 40 --no-pager -p warning..alert || true && "
        "echo '=== sockets ===' && ss -tupna | head -n 40 || true"
    )


def _linux_refresh_command() -> str:
    return (
        "systemctl restart rsyslog >/dev/null 2>&1 || true; "
        "systemctl restart siem-host-runtime-agent.service >/dev/null 2>&1 || true; "
        "systemctl start siem-host-runtime-agent.service >/dev/null 2>&1 || true; "
        "systemctl restart systemd-resolved >/dev/null 2>&1 || true; "
        "echo telemetry refreshed"
    )


def _windows_snapshot_command() -> str:
    return (
        "powershell -NoProfile -Command "
        "\"$host = Get-CimInstance Win32_OperatingSystem | Select-Object CSName,LastBootUpTime; "
        "$services = Get-Service | Where-Object {$_.Status -eq 'Running'} | Select-Object -First 10 Name,DisplayName,Status; "
        "$net = Get-NetTCPConnection | Select-Object -First 15 LocalAddress,LocalPort,RemoteAddress,RemotePort,State; "
        "Write-Output '=== host ==='; $host | Format-List | Out-String; "
        "Write-Output '=== services ==='; $services | Format-Table -Auto | Out-String; "
        "Write-Output '=== net ==='; $net | Format-Table -Auto | Out-String\""
    )


def run_incident_host_action(view: str, record_id: str, action: str, *, requested_by: str = "") -> dict[str, Any]:
    safe_action = str(action or "").strip().lower()
    if safe_action not in {"snapshot", "refresh_telemetry"}:
        raise ValueError(f"Unsupported host action: {action}")
    row = _get_incident_row("raw" if view == "raw" else "agg", record_id)
    targets = _incident_hosts(row)
    if not targets:
        raise ValueError("No mapped Proxmox hosts were found for this incident")
    results: list[dict[str, Any]] = []
    for target in targets[:2]:
        if safe_action not in list(target.get("supported_actions") or []):
            results.append({"host": target["name"], "status": "unsupported", "message": f"Action {safe_action} is not supported on this host"})
            continue
        command = _linux_snapshot_command()
        if str(target.get("os_family") or "").lower() == "windows":
            if safe_action != "snapshot":
                results.append({"host": target["name"], "status": "unsupported", "message": "Windows refresh_telemetry is not implemented"})
                continue
            command = _windows_snapshot_command()
        elif safe_action == "refresh_telemetry":
            command = _linux_refresh_command()
        try:
            output = guest_exec(int(target.get("vmid") or 0), str(target.get("guest_type") or ""), command, timeout=180)
            results.append(
                {
                    "host": target["name"],
                    "label": target["label"],
                    "status": "ok",
                    "action": safe_action,
                    "output": str(output or "").strip()[:4000],
                }
            )
        except Exception as exc:  # noqa: BLE001
            results.append({"host": target["name"], "label": target["label"], "status": "error", "action": safe_action, "message": str(exc)})
    return {
        "incident_ref": _incident_key(view, record_id),
        "requested_by": str(requested_by or "").strip(),
        "action": safe_action,
        "results": results,
        "generated_ts": _now_iso(),
    }
