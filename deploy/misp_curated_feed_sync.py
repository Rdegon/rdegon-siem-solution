from __future__ import annotations

import argparse
import json
import ssl
import time
import urllib.request
from pathlib import Path
from typing import Any

try:
    from deploy.misp_event_exporter import _load_key
except ModuleNotFoundError:
    from misp_event_exporter import _load_key


DEFAULT_FEEDS = (
    "CIRCL OSINT Feed",
    "URLhaus",
    "Threatfox",
)


def _request(
    base_url: str,
    path: str,
    api_key: str,
    *,
    method: str = "GET",
    payload: dict[str, Any] | None = None,
    timeout: int = 900,
) -> Any:
    data = None
    if payload is not None:
        data = json.dumps(payload, ensure_ascii=True, separators=(",", ":")).encode("ascii")
    request = urllib.request.Request(
        f"{base_url.rstrip('/')}/{path.lstrip('/')}",
        data=data,
        method=method,
        headers={
            "Authorization": api_key,
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "siem-misp-curated-sync/1",
        },
    )
    with urllib.request.urlopen(
        request,
        timeout=timeout,
        context=ssl._create_unverified_context(),
    ) as response:
        return json.load(response)


def _request_bytes(
    base_url: str,
    path: str,
    api_key: str,
    *,
    timeout: int = 900,
) -> bytes:
    request = urllib.request.Request(
        f"{base_url.rstrip('/')}/{path.lstrip('/')}",
        method="GET",
        headers={
            "Authorization": api_key,
            "Accept": "application/json,text/html",
            "User-Agent": "siem-misp-curated-sync/1",
        },
    )
    with urllib.request.urlopen(
        request,
        timeout=timeout,
        context=ssl._create_unverified_context(),
    ) as response:
        return response.read()


def _feed_rows(payload: Any) -> list[dict[str, Any]]:
    if not isinstance(payload, list):
        return []
    rows = []
    for item in payload:
        feed = item.get("Feed") if isinstance(item, dict) else None
        if not isinstance(feed, dict):
            continue
        rows.append(
            {
                "id": str(feed.get("id") or ""),
                "name": str(feed.get("name") or ""),
                "provider": str(feed.get("provider") or ""),
                "url": str(feed.get("url") or ""),
                "enabled": str(feed.get("enabled") or "0") in {"1", "True", "true"},
                "caching_enabled": str(feed.get("caching_enabled") or "0")
                in {"1", "True", "true"},
                "lookup_visible": str(feed.get("lookup_visible") or "0")
                in {"1", "True", "true"},
            }
        )
    return rows


def _published_inventory(base_url: str, api_key: str) -> dict[str, int]:
    payload = _request(
        base_url,
        "/events/restSearch",
        api_key,
        method="POST",
        payload={
            "returnFormat": "json",
            "published": True,
            "limit": 100,
            "page": 1,
            "metadata": False,
        },
        timeout=120,
    )
    response = payload.get("response", []) if isinstance(payload, dict) else []
    events = response if isinstance(response, list) else []
    attributes = 0
    for item in events:
        event = item.get("Event") if isinstance(item, dict) else None
        if not isinstance(event, dict):
            continue
        values = event.get("Attribute")
        if isinstance(values, list):
            attributes += len(values)
        elif isinstance(values, dict):
            attributes += 1
    return {"events_returned": len(events), "attributes_returned": attributes}


def sync_curated_feeds(
    *,
    base_url: str,
    api_key: str,
    selected_names: tuple[str, ...],
    apply: bool,
    import_recent_days: int = 0,
    max_events_per_feed: int = 0,
) -> dict[str, Any]:
    rows = _feed_rows(_request(base_url, "/feeds/index", api_key))
    selected = [row for row in rows if row["name"] in selected_names]
    missing = sorted(set(selected_names) - {row["name"] for row in selected})
    actions: list[dict[str, str]] = []
    if apply:
        if missing:
            _request(
                base_url,
                "/feeds/loadDefaultFeeds",
                api_key,
                method="POST",
                timeout=300,
            )
            actions.append({"feed_id": "defaults", "action": "loaded"})
            rows = _feed_rows(_request(base_url, "/feeds/index", api_key))
            selected = [row for row in rows if row["name"] in selected_names]
            missing = sorted(set(selected_names) - {row["name"] for row in selected})
        for feed in selected:
            if not (feed["enabled"] and feed["caching_enabled"] and feed["lookup_visible"]):
                _request(
                    base_url,
                    f"/feeds/edit/{feed['id']}",
                    api_key,
                    method="POST",
                    payload={
                        "Feed": {
                            "id": feed["id"],
                            "enabled": 1,
                            "caching_enabled": 1,
                            "lookup_visible": 1,
                        }
                    },
                    timeout=120,
                )
                actions.append({"feed_id": feed["id"], "action": "enabled"})
            _request(
                base_url,
                f"/feeds/cacheFeeds/{feed['id']}",
                api_key,
                method="POST",
                timeout=900,
            )
            actions.append({"feed_id": feed["id"], "action": "cache_queued"})
            if (
                import_recent_days > 0
                and max_events_per_feed > 0
                and feed["url"].startswith("https://")
            ):
                manifest_url = f"{feed['url'].rstrip('/')}/manifest.json"
                with urllib.request.urlopen(
                    manifest_url,
                    timeout=120,
                    context=ssl.create_default_context(),
                ) as response:
                    manifest = json.load(response)
                if not isinstance(manifest, dict):
                    continue
                cutoff = int(time.time()) - import_recent_days * 86_400
                recent = sorted(
                    (
                        (str(uuid), metadata)
                        for uuid, metadata in manifest.items()
                        if isinstance(metadata, dict)
                        and int(metadata.get("timestamp") or 0) >= cutoff
                    ),
                    key=lambda item: int(item[1].get("timestamp") or 0),
                    reverse=True,
                )[:max_events_per_feed]
                for event_uuid, _metadata in recent:
                    _request_bytes(
                        base_url,
                        f"/feeds/getEvent/{feed['id']}/{event_uuid}",
                        api_key,
                        timeout=300,
                    )
                    actions.append(
                        {
                            "feed_id": feed["id"],
                            "action": "recent_event_imported",
                        }
                    )
        rows = _feed_rows(_request(base_url, "/feeds/index", api_key))
        selected = [row for row in rows if row["name"] in selected_names]
    return {
        "feeds_available": len(rows),
        "selected": selected,
        "missing": missing,
        "actions": actions,
        "published": _published_inventory(base_url, api_key),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit and synchronize curated MISP feeds.")
    parser.add_argument("--base-url", default="https://127.0.0.1")
    parser.add_argument("--key-path", default="/etc/siem/misp-api.env")
    parser.add_argument("--feed", action="append", dest="feeds")
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--import-recent-days", type=int, default=0)
    parser.add_argument("--max-events-per-feed", type=int, default=0)
    args = parser.parse_args()
    api_key = _load_key(Path(args.key_path))
    if not api_key:
        raise RuntimeError("MISP API key is unavailable")
    selected_names = tuple(args.feeds or DEFAULT_FEEDS)
    result = sync_curated_feeds(
        base_url=args.base_url,
        api_key=api_key,
        selected_names=selected_names,
        apply=args.apply,
        import_recent_days=max(0, args.import_recent_days),
        max_events_per_feed=max(0, args.max_events_per_feed),
    )
    print(json.dumps(result, indent=2, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
