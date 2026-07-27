from __future__ import annotations

import argparse
import json
import ssl
import urllib.request
from pathlib import Path
from typing import Any


def _api_key(path: Path) -> str:
    for line in path.read_text(encoding="ascii").splitlines():
        key, separator, value = line.partition("=")
        if separator and key.strip() == "MISP_API_KEY":
            candidate = value.strip()
            if len(candidate) == 40 and candidate.isalnum():
                return candidate
    raise RuntimeError("MISP API key is missing or invalid")


def _request(url: str, api_key: str, *, method: str = "GET") -> Any:
    request = urllib.request.Request(
        url,
        method=method,
        headers={
            "Authorization": api_key,
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "siem-misp-feed-cache/1",
        },
    )
    with urllib.request.urlopen(
        request,
        timeout=900,
        context=ssl._create_unverified_context(),
    ) as response:
        return json.load(response)


def main() -> int:
    parser = argparse.ArgumentParser(description="Refresh the curated CIRCL MISP feed cache")
    parser.add_argument("--base-url", default="https://127.0.0.1")
    parser.add_argument("--key-path", default="/etc/siem/misp-api.env")
    parser.add_argument("--feed-id", default="1")
    args = parser.parse_args()

    api_key = _api_key(Path(args.key_path))
    feeds = _request(f"{args.base_url}/feeds/index", api_key)
    selected = next(
        (
            item.get("Feed", {})
            for item in feeds
            if isinstance(item, dict)
            and str(item.get("Feed", {}).get("id")) == str(args.feed_id)
        ),
        {},
    )
    enabled = selected.get("enabled") in (True, 1, "1")
    if selected.get("name") != "CIRCL OSINT Feed" or not enabled:
        raise RuntimeError("The curated CIRCL feed is missing or disabled")
    _request(
        f"{args.base_url}/feeds/cacheFeeds/{args.feed_id}",
        api_key,
        method="POST",
    )
    print(json.dumps({"feed_id": args.feed_id, "name": selected["name"], "cache": "queued"}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
