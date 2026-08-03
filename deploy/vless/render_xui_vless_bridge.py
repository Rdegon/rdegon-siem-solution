#!/usr/bin/env python3
"""Render an Xray loopback bridge to the private 3x-ui controller over VLESS."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import tempfile
from urllib import parse as url_parse
from uuid import UUID


class BridgeConfigError(ValueError):
    pass


def _integer(value: str | int, *, label: str) -> int:
    try:
        result = int(value)
    except (TypeError, ValueError) as exc:
        raise BridgeConfigError(f"{label} must be an integer") from exc
    if not 1 <= result <= 65535:
        raise BridgeConfigError(f"{label} must be between 1 and 65535")
    return result


def parse_vless_uri(value: str) -> dict:
    try:
        parsed = url_parse.urlsplit(value.strip())
    except ValueError as exc:
        raise BridgeConfigError("VLESS URI is invalid") from exc
    if parsed.scheme.lower() != "vless" or not parsed.username or not parsed.hostname:
        raise BridgeConfigError("A complete vless:// URI is required")
    try:
        UUID(url_parse.unquote(parsed.username))
    except ValueError as exc:
        raise BridgeConfigError("VLESS user ID must be a UUID") from exc
    query = {key: values[-1] for key, values in url_parse.parse_qs(parsed.query, keep_blank_values=True).items()}
    network = str(query.get("type") or "tcp").lower()
    security = str(query.get("security") or "none").lower()
    if network not in {"tcp", "ws", "grpc"}:
        raise BridgeConfigError(f"Unsupported VLESS transport: {network}")
    if security not in {"tls", "reality"}:
        raise BridgeConfigError("The management VLESS bridge requires TLS or Reality")
    if str(query.get("encryption") or "none") != "none":
        raise BridgeConfigError("Only VLESS encryption=none is supported")
    if security == "reality" and not (query.get("pbk") and query.get("sni")):
        raise BridgeConfigError("Reality profile requires pbk and sni")
    return {
        "id": url_parse.unquote(parsed.username),
        "server": parsed.hostname,
        "port": parsed.port or 443,
        "network": network,
        "security": security,
        "flow": str(query.get("flow") or ""),
        "sni": str(query.get("sni") or query.get("serverName") or ""),
        "public_key": str(query.get("pbk") or query.get("publicKey") or ""),
        "short_id": str(query.get("sid") or query.get("shortId") or ""),
        "fingerprint": str(query.get("fp") or "chrome"),
        "path": str(query.get("path") or "/"),
        "host": str(query.get("host") or ""),
        "service_name": str(query.get("serviceName") or ""),
    }


def render_config(
    profile: dict,
    *,
    listen_host: str = "127.0.0.1",
    listen_port: int = 18787,
    target_host: str = "127.0.0.1",
    target_port: int = 8787,
) -> dict:
    if listen_host not in {"127.0.0.1", "::1", "localhost"}:
        raise BridgeConfigError("Bridge listener must remain on loopback")
    if target_host not in {"127.0.0.1", "::1", "localhost"}:
        raise BridgeConfigError("Controller target must remain on VPS loopback")
    listen_port = _integer(listen_port, label="Bridge listen port")
    target_port = _integer(target_port, label="Controller target port")
    user = {"id": profile["id"], "encryption": "none"}
    if profile.get("flow"):
        user["flow"] = profile["flow"]
    stream: dict = {"network": profile["network"], "security": profile["security"]}
    if profile["network"] == "ws":
        headers = {"Host": profile["host"]} if profile.get("host") else {}
        stream["wsSettings"] = {"path": profile.get("path") or "/", "headers": headers}
    elif profile["network"] == "grpc":
        stream["grpcSettings"] = {"serviceName": profile.get("service_name") or ""}
    if profile["security"] == "reality":
        stream["realitySettings"] = {
            "serverName": profile["sni"],
            "fingerprint": profile.get("fingerprint") or "chrome",
            "publicKey": profile["public_key"],
            "shortId": profile.get("short_id") or "",
            "spiderX": "/",
        }
    elif profile["security"] == "tls":
        stream["tlsSettings"] = {
            "serverName": profile.get("sni") or profile["server"],
            "allowInsecure": False,
            "fingerprint": profile.get("fingerprint") or "chrome",
        }
    return {
        "log": {"loglevel": "warning"},
        "inbounds": [
            {
                "tag": "xui-controller-loopback",
                "listen": listen_host,
                "port": listen_port,
                "protocol": "dokodemo-door",
                "settings": {"address": target_host, "port": target_port, "network": "tcp"},
            }
        ],
        "outbounds": [
            {
                "tag": "xui-controller-vless",
                "protocol": "vless",
                "settings": {
                    "vnext": [
                        {
                            "address": profile["server"],
                            "port": profile["port"],
                            "users": [user],
                        }
                    ]
                },
                "streamSettings": stream,
            },
            {"tag": "blocked", "protocol": "blackhole", "settings": {}},
        ],
        "routing": {
            "domainStrategy": "AsIs",
            "rules": [
                {
                    "type": "field",
                    "inboundTag": ["xui-controller-loopback"],
                    "outboundTag": "xui-controller-vless",
                }
            ],
        },
    }


def atomic_write(path: Path, config: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    handle, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            json.dump(config, stream, ensure_ascii=False, separators=(",", ":"))
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--uri-file", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--listen-host", default="127.0.0.1")
    parser.add_argument("--listen-port", type=int, default=18787)
    parser.add_argument("--target-host", default="127.0.0.1")
    parser.add_argument("--target-port", type=int, default=8787)
    args = parser.parse_args(argv)
    uri_path = Path(args.uri_file)
    if not uri_path.is_file() or uri_path.is_symlink():
        raise BridgeConfigError("VLESS URI secret must be a regular file")
    profile = parse_vless_uri(uri_path.read_text(encoding="utf-8").strip())
    config = render_config(
        profile,
        listen_host=args.listen_host,
        listen_port=args.listen_port,
        target_host=args.target_host,
        target_port=args.target_port,
    )
    atomic_write(Path(args.output), config)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
