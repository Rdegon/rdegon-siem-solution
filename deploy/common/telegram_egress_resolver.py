#!/usr/bin/env python3
from __future__ import annotations

import ipaddress
import os
import socket
import ssl
from pathlib import Path


TELEGRAM_HOST = "api.telegram.org"
HOSTS_MARKER = "# siem-telegram-egress"
DEFAULT_CANDIDATES = ("149.154.167.220", "149.154.166.110")


def unique_candidates(*groups: list[str] | tuple[str, ...]) -> list[str]:
    result: list[str] = []
    for group in groups:
        for raw in group:
            value = str(raw or "").strip()
            try:
                address = str(ipaddress.ip_address(value))
            except ValueError:
                continue
            if address not in result:
                result.append(address)
    return result


def resolved_candidates(host: str = TELEGRAM_HOST) -> list[str]:
    try:
        values = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    except OSError:
        return []
    return unique_candidates([str(item[4][0]) for item in values])


def probe_endpoint(address: str, *, timeout: float = 6.0) -> bool:
    context = ssl.create_default_context()
    try:
        with socket.create_connection((address, 443), timeout=timeout) as connection:
            with context.wrap_socket(connection, server_hostname=TELEGRAM_HOST) as secured:
                secured.settimeout(timeout)
                secured.sendall(
                    b"HEAD / HTTP/1.1\r\n"
                    b"Host: api.telegram.org\r\n"
                    b"Connection: close\r\n\r\n"
                )
                return secured.recv(16).startswith(b"HTTP/")
    except (OSError, ssl.SSLError):
        return False


def rewrite_hosts(path: Path, address: str) -> None:
    lines = [
        line
        for line in path.read_text(encoding="utf-8").splitlines()
        if HOSTS_MARKER not in line
    ]
    lines.append(f"{address} {TELEGRAM_HOST} {HOSTS_MARKER}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    configured = tuple(
        item.strip()
        for item in os.getenv("SIEM_TELEGRAM_IP_CANDIDATES", "").split(",")
        if item.strip()
    )
    candidates = unique_candidates(resolved_candidates(), configured, DEFAULT_CANDIDATES)
    for address in candidates:
        if probe_endpoint(address):
            rewrite_hosts(
                Path(os.getenv("SIEM_TELEGRAM_HOSTS_PATH", "/etc/hosts")),
                address,
            )
            print(f"telegram_api_address={address}")
            return 0
    print("telegram_api_address=unavailable")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
