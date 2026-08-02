#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import subprocess
import sys


SSH_KEY = Path("/etc/siem/credentials/vpnadmin_ed25519")
SSH_TARGET = "vpnadmin_rdegon@10.66.66.1"
REMOTE_CONTROLLER = "/usr/local/sbin/siem-openvpn-ca-controller"
NAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]{2,31}$")
PRESETS = {"siem-ingest-only", "siem-ingest-and-web", "siem-core-admin", "siem-full-lab"}


def _validate_name(value: str) -> str:
    name = value.strip().lower()
    if not NAME_PATTERN.fullmatch(name):
        raise ValueError("invalid profile name")
    return name


def run_remote(arguments: list[str]) -> dict[str, object]:
    if not SSH_KEY.is_file():
        raise RuntimeError("VPN controller SSH credential is not installed")
    command = [
        "ssh",
        "-i",
        str(SSH_KEY),
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=7",
        "-o",
        "StrictHostKeyChecking=accept-new",
        SSH_TARGET,
        "sudo",
        "-n",
        REMOTE_CONTROLLER,
        *arguments,
    ]
    result = subprocess.run(command, check=False, capture_output=True, text=True, timeout=90)
    raw = (result.stdout or "").strip()
    try:
        payload = json.loads(raw or "{}")
    except json.JSONDecodeError as exc:
        raise RuntimeError((result.stderr or raw or "invalid controller response")[:1000]) from exc
    if result.returncode or payload.get("status") == "failed":
        raise RuntimeError(str(payload.get("issue") or result.stderr or "controller operation failed")[:1000])
    return payload


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="operation", required=True)
    subparsers.add_parser("status")
    create_parser = subparsers.add_parser("create")
    create_parser.add_argument("name")
    create_parser.add_argument("preset")
    revoke_parser = subparsers.add_parser("revoke")
    revoke_parser.add_argument("name")
    args = parser.parse_args()
    try:
        if args.operation == "status":
            payload = run_remote(["status"])
        elif args.operation == "create":
            name = _validate_name(args.name)
            if args.preset not in PRESETS:
                raise ValueError("invalid route preset")
            payload = run_remote(["create", name, args.preset])
        else:
            payload = run_remote(["revoke", _validate_name(args.name)])
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as exc:
        print(json.dumps({"status": "failed", "issue": str(exc)}, ensure_ascii=True))
        return 1
    print(json.dumps(payload, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
