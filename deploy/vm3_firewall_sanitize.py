from __future__ import annotations

import json
import subprocess


TARGET_PORTS = ("6379", "26379")
CHAIN = "ufw-user-input"


def _run(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=False, capture_output=True, text=True)


def _list_rules() -> list[str]:
    completed = _run(["iptables", "-S", CHAIN])
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.strip() or completed.stdout.strip() or "iptables -S failed")
    return [line.strip() for line in completed.stdout.splitlines() if line.strip()]


def _matching_rules() -> list[list[str]]:
    matches: list[list[str]] = []
    for line in _list_rules():
        if not any(f"--dport {port}" in line for port in TARGET_PORTS):
            continue
        if not line.startswith("-A "):
            continue
        matches.append(line.replace("-A", "-D", 1).split())
    return matches


def main() -> int:
    removed: list[str] = []
    for command in _matching_rules():
        completed = _run(["iptables", *command])
        if completed.returncode == 0:
            removed.append(" ".join(command))
    remaining = [" ".join(command) for command in _matching_rules()]
    print(json.dumps({"removed": removed, "remaining": remaining, "ports": list(TARGET_PORTS)}, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
