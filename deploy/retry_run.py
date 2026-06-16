from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Retry a command with a fixed delay.")
    parser.add_argument("--attempts", type=int, default=3)
    parser.add_argument("--delay", type=float, default=10.0)
    parser.add_argument(
        "--timeout",
        type=float,
        default=0.0,
        help="Per-attempt timeout in seconds. A value <= 0 disables the timeout.",
    )
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.attempts < 1:
        parser.error("--attempts must be >= 1")
    if not args.command:
        parser.error("missing command after --")
    if args.command and args.command[0] == "--":
        args.command = args.command[1:]
    if not args.command:
        parser.error("missing command after --")
    if args.timeout < 0:
        parser.error("--timeout must be >= 0")
    return args


def normalize_command(command: list[str]) -> list[str]:
    if not command:
        return command
    executable = os.path.basename(command[0]).lower()
    if executable in {"python", "python3"}:
        return [sys.executable, *command[1:]]
    return command


def main() -> int:
    args = parse_args()
    command = normalize_command(list(args.command))
    last_code = 1
    for attempt in range(1, args.attempts + 1):
        print(f"retry_run attempt={attempt}/{args.attempts} command={' '.join(command)}")
        try:
            completed = subprocess.run(command, check=False, timeout=args.timeout or None)
            last_code = completed.returncode
        except subprocess.TimeoutExpired:
            last_code = 124
            print(f"retry_run result=timeout timeout_seconds={args.timeout:g}")
        if last_code == 0:
            print("retry_run result=success")
            return 0
        if attempt < args.attempts:
            print(f"retry_run result=retry delay_seconds={args.delay}")
            time.sleep(args.delay)
    print(f"retry_run result=failed exit_code={last_code}")
    return last_code


if __name__ == "__main__":
    sys.exit(main())
