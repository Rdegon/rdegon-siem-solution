from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _run(command: list[str], timeout: int) -> tuple[int, str]:
    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return 127, f"{type(exc).__name__}: {exc}"
    output = "\n".join(part.strip() for part in (completed.stdout, completed.stderr) if part.strip())
    return completed.returncode, output[:32_768]


def _clamav(path: Path, timeout: int) -> dict[str, Any]:
    code, output = _run(
        ["/usr/bin/clamscan", "--no-summary", "--infected", "--", str(path)],
        timeout,
    )
    signature = ""
    if code == 1 and ": " in output and output.rstrip().endswith(" FOUND"):
        signature = output.rsplit(": ", 1)[-1].removesuffix(" FOUND").strip()
    return {
        "engine": "clamav",
        "status": "malicious" if code == 1 else ("clean" if code == 0 else "error"),
        "signature": signature,
        "exit_code": code,
        "output": output,
    }


def _yara(path: Path, rules_dir: Path, timeout: int) -> dict[str, Any]:
    rule_files = sorted(
        item
        for pattern in ("*.yar", "*.yara")
        for item in rules_dir.glob(pattern)
        if item.is_file()
    )
    if not rule_files:
        return {"engine": "yara", "status": "not_configured", "matches": []}

    matches: list[str] = []
    errors: list[str] = []
    for rule_file in rule_files:
        code, output = _run(
            ["/usr/bin/yara", "--no-warnings", str(rule_file), str(path)],
            timeout,
        )
        if code == 0 and output:
            matches.extend(line.split(maxsplit=1)[0] for line in output.splitlines() if line.strip())
        elif code not in (0, 1):
            errors.append(f"{rule_file.name}: {output}")
    return {
        "engine": "yara",
        "status": "matched" if matches else ("error" if errors else "clean"),
        "matches": sorted(set(matches)),
        "errors": errors,
    }


def _trivy(path: Path, timeout: int) -> dict[str, Any]:
    with tempfile.NamedTemporaryFile(prefix="trivy-", suffix=".json", delete=False) as handle:
        output_path = Path(handle.name)
    try:
        code, output = _run(
            [
                "/usr/bin/trivy",
                "fs",
                "--quiet",
                "--scanners",
                "vuln,secret,misconfig",
                "--format",
                "json",
                "--output",
                str(output_path),
                str(path),
            ],
            timeout,
        )
        try:
            report = json.loads(output_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            report = {}
        results = report.get("Results") if isinstance(report, dict) else []
        vulnerabilities = 0
        secrets = 0
        misconfigurations = 0
        for result in results if isinstance(results, list) else []:
            if not isinstance(result, dict):
                continue
            vulnerabilities += len(result.get("Vulnerabilities") or [])
            secrets += len(result.get("Secrets") or [])
            misconfigurations += len(result.get("Misconfigurations") or [])
        finding_count = vulnerabilities + secrets + misconfigurations
        return {
            "engine": "trivy",
            "status": "findings" if finding_count else ("clean" if code == 0 else "error"),
            "vulnerabilities": vulnerabilities,
            "secrets": secrets,
            "misconfigurations": misconfigurations,
            "exit_code": code,
            "output": output,
        }
    finally:
        output_path.unlink(missing_ok=True)


def _optional_analyzer(
    engine: str,
    executable: str,
    arguments: list[str],
    timeout: int,
) -> dict[str, Any]:
    resolved = shutil.which(executable)
    if not resolved:
        return {"engine": engine, "status": "not_installed"}
    code, output = _run([resolved, *arguments], timeout)
    return {
        "engine": engine,
        "status": "completed" if code == 0 else "error",
        "exit_code": code,
        "output": output,
    }


def _file_specific_analysis(path: Path, timeout: int) -> dict[str, dict[str, Any]]:
    suffix = path.suffix.lower()
    analyzers: dict[str, dict[str, Any]] = {}
    if suffix in {".exe", ".dll", ".sys", ".scr", ".com", ".elf"}:
        analyzers["capa"] = _optional_analyzer("capa", "capa", ["-j", str(path)], timeout)
        analyzers["floss"] = _optional_analyzer(
            "floss",
            "floss",
            ["--json", str(path)],
            timeout,
        )
    if suffix in {
        ".doc",
        ".docm",
        ".docx",
        ".dotm",
        ".ppt",
        ".pptm",
        ".pptx",
        ".xls",
        ".xlsm",
        ".xlsx",
        ".rtf",
    }:
        analyzers["oleid"] = _optional_analyzer("oleid", "oleid", [str(path)], timeout)
    if suffix == ".pdf":
        analyzers["pdfid"] = _optional_analyzer("pdfid", "pdfid", [str(path)], timeout)
    return analyzers


def analyze_file(path: Path, *, rules_dir: Path, timeout: int) -> dict[str, Any]:
    stat = path.stat()
    file_hash = _sha256(path)
    clamav = _clamav(path, timeout)
    yara = _yara(path, rules_dir, timeout)
    trivy = _trivy(path, max(timeout, 300))
    file_specific = _file_specific_analysis(path, timeout)
    malicious = clamav["status"] == "malicious" or yara["status"] == "matched"
    finding = malicious or trivy["status"] == "findings"
    rule_names = []
    if clamav.get("signature"):
        rule_names.append(str(clamav["signature"]))
    rule_names.extend(str(item) for item in yara.get("matches") or [])
    return {
        "@timestamp": datetime.now(timezone.utc).isoformat(),
        "event.kind": "alert" if finding else "event",
        "event.category": ["malware", "vulnerability"],
        "event.type": ["info", "indicator"],
        "event.dataset": "security_analysis.static",
        "source_type": "malware",
        "host.name": os.uname().nodename,
        "file.path": str(path),
        "file.name": path.name,
        "file.size": stat.st_size,
        "file.sha256": file_hash,
        "sha256": file_hash,
        "evidence.id": f"sha256:{file_hash}",
        "rule.name": ",".join(rule_names) if rule_names else "static-analysis-clean",
        "rule": ",".join(rule_names) if rule_names else "static-analysis-clean",
        "verdict": "malicious" if malicious else ("suspicious" if finding else "clean"),
        "severity": "critical" if malicious else ("medium" if finding else "info"),
        "analysis": {
            "clamav": clamav,
            "yara": yara,
            "trivy": trivy,
            **file_specific,
        },
    }


def _append_jsonl(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(payload, ensure_ascii=True, separators=(",", ":"), default=str))
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())


def process_once(args: argparse.Namespace) -> int:
    inbox = Path(args.inbox)
    quarantine = Path(args.quarantine)
    rules_dir = Path(args.rules)
    output = Path(args.output)
    quarantine.mkdir(parents=True, exist_ok=True)
    processed = 0
    for path in sorted(inbox.iterdir() if inbox.exists() else []):
        if processed >= args.limit or path.is_symlink() or not path.is_file():
            continue
        try:
            result = analyze_file(path, rules_dir=rules_dir, timeout=args.timeout)
            target = quarantine / f"{result['file.sha256']}{path.suffix[:16]}"
            if target.exists():
                path.unlink()
            else:
                shutil.move(str(path), str(target))
            result["file.quarantine_path"] = str(target)
            _append_jsonl(output, result)
            processed += 1
        except (OSError, ValueError) as exc:
            _append_jsonl(
                output,
                {
                    "@timestamp": datetime.now(timezone.utc).isoformat(),
                    "source_type": "malware",
                    "event.dataset": "security_analysis.error",
                    "file.path": str(path),
                    "error": f"{type(exc).__name__}: {exc}",
                },
            )
    return processed


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Non-executing static analysis queue worker")
    parser.add_argument("--inbox", default="/srv/analysis/inbox")
    parser.add_argument("--quarantine", default="/srv/analysis/quarantine")
    parser.add_argument("--rules", default="/etc/siem/yara")
    parser.add_argument("--output", default="/var/log/siem/security-analysis.jsonl")
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument("--limit", type=int, default=20)
    parser.add_argument("--interval", type=int, default=5)
    parser.add_argument("--once", action="store_true")
    return parser


def main() -> int:
    args = _parser().parse_args()
    while True:
        process_once(args)
        if args.once:
            return 0
        time.sleep(max(1, args.interval))


if __name__ == "__main__":
    raise SystemExit(main())
