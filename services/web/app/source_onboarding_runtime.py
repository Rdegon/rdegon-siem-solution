from __future__ import annotations

import json
import time
import zipfile
from pathlib import Path
from typing import Any

try:
    import paramiko  # type: ignore[import-not-found]
except Exception:  # noqa: BLE001
    paramiko = None  # type: ignore[assignment]


NETWORK_VENDOR_PROFILES: dict[str, dict[str, Any]] = {
    "cisco_ios": {
        "title": "Cisco IOS / IOS-XE syslog automation",
        "credential_requirements": [
            {"id": "username", "label": "SSH username", "required": True},
            {"id": "password", "label": "SSH password", "required": True},
            {"id": "enable_password", "label": "Enable password", "required": False},
            {"id": "port", "label": "SSH port", "required": False},
        ],
    },
    "mikrotik_routeros": {
        "title": "MikroTik RouterOS syslog automation",
        "credential_requirements": [
            {"id": "username", "label": "SSH username", "required": True},
            {"id": "password", "label": "SSH password", "required": True},
            {"id": "port", "label": "SSH port", "required": False},
        ],
    },
    "ubiquiti_edgeos": {
        "title": "Ubiquiti EdgeOS syslog automation",
        "credential_requirements": [
            {"id": "username", "label": "SSH username", "required": True},
            {"id": "password", "label": "SSH password", "required": True},
            {"id": "port", "label": "SSH port", "required": False},
        ],
    },
}


def _string(value: Any) -> str:
    return str(value or "").strip()


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, indent=2)


def build_windows_native_package_spec(
    candidate: dict[str, Any],
    job: dict[str, Any],
    *,
    base_url: str,
    shared_secret_required: bool,
) -> dict[str, Any]:
    hostname = _string(candidate.get("hostname") or candidate.get("ip") or "windows-endpoint")
    return {
        "delivery_mode": "native_service_agent",
        "base_url": _string(base_url).rstrip("/"),
        "shared_secret_required": bool(shared_secret_required),
        "package_format": "zip",
        "install_script": "install-native-agent.cmd",
        "profile_path": "windows-agent-profile.local.json",
        "recommended_bundle_builder": "deploy/windows-agent/package-windows-event-agent.ps1",
        "recommended_runtime": "win-x64",
        "candidate_ip": _string(candidate.get("ip")),
        "candidate_hostname": hostname,
        "job_id": _string(job.get("id")),
        "service_name": "RdegonWindowsEventAgent",
        "channels": [
            "Security",
            "System",
            "Application",
            "Microsoft-Windows-Sysmon/Operational",
            "Microsoft-Windows-PowerShell/Operational",
            "Windows PowerShell",
        ],
        "vpn_profiles": [
            "remote-vpn-profile-01-windows-agent-vpn-ingest-only.ovpn",
            "remote-vpn-profile-02-windows-agent-vpn-ingest-and-web.ovpn",
        ],
        "notes": [
            "This package stages a native Windows service rollout, not a scheduled-task collector.",
            "Build the release bundle with package-windows-event-agent.ps1 or supply a prebuilt bundle produced by CI.",
            "The generated host profile already aligns base URL, channel routing, and service metadata for this endpoint.",
        ],
    }


def _windows_native_profile(candidate: dict[str, Any], spec: dict[str, Any]) -> dict[str, Any]:
    hostname = _string(candidate.get("hostname") or candidate.get("ip") or "windows-endpoint")
    state_root = f"%ProgramData%\\RdegonSIEM\\WindowsEventAgent\\{hostname}"
    return {
        "installDir": f"%ProgramFiles%\\Rdegon\\WindowsEventAgent\\{hostname}",
        "stateDirectory": state_root,
        "serviceName": f"RdegonWindowsEventAgent-{hostname}".replace(".", "-"),
        "displayName": f"Rdegon Windows Event Agent ({hostname})",
        "instanceName": hostname,
        "baseUrl": _string(spec.get("base_url")),
        "sharedSecret": "replace-me" if bool(spec.get("shared_secret_required")) else "",
        "allowInvalidServerCertificate": False,
        "pollIntervalSeconds": 30,
        "batchSize": 400,
        "maxSendBatch": 100,
        "timeoutSeconds": 10,
        "includeXml": True,
        "channels": [
            {"name": "Security", "routePath": "/ingest/windows/security", "enabled": True},
            {"name": "System", "routePath": "/ingest/windows/base", "enabled": True},
            {"name": "Application", "routePath": "/ingest/windows/base", "enabled": True},
            {"name": "Microsoft-Windows-Sysmon/Operational", "routePath": "/ingest/windows/sysmon", "enabled": True},
            {"name": "Microsoft-Windows-PowerShell/Operational", "routePath": "/ingest/windows/powershell", "enabled": True},
            {"name": "Windows PowerShell", "routePath": "/ingest/windows/powershell", "enabled": True},
        ],
    }


def _windows_native_install_cmd(spec: dict[str, Any], profile_path: str) -> str:
    base_url = _string(spec.get("base_url"))
    shared_secret_required = bool(spec.get("shared_secret_required"))
    secret_check = (
        "if \"%SHAREDSECRET%\"==\"\" (\n"
        "    echo Shared secret is required. Pass it as the first argument.\n"
        "    exit /b 2\n"
        ")\n"
        if shared_secret_required
        else ""
    )
    return (
        "@echo off\n"
        "setlocal\n\n"
        "set \"ROOT=%~dp0\"\n"
        "set \"SHAREDSECRET=%~1\"\n"
        f"set \"BASEURL={base_url}\"\n"
        f"set \"PROFILE=%ROOT%{profile_path}\"\n"
        "set \"INSTALL=%ROOT%install-windows-event-agent.ps1\"\n\n"
        "if not exist \"%INSTALL%\" (\n"
        "    echo Native install script not found: %INSTALL%\n"
        "    exit /b 1\n"
        ")\n"
        f"{secret_check}"
        "powershell.exe -NoProfile -ExecutionPolicy Bypass -File \"%INSTALL%\" -BaseUrl \"%BASEURL%\" -SharedSecret \"%SHAREDSECRET%\" -StartAfterInstall\n"
        "endlocal\n"
    )


def _windows_native_readme(candidate: dict[str, Any], job: dict[str, Any], spec: dict[str, Any]) -> str:
    hostname = _string(candidate.get("hostname") or candidate.get("ip") or "windows-endpoint")
    return (
        f"# Native Windows Agent Onboarding for {hostname}\n\n"
        "This package was generated by the discovery plane to stage an enterprise-style Windows service rollout.\n\n"
        "## Delivery model\n\n"
        "- native Windows service agent\n"
        "- host-specific profile file\n"
        "- reproducible packaging scripts from the repo\n"
        "- optional VPN route profile alignment\n\n"
        "## Operator flow\n\n"
        "1. Copy this package to the Windows endpoint or jump host.\n"
        "2. Build or provide the release bundle with `package-windows-event-agent.ps1`.\n"
        "3. Review `windows-agent-profile.local.json` and replace `sharedSecret` if required.\n"
        "4. Run `install-native-agent.cmd <shared-secret>` from an elevated shell.\n"
        "5. Validate service and runtime state with `get-windows-event-agent-status.ps1 -Detailed`.\n\n"
        "## Package metadata\n\n"
        f"- Base URL: `{_string(spec.get('base_url'))}`\n"
        f"- Shared secret required: `{'yes' if bool(spec.get('shared_secret_required')) else 'no'}`\n"
        f"- Discovery job: `{_string(job.get('id'))}`\n"
        f"- Delivery mode: `{_string(spec.get('delivery_mode'))}`\n\n"
        "## Included files\n\n"
        "- `windows-agent-profile.local.json`\n"
        "- `install-native-agent.cmd`\n"
        "- `install-windows-event-agent.ps1`\n"
        "- `package-windows-event-agent.ps1`\n"
        "- `get-windows-event-agent-status.ps1`\n"
        "- `build-openvpn-route-profile.ps1`\n"
        "- `README.md`\n"
        "- `package-manifest.json`\n"
    )


def build_windows_native_package(
    candidate: dict[str, Any],
    job: dict[str, Any],
    *,
    repo_root: Path,
    output_root: Path,
    base_url: str,
    shared_secret_required: bool,
) -> dict[str, Any]:
    package_dir = output_root / _string(job.get("id") or "windows-native-package")
    package_dir.mkdir(parents=True, exist_ok=True)
    zip_path = package_dir.parent / f"{package_dir.name}.zip"
    spec = build_windows_native_package_spec(candidate, job, base_url=base_url, shared_secret_required=shared_secret_required)
    profile_name = "windows-agent-profile.local.json"
    profile = _windows_native_profile(candidate, spec)

    files_to_write: dict[str, str] = {
        profile_name: _json(profile),
        "install-native-agent.cmd": _windows_native_install_cmd(spec, profile_name),
        "README.md": _windows_native_readme(candidate, job, spec),
        "package-manifest.json": _json(
            {
                "generated_ts": _now_iso(),
                "job_id": _string(job.get("id")),
                "candidate_id": _string(candidate.get("id")),
                "candidate_ip": _string(candidate.get("ip")),
                "candidate_hostname": _string(candidate.get("hostname")),
                "collector_profile": _string(job.get("collector_profile") or "windows-event-http"),
                "package_spec": spec,
                "profile": profile,
            }
        ),
    }

    file_copies = {
        "install-windows-event-agent.ps1": repo_root / "deploy" / "windows-agent" / "install-windows-event-agent.ps1",
        "package-windows-event-agent.ps1": repo_root / "deploy" / "windows-agent" / "package-windows-event-agent.ps1",
        "get-windows-event-agent-status.ps1": repo_root / "deploy" / "windows-agent" / "get-windows-event-agent-status.ps1",
        "build-openvpn-route-profile.ps1": repo_root / "deploy" / "windows-agent" / "build-openvpn-route-profile.ps1",
        "windows-agent-profile.local.example.json": repo_root / "ops" / "windows-agent-profile.local.example.json",
    }

    written_files: list[str] = []
    for relative_name, content in files_to_write.items():
        target = package_dir / relative_name
        target.write_text(content, encoding="utf-8")
        written_files.append(str(target))
    for relative_name, source in file_copies.items():
        if not source.exists():
            continue
        target = package_dir / relative_name
        target.write_text(source.read_text(encoding="utf-8"), encoding="utf-8")
        written_files.append(str(target))

    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path_text in written_files:
            path = Path(path_text)
            archive.write(path, arcname=path.name)

    return {
        "directory": str(package_dir),
        "zip_path": str(zip_path),
        "files": written_files,
        "package_spec": spec,
        "profile": profile,
    }


def infer_network_vendor(candidate: dict[str, Any]) -> str:
    evidence = " ".join(
        [
            _string(candidate.get("hostname")).lower(),
            _string(candidate.get("probable_role")).lower(),
            _string(candidate.get("source_family")).lower(),
            " ".join(_string(port.get("banner")).lower() for port in (candidate.get("open_ports") or []) if isinstance(port, dict)),
            " ".join(_string(port.get("server")).lower() for port in (candidate.get("open_ports") or []) if isinstance(port, dict)),
            " ".join(_string(port.get("title")).lower() for port in (candidate.get("open_ports") or []) if isinstance(port, dict)),
        ]
    )
    if any(token in evidence for token in ("mikrotik", "routeros")):
        return "mikrotik_routeros"
    if any(token in evidence for token in ("edgeos", "vyatta", "ubiquiti", "unifi")):
        return "ubiquiti_edgeos"
    return "cisco_ios"


def build_network_command_set(*, vendor: str, ingest_host: str, ingest_port: int) -> list[str]:
    if vendor == "mikrotik_routeros":
        return [
            "/system logging action set [ find name=remote ] target=remote remote={0} remote-port={1}".format(ingest_host, ingest_port),
            "/system logging add topics=info action=remote",
            "/system logging add topics=warning action=remote",
            "/system logging add topics=error action=remote",
        ]
    if vendor == "ubiquiti_edgeos":
        return [
            "configure",
            f"set system syslog host {ingest_host} facility all level info",
            f"set system syslog host {ingest_host} port {ingest_port}",
            "commit",
            "save",
            "exit",
        ]
    return [
        "terminal length 0",
        "configure terminal",
        f"logging host {ingest_host} transport tcp port {ingest_port}",
        "logging trap informational",
        "logging facility local6",
        "end",
        "write memory",
    ]


def build_network_onboarding_plan(candidate: dict[str, Any], *, ingest_host: str, ingest_port: int) -> dict[str, Any]:
    vendor = infer_network_vendor(candidate)
    profile = dict(NETWORK_VENDOR_PROFILES.get(vendor) or NETWORK_VENDOR_PROFILES["cisco_ios"])
    commands = build_network_command_set(vendor=vendor, ingest_host=ingest_host, ingest_port=ingest_port)
    return {
        "vendor": vendor,
        "title": _string(profile.get("title")),
        "credential_requirements": list(profile.get("credential_requirements") or []),
        "config_preview": "\n".join(commands),
        "command_preview": [f"push {len(commands)} CLI command(s) over SSH", f"configure syslog target {ingest_host}:{ingest_port}/tcp", "save running configuration"],
        "commands": commands,
    }


def execute_network_cli_push(ip_text: str, *, vendor: str, commands: list[str], credentials: dict[str, Any]) -> dict[str, Any]:
    if paramiko is None:
        raise RuntimeError("paramiko_not_available")
    username = _string(credentials.get("username"))
    password = _string(credentials.get("password"))
    enable_password = _string(credentials.get("enable_password") or password)
    port = max(1, min(65535, int(credentials.get("port") or 22)))
    if not username or not password:
        raise RuntimeError("network_ssh_credentials_required")
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        ip_text,
        port=port,
        username=username,
        password=password,
        timeout=20,
        auth_timeout=20,
        banner_timeout=20,
        look_for_keys=False,
        allow_agent=False,
    )
    transcript = ""
    try:
        channel = client.invoke_shell()
        time.sleep(0.6)
        transcript += channel.recv(4096).decode("utf-8", errors="replace")
        for command in commands:
            if vendor == "cisco_ios" and command == "configure terminal" and ">" in transcript and enable_password:
                channel.send("enable\n")
                time.sleep(0.4)
                transcript += channel.recv(4096).decode("utf-8", errors="replace")
                if "Password" in transcript.splitlines()[-1]:
                    channel.send(f"{enable_password}\n")
                    time.sleep(0.4)
                    transcript += channel.recv(4096).decode("utf-8", errors="replace")
            channel.send(f"{command}\n")
            time.sleep(0.5)
            while channel.recv_ready():
                transcript += channel.recv(4096).decode("utf-8", errors="replace")
        channel.close()
    finally:
        client.close()
    return {"status": "executed", "vendor": vendor, "commands_applied": len(commands), "transcript_tail": transcript[-4000:]}
