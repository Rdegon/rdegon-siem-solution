#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import ipaddress
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys


LEGACY_PKI = Path("/home/vpnadmin_rdegon/openvpn-nextcloud/pki")
STATE_ROOT = Path("/var/lib/siem-openvpn-ca")
PROFILE_ROOT = STATE_ROOT / "profiles"
OPENSSL_CONFIG = STATE_ROOT / "openssl.cnf"
SERVER_CONFIG = Path("/etc/openvpn/server/nextcloud.conf")
SERVER_CRL = Path("/etc/openvpn/server/crl.pem")
SERVICE = "openvpn-server@nextcloud"
NAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]{2,31}$")
ROUTE_PRESETS = {
    "siem-ingest-only": ["192.168.3.102/32"],
    "siem-ingest-and-web": ["192.168.3.102/32", "10.20.10.0/24"],
    "siem-core-admin": ["10.20.10.0/24", "192.168.3.102/32"],
    "siem-full-lab": [
        "192.168.3.0/24",
        "10.20.10.0/24",
        "10.20.20.0/24",
        "10.20.30.0/24",
        "10.20.40.0/24",
    ],
}


def _run(*args: str, input_text: str | None = None) -> str:
    result = subprocess.run(
        list(args),
        check=False,
        capture_output=True,
        text=True,
        input=input_text,
        timeout=60,
    )
    if result.returncode:
        raise RuntimeError((result.stderr or result.stdout or "command failed").strip()[:1000])
    return (result.stdout or "").strip()


def _validate_name(name: str) -> str:
    value = name.strip().lower()
    if not NAME_PATTERN.fullmatch(value):
        raise ValueError("profile name must match [a-z0-9][a-z0-9_-]{2,31}")
    return value


def _write_openssl_config() -> None:
    content = f"""[ ca ]
default_ca = ca_default

[ ca_default ]
dir = {STATE_ROOT}
database = $dir/index.txt
new_certs_dir = $dir/newcerts
certificate = {LEGACY_PKI / 'ca.crt'}
private_key = {LEGACY_PKI / 'ca.key'}
serial = $dir/serial
crlnumber = $dir/crlnumber
default_days = 825
default_crl_days = 30
default_md = sha256
policy = policy_any
x509_extensions = client_ext
copy_extensions = none
unique_subject = no

[ policy_any ]
countryName = optional
stateOrProvinceName = optional
localityName = optional
organizationName = optional
organizationalUnitName = optional
commonName = supplied
emailAddress = optional

[ client_ext ]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = clientAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
"""
    OPENSSL_CONFIG.write_text(content, encoding="utf-8")
    OPENSSL_CONFIG.chmod(0o600)


def _restart_openvpn() -> None:
    _run("systemctl", "--no-block", "restart", SERVICE)


def initialize() -> dict[str, object]:
    for required in (LEGACY_PKI / "ca.crt", LEGACY_PKI / "ca.key", LEGACY_PKI / "tls-crypt.key"):
        if not required.is_file():
            raise RuntimeError(f"required PKI file is missing: {required}")
    STATE_ROOT.mkdir(parents=True, exist_ok=True, mode=0o700)
    PROFILE_ROOT.mkdir(parents=True, exist_ok=True, mode=0o700)
    (STATE_ROOT / "newcerts").mkdir(parents=True, exist_ok=True, mode=0o700)
    for filename, default in (("index.txt", ""), ("serial", "1000\n"), ("crlnumber", "1000\n")):
        target = STATE_ROOT / filename
        if not target.exists():
            target.write_text(default, encoding="ascii")
    _write_openssl_config()
    crl_existed = SERVER_CRL.exists()
    _run("openssl", "ca", "-batch", "-config", str(OPENSSL_CONFIG), "-gencrl", "-out", str(SERVER_CRL))
    SERVER_CRL.chmod(0o644)
    directive = f"crl-verify {SERVER_CRL}"
    current = SERVER_CONFIG.read_text(encoding="utf-8")
    config_changed = directive not in current.splitlines()
    if config_changed:
        with SERVER_CONFIG.open("a", encoding="utf-8") as handle:
            handle.write(f"\n{directive}\n")
    if config_changed or not crl_existed:
        _restart_openvpn()
        return {
            "status": "restarting",
            "provider": "openvpn",
            "pki_ready": True,
            "managed_profiles": len(list(PROFILE_ROOT.glob("*/*.ovpn"))),
        }
    return status()


def _pem(path: Path, label: str) -> str:
    content = path.read_text(encoding="utf-8")
    marker = f"-----BEGIN {label}-----"
    offset = content.find(marker)
    if offset < 0:
        raise RuntimeError(f"invalid PEM file: {path}")
    return content[offset:].strip()


def _route_lines(preset: str) -> list[str]:
    if preset not in ROUTE_PRESETS:
        raise ValueError("unknown route preset")
    result: list[str] = []
    for raw_network in ROUTE_PRESETS[preset]:
        network = ipaddress.ip_network(raw_network, strict=False)
        result.append(f"route {network.network_address} {network.netmask} vpn_gateway")
    return result


def create_profile(name: str, preset: str) -> dict[str, object]:
    initialize()
    common_name = _validate_name(name)
    profile_dir = PROFILE_ROOT / common_name
    if profile_dir.exists():
        raise ValueError("profile already exists")
    profile_dir.mkdir(mode=0o700)
    key = profile_dir / f"{common_name}.key"
    csr = profile_dir / f"{common_name}.csr"
    certificate = profile_dir / f"{common_name}.crt"
    profile = profile_dir / f"{common_name}.ovpn"
    try:
        _run("openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(key))
        _run("openssl", "req", "-new", "-key", str(key), "-subj", f"/CN={common_name}", "-out", str(csr))
        _run(
            "openssl",
            "ca",
            "-batch",
            "-config",
            str(OPENSSL_CONFIG),
            "-extensions",
            "client_ext",
            "-in",
            str(csr),
            "-out",
            str(certificate),
        )
        profile_text = "\n".join(
            [
                "client",
                "dev tun",
                "proto tcp-client",
                "remote 176.108.250.215 443",
                "resolv-retry infinite",
                "nobind",
                "persist-key",
                "persist-tun",
                "remote-cert-tls server",
                "cipher AES-256-GCM",
                "data-ciphers AES-256-GCM:AES-128-GCM",
                "data-ciphers-fallback AES-256-CBC",
                "auth SHA256",
                "auth-nocache",
                "verb 3",
                "route-nopull",
                *_route_lines(preset),
                "<ca>",
                _pem(LEGACY_PKI / "ca.crt", "CERTIFICATE"),
                "</ca>",
                "<cert>",
                _pem(certificate, "CERTIFICATE"),
                "</cert>",
                "<key>",
                _pem(key, "PRIVATE KEY"),
                "</key>",
                "<tls-crypt>",
                _pem(LEGACY_PKI / "tls-crypt.key", "OpenVPN Static key V1"),
                "</tls-crypt>",
                "",
            ]
        )
        profile.write_text(profile_text, encoding="utf-8")
        profile.chmod(0o600)
        fingerprint = _run("openssl", "x509", "-in", str(certificate), "-noout", "-fingerprint", "-sha256")
        expires = _run("openssl", "x509", "-in", str(certificate), "-noout", "-enddate").partition("=")[2]
        return {
            "status": "active",
            "provider": "openvpn",
            "controller_id": common_name,
            "download_ready": True,
            "fingerprint": fingerprint.partition("=")[2],
            "expires": expires,
            "profile_b64": base64.b64encode(profile.read_bytes()).decode("ascii"),
        }
    except Exception:
        if not certificate.exists():
            shutil.rmtree(profile_dir, ignore_errors=True)
        raise


def revoke_profile(name: str) -> dict[str, object]:
    common_name = _validate_name(name)
    certificate = PROFILE_ROOT / common_name / f"{common_name}.crt"
    if not certificate.is_file():
        raise KeyError(common_name)
    _run("openssl", "ca", "-batch", "-config", str(OPENSSL_CONFIG), "-revoke", str(certificate))
    _run("openssl", "ca", "-batch", "-config", str(OPENSSL_CONFIG), "-gencrl", "-out", str(SERVER_CRL))
    SERVER_CRL.chmod(0o644)
    _restart_openvpn()
    shutil.rmtree(certificate.parent, ignore_errors=True)
    return {"status": "revoked", "provider": "openvpn", "controller_id": common_name}


def status() -> dict[str, object]:
    result = subprocess.run(
        ["systemctl", "is-active", SERVICE],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    service = (result.stdout or "unknown").strip()
    return {
        "status": "active" if service == "active" else "degraded",
        "provider": "openvpn",
        "service": service,
        "pki_ready": (LEGACY_PKI / "ca.key").is_file(),
        "managed_profiles": len(list(PROFILE_ROOT.glob("*/*.ovpn"))) if PROFILE_ROOT.exists() else 0,
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="operation", required=True)
    subparsers.add_parser("initialize")
    subparsers.add_parser("status")
    create_parser = subparsers.add_parser("create")
    create_parser.add_argument("name")
    create_parser.add_argument("preset", choices=sorted(ROUTE_PRESETS))
    revoke_parser = subparsers.add_parser("revoke")
    revoke_parser.add_argument("name")
    args = parser.parse_args()
    try:
        if args.operation == "initialize":
            result = initialize()
        elif args.operation == "status":
            result = status()
        elif args.operation == "create":
            result = create_profile(args.name, args.preset)
        else:
            result = revoke_profile(args.name)
    except (KeyError, ValueError, RuntimeError, OSError) as exc:
        print(json.dumps({"status": "failed", "issue": str(exc)}, ensure_ascii=True))
        return 1
    print(json.dumps(result, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
