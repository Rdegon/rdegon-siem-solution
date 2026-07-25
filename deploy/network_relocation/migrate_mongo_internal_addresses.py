from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.parse
from pathlib import Path

from pymongo import MongoClient


ADDRESS_MAP = {
    "192.168.1.35": "10.20.10.104",
    "192.168.1.39": "10.20.10.107",
    "192.168.1.40": "10.20.10.108",
}


def parse_env_file(path: Path) -> dict[str, str]:
    payload: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        payload[key.strip()] = value.strip().strip('"').strip("'")
    return payload


def rewrite_mongo_uri(uri: str) -> str:
    result = str(uri or "")
    for old, new in ADDRESS_MAP.items():
        result = result.replace(old, new)
    return result


def _load_secret_runtime(repo_root: Path):
    app_dir = repo_root / "services" / "web" / "app"
    sys.path.insert(0, str(app_dir))
    import secret_runtime  # type: ignore[import-not-found]

    return secret_runtime


def _admin_uri(storage_env: dict[str, str]) -> str:
    user = urllib.parse.quote_plus(storage_env["SIEM_MONGO_ADMIN_USER"])
    password = urllib.parse.quote_plus(storage_env["SIEM_MONGO_ADMIN_PASSWORD"])
    return f"mongodb://{user}:{password}@127.0.0.1:27017/admin?directConnection=true"


def migrate(
    *,
    repo_root: Path,
    web_env_path: Path,
    storage_env_path: Path,
    vault_operator_state_path: Path,
    apply: bool,
) -> dict[str, object]:
    web_env = parse_env_file(web_env_path)
    storage_env = parse_env_file(storage_env_path)
    os.environ.update(web_env)
    secret_runtime = _load_secret_runtime(repo_root)
    current_uri, reference, _ = secret_runtime.resolve_secret_value("SIEM_MONGO_URI")
    if not current_uri:
        raise RuntimeError("SIEM_MONGO_URI could not be resolved")
    if not str(reference).startswith("vault://"):
        raise RuntimeError("SIEM_MONGO_URI must use a versioned Vault reference")

    new_uri = rewrite_mongo_uri(current_uri)
    client = MongoClient(_admin_uri(storage_env), serverSelectionTimeoutMS=5000)
    config = dict(client.admin.command("replSetGetConfig")["config"])
    old_hosts = [str(member.get("host") or "") for member in config.get("members") or []]
    new_hosts = [rewrite_mongo_uri(host) for host in old_hosts]
    changed = old_hosts != new_hosts or current_uri != new_uri

    if apply and old_hosts != new_hosts:
        for member, host in zip(config["members"], new_hosts, strict=True):
            member["host"] = host
        config["version"] = int(config.get("version") or 1) + 1
        client.admin.command("replSetReconfig", config, force=True)

    if apply and current_uri != new_uri:
        operator_state = json.loads(vault_operator_state_path.read_text(encoding="utf-8"))
        root_token = str(operator_state.get("root_token") or "").strip()
        if not root_token:
            raise RuntimeError("Vault operator state does not contain a root token")
        os.environ["SIEM_VAULT_AUTH_METHOD"] = "token"
        os.environ["SIEM_VAULT_TOKEN"] = root_token
        secret_runtime.vault_kv_write(reference, {"value": new_uri})
        os.environ.pop("SIEM_VAULT_TOKEN", None)
        os.environ.pop("SIEM_VAULT_AUTH_METHOD", None)

    if apply:
        deadline = time.monotonic() + 45
        last_error: Exception | None = None
        while time.monotonic() < deadline:
            try:
                verify = MongoClient(new_uri, serverSelectionTimeoutMS=3000)
                verify.admin.command("ping")
                verify.close()
                last_error = None
                break
            except Exception as exc:  # noqa: BLE001
                last_error = exc
                time.sleep(2)
        if last_error is not None:
            raise RuntimeError(f"Mongo replica set did not become healthy: {last_error}")

    client.close()
    return {
        "changed": changed,
        "applied": apply,
        "old_hosts": old_hosts,
        "new_hosts": new_hosts,
        "vault_reference": reference,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Move the SIEM Mongo replica set from legacy aliases to sec addresses.")
    parser.add_argument("--repo-root", default="/opt/siem/siem-solution")
    parser.add_argument("--web-env", default="/etc/siem/web.env")
    parser.add_argument("--storage-env", default="/etc/siem/storage-ha.env")
    parser.add_argument("--vault-operator-state", default="/etc/siem/vault-operator.json")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()
    result = migrate(
        repo_root=Path(args.repo_root),
        web_env_path=Path(args.web_env),
        storage_env_path=Path(args.storage_env),
        vault_operator_state_path=Path(args.vault_operator_state),
        apply=bool(args.apply),
    )
    print(f"changed={result['changed']} applied={result['applied']}")
    print(f"old_hosts={','.join(result['old_hosts'])}")
    print(f"new_hosts={','.join(result['new_hosts'])}")
    print(f"vault_reference={result['vault_reference']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
