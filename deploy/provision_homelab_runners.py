from __future__ import annotations

import os
import sys

from github_runner_provision import (
    DEFAULT_INSTALL_ROOT,
    DEFAULT_RUNNER_ASSET,
    DEFAULT_RUNNER_URL,
    RunnerTarget,
    _get_registration_token,
    _required_env,
    provision_runner,
)


def _target(prefix: str, *, name: str) -> RunnerTarget:
    return RunnerTarget(
        host=_required_env(f"{prefix}_HOST"),
        user=_required_env(f"{prefix}_USER"),
        password=_required_env(f"{prefix}_PASSWORD"),
        name=name,
        labels=f"siem-homelab,{name}",
        install_root=_required_env("RUNNER_INSTALL_ROOT", default=DEFAULT_INSTALL_ROOT),
    )


def _optional_target(prefix: str, *, name: str) -> RunnerTarget | None:
    host = str(os.getenv(f"{prefix}_HOST", "") or "").strip()
    user = str(os.getenv(f"{prefix}_USER", "") or "").strip()
    password = str(os.getenv(f"{prefix}_PASSWORD", "") or "").strip()
    if not (host and user and password):
        return None
    return RunnerTarget(
        host=host,
        user=user,
        password=password,
        name=name,
        labels=f"siem-homelab,{name}",
        install_root=_required_env("RUNNER_INSTALL_ROOT", default=DEFAULT_INSTALL_ROOT),
    )


def main() -> int:
    owner = _required_env("GITHUB_REPO_OWNER", default="Rdegon")
    repo = _required_env("GITHUB_REPO_NAME", default="siem-solution")
    pat = _required_env("GITHUB_PAT")
    runner_asset_url = _required_env("GITHUB_RUNNER_ASSET_URL", default=DEFAULT_RUNNER_URL)
    runner_asset_name = _required_env("GITHUB_RUNNER_ASSET_NAME", default=DEFAULT_RUNNER_ASSET)
    repo_url = f"https://github.com/{owner}/{repo}"

    targets = [
        _target("SIEM_VM1", name="siem-vm1"),
        _target("SIEM_VM2", name="siem-vm2"),
        _target("SIEM_VM3", name="siem-vm3"),
        _target("SIEM_VM4", name="siem-vm4"),
    ]
    vm5_target = _optional_target("SIEM_VM5", name="siem-vm5")
    if vm5_target is not None:
        targets.append(vm5_target)

    failures: list[str] = []
    for target in targets:
        print(f"== provisioning {target.name} on {target.host} ==")
        try:
            registration_token = _get_registration_token(owner, repo, pat)
            provision_runner(
                target,
                repo_url=repo_url,
                registration_token=registration_token,
                runner_asset_url=runner_asset_url,
                runner_asset_name=runner_asset_name,
            )
        except Exception as exc:  # noqa: BLE001
            failures.append(f"{target.name}@{target.host}: {exc}")
            print(f"runner_provision_failed {target.name} {exc}")
    if failures:
        print("failures:")
        for failure in failures:
            print(f"- {failure}")
        return 1
    print("runner_provision=success")
    return 0


if __name__ == "__main__":
    sys.exit(main())
