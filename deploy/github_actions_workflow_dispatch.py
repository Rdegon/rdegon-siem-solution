from __future__ import annotations

import json
import os
import sys
import urllib.request


def _required_env(name: str, *, default: str | None = None) -> str:
    value = os.getenv(name, default or "").strip()
    if value:
        return value
    raise SystemExit(f"Missing required environment variable: {name}")


def _dispatch_workflow(owner: str, repo: str, workflow_id: str, pat: str, *, ref: str, inputs: dict[str, str]) -> None:
    payload = json.dumps({"ref": ref, "inputs": inputs}).encode("utf-8")
    request = urllib.request.Request(
        f"https://api.github.com/repos/{owner}/{repo}/actions/workflows/{workflow_id}/dispatches",
        method="POST",
        data=payload,
        headers={
            "Authorization": f"Bearer {pat}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "Content-Type": "application/json",
        },
    )
    with urllib.request.urlopen(request, timeout=30):
        return


def main() -> int:
    owner = _required_env("GITHUB_REPO_OWNER", default="Rdegon")
    repo = _required_env("GITHUB_REPO_NAME", default="siem-solution")
    pat = _required_env("GITHUB_PAT")
    workflow_id = _required_env("GITHUB_WORKFLOW_ID", default="deploy-homelab.yml")
    ref = _required_env("GITHUB_WORKFLOW_REF", default="main")
    target = _required_env("GITHUB_WORKFLOW_TARGET", default="vm4")
    _dispatch_workflow(owner, repo, workflow_id, pat, ref=ref, inputs={"target": target})
    print(f"workflow_dispatch=success workflow={workflow_id} ref={ref} target={target}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
