from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from deploy import publish_rule_noise_tuning  # noqa: E402
from tools.full_rule_audit import build_audit, render_markdown  # noqa: E402


def _write_report(output_dir: Path, name: str, audit: dict[str, object]) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / f"{name}.json").write_text(json.dumps(audit, ensure_ascii=False, indent=2), encoding="utf-8")
    (output_dir / f"{name}.md").write_text(render_markdown(audit), encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run full rule audit and publish calibrated runtime rules.")
    parser.add_argument("--days", type=int, default=30)
    parser.add_argument("--output-dir", default="artifacts/rule-audit")
    parser.add_argument("--skip-publish", action="store_true", help="Only build audit reports.")
    args = parser.parse_args(argv)

    output_dir = Path(args.output_dir)
    before = build_audit(args.days, live=True)
    _write_report(output_dir, "full_rule_audit_before", before)

    publish_rc = 0
    if not args.skip_publish:
        publish_rc = publish_rule_noise_tuning.main()

    after = build_audit(args.days, live=True)
    _write_report(output_dir, "full_rule_audit_after", after)

    print(
        json.dumps(
            {
                "output_dir": str(output_dir),
                "publish_rc": publish_rc,
                "before": before.get("summary", {}),
                "after": after.get("summary", {}),
            },
            ensure_ascii=False,
        )
    )
    return int(publish_rc)


if __name__ == "__main__":
    raise SystemExit(main())
