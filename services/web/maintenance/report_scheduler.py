from __future__ import annotations

import json

from services.web.app.control_plane_report_ops import run_due_report_templates


def main() -> int:
    result = run_due_report_templates()
    print(
        json.dumps(
            {
                "generated_ts": result["generated_ts"],
                "generated": [
                    {
                        "id": item.get("id"),
                        "template_id": item.get("template_id"),
                        "status": item.get("status"),
                        "record_count": item.get("record_count"),
                    }
                    for item in result["generated"]
                ],
                "skipped": result["skipped"],
            },
            ensure_ascii=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
