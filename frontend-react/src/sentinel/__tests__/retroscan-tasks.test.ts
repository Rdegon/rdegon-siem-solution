import { describe, expect, it } from "vitest";
import { retroscanTask, taskStatusGroup } from "../task-dispatcher";
import type { RetroscanRunRecord } from "../runtime/types";

describe("retroscan task feed", () => {
  it("maps a tracked retroscan run into the shared task manager", () => {
    const row = retroscanTask({
      id: "retroscan-42",
      run_id: "retroscan-42",
      type: "retroscan_run",
      status: "running",
      owner: "soc-analyst",
      mode: "dry_run",
      request: {
        from_ts: "2026-08-03T00:00:00Z",
        to_ts: "2026-08-03T01:00:00Z",
        max_rows: 10000,
        rule_ids: [1002, 2701],
        dry_run: true,
        commit: false,
      },
      capabilities: {
        dry_run: true,
        commit: false,
        commit_reason: "No reusable alert service path exists",
        engines: ["stream_threshold"],
        event_table: "siem.events",
        rule_table: "siem.correlation_rules_stream",
        max_range_hours: 720,
        max_rows: 50000,
        preview_limit: 100,
      },
      progress: {
        phase: "evaluating",
        percent: 45,
        events_available: 2000,
        events_scanned: 900,
        matched_events: 14,
        candidate_alerts: 2,
      },
      cancel_requested: false,
      created_ts: "2026-08-03T00:00:00Z",
      started_ts: "2026-08-03T00:00:01Z",
      heartbeat_ts: "2026-08-03T00:00:02Z",
      completed_ts: "",
      duration_ms: 0,
    } satisfies RetroscanRunRecord);

    expect(row.kind).toBe("retroscan");
    expect(row.title).toContain("2 правил");
    expect(row.actor).toBe("soc-analyst");
    expect(row.progress).toBe(45);
    expect(taskStatusGroup(row.status)).toBe("active");
  });
});
