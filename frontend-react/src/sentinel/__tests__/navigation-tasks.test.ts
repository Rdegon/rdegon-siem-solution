import { describe, expect, it } from "vitest";
import { pathByView, platformNavigation, securityNavigation, securityNavigationGroups, viewFromPath } from "../model";
import { taskStatusGroup } from "../task-dispatcher";
import { humanizeEntity } from "../incident-details";

describe("production navigation", () => {
  it("exposes the real task dispatcher as a stable route", () => {
    expect(platformNavigation).toContain("tasks");
    expect(pathByView.tasks).toBe("/app/tasks");
    expect(viewFromPath("/app/tasks")).toBe("tasks");
  });

  it("keeps every security module in exactly one second-level group", () => {
    const grouped = securityNavigationGroups.flatMap((group) => group.items);
    expect(grouped).toEqual(securityNavigation);
    expect(new Set(grouped).size).toBe(grouped.length);
  });
});

describe("task status normalization", () => {
  it.each([
    ["running", "active"],
    ["pending_approval", "active"],
    ["completed", "completed"],
    ["success", "completed"],
    ["completed_with_warnings", "completed"],
    ["dry_run", "completed"],
    ["superseded", "completed"],
    ["failed", "failed"],
    ["timeout", "failed"],
    ["rejected", "failed"],
  ])("maps %s to %s", (status, expected) => {
    expect(taskStatusGroup(status)).toBe(expected);
  });
});

describe("incident entity presentation", () => {
  it("turns structured and serialized entities into readable labels", () => {
    expect(humanizeEntity({ "host.name": "DESKTOP-5JMJVBH" })).toBe("DESKTOP-5JMJVBH");
    expect(humanizeEntity('{"host.name":"asset-desktop-5jmjvbh"}')).toBe("asset-desktop-5jmjvbh");
    expect(humanizeEntity({ ip: "192.168.3.81", confidence: 90 })).toBe("192.168.3.81");
  });
});
