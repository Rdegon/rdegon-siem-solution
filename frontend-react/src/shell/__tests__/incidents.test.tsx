import { describe, expect, it } from "vitest";
import { buildIncidentDeepLink, incidentRowId } from "../incidents";

describe("incident helpers", () => {
  it("prefers aggregate ids for aggregate view and alert ids for raw view", () => {
    const record = { agg_id: "agg-42", alert_id: "alert-42" };
    expect(incidentRowId(record, "agg")).toBe("agg-42");
    expect(incidentRowId(record, "raw")).toBe("alert-42");
  });

  it("builds a deep link into the incidents workspace", () => {
    expect(buildIncidentDeepLink("https://siem.local", "?view=raw&focus=abc")).toBe(
      "https://siem.local/app/incidents?view=raw&focus=abc",
    );
  });
});
