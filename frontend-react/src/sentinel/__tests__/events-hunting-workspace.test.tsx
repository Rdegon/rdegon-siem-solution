import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { buildHuntingSpecification, EventsHuntingWorkspace } from "../events-hunting-workspace";
import { api } from "../runtime/api";


function mockRuntime() {
  vi.spyOn(api, "huntingCapabilities").mockResolvedValue({
    items: [{ id: "hot", label: "Оперативное хранилище", table: "siem.events", available: true }],
    default: "hot",
    facets: ["source_type", "source", "collector_profile", "category", "severity", "host"],
    max_range_hours: 744,
    max_page_size: 250,
  });
  vi.spyOn(api, "huntingSavedSearches").mockResolvedValue({ items: [], tenant_id: "main", owner: "analyst" });
  vi.spyOn(api, "huntingFacets").mockResolvedValue({
    source: "hot",
    from_ts: "2026-08-02T00:00:00Z",
    to_ts: "2026-08-03T00:00:00Z",
    facets: {
      source_type: [{ value: "linux", count: 12 }],
      source: [], collector_profile: [], category: [], severity: [], host: [],
    },
  });
  return vi.spyOn(api, "huntingQuery").mockImplementation(async (body) => ({
    rows: [{
      ts: "2026-08-02T12:00:00Z",
      stable_id: "evt-1",
      event_id: "evt-1",
      source: "pilot-web-01",
      source_type: "linux",
      host: "pilot-web-01",
      severity: "high",
      category: "authentication",
      message: "Failed SSH login",
    }],
    row_count: 1,
    total_count: null,
    total_count_is_estimate: true,
    source: "hot",
    from_ts: "2026-08-02T00:00:00Z",
    to_ts: "2026-08-03T00:00:00Z",
    limit: 100,
    offset: 0,
    cursor: String(body.cursor ?? ""),
    next_cursor: body.cursor ? "" : "cursor-2",
    has_more: !body.cursor,
    pagination: body.cursor ? "cursor" : "offset",
  }));
}


describe("event hunting workspace", () => {
  afterEach(() => vi.restoreAllMocks());

  it("builds a structured request and never emits browser-side SQL", () => {
    const specification = buildHuntingSpecification({
      source: "hot",
      window: "24h",
      rangeMode: "window",
      fromTs: "",
      toTs: "",
      filters: [{ field: "severity", operator: "in", value: "high, critical" }],
      expertQuery: "source:linux*",
      pageSize: 100,
    });

    expect(specification).toMatchObject({
      source: "hot",
      window: "24h",
      filters: [{ field: "severity", operator: "in", values: ["high", "critical"] }],
      expert_query: "source:linux*",
      limit: 100,
    });
    expect(JSON.stringify(specification).toLowerCase()).not.toContain("select ");
    expect(JSON.stringify(specification)).not.toContain("siem.events");
  });

  it("renders real facets and advances with the server cursor", async () => {
    const query = mockRuntime();
    render(<EventsHuntingWorkspace notify={vi.fn()} />);

    expect(await screen.findByText("Failed SSH login")).toBeInTheDocument();
    expect(await screen.findByRole("button", { name: "linux · 12" })).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Следующая страница" }));

    await waitFor(() => expect(query.mock.calls.some(([body]) => body.cursor === "cursor-2")).toBe(true));
    expect(query.mock.calls.every(([body]) => !("query" in body))).toBe(true);
  });

  it("loads a curated event card instead of rendering normalized JSON", async () => {
    mockRuntime();
    vi.spyOn(api, "huntingEventDetail").mockResolvedValue({
      event: {
        event_id: "evt-1",
        ts: "2026-08-02T12:00:00Z",
        log_source: "pilot-web-01",
        severity: "high",
        category: "authentication",
        message: "Failed SSH login",
      },
      sections: { normalized: { "event.kind": "event" } },
      raw_json_available: false,
      source: "hot",
    });
    render(<EventsHuntingWorkspace notify={vi.fn()} />);
    fireEvent.click(await screen.findByText("Failed SSH login"));

    expect(await screen.findByText("evt-1")).toBeInTheDocument();
    expect(screen.queryByText(/normalized_json/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/\{\s*"event.kind"/i)).not.toBeInTheDocument();
  });
});
