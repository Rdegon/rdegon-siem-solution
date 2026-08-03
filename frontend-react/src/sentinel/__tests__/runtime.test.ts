import { afterEach, describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import { createElement } from "react";
import { viewFromPath } from "../model";
import { formatTime, number, severityTone, text } from "../runtime/query";
import { api, setApiTenantScope } from "../runtime/api";
import { incidentSla } from "../dashboard";
import { buildRuleBlocks, DEFAULT_EVENT_QUERY, RESOURCE_DEFINITIONS } from "../kuma-workspaces";
import { RecordDetails } from "../record-details";

describe("production UI routing", () => {
  it("maps deep links to the new workspace", () => {
    expect(viewFromPath("/app/incidents")).toBe("incidents");
    expect(viewFromPath("/app/sources/details")).toBe("sources");
    expect(viewFromPath("/app/unknown")).toBe("overview");
  });
});

describe("production data formatting", () => {
  it("keeps zero values and renders arrays without fixtures", () => {
    expect(number("0")).toBe(0);
    expect(text(["192.168.3.1", "192.168.3.101"])).toBe("192.168.3.1, 192.168.3.101");
    expect(severityTone("critical")).toBe("critical");
    expect(formatTime("")).toBe("—");
  });

  it("calculates incident SLA from real first-seen timestamps and status", () => {
    const now = new Date("2026-07-31T12:00:00Z").getTime();
    expect(incidentSla({ severity_agg: "critical", status: "open", ts_first: "2026-07-31T11:30:00Z" }, now)).toMatchObject({ targetMinutes: 15, breached: true });
    expect(incidentSla({ severity_agg: "high", status: "resolved", ts_first: "2026-07-30T10:00:00Z" }, now)).toMatchObject({ targetMinutes: 60, breached: false, terminal: true });
  });
});

describe("KUMA-compatible workspaces", () => {
  it("builds a publishable detection pipeline from the rule editor", () => {
    const blocks = buildRuleBlocks({
      title: "SSH failure burst",
      description: "Repeated failed authentication",
      kind: "detection",
      sourceProfile: "linux-auth",
      sourceQuery: "category = 'authentication'",
      expression: "event_outcome = 'failure'",
      threshold: 5,
      windowS: 300,
      entityField: "src.ip",
      severity: "high",
      suppressionKey: "src.ip",
      target: "stream-correlation",
    });

    expect(blocks.map((block) => block.type)).toEqual(["source", "detection", "incident", "publish"]);
    expect((blocks[1].config as Record<string, unknown>).threshold).toBe(5);
  });

  it("does not expose SQL in the browser and keeps every supported resource kind once", () => {
    expect(DEFAULT_EVENT_QUERY).toBe("");
    expect(new Set(RESOURCE_DEFINITIONS.map((item) => item.kind)).size).toBe(RESOURCE_DEFINITIONS.length);
    expect(RESOURCE_DEFINITIONS.map((item) => item.kind)).toContain("correlationRule");
  });

  it("renders runtime records as operational cards instead of a JSON dump", () => {
    const { container } = render(createElement(RecordDetails, { kind: "service", value: {
      service_id: "ndr",
      title: "Network Detection",
      telemetry_state: "healthy",
      host_name: "soc-ndr-01",
      address: "10.20.10.127",
      events_24h: 4312,
      workspaces: [{ label: "Arkime", href: "https://siem.example:8005", external: true }],
    } }));

    expect(screen.getByText("Основные сведения")).toBeInTheDocument();
    expect(screen.getByText("Сеть и размещение")).toBeInTheDocument();
    expect(screen.getByText("4 312")).toBeInTheDocument();
    expect(container.querySelector("pre.sentinel-json")).not.toBeInTheDocument();
  });
});

describe("tenant-scoped API", () => {
  afterEach(() => {
    setApiTenantScope([]);
    vi.restoreAllMocks();
  });

  it("sends selected tenants to the server", async () => {
    setApiTenantScope(["main", "dmz"]);
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(new Response(JSON.stringify({ user: {}, labels: {} }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    }));

    await api.bootstrap();

    const init = fetchMock.mock.calls[0][1] as RequestInit;
    expect(init.headers).toMatchObject({ "X-SIEM-Tenant-Scope": "main,dmz" });
  });
});
