import { afterEach, describe, expect, it, vi } from "vitest";
import { viewFromPath } from "../model";
import { formatTime, number, severityTone, text } from "../runtime/query";
import { api, setApiTenantScope } from "../runtime/api";
import { incidentSla } from "../dashboard";

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
