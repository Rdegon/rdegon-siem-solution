import { fireEvent, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { renderWithShell } from "../../test/renderWithShell";
import { ReportsPage } from "../pages/ReportsPage";

function jsonResponse(payload: unknown) {
  return new Response(JSON.stringify(payload), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}

describe("ReportsPage", () => {
  beforeEach(() => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input);
        if (url.endsWith("/api/reporting/templates")) {
          return jsonResponse({
            items: [{
              id: "soc-shift-summary",
              type: "report_template",
              name: "SOC shift summary",
              owner: "soc-ops",
              tenant_scope: ["all"],
              period: "12h",
              retention_days: 90,
              sections: ["executive_summary", "incidents"],
              formats: ["json", "csv"],
              schedule: { enabled: false, frequency: "shift", time: "08:00", timezone: "Europe/Moscow", recipients: [] },
              updated_ts: "2026-07-31T00:00:00Z",
            }],
          });
        }
        if (url.includes("/api/reporting/runs")) {
          return jsonResponse({ items: [] });
        }
        if (url.endsWith("/api/reports")) {
          return jsonResponse({
            items: [{
              report_id: "gvm-2026-07-31",
              title: "Greenbone nightly scan",
              scanner_family: "greenbone",
              targets: ["192.168.3.120"],
              ts_first: "2026-07-31T00:00:00Z",
              ts_last: "2026-07-31T00:30:00Z",
            }],
          });
        }
        throw new Error(`Unhandled fetch: ${url}`);
      }),
    );
  });

  it("renders persisted templates and keeps scanner reports in the same workspace", async () => {
    renderWithShell(
      <MemoryRouter initialEntries={["/reports"]}>
        <Routes>
          <Route path="/reports" element={<ReportsPage />} />
        </Routes>
      </MemoryRouter>,
    );

    expect(await screen.findByText("SOC shift summary")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("tab", { name: /Scanner reports/i }));
    expect(await screen.findByText("Greenbone nightly scan")).toBeInTheDocument();
    expect(screen.getByText("gvm-2026-07-31")).toBeInTheDocument();
    expect(screen.getByText("192.168.3.120")).toBeInTheDocument();
  });

  it("runs a template through the reporting API", async () => {
    const fetchMock = vi.mocked(fetch);
    fetchMock.mockImplementation(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith("/api/reporting/templates/soc-shift-summary/run") && init?.method === "POST") {
        return jsonResponse({
          id: "report-run-1",
          type: "report_run",
          template_id: "soc-shift-summary",
          name: "SOC shift summary",
          status: "completed",
          owner: "analyst",
          tenant_scope: ["all"],
          period: { window: "12h", from_ts: "2026-07-30T12:00:00Z", to_ts: "2026-07-31T00:00:00Z" },
          formats: ["json", "csv"],
          sections: ["executive_summary"],
          section_count: 1,
          record_count: 12,
          errors: [],
          created_ts: "2026-07-31T00:00:00Z",
          completed_ts: "2026-07-31T00:00:01Z",
          duration_ms: 1000,
        });
      }
      if (url.endsWith("/api/reporting/templates")) {
        return jsonResponse({
          items: [{
            id: "soc-shift-summary",
            type: "report_template",
            name: "SOC shift summary",
            owner: "soc-ops",
            tenant_scope: ["all"],
            period: "12h",
            retention_days: 90,
            sections: ["executive_summary"],
            formats: ["json", "csv"],
            schedule: { enabled: false, frequency: "shift", time: "08:00", timezone: "Europe/Moscow", recipients: [] },
          }],
        });
      }
      if (url.endsWith("/api/reporting/runs/report-run-1")) {
        return jsonResponse({
          item: {
            id: "report-run-1",
            type: "report_run",
            template_id: "soc-shift-summary",
            name: "SOC shift summary",
            status: "completed",
            owner: "analyst",
            tenant_scope: ["all"],
            period: { window: "12h", from_ts: "2026-07-30T12:00:00Z", to_ts: "2026-07-31T00:00:00Z" },
            formats: ["json", "csv"],
            sections: ["executive_summary"],
            section_count: 1,
            record_count: 12,
            errors: [],
            snapshot: { executive_summary: { events: 12 } },
            created_ts: "2026-07-31T00:00:00Z",
            completed_ts: "2026-07-31T00:00:01Z",
            duration_ms: 1000,
          },
        });
      }
      if (url.includes("/api/reporting/runs")) return jsonResponse({ items: [] });
      if (url.endsWith("/api/reports")) return jsonResponse({ items: [] });
      throw new Error(`Unhandled fetch: ${url}`);
    });

    renderWithShell(
      <MemoryRouter initialEntries={["/reports"]}>
        <Routes><Route path="/reports" element={<ReportsPage />} /></Routes>
      </MemoryRouter>,
    );

    expect(await screen.findByText("SOC shift summary")).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Run" }));
    await waitFor(() => {
      expect(fetchMock).toHaveBeenCalledWith(
        "/api/reporting/templates/soc-shift-summary/run",
        expect.objectContaining({ method: "POST" }),
      );
    });
  });
});
