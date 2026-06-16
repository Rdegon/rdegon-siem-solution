import { screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { VulnPage } from "../pages/VulnPage";
import { renderWithShell } from "../../test/renderWithShell";

function jsonResponse(payload: unknown) {
  return new Response(JSON.stringify(payload), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}

describe("VulnPage", () => {
  beforeEach(() => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input);
        if (url.includes("/api/reports")) {
          return jsonResponse({ items: [{ report_id: "rep-1", title: "Nightly sync", created_ts: "2026-03-26T23:18:00Z" }] });
        }
        if (url.includes("/api/vuln/overview")) {
          return jsonResponse({
            summary: { open_findings: 18, critical_open: 3, reports: 42 },
            critical_queue: [{ finding_id: "finding-1", asset_name: "dc-01", severity: "critical", title: "SMB Signing Disabled" }],
            top_exposure: [{ label: "dc-01", count: 6 }],
          });
        }
        if (url.includes("/api/integrations/catalog")) {
          return jsonResponse({ items: [{ id: "greenbone", family: "source", group: "vulnerability", mode: "pull", title: "Greenbone" }] });
        }
        if (url.includes("/api/vuln/integration-contract")) {
          return jsonResponse({ items: [] });
        }
        if (url.includes("/api/vuln/runtime")) {
          return jsonResponse({ healthy: true, ready_for_incident_policies: true, structured_reports: 42 });
        }
        if (url.includes("/api/vuln/maturity")) {
          return jsonResponse({
            healthy: true,
            ready_for_incident_policies: true,
            critical_open: 3,
            unmapped_targets_total: 2,
            binding_overrides_total: 1,
            binding_overrides_active: 1,
            critical_queue: [{ finding_id: "finding-1", asset_name: "dc-01", severity: "critical", title: "SMB Signing Disabled" }],
            unmapped_targets: [{ finding_key: "finding-3", target: "ws-17.corp.local", hostname: "ws-17", ip: "192.168.1.117", suggested_asset_id: "asset-ws-17", severity: "high", reason: "Needs asset binding" }],
          });
        }
        if (url.includes("/api/vuln/hosts")) {
          return jsonResponse({ items: [] });
        }
        if (url.includes("/api/vuln/software")) {
          return jsonResponse({ items: [] });
        }
        if (url.includes("/api/vuln/cves")) {
          return jsonResponse({ items: [] });
        }
        if (url.includes("/api/vuln/findings")) {
          return jsonResponse({ items: [] });
        }
        if (url.includes("/api/assets/inventory")) {
          return jsonResponse({ items: [{ asset_id: "asset-ws-17", hostname: "ws-17", ip: "192.168.1.117" }] });
        }
        throw new Error(`Unhandled fetch: ${url}`);
      }),
    );
  });

  it("surfaces the unmapped target queue in the vulnerability workspace", async () => {
    renderWithShell(
      <MemoryRouter initialEntries={["/vuln"]}>
        <Routes>
          <Route path="/vuln" element={<VulnPage />} />
        </Routes>
      </MemoryRouter>,
    );

    expect(await screen.findByText("Exposure and scan intelligence")).toBeInTheDocument();
    await waitFor(() => expect(screen.getByText("Unmapped target queue")).toBeInTheDocument());
    expect(screen.getByDisplayValue("asset-ws-17")).toBeInTheDocument();
  });
});
