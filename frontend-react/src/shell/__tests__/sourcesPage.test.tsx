import { fireEvent, screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { SourcesPage } from "../pages/SourcesPage";
import { renderWithShell } from "../../test/renderWithShell";

function jsonResponse(payload: unknown) {
  return new Response(JSON.stringify(payload), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}

describe("SourcesPage", () => {
  beforeEach(() => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input);
        if (url.includes("/api/sources/discovery")) {
          return jsonResponse({
            items: [
              {
                id: "cand-1",
                hostname: "edge-sw-01",
                ip: "192.168.1.40",
                vendor: "cisco_ios",
                connected: false,
                connected_source: "",
                binding_target: "asset-edge-sw-01",
                binding_override_id: "ovr-1",
                binding_override: { id: "ovr-1", target: "asset-edge-sw-01", note: "Matched via alias" },
                last_job_id: "job-1",
              },
            ],
            jobs: [{ id: "job-1", status: "dry_run", transcript: ["connection ok"], artifacts: [{ name: "edge-sw-01.cfg" }] }],
            metrics: { binding_overrides_total: 1, binding_overrides_applied: 1, unmanaged_without_override: 0, total: 1 },
          });
        }
        if (url.includes("/api/sources/policies")) {
          return jsonResponse({
            items: [
              {
                id: "windows-freshness",
                type: "source_monitoring_policy",
                name: "Windows telemetry freshness",
                enabled: true,
                source_pattern: "windows",
                window_hours: 24,
                min_events: 10,
                max_events: 0,
                stale_after_minutes: 30,
                severity: "high",
                notifications: ["telegram"],
                owner: "siem-engineering",
                matched_sources: 2,
                violation_count: 1,
                evaluation_status: "breached",
                violations: [
                  {
                    source_name: "dc-01",
                    events: 3,
                    last_seen: "2026-07-31T11:00:00Z",
                    reasons: ["below_min_events"],
                  },
                ],
              },
            ],
          });
        }
        if (url.includes("/api/sources")) {
          return jsonResponse({
            items: [
              {
                source_name: "dc-01",
                source_type: "windows",
                status: "active",
                collector_name: "collector-a",
                notable_events: 3,
                cmdb_ip: "192.168.1.10",
                source_ips: ["192.168.1.10"],
                observed_ips: ["192.168.1.10", "192.168.1.42"],
              },
            ],
          });
        }
        if (url.includes("/api/integrations/catalog")) {
          return jsonResponse({
            items: [
              { id: "ssh-config-push", family: "source", group: "network", mode: "runtime", title: "SSH config push" },
              { id: "windows-agent", family: "source", group: "endpoint", mode: "push", title: "Windows native agent" },
            ],
          });
        }
        throw new Error(`Unhandled fetch: ${url}`);
      }),
    );
  });

  it("shows discovery and binding remediation in the /app sources workspace", async () => {
    renderWithShell(
      <MemoryRouter initialEntries={["/sources?view=discovery"]}>
        <Routes>
          <Route path="/sources" element={<SourcesPage />} />
        </Routes>
      </MemoryRouter>,
    );

    expect(await screen.findByText("LAN discovery and onboarding")).toBeInTheDocument();
    await waitFor(() => expect(screen.getByText("Binding remediation")).toBeInTheDocument());
    expect(screen.getByDisplayValue("asset-edge-sw-01")).toBeInTheDocument();
  });

  it("opens the discovery workspace from the security navigation route", async () => {
    renderWithShell(
      <MemoryRouter initialEntries={["/security/discovery"]}>
        <Routes>
          <Route path="/security/discovery" element={<SourcesPage />} />
        </Routes>
      </MemoryRouter>,
    );

    expect(await screen.findByText("LAN discovery and onboarding")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Discovery" })).toHaveClass("active");
  });

  it("shows source IPs in the source register", async () => {
    renderWithShell(
      <MemoryRouter initialEntries={["/sources"]}>
        <Routes>
          <Route path="/sources" element={<SourcesPage />} />
        </Routes>
      </MemoryRouter>,
    );

    expect(await screen.findByText("dc-01")).toBeInTheDocument();
    expect(screen.getAllByText("192.168.1.10").length).toBeGreaterThan(0);
  });

  it("evaluates persisted source policies against live inventory", async () => {
    renderWithShell(
      <MemoryRouter initialEntries={["/sources?view=policies"]}>
        <Routes>
          <Route path="/sources" element={<SourcesPage />} />
        </Routes>
      </MemoryRouter>,
    );

    expect(await screen.findByText("Windows telemetry freshness")).toBeInTheDocument();
    expect(screen.getByText("windows")).toBeInTheDocument();
    expect(screen.getAllByText("breached").length).toBeGreaterThan(0);
    fireEvent.click(screen.getByRole("button", { name: "Windows telemetry freshness" }));
    expect(await screen.findByText("Affected sources")).toBeInTheDocument();
    expect(screen.getByText("below_min_events")).toBeInTheDocument();
  });
});
