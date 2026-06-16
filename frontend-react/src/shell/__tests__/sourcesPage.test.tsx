import { screen, waitFor } from "@testing-library/react";
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
});
