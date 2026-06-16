import { screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { BuildersPage } from "../pages/builders/BuildersWorkbench";
import { renderWithShell } from "../../test/renderWithShell";

function jsonResponse(payload: unknown) {
  return new Response(JSON.stringify(payload), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}

describe("BuildersPage correlation workspace", () => {
  beforeEach(() => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes("/api/builders/drafts")) {
        return jsonResponse({ items: [] });
      }
      if (url.includes("/api/correlation/packs/identity-access-v1")) {
        return jsonResponse({
          item: {
            pack_id: "identity-access-v1",
            title: "Identity access",
            version: "1.0.0",
            status: "active",
            owner: "platform-release",
            notes: ["note"],
            stream_rules: [
              {
                id: 2501,
                title: "Repeated auth failures",
                severity: "medium",
                window_s: 600,
                threshold: 5,
                entity_field: "user.name",
                suppression_key: "host.name + service.name + identity_access_v1",
                status: "active",
                operator_action: "Inspect",
                sigma_yaml: "title: Repeated auth failures",
              },
            ],
            batch_rules: [],
          },
        });
      }
      if (url.includes("/api/correlation/packs")) {
        return jsonResponse({
          items: [
            {
              pack_id: "identity-access-v1",
              title: "Identity access",
              status: "active",
              rule_count: 1,
              active_stream_rules: 1,
            },
          ],
        });
      }
      throw new Error(`Unhandled fetch: ${url}`);
    });
    vi.stubGlobal("fetch", fetchMock);
  });

  it("renders the dedicated correlation workspace inside Builders", async () => {
    renderWithShell(
      <MemoryRouter initialEntries={["/builders?workspace=correlation"]}>
        <Routes>
          <Route path="/builders" element={<BuildersPage />} />
        </Routes>
      </MemoryRouter>,
    );

    expect(await screen.findByRole("button", { name: "Correlation" })).toBeInTheDocument();
    await waitFor(() => expect(screen.getByText("Correlation packs")).toBeInTheDocument());
    expect(screen.getByText("Rule deck")).toBeInTheDocument();
    expect(screen.getAllByText("Validation and publish").length).toBeGreaterThan(0);
    expect(screen.getAllByText("Identity access").length).toBeGreaterThan(0);
    expect(screen.getAllByText(/identity-access-v1/i).length).toBeGreaterThan(0);
  });
});
