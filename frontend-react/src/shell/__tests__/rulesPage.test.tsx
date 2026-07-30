import { screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { renderWithShell } from "../../test/renderWithShell";
import { RulesPage } from "../pages/RulesPage";

function jsonResponse(payload: unknown) {
  return new Response(JSON.stringify(payload), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}

describe("RulesPage", () => {
  beforeEach(() => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input);
        if (url.includes("/api/correlation/packs")) {
          return jsonResponse({
            items: [{
              pack_id: "linux-auth",
              title: "Linux authentication",
              version: "4",
              status: "active",
              owner: "detection-engineering",
              active_stream_rules: 1,
              stream_rules: [{
                id: 2701,
                title: "Linux SSH brute force",
                severity: "high",
                window_s: 300,
                threshold: 8,
                suppression_key: "src.ip + host.name",
                status: "active",
              }],
              batch_rules: [],
            }],
          });
        }
        throw new Error(`Unhandled fetch: ${url}`);
      }),
    );
  });

  it("renders runtime correlation rules from the production API contract", async () => {
    renderWithShell(<MemoryRouter><RulesPage /></MemoryRouter>);

    expect(await screen.findByText("Linux SSH brute force")).toBeInTheDocument();
    expect(screen.getByText("2701")).toBeInTheDocument();
    expect(screen.getByText("linux-auth")).toBeInTheDocument();
    expect(screen.getAllByLabelText("status active").length).toBeGreaterThan(0);
  });
});
