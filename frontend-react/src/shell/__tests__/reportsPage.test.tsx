import { screen } from "@testing-library/react";
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

  it("renders generated scanner reports instead of the vulnerability overview route", async () => {
    renderWithShell(
      <MemoryRouter initialEntries={["/reports"]}>
        <Routes>
          <Route path="/reports" element={<ReportsPage />} />
        </Routes>
      </MemoryRouter>,
    );

    expect(await screen.findByText("Greenbone nightly scan")).toBeInTheDocument();
    expect(screen.getByText("gvm-2026-07-31")).toBeInTheDocument();
    expect(screen.getByText("192.168.3.120")).toBeInTheDocument();
  });
});
