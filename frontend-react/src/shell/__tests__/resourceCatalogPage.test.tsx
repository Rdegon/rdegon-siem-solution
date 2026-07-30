import { screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { ResourceCatalogPage } from "../pages/ResourceCatalogPage";
import { renderWithShell } from "../../test/renderWithShell";

function jsonResponse(payload: unknown) {
  return new Response(JSON.stringify(payload), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}

describe("ResourceCatalogPage", () => {
  beforeEach(() => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input);
        if (url.includes("/api/integrations/kuma/status")) {
          return jsonResponse({
            configured: true,
            healthy: true,
            resource_count: 0,
            api_url: "https://kuma.example:7223",
            tenant_id: "tenant-1",
            issues: [],
          });
        }
        if (url.includes("/api/integrations/kuma/resources")) {
          return jsonResponse({ items: [], total: 0, page: 1 });
        }
        if (url.includes("/api/resources/catalog")) {
          const items = Array.from({ length: 105 }, (_, index) => ({
            id: `collector-${index + 1}`,
            name: `Collector ${index + 1}`,
            kind: "collector",
            description: "Production collector",
            status: "active",
            version: 1,
            tenant_id: "main",
            origin: "sentinel-runtime",
            read_only: true,
            config: {},
            bindings: {},
            activation: {},
          }));
          return jsonResponse({
            items,
            total: items.length,
            summary: { collector: items.length },
            issues: [],
          });
        }
        throw new Error(`Unhandled fetch: ${url}`);
      }),
    );
  });

  it("shows active runtime status and limits the first page to 100 resources", async () => {
    renderWithShell(<ResourceCatalogPage />);

    expect(await screen.findByText("Collector 1")).toBeInTheDocument();
    expect(screen.getByText("1–100 / 105")).toBeInTheDocument();
    expect(screen.queryByText("Collector 101")).not.toBeInTheDocument();
    expect(screen.getAllByLabelText("status active").length).toBeGreaterThan(0);
  });
});
