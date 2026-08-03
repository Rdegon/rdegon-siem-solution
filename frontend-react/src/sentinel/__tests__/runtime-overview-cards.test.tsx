import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { RuntimeOverviewCards } from "../record-details";

describe("RuntimeOverviewCards", () => {
  it("renders content-store health as structured fields instead of raw JSON", () => {
    const { container } = render(<RuntimeOverviewCards
      certification={{ healthy: true }}
      health={{
        platform: {
          clickhouse_ok: true,
          content_store_backend: "mongo",
          content_store_status: {
            backend: "mongo",
            requested_backend: "mongo",
            mongo_healthy: true,
            healthy: true,
            mongo_db: "siem_content",
            migration_status: "completed",
            collection_counts: { docs_pages: 124, dashboard_instances: 4 },
          },
        },
      }}
      ingest={{}}
    />);

    expect(screen.getByText("siem_content")).toBeInTheDocument();
    expect(screen.getByText("Migration")).toBeInTheDocument();
    expect(screen.getByText("Docs Pages")).toBeInTheDocument();
    expect(container.textContent).not.toContain("{\"backend\":\"mongo\"");
  });
});
