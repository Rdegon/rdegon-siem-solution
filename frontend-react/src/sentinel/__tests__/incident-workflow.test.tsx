import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { IncidentDetailContent } from "../incident-details";
import { IncidentQueueWorkspace } from "../kuma-workspaces";
import { api } from "../runtime/api";
import type { IncidentDetailResponse } from "../runtime/types";


const detail: IncidentDetailResponse = {
  view: "agg",
  item: {
    agg_id: "agg:incident-1",
    rule_name: "Suspicious process chain",
    severity_agg: "high",
    status: "open",
    workflow: { revision: "rev-1", alert_ids: ["raw-1"] },
  },
  summary: {},
  risk: {},
  entities: {},
  rules: [],
  timeline: [],
  raw_alerts: { items: [{ alert_id: "raw-1", rule_name: "Suspicious process chain", severity: "high" }], total: 1 },
  related_events: { items: [], total: 0 },
  workflow: { revision: "rev-1", alert_ids: ["raw-1"], manual: false },
  permissions: { required_write_permission: "response:run" },
};


describe("incident workflow forms", () => {
  afterEach(() => vi.restoreAllMocks());

  it("updates severity with revision and idempotency checks", async () => {
    const severity = vi.spyOn(api, "changeIncidentSeverity").mockResolvedValue({ status: "ok", revision: "rev-2" });
    vi.spyOn(api, "incidentDetail").mockResolvedValue({
      ...detail,
      item: { ...detail.item, severity_agg: "critical", workflow: { revision: "rev-2", alert_ids: ["raw-1"] } },
      workflow: { revision: "rev-2", alert_ids: ["raw-1"] },
    });

    render(<IncidentDetailContent detail={detail} />);
    fireEvent.click(screen.getByRole("button", { name: /Управление/ }));
    fireEvent.change(screen.getAllByRole("combobox")[0], { target: { value: "critical" } });
    fireEvent.click(screen.getByRole("button", { name: "Сохранить severity" }));

    await waitFor(() => expect(severity).toHaveBeenCalledTimes(1));
    expect(severity.mock.calls[0][0]).toBe("agg:incident-1");
    expect(severity.mock.calls[0][1]).toMatchObject({ severity: "critical", expected_revision: "rev-1" });
    expect(String(severity.mock.calls[0][1].idempotency_key)).toContain("sentinel-ui:severity:");
    expect(await screen.findByText("Важность обновлена")).toBeInTheDocument();
  });

  it("renders link, unlink, merge and manual creation as real controls", async () => {
    const create = vi.spyOn(api, "createManualIncident").mockResolvedValue({ status: "ok", incident_id: "manual:new" });

    render(<IncidentDetailContent detail={detail} />);
    fireEvent.click(screen.getByRole("button", { name: /Управление/ }));

    expect(screen.getByLabelText("Raw alert ID")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Отвязать" })).toBeInTheDocument();
    expect(screen.getByLabelText("Целевой incident ID")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Объединить с сохранением истории" })).toBeInTheDocument();

    fireEvent.change(screen.getByLabelText("Название ручного инцидента"), { target: { value: "Confirmed chain" } });
    fireEvent.change(screen.getByLabelText("Alert IDs ручного инцидента"), { target: { value: "raw-1\nraw-2" } });
    fireEvent.click(screen.getByRole("button", { name: "Создать из существующих алертов" }));

    await waitFor(() => expect(create).toHaveBeenCalledTimes(1));
    expect(create.mock.calls[0][0]).toMatchObject({
      alert_ids: ["raw-1", "raw-2"],
      title: "Confirmed chain",
    });
    expect(await screen.findByText("Создан инцидент manual:new")).toBeInTheDocument();
  });

  it("loads the active incident queue with the Telegram-aligned 24 hour window", async () => {
    const incidents = vi.spyOn(api, "incidents").mockResolvedValue({
      view: "agg",
      items: [],
      available_count: 0,
      metrics: {},
      scope: "main",
      notification_delivery: {},
    });

    render(<IncidentQueueWorkspace mode="agg" notify={vi.fn()} />);

    await waitFor(() => expect(incidents).toHaveBeenCalledWith(expect.objectContaining({
      view: "agg",
      window: "24h",
      include_terminal: false,
    })));
  });
});
