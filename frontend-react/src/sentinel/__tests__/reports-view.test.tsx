import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ReportsView } from "../Views";
import { api } from "../runtime/api";
import type { ReportTemplateRecord } from "../runtime/types";


const template: ReportTemplateRecord = {
  id: "soc-daily",
  type: "report_template",
  name: "SOC daily",
  description: "Operational report",
  owner: "soc-ops",
  tenant_scope: ["main"],
  period: "24h",
  retention_days: 90,
  sections: ["executive_summary", "incidents"],
  formats: ["json", "csv", "pdf"],
  schedule: {
    enabled: true,
    frequency: "daily",
    time: "08:00",
    timezone: "Europe/Moscow",
    recipients: [],
    next_run_ts: "2026-08-04T05:00:00Z",
    last_run_ts: "2026-08-03T05:00:00Z",
    last_run_status: "completed",
  },
};


function mockReporting() {
  vi.spyOn(api, "reportTemplates").mockResolvedValue({ items: [template] });
  vi.spyOn(api, "generatedReports").mockResolvedValue({ items: [] });
  vi.spyOn(api, "reportingCapabilities").mockResolvedValue({
    formats: ["json", "csv", "pdf"],
    pdf_available: true,
    pdf_unavailable_reason: "",
    periods: ["12h", "24h", "7d", "30d"],
    max_range_hours: 720,
    tenants: ["main"],
    frequencies: ["shift", "daily", "weekly", "monthly"],
  });
}


describe("reports production workspace", () => {
  afterEach(() => vi.restoreAllMocks());

  it("creates a structured template without a raw JSON editor", async () => {
    mockReporting();
    const save = vi.spyOn(api, "saveReportTemplate").mockResolvedValue(template);
    render(<ReportsView notify={vi.fn()} />);

    fireEvent.click(await screen.findByRole("button", { name: "Создать шаблон" }));
    fireEvent.change(screen.getByLabelText("Название"), { target: { value: "Weekly operations" } });
    fireEvent.click(screen.getByRole("button", { name: "Сохранить" }));

    await waitFor(() => expect(save).toHaveBeenCalledTimes(1));
    expect(save.mock.calls[0][0]).toMatchObject({
      name: "Weekly operations",
      tenant_scope: ["main"],
      period: "24h",
    });
    expect(screen.queryByText(/raw json/i)).not.toBeInTheDocument();
    expect(document.querySelector("pre")).toBeNull();
  });

  it("runs templates as tracked jobs and exposes real schedule controls", async () => {
    mockReporting();
    const run = vi.spyOn(api, "runReportTemplate").mockResolvedValue({
      item: {
        id: "report-run-1", type: "report_run", template_id: template.id, name: template.name,
        status: "queued", owner: "admin", tenant_scope: ["main"], period: { window: "24h", from_ts: "", to_ts: "" },
        formats: ["json", "csv", "pdf"], sections: template.sections, section_count: 0, record_count: 0, errors: [],
        progress: { phase: "queued", percent: 0, sections_total: 2, sections_completed: 0, current_section: "" },
        created_ts: "2026-08-03T00:00:00Z", completed_ts: "", duration_ms: 0,
      },
      created: true,
      idempotent_replay: false,
    });
    render(<ReportsView notify={vi.fn()} />);

    fireEvent.click(await screen.findByRole("button", { name: /Шаблоны/ }));
    fireEvent.click(await screen.findByText("SOC daily"));
    expect(screen.getByRole("button", { name: "Выключить расписание" })).toBeInTheDocument();
    fireEvent.click(screen.getByRole("button", { name: "Сформировать" }));

    await waitFor(() => expect(run).toHaveBeenCalledTimes(1));
    expect(run.mock.calls[0][0]).toBe("soc-daily");
    expect(run.mock.calls[0][1]).toMatchObject({ tenant_scope: ["main"] });
  });
});
