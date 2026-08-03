import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { DiscoveryWorkspace } from "../discovery-workspace";
import { api } from "../runtime/api";

describe("source discovery workspace", () => {
  afterEach(() => vi.restoreAllMocks());

  it("separates lifecycle states and renders real source processing telemetry", async () => {
    vi.spyOn(api, "sourceDiscovery").mockResolvedValue({
      jobs: [],
      items: [
        {
          id: "connected-1",
          ip: "10.20.30.123",
          hostname: "pilot-web-01",
          lifecycle_state: "connected",
          monitoring_status: "verified",
          log_capable: true,
          relevance_score: 100,
          asset_id: "asset-pilot-web",
          segment_label: "LAB",
          source_telemetry: {
            last_event_ts: "2026-08-03T10:00:00Z",
            eps: 12.5,
            event_lag_seconds: 4,
            ingest_health: "healthy",
            parsing_health: "healthy",
            normalization_health: "healthy",
            accepted_total: 100,
            rejected_total: 0,
            collector: "syslog-tcp",
            collector_profile: "linux-syslog-audit",
          },
        },
        {
          id: "web-only",
          ip: "192.0.2.80",
          hostname: "web-only",
          lifecycle_state: "low_priority",
          monitoring_status: "candidate",
          log_capable: false,
          relevance_score: 20,
        },
      ],
    });

    render(<DiscoveryWorkspace notify={vi.fn()} />);

    await screen.findByText("Обнаружение и мониторинг источников");
    fireEvent.click(screen.getByRole("button", { name: /Подключенные/ }));

    expect(await screen.findByText("pilot-web-01")).toBeInTheDocument();
    expect(screen.getByText("asset-pilot-web")).toBeInTheDocument();
    expect(screen.getByText("syslog-tcp")).toBeInTheDocument();
    expect(screen.getByText(/12\.500 EPS/)).toBeInTheDocument();
    expect(screen.getByText(/Парсинг: Норма · нормализация: Норма/)).toBeInTheDocument();
    expect(screen.queryByText("web-only")).not.toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: /Низкий приоритет/ }));
    expect(await screen.findByText("web-only")).toBeInTheDocument();
  });

  it("uses the real source-policy API for threshold controls", async () => {
    vi.spyOn(api, "sourceDiscovery").mockResolvedValue({ items: [], jobs: [] });
    vi.spyOn(api, "sourcePolicies").mockResolvedValue({ items: [] });
    const save = vi.spyOn(api, "saveSourcePolicy").mockResolvedValue({
      id: "linux-policy",
      type: "source_monitoring_policy",
      name: "Linux sources",
      description: "",
      enabled: true,
      source_pattern: "linux",
      window_hours: 24,
      min_events: 1,
      max_events: 0,
      stale_after_minutes: 30,
      severity: "high",
      notifications: [],
      owner: "SOC",
    });

    render(<DiscoveryWorkspace notify={vi.fn()} />);
    fireEvent.click(await screen.findByRole("button", { name: "Политики мониторинга" }));
    fireEvent.click(await screen.findByRole("button", { name: "Добавить" }));
    fireEvent.change(screen.getByLabelText("Название"), { target: { value: "Linux sources" } });
    fireEvent.change(screen.getByLabelText("Шаблон источника"), { target: { value: "linux" } });
    fireEvent.click(screen.getByRole("button", { name: "Сохранить" }));

    await waitFor(() => expect(save).toHaveBeenCalledTimes(1));
    expect(save.mock.calls[0][0]).toMatchObject({ source_pattern: "linux", min_events: 1, stale_after_minutes: 30 });
  });
});
