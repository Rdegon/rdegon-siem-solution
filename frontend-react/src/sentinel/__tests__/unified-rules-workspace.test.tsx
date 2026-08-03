import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { RulesWorkspace } from "../kuma-workspaces";
import { api } from "../runtime/api";
import type { UnifiedRuleRecord } from "../runtime/types";

function rule(overrides: Partial<UnifiedRuleRecord> = {}): UnifiedRuleRecord {
  return {
    identity: "rule:1002",
    rule_id: 1002,
    title: "Linux SSH brute force",
    description: "Repeated failed SSH authentication",
    enabled: true,
    status: "active",
    severity: "high",
    kind: "stream",
    engines: ["stream"],
    version: "2.1.0",
    source: "runtime",
    pack: { id: "linux-security", title: "Linux security", owner: "soc-content" },
    noise: {
      window_days: 30,
      alert_count: 80,
      false_positive_count: 4,
      false_positive_ratio: 0.05,
      suppressed_count: 12,
      suppressed_ratio: 0.15,
    },
    issues: [],
    capabilities: { publish: true, enable: true, disable: true },
    updated_ts: "2026-08-03T10:00:00Z",
    ...overrides,
  };
}

function mockCatalog(items: UnifiedRuleRecord[]) {
  vi.spyOn(api, "builderDrafts").mockResolvedValue({ items: [] });
  vi.spyOn(api, "correlationPacks").mockResolvedValue({ items: [] });
  vi.spyOn(api, "unifiedRules").mockResolvedValue({
    items,
    total: items.length,
    limit: 5_000,
    offset: 0,
    summary: { enabled_rule_count: items.filter((item) => item.enabled).length },
  });
}

describe("unified rules runtime workspace", () => {
  afterEach(() => vi.restoreAllMocks());

  it("renders real runtime state, noise metrics, issues and pack ownership", async () => {
    mockCatalog([rule({ status: "drift", issues: ["catalog_runtime_enabled_drift"] })]);
    render(<RulesWorkspace notify={vi.fn()} />);

    fireEvent.click(await screen.findByRole("button", { name: /Runtime/ }));
    expect(await screen.findByText("Linux SSH brute force")).toBeInTheDocument();
    expect(screen.getByText("Расхождение")).toBeInTheDocument();
    expect(screen.getByText("4 · 5.0%")).toBeInTheDocument();
    expect(screen.getByText("linux-security")).toBeInTheDocument();
    expect(screen.getByText("soc-content")).toBeInTheDocument();

    fireEvent.click(screen.getByText("Linux SSH brute force"));
    expect(await screen.findByText("Статус каталога расходится с runtime")).toBeInTheDocument();
    expect(document.querySelector("pre")).toBeNull();
  });

  it("publishes and enables only when runtime capabilities allow it", async () => {
    const disabled = rule({
      identity: "rule:2701",
      rule_id: 2701,
      title: "SSH password spray",
      enabled: false,
      status: "disabled",
      capabilities: { publish: true, enable: true, disable: true },
    });
    mockCatalog([disabled]);
    const publish = vi.spyOn(api, "publishUnifiedRule").mockResolvedValue({ status: "published" });
    const enable = vi.spyOn(api, "setUnifiedRuleEnabled").mockResolvedValue({ status: "enabled", enabled: true });
    render(<RulesWorkspace notify={vi.fn()} />);

    fireEvent.click(await screen.findByRole("button", { name: /Runtime/ }));
    fireEvent.click(await screen.findByText("SSH password spray"));
    fireEvent.click(screen.getByRole("button", { name: "Опубликовать" }));
    await waitFor(() => expect(publish).toHaveBeenCalledWith("rule:2701"));

    fireEvent.click(await screen.findByText("SSH password spray"));
    fireEvent.click(screen.getByRole("button", { name: "Включить" }));
    await waitFor(() => expect(enable).toHaveBeenCalledWith("rule:2701", { enabled: true }));
  });

  it("requires a meaningful reason and a different active replacement before retirement", async () => {
    mockCatalog([
      rule(),
      rule({ identity: "rule:4002", rule_id: 4002, title: "Multi-host SSH", enabled: true }),
    ]);
    const mutate = vi.spyOn(api, "setUnifiedRuleEnabled").mockResolvedValue({
      status: "retired_with_replacement",
      enabled: false,
      replacement_identity: "rule:4002",
    });
    render(<RulesWorkspace notify={vi.fn()} />);

    fireEvent.click(await screen.findByRole("button", { name: /Runtime/ }));
    fireEvent.click(await screen.findByText("Linux SSH brute force"));
    fireEvent.click(screen.getByRole("button", { name: "Вывести правило" }));

    const confirm = screen.getByRole("button", { name: "Подтвердить отключение" });
    expect(confirm).toBeDisabled();
    fireEvent.change(screen.getByLabelText("Причина"), { target: { value: "Заменено более точным правилом" } });
    expect(confirm).toBeDisabled();
    fireEvent.change(screen.getByLabelText("Активное правило-замена"), { target: { value: "rule:4002" } });
    expect(confirm).toBeEnabled();
    fireEvent.click(confirm);

    await waitFor(() => expect(mutate).toHaveBeenCalledWith("rule:1002", {
      enabled: false,
      reason: "Заменено более точным правилом",
      replacement_identity: "rule:4002",
    }));
  });
});
