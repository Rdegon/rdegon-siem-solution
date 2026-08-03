import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { Sidebar } from "../App";
import type { BootstrapResponse, TenantScopeResponse } from "../runtime/api";

const bootstrap: BootstrapResponse = {
  user: {
    username: "soc-admin",
    role: "admin",
    permissions: [],
    principal_type: "user",
    service_account_id: "",
    auth_mechanism: "test",
  },
  ui_lang: "ru",
  theme: "system",
  labels: {},
};

const tenants: TenantScopeResponse = {
  available: [{ id: "default", name: "SOC", source_count: 12, incident_count: 3 }],
  default: ["default"],
  generated_ts: "2026-08-03T00:00:00Z",
};

function renderSidebar(collapsed = false) {
  const setCollapsed = vi.fn();
  render(<Sidebar
    bootstrap={bootstrap}
    collapsed={collapsed}
    current="overview"
    darkTheme={false}
    mobileOpen={false}
    navigate={vi.fn()}
    onTenantChange={vi.fn()}
    selectedTenants={["default"]}
    setCollapsed={setCollapsed}
    setMobileOpen={vi.fn()}
    tenants={tenants}
    toggleTheme={vi.fn()}
  />);
  return { setCollapsed };
}

afterEach(() => vi.restoreAllMocks());

describe("security navigation scroll ownership", () => {
  it("opens the security menu at the first item and restores focus without page scrolling", async () => {
    renderSidebar();
    const mainScroll = document.querySelector<HTMLElement>(".app-navigation-scroll");
    expect(mainScroll).not.toBeNull();
    mainScroll!.scrollTop = 420;

    fireEvent.click(screen.getByTitle("Средства защиты"));

    const securityScroll = document.querySelector<HTMLElement>(".security-nav-subsection");
    const back = screen.getByRole("button", { name: "Вернуться в основную навигацию" });
    expect(securityScroll).not.toBeNull();
    expect(securityScroll!.scrollTop).toBe(0);
    expect(back).toHaveFocus();
    expect(document.documentElement.scrollTop).toBe(0);

    securityScroll!.scrollTop = 360;
    fireEvent.click(back);

    await waitFor(() => expect(screen.getByTitle("Средства защиты")).toHaveFocus());
    expect(document.querySelector<HTMLElement>(".app-navigation-scroll")?.scrollTop).toBe(0);

    fireEvent.click(screen.getByTitle("Средства защиты"));
    fireEvent.keyDown(window, { key: "Escape" });
    await waitFor(() => expect(screen.getByTitle("Средства защиты")).toHaveFocus());
    expect(document.querySelector(".security-nav-subsection")).not.toBeInTheDocument();
  });

  it("expands a collapsed sidebar before presenting the independently scrollable submenu", () => {
    const { setCollapsed } = renderSidebar(true);

    fireEvent.click(screen.getByTitle("Средства защиты"));

    expect(setCollapsed).toHaveBeenCalledWith(false);
    expect(document.querySelector(".security-nav-subsection")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Вернуться в основную навигацию" })).toHaveFocus();
  });
});
