import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen } from "@testing-library/react";
import { api } from "../runtime/api";
import { VlessManagement } from "../vless-management";

describe("VLESS management", () => {
  afterEach(() => vi.restoreAllMocks());

  it("renders only controller-observed inbounds and clients", async () => {
    vi.spyOn(api, "xuiState").mockResolvedValue({
      configured: true,
      status: "active",
      capabilities: ["clients.create", "clients.profile"],
      issue: "",
      traffic: { up: 1024, down: 2048 },
      online: ["operator"],
      inbounds: [{
        id: 7,
        remark: "reality-main",
        enable: true,
        protocol: "vless",
        port: 443,
        protected: true,
        up: 1024,
        down: 2048,
        clients: [{ id: "client-1", email: "operator", enable: true }],
      }],
      clients: [{
        id: "client-1",
        email: "operator",
        enable: true,
        inbound_id: 7,
        inbound_remark: "reality-main",
      }],
    });

    render(<VlessManagement notify={vi.fn()} />);

    expect(await screen.findByRole("region", { name: "Управление 3x-ui" })).toBeInTheDocument();
    expect(screen.getByText("operator")).toBeInTheDocument();
    expect(screen.getByText("reality-main")).toBeInTheDocument();
    expect(screen.queryByText(/demo/i)).not.toBeInTheDocument();
  });

  it("never offers deletion for a protected production inbound", async () => {
    vi.spyOn(api, "xuiState").mockResolvedValue({
      configured: true,
      status: "active",
      capabilities: ["inbounds.update"],
      inbounds: [{
        id: 7, remark: "reality-main", enable: true, protocol: "vless", port: 443,
        protected: true, clients: [],
      }],
      clients: [],
    });
    render(<VlessManagement notify={vi.fn()} />);

    fireEvent.click(await screen.findByRole("button", { name: /Inbounds/ }));
    expect(await screen.findByText("защищенный production inbound")).toBeInTheDocument();
    fireEvent.click(screen.getByText("reality-main"));
    expect(screen.getAllByText("защищенный production inbound").length).toBeGreaterThan(0);
    expect(screen.queryByRole("button", { name: "Удалить" })).not.toBeInTheDocument();
  });

  it("does not offer fake controls when the private controller is absent", async () => {
    vi.spyOn(api, "xuiState").mockResolvedValue({
      configured: false,
      status: "unavailable",
      capabilities: [],
      issue: "private controller unavailable",
      inbounds: [],
      clients: [],
    });

    render(<VlessManagement notify={vi.fn()} />);

    expect(await screen.findByText("Контроллер 3x-ui не подключен")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Профиль" })).not.toBeInTheDocument();
  });
});
