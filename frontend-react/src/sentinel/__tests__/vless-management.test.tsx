import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { api } from "../runtime/api";
import { VlessManagement } from "../vless-management";

describe("VLESS management", () => {
  beforeEach(() => {
    vi.spyOn(api, "authMe").mockResolvedValue({
      principal: {
        username: "admin",
        role: "admin",
        permissions: ["vpn:view", "vpn:manage", "vpn:profile:issue"],
        principal_type: "user",
        service_account_id: "",
        auth_mechanism: "oidc",
      },
    });
  });
  afterEach(() => vi.restoreAllMocks());

  it("renders only controller-observed inbounds and clients", async () => {
    vi.spyOn(api, "xuiManagementState").mockResolvedValue({
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
        clients: [{ client_ref: "client-opaque-1", email: "operator", enable: true }],
      }],
      clients: [{
        client_ref: "client-opaque-1",
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
    vi.spyOn(api, "xuiManagementState").mockResolvedValue({
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
    expect(screen.getByText("неизменяемый production baseline")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Удалить" })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Отключить" })).not.toBeInTheDocument();
  });

  it("updates a real profile without mutating its production inbound", async () => {
    vi.spyOn(api, "xuiManagementState").mockResolvedValue({
      configured: true,
      status: "active",
      capabilities: ["clients.update"],
      inbounds: [{
        id: 7, remark: "reality-main", enable: true, protocol: "vless", port: 443,
        protected: true, clients: [],
      }],
      clients: [{
        client_ref: "client-opaque-reference-1",
        email: "operator",
        enable: true,
        inbound_id: 7,
        inbound_remark: "reality-main",
        limitIp: 2,
        totalGB: 1024 ** 3,
      }],
    });
    const update = vi.spyOn(api, "updateXuiClient").mockResolvedValue({ success: true });
    render(<VlessManagement notify={vi.fn()} />);

    fireEvent.click(await screen.findByText("operator"));
    const dialog = screen.getByRole("dialog", { name: "operator" });
    fireEvent.change(within(dialog).getByLabelText("Имя / email"), { target: { value: "operator-2" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Сохранить" }));

    await waitFor(() => expect(update).toHaveBeenCalledWith(
      7,
      "client-opaque-reference-1",
      expect.objectContaining({ email: "operator-2", limit_ip: 2, total_gb: 1 }),
    ));
  });

  it("does not offer fake controls when the private controller is absent", async () => {
    vi.spyOn(api, "xuiManagementState").mockResolvedValue({
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

  it("uses the credential-free monitoring endpoint for non-managers", async () => {
    vi.mocked(api.authMe).mockResolvedValue({
      principal: {
        username: "viewer",
        role: "viewer",
        permissions: ["vpn:view"],
        principal_type: "user",
        service_account_id: "",
        auth_mechanism: "oidc",
      },
    });
    const monitoring = vi.spyOn(api, "xuiState").mockResolvedValue({
      configured: true,
      status: "active",
      capabilities: ["inbounds.read", "traffic.read", "online.read"],
      inbounds: [{
        id: 7,
        remark: "reality-main",
        enable: true,
        protocol: "vless",
        port: 443,
        protected: true,
        client_count: 3,
      }],
      clients: [],
      client_count: 3,
      online_count: 1,
    });
    const management = vi.spyOn(api, "xuiManagementState");

    render(<VlessManagement notify={vi.fn()} />);

    fireEvent.click(await screen.findByRole("button", { name: /Inbounds/ }));
    expect(await screen.findByText("reality-main")).toBeInTheDocument();
    expect(monitoring).toHaveBeenCalled();
    expect(management).not.toHaveBeenCalled();
    expect(screen.queryByRole("button", { name: "Профиль" })).not.toBeInTheDocument();
  });
});
