import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AccessUsersWorkspace } from "../access-users-workspace";
import { api } from "../runtime/api";


function mockKeycloak() {
  vi.spyOn(api, "authMe").mockResolvedValue({
    principal: {
      username: "admin",
      role: "admin",
      permissions: ["auth:view", "auth:write"],
      principal_type: "user",
      service_account_id: "",
      auth_mechanism: "oidc",
      break_glass: false,
    },
  });
  vi.spyOn(api, "keycloakStatus").mockResolvedValue({
    healthy: true,
    admin_ready: true,
    realm: "siem",
    base_url: "https://sso.example.test",
    inventory: { users: 1 },
  });
  vi.spyOn(api, "keycloakUsers").mockResolvedValue({
    items: [{
      id: "user-1",
      username: "alice",
      email: "alice@example.test",
      enabled: true,
      siem_role: "analyst",
      siem_access_enabled: true,
      management_backend: "keycloak",
    }],
  });
  vi.spyOn(api, "keycloakRoles").mockResolvedValue({
    items: [
      { id: "role-admin", name: "admin" },
      { id: "role-analyst", name: "analyst" },
      { id: "role-viewer", name: "viewer" },
    ],
  });
}


describe("Access users workspace", () => {
  afterEach(() => vi.restoreAllMocks());

  it("creates a real Keycloak user and a SIEM role assignment", async () => {
    mockKeycloak();
    const create = vi.spyOn(api, "createKeycloakUser").mockResolvedValue({
      id: "user-2", username: "bob", enabled: true, siem_role: "viewer",
    });
    const localCreate = vi.spyOn(api, "saveLocalUser");
    render(<AccessUsersWorkspace notify={vi.fn()} />);

    fireEvent.click(await screen.findByRole("button", { name: "Создать пользователя" }));
    const dialog = screen.getByRole("dialog", { name: "Новый пользователь Keycloak" });
    fireEvent.change(within(dialog).getByLabelText("Username"), { target: { value: "bob" } });
    fireEvent.change(within(dialog).getByLabelText("Email"), { target: { value: "bob@example.test" } });
    fireEvent.change(within(dialog).getByLabelText("Начальный пароль"), { target: { value: "StrongSecret!23" } });
    fireEvent.change(within(dialog).getByLabelText("Роль в Sentinel"), { target: { value: "viewer" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Создать" }));

    await waitFor(() => expect(create).toHaveBeenCalledTimes(1));
    expect(create.mock.calls[0][0]).toMatchObject({
      username: "bob",
      email: "bob@example.test",
      password: "StrongSecret!23",
      temporary_password: true,
      siem_role: "viewer",
    });
    expect(localCreate).not.toHaveBeenCalled();
  });

  it("edits status and role, resets a password, and deletes through Keycloak APIs", async () => {
    mockKeycloak();
    vi.spyOn(api, "keycloakUserDetail").mockResolvedValue({
      item: {
        id: "user-1", username: "alice", email: "alice@example.test", enabled: true,
        roles: [{ id: "role-analyst", name: "analyst" }], siem_role: "analyst", siem_access_enabled: true,
      },
    });
    const update = vi.spyOn(api, "updateKeycloakUser").mockResolvedValue({ id: "user-1", username: "alice", enabled: false });
    const reset = vi.spyOn(api, "setKeycloakUserPassword").mockResolvedValue({ id: "user-1", username: "alice", enabled: false });
    const remove = vi.spyOn(api, "deleteKeycloakUser").mockResolvedValue({ deleted: true });
    vi.spyOn(window, "confirm").mockReturnValue(true);
    render(<AccessUsersWorkspace notify={vi.fn()} />);

    fireEvent.click(await screen.findByText("alice"));
    const editor = await screen.findByRole("dialog", { name: "alice" });
    fireEvent.change(within(editor).getByLabelText("Роль в Sentinel"), { target: { value: "viewer" } });
    fireEvent.click(within(editor).getByLabelText("Учетная запись активна"));
    fireEvent.click(within(editor).getByRole("button", { name: "Сохранить" }));
    await waitFor(() => expect(update).toHaveBeenCalledWith("user-1", expect.objectContaining({ enabled: false, siem_role: "viewer" })));

    fireEvent.click(within(editor).getByRole("button", { name: "Сбросить пароль" }));
    const passwordDialog = await screen.findByRole("dialog", { name: "Сброс пароля" });
    fireEvent.change(within(passwordDialog).getByLabelText("Новый пароль"), { target: { value: "AnotherSecret!23" } });
    fireEvent.click(within(passwordDialog).getByRole("button", { name: "Применить" }));
    await waitFor(() => expect(reset).toHaveBeenCalledWith("user-1", { password: "AnotherSecret!23", temporary: true }));

    fireEvent.click(within(editor).getByRole("button", { name: "Удалить" }));
    await waitFor(() => expect(remove).toHaveBeenCalledWith("user-1"));
  });

  it("uses the established local store only during an authenticated break-glass fallback", async () => {
    vi.spyOn(api, "authMe").mockResolvedValue({ principal: { username: "admin", role: "admin", permissions: ["auth:write"], principal_type: "user", service_account_id: "", auth_mechanism: "break_glass", break_glass: true } });
    vi.spyOn(api, "keycloakStatus").mockResolvedValue({ healthy: false, admin_ready: false, issues: ["connection refused"] });
    vi.spyOn(api, "authUsers").mockResolvedValue({ items: [], available_permissions: [], available_roles: ["admin"], permission_bundles: [], permission_categories: [] });
    const keycloakUsers = vi.spyOn(api, "keycloakUsers");
    render(<AccessUsersWorkspace notify={vi.fn()} />);

    expect(await screen.findByText("Break-glass fallback")).toBeInTheDocument();
    expect(api.authUsers).toHaveBeenCalledWith({ include_disabled: true });
    expect(keycloakUsers).not.toHaveBeenCalled();
  });
});
