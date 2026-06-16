import { screen, waitFor } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { AccessWorkspace } from "../pages/access/AccessWorkspace";
import { renderWithShell } from "../../test/renderWithShell";

function jsonResponse(payload: unknown) {
  return new Response(JSON.stringify(payload), {
    status: 200,
    headers: { "Content-Type": "application/json" },
  });
}

function installFetchMock() {
  const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
    const url = String(input);
    if (url.includes("/api/ui/bootstrap")) {
      return jsonResponse({
        user: {
          username: "alice.admin",
          role: "admin",
          permissions: ["auth:view", "auth:write"],
          principal_type: "user",
          service_account_id: "",
          auth_mechanism: "oidc",
          issuer: "http://sso.example.test/realms/siem",
          groups: ["siem-admins"],
          break_glass: false,
          session_expires_ts: "2026-03-27T12:00:00Z",
        },
        ui_lang: "en",
        theme: "dark",
        labels: {},
      });
    }
    if (url.includes("/api/auth/users")) {
      return jsonResponse({
        items: [{ username: "recovery-admin", role: "admin", enabled: true, permission_bundles: ["admin"] }],
        permission_bundles: [{ id: "admin", title: "Admin", permissions: ["auth:view"] }],
        permission_categories: [{ id: "core", title: "Core" }],
      });
    }
    if (url.includes("/api/auth/service-accounts/svc-greenbone")) {
      return jsonResponse({
        item: { id: "svc-greenbone", name: "Greenbone bridge", description: "Structured sync", enabled: true, permission_bundles: ["admin"] },
        tokens: [{ id: "tok-1", title: "current", active: true }],
      });
    }
    if (url.includes("/api/auth/service-accounts")) {
      return jsonResponse({
        items: [{ id: "svc-greenbone", name: "Greenbone bridge", description: "Structured sync", enabled: true, permission_bundles: ["admin"] }],
        permission_bundles: [{ id: "admin", title: "Admin", permissions: ["auth:view"] }],
        permission_categories: [{ id: "core", title: "Core" }],
        metrics: { active_tokens: 1, tokens_expiring_14d: 0 },
      });
    }
    if (url.includes("/api/auth/governance")) {
      return jsonResponse({
        vault: { healthy: true, ready: true },
        break_glass: { metrics: { active: 0 }, items: [] },
        secrets: { summary: { vault_backed: 12, required_missing: 0 }, items: [] },
      });
    }
    if (url.includes("/api/auth/providers")) {
      return jsonResponse({
        items: [{ id: "oidc-enterprise", title: "Enterprise SSO", kind: "oidc", enabled: true, healthy: true, issues: [] }],
      });
    }
    if (url.includes("/api/auth/access-systems")) {
      return jsonResponse({
        items: [
          {
            id: "siem",
            title: "SIEM",
            grantable: true,
            roles: [{ id: "viewer", title: "Viewer" }, { id: "analyst", title: "Analyst" }, { id: "admin", title: "Admin" }],
            sections: [{ id: "overview", title: "Overview" }, { id: "events", title: "Events" }, { id: "access", title: "Access" }],
          },
          {
            id: "nextcloud",
            title: "Nextcloud",
            grantable: true,
            enforcement_mode: "native_oidc",
            client_id: "nextcloud",
            internal_url: "https://nextcloud-siem.lab.home.arpa",
            roles: [{ id: "user", title: "User" }, { id: "admin", title: "Admin" }],
            sections: [{ id: "files", title: "Files" }, { id: "admin", title: "Admin" }],
          },
          {
            id: "gitea",
            title: "Gitea",
            grantable: true,
            enforcement_mode: "native_oidc",
            client_id: "pilot-gitea",
            internal_url: "http://pilot-web-01.lab.home.arpa:3000",
            roles: [{ id: "user", title: "User" }, { id: "admin", title: "Admin" }],
            sections: [{ id: "repos", title: "Repositories" }, { id: "admin", title: "Admin" }],
          },
          {
            id: "navidrome",
            title: "Navidrome",
            grantable: true,
            enforcement_mode: "proxy_extauth",
            client_id: "navidrome-proxy",
            internal_url: "http://navidrome-01.lab.home.arpa",
            roles: [{ id: "user", title: "User" }, { id: "admin", title: "Admin" }],
            sections: [{ id: "library", title: "Library" }, { id: "admin", title: "Admin" }],
          },
        ],
      });
    }
    if (url.includes("/api/auth/access-grants")) {
      return jsonResponse({
        items: [
          {
            id: "grant-1",
            principal_kind: "keycloak_user",
            principal_id: "alice",
            system_id: "siem",
            system_title: "SIEM",
            role: "admin",
            sections: ["overview", "events", "access"],
            enabled: true,
            sync_status: "mirrored",
          },
        ],
      });
    }
    if (url.includes("/api/health/certification")) {
      return jsonResponse({ healthy: true, latest_certified_ceiling_eps: 79 });
    }
    if (url.includes("/api/auth/keycloak/status")) {
      return jsonResponse({ healthy: true, admin_ready: true, realm: "siem", inventory: { users: 12, groups: 2, clients: 3 } });
    }
    if (url.includes("/api/auth/keycloak/users/u-1")) {
      return jsonResponse({
        item: {
          id: "u-1",
          username: "alice",
          email: "alice@example.test",
          first_name: "Alice",
          last_name: "Warden",
          enabled: true,
          email_verified: true,
          groups: [{ id: "g-1", name: "siem-admins" }],
          roles: [{ name: "siem-admin" }],
        },
      });
    }
    if (url.includes("/api/auth/keycloak/users")) {
      return jsonResponse({
        items: [
          { id: "u-1", username: "alice", email: "alice@example.test", first_name: "Alice", last_name: "Warden", enabled: true, email_verified: true, created_ts: "2026-03-01T00:00:00Z" },
        ],
      });
    }
    if (url.includes("/api/auth/keycloak/groups")) {
      return jsonResponse({ items: [{ id: "g-1", name: "siem-admins", path: "/siem-admins", sub_group_count: 0 }] });
    }
    if (url.includes("/api/auth/keycloak/roles")) {
      return jsonResponse({ items: [{ name: "siem-admin", description: "Full admin" }] });
    }
    if (url.includes("/api/auth/keycloak/clients/siem-web")) {
      return jsonResponse({
        item: {
          id: "c-1",
          client_id: "siem-web",
          name: "SIEM Web",
          description: "Primary shell client",
          enabled: true,
          public_client: false,
          service_accounts_enabled: false,
          redirect_uris: ["http://localhost/app/*"],
          web_origins: ["http://localhost"],
          root_url: "http://localhost/app",
          base_url: "/app",
        },
      });
    }
    if (url.includes("/api/auth/keycloak/clients")) {
      return jsonResponse({
        items: [{ id: "c-1", client_id: "siem-web", name: "SIEM Web", enabled: true, service_accounts_enabled: false, public_client: false }],
      });
    }
    throw new Error(`Unhandled fetch: ${url}`);
  });
  vi.stubGlobal("fetch", fetchMock);
}

describe("AccessWorkspace", () => {
  beforeEach(() => {
    installFetchMock();
  });

  it("renders keycloak admin tabs and the user editor on /app/access", async () => {
    renderWithShell(
      <MemoryRouter initialEntries={["/access?tab=keycloak-users"]}>
        <Routes>
          <Route path="/access" element={<AccessWorkspace />} />
        </Routes>
      </MemoryRouter>,
    );

    expect(await screen.findByText("Identity control center")).toBeInTheDocument();
    expect(await screen.findByRole("button", { name: "Keycloak users" })).toBeInTheDocument();
    await waitFor(() => expect(screen.getByText("Realm users")).toBeInTheDocument());
    expect(screen.getByText("User editor")).toBeInTheDocument();
    expect(screen.getAllByText("Alice Warden").length).toBeGreaterThan(0);
    expect(screen.getByText("System access")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Add access" })).toBeInTheDocument();
    screen.getByRole("button", { name: "Add access" }).click();
    expect(await screen.findByText("System access grant")).toBeInTheDocument();
    expect(screen.getByRole("option", { name: "Gitea" })).toBeInTheDocument();
    expect(screen.getByRole("option", { name: "Navidrome" })).toBeInTheDocument();
    expect(screen.getByText("Mode")).toBeInTheDocument();
    expect(screen.getByText("Client")).toBeInTheDocument();
    expect(screen.getByText("Internal URL")).toBeInTheDocument();
  });
});
