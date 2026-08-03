import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ResourcesWorkspace } from "../kuma-workspaces";
import { api } from "../runtime/api";
import type { ResourceCatalogRecord } from "../runtime/types";

function resource(overrides: Partial<ResourceCatalogRecord> = {}): ResourceCatalogRecord {
  return {
    id: "collector-main",
    name: "Managed collector",
    kind: "collector",
    status: "draft",
    version: 3,
    revision: 7,
    origin: "sentinel-managed",
    tenant_id: "main",
    updated_ts: "2026-08-03T10:00:00Z",
    description: "Production collector",
    config: { threshold: 10 },
    bindings: {},
    read_only: false,
    ...overrides,
  };
}

function mockCatalog(items: ResourceCatalogRecord[]) {
  vi.spyOn(api, "resourceCatalog").mockResolvedValue({
    items,
    total: items.length,
    summary: {},
    issues: [],
    generated_ts: "2026-08-03T10:00:00Z",
  });
}

async function openList() {
  fireEvent.click(await screen.findByRole("button", { name: "Список" }));
}

describe("managed resource lifecycle workspace", () => {
  afterEach(() => vi.restoreAllMocks());

  it("duplicates a runtime/read-only resource into a managed draft", async () => {
    const runtime = resource({
      id: "runtime-collector-1",
      name: "Runtime collector",
      origin: "runtime",
      read_only: true,
      status: "active",
    });
    mockCatalog([runtime]);
    const versions = vi.spyOn(api, "resourceVersions").mockRejectedValue(new Error("must not load"));
    const duplicate = vi.spyOn(api, "duplicateResource").mockResolvedValue({
      status: "created",
      source_id: runtime.id,
      resource: resource({ id: "collector-runtime-managed", name: "Runtime collector managed", version: 1, revision: 1 }),
    });
    render(<ResourcesWorkspace notify={vi.fn()} />);
    await openList();
    fireEvent.click(await screen.findByText("Runtime collector"));
    fireEvent.click(await screen.findByRole("button", { name: "Создать managed draft" }));

    await waitFor(() => expect(duplicate).toHaveBeenCalledWith("runtime-collector-1", {
      name: "Runtime collector managed",
    }));
    expect(versions).not.toHaveBeenCalled();
  });

  it("compares JSON Pointer changes and rolls back with the current revision", async () => {
    mockCatalog([resource()]);
    vi.spyOn(api, "resourceVersions").mockResolvedValue({
      resource_id: "collector-main",
      tenant_id: "main",
      current_version: 3,
      current_revision: 7,
      deleted: false,
      total: 2,
      items: [
        { id: "main:collector-main:3", resource_id: "collector-main", tenant_id: "main", version: 3, definition_hash: "hash3", created_ts: "2026-08-03T10:00:00Z", created_by: "admin", action: "save", immutable: true },
        { id: "main:collector-main:1", resource_id: "collector-main", tenant_id: "main", version: 1, definition_hash: "hash1", created_ts: "2026-08-01T10:00:00Z", created_by: "admin", action: "create", immutable: true },
      ],
    });
    vi.spyOn(api, "compareResourceVersions").mockResolvedValue({
      resource_id: "collector-main",
      tenant_id: "main",
      from_version: 1,
      to_version: 3,
      identical: false,
      truncated: false,
      changes: [{ op: "replace", path: "/config/threshold", before: 5, after: 10 }],
    });
    const rollback = vi.spyOn(api, "rollbackResource").mockResolvedValue({ status: "created" });
    vi.spyOn(window, "confirm").mockReturnValue(true);

    render(<ResourcesWorkspace notify={vi.fn()} />);
    await openList();
    fireEvent.click(await screen.findByText("Managed collector"));
    const compare = await screen.findByRole("button", { name: "Сравнить версии" });
    await waitFor(() => expect(compare).toBeEnabled());
    fireEvent.click(compare);

    expect(await screen.findByText("/config/threshold")).toBeInTheDocument();
    expect(screen.getByText("5")).toBeInTheDocument();
    expect(screen.getAllByText("10").length).toBeGreaterThan(0);
    expect(document.querySelector("pre")).toBeNull();

    fireEvent.click(screen.getByRole("button", { name: "Откатить к v1" }));
    await waitFor(() => expect(rollback).toHaveBeenCalledWith("collector-main", {
      target_version: 1,
      expected_revision: 7,
    }));
  });

  it("deletes only unpublished drafts and imports/exports selected packages", async () => {
    mockCatalog([resource()]);
    vi.spyOn(api, "resourceVersions").mockResolvedValue({
      resource_id: "collector-main", tenant_id: "main", current_version: 3, current_revision: 7,
      deleted: false, total: 1,
      items: [{ id: "main:collector-main:3", resource_id: "collector-main", tenant_id: "main", version: 3, definition_hash: "hash3", created_ts: "2026-08-03T10:00:00Z", created_by: "admin", action: "save", immutable: true }],
    });
    const remove = vi.spyOn(api, "deleteResourceDraft").mockResolvedValue({ status: "deleted" });
    const exportPackage = vi.spyOn(api, "exportResourcePackage").mockResolvedValue({ filename: "sentinel-resources.json" });
    const importPackage = vi.spyOn(api, "importResourcePackage").mockResolvedValue({
      status: "imported",
      package_id: "package-sha256",
      tenant_id: "main",
      total: 1,
      items: [{ source_id: "collector-source", resource_id: "collector-imported", version: 1, revision: 1, status: "draft" }],
    });
    vi.spyOn(window, "confirm").mockReturnValue(true);
    render(<ResourcesWorkspace notify={vi.fn()} />);
    await openList();

    fireEvent.click(screen.getByRole("checkbox", { name: "Выбрать Managed collector для пакета" }));
    fireEvent.click(screen.getByRole("button", { name: "Выгрузить выбранные (1)" }));
    await waitFor(() => expect(exportPackage).toHaveBeenCalledWith(["collector-main"]));

    const file = new File(["{}"], "resources.json", { type: "application/json" });
    fireEvent.change(screen.getByLabelText("Файл пакета ресурсов"), { target: { files: [file] } });
    await waitFor(() => expect(importPackage).toHaveBeenCalledWith(file));
    expect(await screen.findByText("package-sha256")).toBeInTheDocument();
    fireEvent.click(screen.getByText("Закрыть"));

    fireEvent.click(screen.getByText("Managed collector"));
    fireEvent.click(await screen.findByRole("button", { name: "Удалить draft" }));
    await waitFor(() => expect(remove).toHaveBeenCalledWith("collector-main", 7));
  });
});
