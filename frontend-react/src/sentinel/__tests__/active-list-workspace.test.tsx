import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ActiveListEntries } from "../kuma-workspaces";
import { api } from "../runtime/api";

function mockInventory() {
  vi.spyOn(api, "activeLists").mockResolvedValue({
    items: [{
      list_name: "blocked-ioc",
      list_kind: "deny",
      item_type: "ip",
      item_value: "203.0.113.10",
      item_label: "Threat intel",
      tags: ["ioc"],
      enabled: true,
      updated_ts: "2026-08-03T10:00:00Z",
    }],
  });
}

describe("active list production workspace", () => {
  afterEach(() => vi.restoreAllMocks());

  it("uses the backend list_name filter and exposes lifecycle controls", async () => {
    mockInventory();
    const toggle = vi.spyOn(api, "toggleActiveList").mockResolvedValue({ status: "disabled" });
    const remove = vi.spyOn(api, "deleteActiveList").mockResolvedValue({ status: "deleted" });
    vi.spyOn(window, "confirm").mockReturnValue(true);

    render(<ActiveListEntries listKind="deny" listName="blocked-ioc" notify={vi.fn()} />);

    expect(await screen.findByText("203.0.113.10")).toBeInTheDocument();
    expect(api.activeLists).toHaveBeenCalledWith({ list_name: "blocked-ioc", limit: 5_000 });
    expect(screen.getAllByText("Включено").length).toBeGreaterThan(0);

    fireEvent.click(screen.getByRole("checkbox", { name: "Отключить 203.0.113.10" }));
    await waitFor(() => expect(toggle).toHaveBeenCalledWith(expect.objectContaining({
      list_name: "blocked-ioc",
      list_kind: "deny",
      item_type: "ip",
      item_value: "203.0.113.10",
      enabled: false,
    })));

    fireEvent.click(screen.getByRole("button", { name: "Удалить 203.0.113.10" }));
    await waitFor(() => expect(remove).toHaveBeenCalledWith(expect.objectContaining({
      list_name: "blocked-ioc",
      item_value: "203.0.113.10",
    })));
  });

  it("validates structured multiline imports before applying them", async () => {
    mockInventory();
    const importer = vi.spyOn(api, "importActiveLists")
      .mockResolvedValueOnce({ status: "validated", dry_run: true, rows: 2, duplicates_removed: 0 })
      .mockResolvedValueOnce({ status: "imported", dry_run: false, rows: 2, duplicates_removed: 0 });

    render(<ActiveListEntries listKind="deny" listName="blocked-ioc" notify={vi.fn()} />);
    await screen.findByText("203.0.113.10");
    fireEvent.change(screen.getByLabelText("Значения импорта"), {
      target: { value: "198.51.100.5\n198.51.100.6" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Проверить импорт" }));

    await waitFor(() => expect(importer).toHaveBeenNthCalledWith(1, {
      dry_run: true,
      items: [
        expect.objectContaining({ list_name: "blocked-ioc", item_value: "198.51.100.5", enabled: true }),
        expect.objectContaining({ list_name: "blocked-ioc", item_value: "198.51.100.6", enabled: true }),
      ],
    }));
    expect(await screen.findByText("Проверено: 2")).toBeInTheDocument();

    fireEvent.click(screen.getByRole("button", { name: "Применить импорт" }));
    await waitFor(() => expect(importer).toHaveBeenNthCalledWith(2, expect.objectContaining({ dry_run: false })));
    expect(document.querySelector("pre")).toBeNull();
  });

  it("downloads bounded CSV and JSON exports for the selected list", async () => {
    mockInventory();
    const exporter = vi.spyOn(api, "exportActiveLists").mockResolvedValue({ filename: "active-lists.csv" });
    render(<ActiveListEntries listKind="deny" listName="blocked-ioc" notify={vi.fn()} />);
    await screen.findByText("203.0.113.10");

    fireEvent.click(screen.getByRole("button", { name: "CSV" }));
    fireEvent.click(screen.getByRole("button", { name: "JSON" }));

    await waitFor(() => expect(exporter).toHaveBeenCalledTimes(2));
    expect(exporter).toHaveBeenNthCalledWith(1, "blocked-ioc", "csv");
    expect(exporter).toHaveBeenNthCalledWith(2, "blocked-ioc", "json");
  });
});
