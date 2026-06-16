import { fireEvent, screen, waitFor } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";
import { renderWithShell } from "../../test/renderWithShell";
import { DrawerOverlay } from "../ui";

describe("DrawerOverlay", () => {
  it("locks the page scroll, focuses the dialog content and closes on Escape", async () => {
    const onClose = vi.fn();

    renderWithShell(
      <DrawerOverlay open title="Drawer title" subtitle="Drawer subtitle" onClose={onClose}>
        <button type="button">Primary action</button>
      </DrawerOverlay>,
    );

    expect(document.body.style.overflow).toBe("hidden");
    await waitFor(() => expect(screen.getByRole("button", { name: "Close" })).toHaveFocus());

    fireEvent.keyDown(document, { key: "Escape" });
    expect(onClose).toHaveBeenCalledTimes(1);
  });
});
