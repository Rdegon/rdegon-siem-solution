import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { AsyncGate } from "../async";

describe("AsyncGate", () => {
  it("shows a loading shell for initial fetches and keeps rendering children once data exists", () => {
    const { rerender } = render(
      <AsyncGate states={[{ loading: true, error: "", data: null }]} loadingMessage="Loading slice...">
        <div>ready</div>
      </AsyncGate>,
    );

    expect(screen.getByText("Loading slice...")).toBeInTheDocument();

    rerender(
      <AsyncGate states={[{ loading: true, error: "", data: { ok: true } }]} loadingMessage="Loading slice...">
        <div>ready</div>
      </AsyncGate>,
    );

    expect(screen.getByText("ready")).toBeInTheDocument();
  });
});
