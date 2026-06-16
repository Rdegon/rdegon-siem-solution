import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { useCallback } from "react";
import { describe, expect, it } from "vitest";
import { readSessionJson, useAsyncData, useWindowedRows, writeSessionJson } from "../hooks";

function WindowedRowsHarness({ size = 240 }: { size?: number }) {
  const rows = Array.from({ length: size }, (_, index) => ({ id: index, label: `row-${index}` }));
  const state = useWindowedRows(rows, {
    rowHeight: 24,
    overscan: 2,
    defaultHeight: 96,
  });

  return (
    <div>
      <div
        ref={(node) => {
          if (!node) return;
          Object.defineProperty(node, "clientHeight", {
            configurable: true,
            value: 96,
          });
          state.containerRef.current = node;
        }}
        data-testid="viewport"
        style={{ height: 96, overflowY: "auto" }}
      >
        <div style={{ height: state.topSpacerHeight }} />
        {state.visibleRows.map((row) => (
          <div key={row.id} data-testid="visible-row">
            {row.label}
          </div>
        ))}
        <div style={{ height: state.bottomSpacerHeight }} />
      </div>
      <div data-testid="range">
        {state.startIndex}:{state.endIndex}
      </div>
      <button type="button" onClick={() => state.scrollToIndex(120)}>
        scroll
      </button>
    </div>
  );
}

function AsyncDataHarness({
  requestKey,
  loader,
}: {
  requestKey: number;
  loader: () => Promise<{ label: string }>;
}) {
  const stableLoader = useCallback(() => {
    void requestKey;
    return loader();
  }, [loader, requestKey]);
  const state = useAsyncData(stableLoader);
  return (
    <div data-testid="async-state">
      {`${state.loading ? "loading" : "ready"}:${state.data?.label || "none"}:${state.error || "ok"}`}
    </div>
  );
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

describe("useWindowedRows", () => {
  it("renders only the visible slice and can scroll to deeper rows", () => {
    render(<WindowedRowsHarness />);

    const initialVisible = screen.getAllByTestId("visible-row");
    expect(initialVisible.length).toBeLessThan(40);
    expect(screen.getByTestId("range").textContent).toMatch(/^0:/);

    fireEvent.click(screen.getByRole("button", { name: "scroll" }));

    const rangeText = screen.getByTestId("range").textContent || "";
    const [start] = rangeText.split(":").map(Number);
    expect(start).toBeGreaterThan(100);
    expect(screen.getAllByTestId("visible-row").length).toBeLessThan(40);
  });
});

describe("session json helpers", () => {
  it("stores and restores persisted shell state safely", () => {
    window.sessionStorage.clear();
    writeSessionJson("events-state", { query: "severity = 'high'", limit: 250 });

    expect(readSessionJson("events-state", { query: "", limit: 100 })).toEqual({
      query: "severity = 'high'",
      limit: 250,
    });
    expect(readSessionJson("missing-state", { query: "", limit: 100 })).toEqual({
      query: "",
      limit: 100,
    });
  });
});

describe("useAsyncData", () => {
  it("keeps the previous payload visible while refresh boundaries reload and even if the refresh fails", async () => {
    const first = deferred<{ label: string }>();
    const { rerender } = render(<AsyncDataHarness requestKey={1} loader={() => first.promise} />);

    expect(screen.getByTestId("async-state").textContent).toBe("loading:none:ok");

    first.resolve({ label: "first" });
    await waitFor(() => expect(screen.getByTestId("async-state").textContent).toBe("ready:first:ok"));

    const second = deferred<{ label: string }>();
    rerender(<AsyncDataHarness requestKey={2} loader={() => second.promise} />);

    await waitFor(() => expect(screen.getByTestId("async-state").textContent).toBe("loading:first:ok"));

    second.reject(new Error("refresh failed"));
    await waitFor(() => expect(screen.getByTestId("async-state").textContent).toBe("ready:first:refresh failed"));
  });
});
