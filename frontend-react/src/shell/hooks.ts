import { useCallback, useEffect, useRef, useState } from "react";

export type DataState<T> = {
  loading: boolean;
  error: string;
  data: T | null;
};

export function readSessionJson<T>(key: string, fallback: T): T {
  if (typeof window === "undefined") return fallback;
  try {
    const raw = window.sessionStorage.getItem(key);
    if (!raw) return fallback;
    const parsed = JSON.parse(raw) as T | null;
    return parsed ?? fallback;
  } catch {
    return fallback;
  }
}

export function writeSessionJson(key: string, value: unknown) {
  if (typeof window === "undefined") return;
  try {
    window.sessionStorage.setItem(key, JSON.stringify(value));
  } catch {
    // Ignore quota and privacy-mode failures. The shell should keep working without persistence.
  }
}

export function useAsyncData<T>(loader: () => Promise<T>, _deps?: unknown[]) {
  const [state, setState] = useState<DataState<T>>({
    loading: true,
    error: "",
    data: null,
  });

  useEffect(() => {
    let cancelled = false;
    setState((current) => ({ loading: true, error: "", data: current.data }));
    loader()
      .then((data) => {
        if (!cancelled) setState({ loading: false, error: "", data });
      })
      .catch((error: Error) => {
        if (!cancelled) {
          setState((current) => ({ loading: false, error: error.message, data: current.data }));
        }
      });
    return () => {
      cancelled = true;
    };
  }, [loader]);

  return state;
}

export function useDebouncedValue<T>(value: T, delay = 350) {
  const [debounced, setDebounced] = useState<T>(value);
  // The caller owns the dependency list here so pages can align polling with runtime filters and refresh tokens.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(() => {
    const timer = window.setTimeout(() => setDebounced(value), delay);
    return () => window.clearTimeout(timer);
  }, [value, delay]);
  return debounced;
}

export function usePolledData<T>(loader: () => Promise<T>, intervalMs: number, _deps?: unknown[]) {
  const [state, setState] = useState<DataState<T>>({
    loading: true,
    error: "",
    data: null,
  });
  useEffect(() => {
    let cancelled = false;
    let timer = 0;
    const computeDelay = () => {
      const baseInterval = intervalMs > 0 ? intervalMs : 0;
      if (!(baseInterval > 0)) return 0;
      let nextDelay = baseInterval;
      if (typeof navigator !== "undefined" && "onLine" in navigator && navigator.onLine === false) {
        nextDelay = Math.max(nextDelay, baseInterval * 4);
      }
      if (typeof document !== "undefined" && document.visibilityState === "hidden") {
        nextDelay = Math.max(nextDelay, baseInterval * 6);
      }
      const connection = typeof navigator !== "undefined" ? (navigator as Navigator & { connection?: { saveData?: boolean; effectiveType?: string } }).connection : undefined;
      if (connection?.saveData) {
        nextDelay = Math.max(nextDelay, baseInterval * 2);
      }
      if (connection?.effectiveType && ["slow-2g", "2g"].includes(String(connection.effectiveType))) {
        nextDelay = Math.max(nextDelay, baseInterval * 3);
      }
      return nextDelay;
    };
    const clearScheduled = () => {
      if (timer) {
        window.clearTimeout(timer);
        timer = 0;
      }
    };
    const scheduleNext = () => {
      clearScheduled();
      const nextDelay = computeDelay();
      if (!(nextDelay > 0) || cancelled) return;
      timer = window.setTimeout(load, nextDelay);
    };
    const load = () => {
      if (typeof document !== "undefined" && document.visibilityState === "hidden") {
        scheduleNext();
        return;
      }
      loader()
        .then((data) => {
          if (!cancelled) {
            setState({ loading: false, error: "", data });
          }
        })
        .catch((error: Error) => {
          if (!cancelled) {
            setState((current) => ({ loading: false, error: error.message, data: current.data }));
          }
        })
        .finally(() => {
          scheduleNext();
        });
    };
    const onVisibilityChange = () => {
      if (document.visibilityState === "visible") {
        load();
        return;
      }
      scheduleNext();
    };
    const onNetworkChange = () => {
      scheduleNext();
      if (typeof document === "undefined" || document.visibilityState === "visible") {
        load();
      }
    };
    setState((current) => ({ ...current, loading: true, error: "" }));
    load();
    document.addEventListener("visibilitychange", onVisibilityChange);
    window.addEventListener("online", onNetworkChange);
    window.addEventListener("offline", onNetworkChange);
    return () => {
      cancelled = true;
      document.removeEventListener("visibilitychange", onVisibilityChange);
      window.removeEventListener("online", onNetworkChange);
      window.removeEventListener("offline", onNetworkChange);
      clearScheduled();
    };
  }, [intervalMs, loader]);

  return state;
}

export function useWindowedRows<T>(
  rows: T[],
  {
    rowHeight = 52,
    overscan = 10,
    enabled = true,
    defaultHeight = 560,
  }: {
    rowHeight?: number;
    overscan?: number;
    enabled?: boolean;
    defaultHeight?: number;
  } = {},
) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const [scrollTop, setScrollTop] = useState(0);
  const [viewportHeight, setViewportHeight] = useState(defaultHeight);
  const totalRows = rows.length;
  const isWindowed = enabled && totalRows > Math.max(overscan * 4, 80);

  useEffect(() => {
    const node = containerRef.current;
    if (!node || !isWindowed) {
      setScrollTop(0);
      setViewportHeight(defaultHeight);
      return;
    }
    const updateViewport = () => {
      setViewportHeight(node.clientHeight || defaultHeight);
    };
    const updateScroll = () => {
      setScrollTop(node.scrollTop);
    };
    updateViewport();
    updateScroll();
    node.addEventListener("scroll", updateScroll, { passive: true });
    window.addEventListener("resize", updateViewport);
    let observer: ResizeObserver | null = null;
    if (typeof ResizeObserver !== "undefined") {
      observer = new ResizeObserver(updateViewport);
      observer.observe(node);
    }
    return () => {
      node.removeEventListener("scroll", updateScroll);
      window.removeEventListener("resize", updateViewport);
      observer?.disconnect();
    };
  }, [defaultHeight, isWindowed]);

  useEffect(() => {
    const node = containerRef.current;
    if (!node || !isWindowed) return;
    const maxScroll = Math.max(0, totalRows * rowHeight - viewportHeight);
    if (node.scrollTop > maxScroll) {
      node.scrollTop = maxScroll;
      setScrollTop(maxScroll);
    }
  }, [isWindowed, rowHeight, totalRows, viewportHeight]);

  const visibleCount = isWindowed
    ? Math.max(1, Math.ceil(viewportHeight / rowHeight) + overscan * 2)
    : totalRows;
  const startIndex = isWindowed ? Math.max(0, Math.floor(scrollTop / rowHeight) - overscan) : 0;
  const endIndex = isWindowed ? Math.min(totalRows, startIndex + visibleCount) : totalRows;
  const visibleRows = isWindowed ? rows.slice(startIndex, endIndex) : rows;
  const topSpacerHeight = isWindowed ? startIndex * rowHeight : 0;
  const bottomSpacerHeight = isWindowed ? Math.max(0, (totalRows - endIndex) * rowHeight) : 0;

  const scrollToIndex = useCallback((index: number) => {
    const node = containerRef.current;
    if (!node || !isWindowed) return;
    const safeIndex = Math.max(0, Math.min(totalRows - 1, index));
    const top = safeIndex * rowHeight;
    const bottom = top + rowHeight;
    const currentTop = node.scrollTop;
    const currentBottom = currentTop + viewportHeight;
    if (top < currentTop) {
      node.scrollTo({ top });
      return;
    }
    if (bottom > currentBottom) {
      node.scrollTo({ top: Math.max(0, bottom - viewportHeight) });
    }
  }, [isWindowed, rowHeight, totalRows, viewportHeight]);

  return {
    containerRef,
    isWindowed,
    visibleRows,
    startIndex,
    endIndex,
    topSpacerHeight,
    bottomSpacerHeight,
    viewportHeight,
    scrollToIndex,
  };
}
