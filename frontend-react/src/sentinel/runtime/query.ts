import { useCallback, useEffect, useRef, useState } from "react";

type QueryState<T> = { data?: T; error?: Error; loading: boolean };

export function useQuery<T>(key: string, loader: () => Promise<T>, refreshMs = 0) {
  const loaderRef = useRef(loader);
  loaderRef.current = loader;
  const [nonce, setNonce] = useState(0);
  const [state, setState] = useState<QueryState<T>>({ loading: true });
  const reload = useCallback(() => setNonce((value) => value + 1), []);

  useEffect(() => {
    let active = true;
    setState((current) => ({ data: current.data, loading: true }));
    loaderRef.current().then(
      (data) => active && setState({ data, loading: false }),
      (reason) => active && setState({ error: reason instanceof Error ? reason : new Error(String(reason)), loading: false }),
    );
    return () => { active = false; };
  }, [key, nonce]);

  useEffect(() => {
    if (!refreshMs) return;
    const timer = window.setInterval(reload, refreshMs);
    return () => window.clearInterval(timer);
  }, [refreshMs, reload]);

  return { ...state, reload };
}

export function text(value: unknown, fallback = "—"): string {
  if (value === null || value === undefined || value === "") return fallback;
  if (Array.isArray(value)) return value.map((item) => text(item, "")).filter(Boolean).join(", ") || fallback;
  if (typeof value === "object") return JSON.stringify(value);
  return String(value);
}

export function number(value: unknown) {
  const parsed = Number(value ?? 0);
  return Number.isFinite(parsed) ? parsed : 0;
}

export function formatTime(value: unknown) {
  const raw = text(value, "");
  if (!raw) return "—";
  const date = new Date(raw);
  return Number.isNaN(date.getTime()) ? raw : new Intl.DateTimeFormat("ru-RU", { dateStyle: "short", timeStyle: "medium" }).format(date);
}

export function severityTone(value: unknown) {
  const lowered = text(value, "info").toLowerCase();
  if (/critical|крит/.test(lowered)) return "critical";
  if (/high|выс/.test(lowered)) return "high";
  if (/medium|сред|warn/.test(lowered)) return "warning";
  if (/low|низ/.test(lowered)) return "low";
  return "info";
}
