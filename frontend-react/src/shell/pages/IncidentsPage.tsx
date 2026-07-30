import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Search } from "lucide-react";
import { Link, useLocation, useNavigate } from "react-router-dom";
import { api } from "../api";
import { readSessionJson, useDebouncedValue, usePolledData, useWindowedRows, writeSessionJson } from "../hooks";
import { useFeedback } from "../feedback";
import { buildIncidentDeepLink, incidentRowId, type IncidentView } from "../incidents";
import { DrawerFieldGrid, DrawerOverlay, EmptyState, InfoList, JsonPreview, KeyValue, PanelHeader, SeverityBadge, StatusBadge } from "../ui";
import { NativeActionBar, NativePageHeader, NativePager } from "../native";
import { shiftTimeZoneInputValue, t, timeZoneDisplayLabel, useShellContext } from "../context";
import { humanizeSourceName, humanizeTechnicalValue } from "../humanize";
import { localizeRuleName } from "../runtimeLocalization";
import { refreshIntervalMs, refreshOptions, rowOptions, timeRangeOptions } from "../timeControls";
import type { IncidentDetailResponse, IncidentHistoryEntry, IncidentListResponse, IncidentRecord, IncidentStatusTransitions, RuntimeBlob } from "../types";

function listValues(value: unknown) {
  return Array.isArray(value)
    ? value.map((item) => String(item || "").trim()).filter(Boolean)
    : [];
}

function displayList(value: unknown) {
  const items = listValues(value);
  return items.length ? items.join(", ") : "n/a";
}

function contextValue(context: RuntimeBlob | null | undefined, ...keys: string[]) {
  if (!context || typeof context !== "object") return "";
  for (const key of keys) {
    if (Object.prototype.hasOwnProperty.call(context, key)) {
      const direct = String(context[key] || "").trim();
      if (direct) return direct;
    }
    let current: unknown = context;
    for (const part of key.split(".")) {
      if (!current || typeof current !== "object") {
        current = "";
        break;
      }
      current = (current as RuntimeBlob)[part];
    }
    const text = String(current || "").trim();
    if (text) return text;
  }
  return "";
}

function primaryContext(selected: IncidentRecord | null) {
  if (selected?.context && typeof selected.context === "object") return selected.context;
  const samples = Array.isArray(selected?.samples) ? selected.samples : [];
  return (samples.find((item) => item && typeof item === "object") as RuntimeBlob | undefined) || {};
}

function asRecordList(value: unknown): RuntimeBlob[] {
  return Array.isArray(value) ? value.filter((item): item is RuntimeBlob => !!item && typeof item === "object" && !Array.isArray(item)) : [];
}

function displayValue(value: unknown) {
  const text = String(value ?? "").trim();
  return text || "Не определено";
}

function shortText(value: unknown, max = 220) {
  const text = displayValue(value);
  return text.length > max ? `${text.slice(0, max)}...` : text;
}

function incidentEvidenceError(value: unknown, lang: "en" | "ru") {
  const message = String(value || "").trim();
  if (!message) {
    return t(lang, { en: "Loading incident details...", ru: "Загрузка деталей инцидента..." });
  }
  if (/HTTPDriver|DB::Exception|SELECT\s|normalized_json|asset_service|ClickHouse|UNKNOWN_IDENTIFIER/i.test(message)) {
    const debugId = message.match(/Debug id:\s*([a-z0-9-]+)/i)?.[1] || "";
    return `${t(lang, { en: "Incident evidence is temporarily unavailable. The queue itself is still usable.", ru: "Evidence инцидента временно недоступны. Очередь инцидентов остается рабочей." })}${debugId ? ` Debug id: ${debugId}` : ""}`;
  }
  return message;
}

function durationLabel(startValue: unknown, endValue: unknown) {
  const start = Date.parse(String(startValue || "").replace(" ", "T"));
  const end = Date.parse(String(endValue || "").replace(" ", "T"));
  if (!Number.isFinite(start) || !Number.isFinite(end) || end < start) return "Не определено";
  const seconds = Math.floor((end - start) / 1000);
  const minutes = Math.floor(seconds / 60);
  const hours = Math.floor(minutes / 60);
  if (hours) return `${hours}h ${minutes % 60}m`;
  if (minutes) return `${minutes}m ${seconds % 60}s`;
  return `${seconds}s`;
}

function statusRequiresComment(status: string) {
  return ["closed", "false_positive", "resolved", "suppressed"].includes(String(status || "").trim().toLowerCase());
}

export function IncidentsPage() {
  const { lang, formatTimestamp, timezone, toInputDateTime, toUtcQueryValue, permissions } = useShellContext();
  const { announce, pushToast } = useFeedback();
  const location = useLocation();
  const navigate = useNavigate();
  const routeView: IncidentView = location.pathname === "/alerts" ? "raw" : "agg";
  const announcedSnapshotRef = useRef("");
  const persistedState = readSessionJson("rdegon-incidents-view", {
    view: "agg",
    scope: "main",
    query: "",
    windowPreset: "24h",
    fromTs: "",
    toTs: "",
    limit: 100,
    refreshSeconds: "0",
    selectedId: "",
  });
  const [view, setView] = useState<IncidentView>(routeView);
  const [scope, setScope] = useState<"main" | "vpn-noise" | "health">(() =>
    persistedState.scope === "vpn-noise" || persistedState.scope === "health" ? persistedState.scope : "main",
  );
  const [query, setQuery] = useState(() => String(persistedState.query || ""));
  const [windowPreset, setWindowPreset] = useState(() => String(persistedState.windowPreset || "24h"));
  const [fromTs, setFromTs] = useState(() => (persistedState.windowPreset === "custom" ? String(persistedState.fromTs || "") : ""));
  const [toTs, setToTs] = useState(() => (persistedState.windowPreset === "custom" ? String(persistedState.toTs || "") : ""));
  const [limit, setLimit] = useState(() => {
    const persistedLimit = Number(persistedState.limit || 100);
    return Number.isFinite(persistedLimit) ? Math.min(250, Math.max(10, persistedLimit)) : 100;
  });
  const [refreshSeconds, setRefreshSeconds] = useState(() => String(persistedState.refreshSeconds || "0"));
  const [selectedId, setSelectedId] = useState("");
  const [refreshToken, setRefreshToken] = useState(0);
  const [statusValue, setStatusValue] = useState("new");
  const [assigneeValue, setAssigneeValue] = useState("");
  const [noteValue, setNoteValue] = useState("");
  const [mutationState, setMutationState] = useState("");
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [viewState, setViewState] = useState("");
  const [hostActionState, setHostActionState] = useState("");
  const [selectedRowIds, setSelectedRowIds] = useState<string[]>([]);
  const [bulkAssignee, setBulkAssignee] = useState("");
  const [bulkState, setBulkState] = useState("");
  const debouncedQuery = useDebouncedValue(query, 250);
  const incidentTimeZoneLabel = useMemo(() => timeZoneDisplayLabel(timezone, lang), [timezone, lang]);

  useEffect(() => {
    setView(routeView);
    setSelectedId("");
    setSelectedRowIds([]);
    setDrawerOpen(false);
  }, [routeView]);

  const formatIncidentTimestamp = useCallback(
    (value: unknown) => {
      const formatted = formatTimestamp(value, "full");
      if (!formatted || formatted === "n/a" || formatted === "н/д") {
        return formatted;
      }
      return `${formatted} ${incidentTimeZoneLabel}`;
    },
    [formatTimestamp, incidentTimeZoneLabel],
  );

  useEffect(() => {
    const params = new URLSearchParams(location.search || "");
    if (!params.toString()) return;
    if (params.has("scope")) {
      const requestedScope = String(params.get("scope") || "main");
      setScope(requestedScope === "vpn-noise" || requestedScope === "health" ? requestedScope : "main");
    }
    if (params.has("q")) setQuery(String(params.get("q") || "").trim());
    if (params.has("window")) setWindowPreset(String(params.get("window") || "24h").trim() || "24h");
    if (params.has("focus")) {
      setSelectedId(String(params.get("focus") || "").trim());
      setDrawerOpen(true);
    }
    if (params.has("from") || params.has("to")) setWindowPreset("custom");
    if (params.has("from")) setFromTs(toInputDateTime(String(params.get("from") || "").trim()));
    if (params.has("to")) setToTs(toInputDateTime(String(params.get("to") || "").trim()));
    if (params.has("limit")) {
      const initialLimit = Number(params.get("limit") || 0);
      if (Number.isFinite(initialLimit) && initialLimit > 0) setLimit(Math.min(1000, Math.max(10, initialLimit)));
    }
  }, [location.search, toInputDateTime]);

  useEffect(() => {
    const previousTimezone = window.sessionStorage.getItem("rdegon-incidents-timezone") || timezone;
    if (previousTimezone === timezone) {
      window.sessionStorage.setItem("rdegon-incidents-timezone", timezone);
      return;
    }
    setFromTs((current) => (current ? shiftTimeZoneInputValue(current, previousTimezone, timezone) : current));
    setToTs((current) => (current ? shiftTimeZoneInputValue(current, previousTimezone, timezone) : current));
    window.sessionStorage.setItem("rdegon-incidents-timezone", timezone);
  }, [timezone]);

  useEffect(() => {
    const params = new URLSearchParams();
    if (scope !== "main") params.set("scope", scope);
    if (query.trim()) params.set("q", query.trim());
    if (windowPreset !== "24h") params.set("window", windowPreset);
    if (windowPreset === "custom" && fromTs) params.set("from", toUtcQueryValue(fromTs));
    if (windowPreset === "custom" && toTs) params.set("to", toUtcQueryValue(toTs));
    if (limit !== 100) params.set("limit", String(limit));
    if (drawerOpen && selectedId) params.set("focus", selectedId);
    const nextSearch = params.toString();
    const currentSearch = location.search.replace(/^\?/, "");
    if (nextSearch !== currentSearch) {
      navigate(
        {
          pathname: location.pathname,
          search: nextSearch ? `?${nextSearch}` : "",
        },
        { replace: true },
      );
    }
    writeSessionJson("rdegon-incidents-view", {
      view,
      scope,
      query,
      windowPreset,
      fromTs: windowPreset === "custom" ? fromTs : "",
      toTs: windowPreset === "custom" ? toTs : "",
      limit,
      refreshSeconds,
      selectedId: drawerOpen ? selectedId : "",
    });
  }, [
    fromTs,
    drawerOpen,
    limit,
    location.pathname,
    location.search,
    navigate,
    query,
    refreshSeconds,
    scope,
    selectedId,
    toTs,
    toUtcQueryValue,
    view,
    windowPreset,
  ]);

  const loadIncidentList = useCallback(
    () => {
      void refreshToken;
      const activeFromTs = windowPreset === "custom" ? fromTs : "";
      const activeToTs = windowPreset === "custom" ? toTs : "";
      return api.incidents({
        view,
        scope,
        q: debouncedQuery,
        window: windowPreset,
        limit,
        from_ts: activeFromTs ? toUtcQueryValue(activeFromTs) : "",
        to_ts: activeToTs ? toUtcQueryValue(activeToTs) : "",
      });
    },
    [view, scope, debouncedQuery, fromTs, toTs, limit, refreshToken, toUtcQueryValue, windowPreset],
  );
  const loadIncidentSummary = useCallback(
    () => {
      void refreshToken;
      const activeFromTs = windowPreset === "custom" ? fromTs : "";
      const activeToTs = windowPreset === "custom" ? toTs : "";
      return selectedId && drawerOpen
        ? api.incidentDetail(view, selectedId, {
            window: windowPreset,
            from_ts: activeFromTs ? toUtcQueryValue(activeFromTs) : "",
            to_ts: activeToTs ? toUtcQueryValue(activeToTs) : "",
            event_limit: 50,
            alert_limit: 50,
            include_evidence: false,
          })
        : Promise.resolve(null);
    },
    [view, selectedId, drawerOpen, refreshToken, windowPreset, fromTs, toTs, toUtcQueryValue],
  );
  const listState = usePolledData<IncidentListResponse>(loadIncidentList, refreshIntervalMs(refreshSeconds));
  const detailState = usePolledData<IncidentDetailResponse | null>(loadIncidentSummary, refreshIntervalMs(refreshSeconds));
  const summaryMatchesSelection = Boolean(
    detailState.data?.item
    && incidentRowId(detailState.data.item, view) === selectedId,
  );
  const loadIncidentEvidence = useCallback(
    () => {
      void refreshToken;
      const activeFromTs = windowPreset === "custom" ? fromTs : "";
      const activeToTs = windowPreset === "custom" ? toTs : "";
      return selectedId && drawerOpen && summaryMatchesSelection
        ? api.incidentDetail(view, selectedId, {
            window: windowPreset,
            from_ts: activeFromTs ? toUtcQueryValue(activeFromTs) : "",
            to_ts: activeToTs ? toUtcQueryValue(activeToTs) : "",
            event_limit: 50,
            alert_limit: 50,
            include_evidence: true,
          })
        : Promise.resolve(null);
    },
    [
      drawerOpen,
      fromTs,
      refreshToken,
      selectedId,
      toTs,
      toUtcQueryValue,
      view,
      windowPreset,
      summaryMatchesSelection,
    ],
  );
  const evidenceState = usePolledData<IncidentDetailResponse | null>(
    loadIncidentEvidence,
    refreshIntervalMs(refreshSeconds),
  );
  const evidenceMatchesSelection = Boolean(
    evidenceState.data?.item
    && incidentRowId(evidenceState.data.item, view) === selectedId,
  );
  const detailData = evidenceMatchesSelection
    ? evidenceState.data
    : summaryMatchesSelection
      ? detailState.data
      : null;
  const items = useMemo<IncidentRecord[]>(() => listState.data?.items || [], [listState.data?.items]);
  const windowedRows = useWindowedRows(items, {
    rowHeight: 48,
    overscan: 12,
    enabled: false,
    defaultHeight: 560,
  });
  const { scrollToIndex } = windowedRows;
  const selectedListIndex = items.findIndex((row) => incidentRowId(row, view) === selectedId);

  useEffect(() => {
    const availableIds = new Set(items.map((row) => incidentRowId(row, view)));
    setSelectedRowIds((current) => current.filter((id) => availableIds.has(id)));
  }, [items, view]);

  useEffect(() => {
    if (!items.length) {
      if (selectedId) setSelectedId("");
      setDrawerOpen(false);
      return;
    }
    const querySettled = query.trim() === debouncedQuery.trim() && String(listState.data?.query || "").trim() === debouncedQuery.trim();
    const selectedInCurrentView = selectedId
      ? items.some((row) => incidentRowId(row, view) === selectedId)
      : false;
    if (!selectedInCurrentView && querySettled) {
      setSelectedId(incidentRowId(items[0], view));
    }
  }, [debouncedQuery, items, listState.data?.query, query, selectedId, view]);

  useEffect(() => {
    const item = detailData?.item;
    if (item) {
      setStatusValue(String(item.status || "new"));
      setAssigneeValue(String(item.assignee || ""));
    }
  }, [detailData]);

  useEffect(() => {
    setHostActionState("");
  }, [selectedId]);

  useEffect(() => {
    if (selectedListIndex < 0) return;
    scrollToIndex(selectedListIndex);
  }, [items.length, scrollToIndex, selectedListIndex]);

  useEffect(() => {
    if (listState.loading || !listState.data) return;
    const snapshot = `${view}:${scope}:${items.length}:${listState.data.metrics?.agg_open || 0}`;
    if (announcedSnapshotRef.current === snapshot) return;
    announcedSnapshotRef.current = snapshot;
    announce(
      t(lang, {
        en: `Incident queue updated. ${items.length} rows loaded in ${view} view.`,
        ru: `Очередь инцидентов обновлена. Загружено ${items.length} строк в режиме ${view}.`,
      }),
    );
  }, [announce, items.length, lang, listState.data, listState.loading, scope, view]);

  useEffect(() => {
    function onKeyDown(event: KeyboardEvent) {
      const target = event.target as HTMLElement | null;
      const tag = target?.tagName || "";
      if (target?.isContentEditable || tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT") return;
      const currentIndex = items.findIndex((row) => incidentRowId(row, view) === selectedId);
      if ((event.key === "j" || event.key === "ArrowDown") && items.length) {
        event.preventDefault();
        const next = items[Math.min(items.length - 1, Math.max(0, currentIndex) + 1)];
        setSelectedId(incidentRowId(next, view));
        return;
      }
      if ((event.key === "k" || event.key === "ArrowUp") && items.length) {
        event.preventDefault();
        const next = items[Math.max(0, (currentIndex >= 0 ? currentIndex : 1) - 1)];
        setSelectedId(incidentRowId(next, view));
        return;
      }
      if (event.key === "Enter" && selectedId) {
        event.preventDefault();
        setDrawerOpen(true);
        return;
      }
      if (event.key === "Escape" && drawerOpen) {
        event.preventDefault();
        setDrawerOpen(false);
      }
    }
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [drawerOpen, items, selectedId, view]);

  async function updateIncident() {
    const recordId = String((view === "raw" ? selected?.alert_id : selected?.agg_id) || selectedId || "");
    if (!recordId) return;
    if (statusRequiresComment(statusValue) && !noteValue.trim()) {
      const message = "Комментарий обязателен для Closed, Resolved, Suppressed и False Positive.";
      setMutationState(message);
      pushToast({
        title: "Нужен комментарий",
        message,
        tone: "warning",
        durationMs: 6200,
      });
      return;
    }
    setMutationState("Saving...");
    try {
      await api.updateIncident(view, recordId, { status: statusValue, assignee: assigneeValue, note: noteValue });
      setNoteValue("");
      setMutationState("Saved");
      pushToast({
        title: t(lang, { en: "Incident updated", ru: "Инцидент обновлен" }),
        message: t(lang, {
          en: `${selected?.rule_name || "Selected incident"} is now ${statusValue}.`,
          ru: `${localizeRuleName(selected?.rule_name || "Выбранный инцидент", "ru")} переведен в статус ${statusValue}.`,
        }),
        tone: "success",
      });
      setRefreshToken((value) => value + 1);
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : "Update failed";
      setMutationState(message);
      pushToast({
        title: t(lang, { en: "Incident update failed", ru: "Не удалось обновить инцидент" }),
        message,
        tone: "error",
        durationMs: 6200,
      });
    }
  }

  async function runHostAction(action: "snapshot" | "refresh_telemetry") {
    const recordId = String((view === "raw" ? selected?.alert_id : selected?.agg_id) || selectedId || "");
    if (!recordId) return;
    setHostActionState(
      action === "snapshot"
        ? t(lang, { en: "Collecting host snapshot...", ru: "Собираю снимок хоста..." })
        : t(lang, { en: "Refreshing telemetry on source host...", ru: "Обновляю телеметрию на исходном хосте..." }),
    );
    try {
      const response = await api.runIncidentHostAction(view, recordId, { action });
      const first = (response.results || [])[0] as RuntimeBlob | undefined;
      const summary = String(first?.message || first?.output || "").trim();
      setHostActionState(summary || t(lang, { en: "Host action completed", ru: "Действие на хосте выполнено" }));
      pushToast({
        title: t(lang, { en: "Host action completed", ru: "Действие на хосте выполнено" }),
        message: summary.slice(0, 220) || t(lang, { en: "The selected machine-side action finished successfully.", ru: "Выбранное машинное действие завершилось успешно." }),
        tone: "success",
        durationMs: 7000,
      });
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : "Host action failed";
      setHostActionState(message);
      pushToast({
        title: t(lang, { en: "Host action failed", ru: "Действие на хосте завершилось ошибкой" }),
        message,
        tone: "error",
        durationMs: 7000,
      });
    }
  }

  async function runBulkUpdate(mode: "assign" | "close") {
    if (!selectedRowIds.length) return;
    if (mode === "assign" && !bulkAssignee.trim()) {
      setBulkState(t(lang, { en: "Enter an assignee before applying the bulk action.", ru: "Укажите ответственного перед массовым назначением." }));
      return;
    }
    setBulkState(t(lang, { en: "Applying changes...", ru: "Применяю изменения..." }));
    try {
      await Promise.all(
        selectedRowIds.map((recordId) =>
          api.updateIncident(view, recordId, mode === "assign"
            ? { assignee: bulkAssignee.trim(), note: "Bulk assignment from analyst queue" }
            : { status: "closed", note: "Bulk closure from analyst queue" }),
        ),
      );
      setBulkState(
        t(lang, {
          en: `${selectedRowIds.length} records updated.`,
          ru: `Обновлено записей: ${selectedRowIds.length}.`,
        }),
      );
      setSelectedRowIds([]);
      setRefreshToken((value) => value + 1);
      pushToast({
        title: t(lang, { en: "Queue updated", ru: "Очередь обновлена" }),
        message: mode === "assign"
          ? t(lang, { en: `Assigned to ${bulkAssignee.trim()}.`, ru: `Назначено: ${bulkAssignee.trim()}.` })
          : t(lang, { en: "Selected records were closed.", ru: "Выбранные записи закрыты." }),
        tone: "success",
      });
    } catch (error: unknown) {
      const message = error instanceof Error ? error.message : "Bulk update failed";
      setBulkState(message);
      pushToast({ title: t(lang, { en: "Bulk action failed", ru: "Массовое действие не выполнено" }), message, tone: "error" });
    }
  }

  function resetViewState() {
    setView(routeView);
    setScope("main");
    setQuery("");
    setWindowPreset("24h");
    setFromTs("");
    setToTs("");
    setLimit(100);
    setRefreshSeconds("0");
    setSelectedId("");
    setSelectedRowIds([]);
    setDrawerOpen(false);
    pushToast({
      title: t(lang, { en: "Queue reset", ru: "Очередь сброшена" }),
      message: t(lang, { en: "Reset to default incident queue", ru: "Сброшено к базовой очереди инцидентов" }),
      tone: "info",
    });
    setViewState(t(lang, { en: "Reset to default incident queue", ru: "Сброшено к базовой очереди инцидентов" }));
  }

  async function copyCurrentViewLink() {
    const currentUrl = buildIncidentDeepLink(window.location.origin, location.search || "");
    try {
      await navigator.clipboard.writeText(currentUrl);
      pushToast({
        title: t(lang, { en: "Link copied", ru: "Ссылка скопирована" }),
        message: t(lang, { en: "Deep link copied", ru: "Глубокая ссылка скопирована" }),
        tone: "success",
      });
      setViewState(t(lang, { en: "Deep link copied", ru: "Глубокая ссылка скопирована" }));
    } catch {
      pushToast({
        title: t(lang, { en: "Copy link manually", ru: "Скопируйте ссылку вручную" }),
        message: currentUrl,
        tone: "warning",
        durationMs: 6500,
      });
      setViewState(currentUrl);
    }
  }

  if (listState.loading) return <EmptyState message={t(lang, { en: "Loading incident queue...", ru: "Загрузка очереди инцидентов..." })} />;
  if (listState.error || !listState.data) return <EmptyState message={listState.error || t(lang, { en: "No incident data", ru: "Нет данных по инцидентам" })} />;

  const transitions: IncidentStatusTransitions = detailData?.status_transitions || listState.data.status_transitions || {};
  const selected: IncidentRecord | null = detailData?.item || null;
  const allowedStatuses = transitions[String(selected?.status || "new")] || ["new", "assigned", "in_progress", "closed"];
  const selectedContext = primaryContext(selected);
  const selectedAssets = listValues(selected?.cluster?.assets);
  const incidentSummary = detailData?.summary || {};
  const incidentRisk = detailData?.risk || {};
  const incidentEntities = detailData?.entities || {};
  const networkContext = detailData?.network_context || {};
  const authenticationContext = detailData?.authentication_context || {};
  const processContext = detailData?.process_context || {};
  const incidentRules = asRecordList(detailData?.rules);
  const incidentTimeline = asRecordList(detailData?.timeline_preview || detailData?.timeline).slice(-12);
  const rawAlertRows = asRecordList(detailData?.raw_alerts?.items).slice(0, 20);
  const relatedEventRows = asRecordList(detailData?.related_events?.items).slice(0, 30);
  const commandEvidenceRows = asRecordList(detailData?.command_evidence)
    .filter((row) => !/^(?:[A-Za-z]:\\.*\\)?(?:powershell|pwsh|cmd|wscript|cscript|rundll32|wmic|schtasks|mshta|regsvr32)(?:\.exe)?$/i.test(String(row.process_command || "").trim()))
    .slice(0, 20);
  const recommendations = Array.isArray(detailData?.recommendations) ? detailData?.recommendations || [] : [];
  const entityUsers = asRecordList(incidentEntities.users);
  const entityHosts = asRecordList(incidentEntities.hosts);
  const entityIps = asRecordList(incidentEntities.ips);
  const entityProcesses = asRecordList(incidentEntities.processes);
  const processEventRows = asRecordList(processContext.process_events).slice(0, 12);
  const totalRawAlerts = Number(detailData?.raw_alerts?.total || rawAlertRows.length || selected?.count_alerts || 0);
  const totalRelatedEvents = Number(detailData?.related_events?.total || relatedEventRows.length || selected?.count_events || selected?.raw_hits_total || 0);
  const sampleHost = contextValue(selectedContext, "host_name", "source", "log_source", "observer_collector", "collector_profile") || "n/a";
  const sampleCategory = contextValue(selectedContext, "category", "event.category", "subcategory", "event.type") || "n/a";
  const incidentRangeOptions = timeRangeOptions(lang);
  const availableIncidentCount = Number(listState.data.available_count ?? items.length ?? 0);
  const returnedIncidentCount = Number(listState.data.returned_count ?? items.length ?? 0);
  const allRowsSelected = items.length > 0 && items.every((row) => selectedRowIds.includes(incidentRowId(row, view)));
  const pageTitle = view === "raw"
    ? t(lang, { en: "Alerts", ru: "Алерты" })
    : t(lang, { en: "Incidents", ru: "Инциденты" });
  const canRunHostAction = permissions.includes("response:run");
  const incidentSeverity = selected?.severity_agg || selected?.severity || "info";
  const incidentSeverityTone =
    incidentSeverity === "critical"
      ? "critical"
      : incidentSeverity === "high" || incidentSeverity === "warning"
        ? "warning"
        : incidentSeverity === "low" || incidentSeverity === "success"
          ? "success"
          : "info";
  const incidentFocusSource = humanizeSourceName(selected?.source_summary || selected?.source || sampleHost || "n/a", lang);
  const incidentPrimaryAsset = selectedAssets.length
    ? humanizeTechnicalValue(selectedAssets[0], lang)
    : humanizeTechnicalValue(selected?.entity_key || "n/a", lang);
  const incidentRangeLabel = `${formatIncidentTimestamp(selected?.ts_first || selected?.ts)} -> ${formatIncidentTimestamp(selected?.ts_last || selected?.ts)}`;
  const incidentDuration = durationLabel(selected?.ts_first || selected?.ts, selected?.ts_last || selected?.ts);
  const incidentRiskScore = Number(incidentRisk.risk_score || 0);
  const primaryRuleSignal = [
    selected?.rule_name,
    incidentSummary.source_category,
    sampleCategory,
  ].join(" ").toLowerCase();
  const isNetworkIncident = /\b(network|dns|doh|dot|suricata|port|scan|destination|ioc|indicator)\b/.test(primaryRuleSignal);
  const isAuthIncident = /\b(auth|login|logon|ssh|credential|brute|password|privilege|sudo)\b/.test(primaryRuleSignal);
  const isProcessIncident = /\b(process|powershell|wmi|lolbin|defender|execution|script|cmd|proc-)\b/.test(primaryRuleSignal);
  const shouldShowNetworkContext = isNetworkIncident && (
    Number(networkContext.unique_source_ip_count || 0) ||
    Number(networkContext.unique_destination_ip_count || 0) ||
    Number(networkContext.unique_destination_port_count || 0)
  );
  const shouldShowAuthenticationContext = isAuthIncident && (
    Number(authenticationContext.auth_event_count || 0) ||
    Number(authenticationContext.failed_login_count || 0) ||
    Number(authenticationContext.successful_login_count || 0)
  );
  const shouldShowCommandEvidence = isProcessIncident && commandEvidenceRows.length > 0;
  const shouldShowProcessContext = isProcessIncident && processEventRows.length > 0 && !shouldShowCommandEvidence;
  return (
    <div className="react-page react-page-incidents native-page">
      <NativePageHeader
        title={pageTitle}
        icon="incidents"
        actions={(
          <>
            <button type="button" className="react-icon-button" onClick={copyCurrentViewLink} title={t(lang, { en: "Copy view link", ru: "Скопировать ссылку на вид" })}>↗</button>
            <button type="button" className="react-primary-button" onClick={() => setRefreshToken((value) => value + 1)}>
              {t(lang, { en: "Refresh", ru: "Обновить" })}
            </button>
          </>
        )}
      />

      <div className="native-list-search">
        <label className="native-search-field">
          <Search size={16} aria-hidden="true" />
          <input
            value={query}
            onChange={(event) => { setSelectedId(""); setQuery(event.target.value); }}
            placeholder={t(lang, {
              en: `Search ${view === "raw" ? "alerts" : "incidents"} by rule, source, asset, IOC or assignee`,
              ru: `Поиск ${view === "raw" ? "алертов" : "инцидентов"} по правилу, источнику, активу, IOC или аналитику`,
            })}
          />
        </label>
        <select aria-label={t(lang, { en: "Queue view", ru: "Срез очереди" })} value={scope} onChange={(event) => { setSelectedId(""); setScope(event.target.value as typeof scope); }}>
          <option value="main">{t(lang, { en: "Security queue", ru: "ИБ-очередь" })}</option>
          <option value="health">{t(lang, { en: "Platform health", ru: "Состояние платформы" })}</option>
          <option value="vpn-noise">{t(lang, { en: "VPN noise", ru: "VPN-шум" })}</option>
        </select>
        <select aria-label={t(lang, { en: "Time range", ru: "Период" })} value={windowPreset} onChange={(event) => {
          const value = event.target.value;
          setSelectedId("");
          setWindowPreset(value);
          if (value !== "custom") {
            setFromTs("");
            setToTs("");
          }
        }}>
          {incidentRangeOptions.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}
        </select>
        <select aria-label={t(lang, { en: "Refresh", ru: "Обновление" })} value={refreshSeconds} onChange={(event) => setRefreshSeconds(event.target.value)}>
          {refreshOptions(lang).map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}
        </select>
        <select aria-label={t(lang, { en: "Rows", ru: "Строк" })} value={limit} onChange={(event) => { setSelectedId(""); setLimit(Number(event.target.value)); }}>
          {rowOptions().map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}
        </select>
        <button type="button" className="react-link-button" onClick={resetViewState}>{t(lang, { en: "Reset", ru: "Сбросить" })}</button>
      </div>
      {windowPreset === "custom" ? (
        <div className="native-custom-range">
          <label><span>{t(lang, { en: "From", ru: "От" })}</span><input type="datetime-local" value={fromTs} onChange={(event) => setFromTs(event.target.value)} /></label>
          <label><span>{t(lang, { en: "To", ru: "До" })}</span><input type="datetime-local" value={toTs} onChange={(event) => setToTs(event.target.value)} /></label>
        </div>
      ) : null}

      <NativeActionBar
        primary={(
          <>
            <input className="native-assignee-input" value={bulkAssignee} onChange={(event) => setBulkAssignee(event.target.value)} placeholder={t(lang, { en: "Assignee", ru: "Ответственный" })} />
            <button type="button" className="react-link-button" disabled={!selectedRowIds.length} onClick={() => void runBulkUpdate("assign")}>
              {t(lang, { en: "Assign", ru: "Назначить" })}
            </button>
            <button type="button" className="react-link-button" disabled={!selectedRowIds.length} onClick={() => void runBulkUpdate("close")}>
              {t(lang, { en: "Close", ru: "Закрыть" })}
            </button>
          </>
        )}
        meta={(
          <>
            <span>{t(lang, { en: "Found", ru: "Найдено" })}: <strong>{availableIncidentCount}</strong></span>
            <span>{t(lang, { en: "Selected", ru: "Выбрано" })}: <strong>{selectedRowIds.length}</strong></span>
            {scope === "main" ? (
              <span className="native-delivery-state">
                Telegram: {listState.data.notification_delivery?.delivered || 0}/{listState.data.notification_delivery?.queue_count || returnedIncidentCount}
                <StatusBadge value={!listState.data.notification_delivery?.synchronized ? "pending" : "synchronized"} />
              </span>
            ) : null}
          </>
        )}
      />
      {bulkState || viewState ? <div className="native-operation-state">{bulkState || viewState}</div> : null}

      <section className="native-grid native-incident-grid">
        <div
          ref={windowedRows.containerRef}
          className={`react-table-wrap react-incidents-table-wrap ${windowedRows.isWindowed ? "react-table-window windowed" : ""}`}
        >
          <table className="react-table react-table-windowed" role="table" aria-label={String(pageTitle)} aria-rowcount={items.length} aria-colcount={9}>
            <thead>
              <tr role="row">
                <th className="native-check"><input type="checkbox" aria-label={t(lang, { en: "Select all rows", ru: "Выбрать все строки" })} checked={allRowsSelected} onChange={(event) => setSelectedRowIds(event.target.checked ? items.map((row) => incidentRowId(row, view)) : [])} /></th>
                <th role="columnheader">{t(lang, { en: "Severity", ru: "Важность" })}</th>
                <th role="columnheader">{t(lang, { en: "Name", ru: "Название" })}</th>
                <th role="columnheader">{t(lang, { en: "Status", ru: "Статус" })}</th>
                <th role="columnheader">{t(lang, { en: "Assignee", ru: "Ответственный" })}</th>
                <th role="columnheader">{view === "raw" ? t(lang, { en: "Incident", ru: "Инцидент" }) : t(lang, { en: "Alerts", ru: "Алерты" })}</th>
                <th role="columnheader">{t(lang, { en: "Source", ru: "Источник" })}</th>
                <th role="columnheader">{t(lang, { en: "First seen", ru: "Первое появление" })}</th>
                <th role="columnheader">{t(lang, { en: "Last seen", ru: "Последняя активность" })}</th>
              </tr>
            </thead>
            <tbody>
              {windowedRows.topSpacerHeight ? (
                <tr className="react-table-spacer" aria-hidden="true">
                  <td colSpan={9} style={{ height: `${windowedRows.topSpacerHeight}px` }} />
                </tr>
              ) : null}
              {windowedRows.visibleRows.map((row: IncidentRecord, visibleIndex: number) => {
                const absoluteIndex = windowedRows.startIndex + visibleIndex;
                const rowId = incidentRowId(row, view);
                return (
                  <tr key={`${rowId}-${absoluteIndex}`} role="row" className={rowId === selectedId ? "selected" : ""} onClick={() => { setSelectedId(rowId); setDrawerOpen(true); }}>
                    <td className="native-check" role="cell"><input type="checkbox" aria-label={`${t(lang, { en: "Select", ru: "Выбрать" })} ${rowId}`} checked={selectedRowIds.includes(rowId)} onClick={(event) => event.stopPropagation()} onChange={(event) => setSelectedRowIds((current) => event.target.checked ? [...new Set([...current, rowId])] : current.filter((id) => id !== rowId))} /></td>
                    <td role="cell"><SeverityBadge value={row.severity_agg || row.severity || "info"} /></td>
                    <td role="cell"><button type="button" className="native-primary-cell" onClick={() => { setSelectedId(rowId); setDrawerOpen(true); }}><strong>{localizeRuleName(row.rule_name, lang)}</strong><small>{rowId}</small></button></td>
                    <td role="cell"><StatusBadge value={row.status || "new"} /></td>
                    <td role="cell">{row.assignee || "n/a"}</td>
                    <td role="cell">{view === "raw" ? String(row.agg_id || "—") : Number(row.count_alerts || row.hits || row.raw_hits_total || 0)}</td>
                    <td role="cell">{row.source_summary || row.source || "n/a"}</td>
                    <td role="cell">{formatIncidentTimestamp(row.ts_first || row.ts)}</td>
                    <td role="cell">{formatIncidentTimestamp(row.ts_last || row.ts)}</td>
                  </tr>
                );
              })}
              {windowedRows.bottomSpacerHeight ? (
                <tr className="react-table-spacer" aria-hidden="true">
                  <td colSpan={9} style={{ height: `${windowedRows.bottomSpacerHeight}px` }} />
                </tr>
              ) : null}
            </tbody>
          </table>
        </div>
      </section>
      <NativePager shown={returnedIncidentCount} total={availableIncidentCount} lang={lang} />
      <DrawerOverlay
        open={drawerOpen && !!selectedId}
        title={t(lang, { en: "Incident details", ru: "Детали инцидента" })}
        subtitle={t(lang, { en: "SOC triage view: summary first, evidence collapsed below.", ru: "Рабочий экран SOC: сводка сверху, evidence ниже свернутыми блоками." })}
        onClose={() => setDrawerOpen(false)}
        panelClassName="react-drawer-panel-wide react-incidents-drawer-panel"
      >
        {selected ? (
          <div className="react-incidents-drawer-layout">
            <div className="react-card react-card-nested react-incidents-drawer-summary">
              <PanelHeader
                title={t(lang, { en: "Operational snapshot", ru: "Оперативная сводка" })}
                subtitle={t(lang, { en: "Priority, ownership and main investigation focus.", ru: "Приоритет, владение и главный фокус расследования." })}
              />
              <div className="react-investigation-summary-strip react-incidents-drawer-summary-strip">
                <div className={`react-investigation-summary tone-${incidentSeverityTone}`}>
                  <span className="react-investigation-summary-label">{t(lang, { en: "Severity", ru: "Важность" })}</span>
                  <div className="react-investigation-summary-value">
                    <SeverityBadge value={incidentSeverity} />
                  </div>
                </div>
                <div className="react-investigation-summary tone-info">
                  <span className="react-investigation-summary-label">{t(lang, { en: "Status", ru: "Статус" })}</span>
                  <div className="react-investigation-summary-value">
                    <StatusBadge value={selected.status || "new"} />
                  </div>
                </div>
                <div className="react-investigation-summary tone-default">
                  <span className="react-investigation-summary-label">{t(lang, { en: "Assignee", ru: "Ответственный" })}</span>
                  <div className="react-investigation-summary-value">{selected.assignee || t(lang, { en: "unassigned", ru: "не назначен" })}</div>
                </div>
                <div className="react-investigation-summary tone-default">
                  <span className="react-investigation-summary-label">{t(lang, { en: "Raw hits", ru: "Сырые совпадения" })}</span>
                  <div className="react-investigation-summary-value">{selected.raw_hits_total || selected.hits || 0}</div>
                </div>
                <div className="react-investigation-summary tone-default react-incidents-drawer-summary-wide">
                  <span className="react-investigation-summary-label">{t(lang, { en: "Primary focus", ru: "Главный фокус" })}</span>
                  <div className="react-investigation-summary-value">{incidentFocusSource}</div>
                </div>
              </div>
              <div className="react-incidents-drawer-focus-note">
                <strong>{localizeRuleName(selected.rule_name, lang)}</strong>
                <span>
                  {incidentPrimaryAsset}
                  {" • "}
                  {incidentRangeLabel}
                </span>
              </div>
            </div>

            {evidenceState.loading && !evidenceState.data ? (
              <div className="react-inline-note">
                {t(lang, {
                  en: "Summary is ready. Related events and evidence are loading in the background.",
                  ru: "Сводка готова. Связанные события и доказательства загружаются в фоне.",
                })}
              </div>
            ) : null}
            {evidenceState.error ? (
              <div className="react-inline-note">
                {incidentEvidenceError(evidenceState.error, lang)}
              </div>
            ) : null}

            {shouldShowCommandEvidence ? (
              <div className="react-card react-card-nested">
                <PanelHeader title="Command highlights" subtitle="Most relevant executed commands extracted from related events." />
                <div className="react-list react-list-compact">
                  {commandEvidenceRows.slice(0, 3).map((row, index) => (
                    <div key={`${row.event_id || index}-command-highlight`} className="react-history-item">
                      <strong>{formatIncidentTimestamp(row.ts)}</strong>
                      <span>{displayValue(row.host_name)}</span>
                      <span>{displayValue(row.process_name || row.process_executable)}</span>
                      <span style={{ overflowWrap: "anywhere" }}>{displayValue(row.process_command)}</span>
                    </div>
                  ))}
                </div>
              </div>
            ) : null}

            <div className="react-card react-card-nested">
              <PanelHeader title="Incident header" subtitle="Core fields required for SOC triage." />
              <DrawerFieldGrid>
                <KeyValue label="Incident ID" value={displayValue(selected.agg_id || selected.alert_id || selectedId)} />
                <KeyValue label="Name" value={displayValue(selected.title || selected.rule_name)} />
                <KeyValue label="Rule ID" value={displayValue(selected.rule_id)} />
                <KeyValue label="Rule name" value={displayValue(localizeRuleName(selected.rule_name, lang))} />
                <KeyValue label="First seen" value={formatIncidentTimestamp(selected.ts_first || selected.ts)} />
                <KeyValue label="Last seen" value={formatIncidentTimestamp(selected.ts_last || selected.ts)} />
                <KeyValue label="Duration" value={incidentDuration} />
                <KeyValue label="Alert count" value={displayValue(totalRawAlerts)} />
                <KeyValue label="Event count" value={displayValue(totalRelatedEvents)} />
                <KeyValue label="Main entity" value={displayValue(selected.entity_key)} />
                <KeyValue label="Source category" value={displayValue(incidentSummary.source_category || sampleCategory)} />
                <KeyValue label="Detection type" value={view === "raw" ? "Raw alert" : "Aggregated stream/batch correlation"} />
              </DrawerFieldGrid>
            </div>

            <div className="react-card react-card-nested">
              <PanelHeader title="Summary" subtitle="Analytical explanation without opening raw JSON." />
              <InfoList
                items={[
                  { label: "Description", value: displayValue(incidentSummary.description) },
                  { label: "Trigger reason", value: displayValue(incidentSummary.trigger_reason) },
                  { label: "Main entity", value: displayValue(incidentSummary.main_entity || selected.entity_key) },
                  { label: "Unique entities", value: displayValue(incidentSummary.unique_entities || selected.unique_entities) },
                  { label: "Time range", value: displayValue(incidentSummary.time_range || incidentRangeLabel) },
                  { label: "MITRE tactic", value: displayValue(incidentSummary.mitre_tactic) },
                  { label: "MITRE technique", value: displayValue(incidentSummary.mitre_technique) },
                  { label: "Business risk", value: displayValue(incidentSummary.business_risk) },
                  { label: "Primary action", value: displayValue(incidentSummary.recommended_primary_action) },
                ]}
              />
              {Array.isArray(incidentSummary.key_indicators) && incidentSummary.key_indicators.length ? (
                <div className="react-chip-row">
                  {incidentSummary.key_indicators.map((item) => <span key={String(item)} className="react-chip">{String(item)}</span>)}
                </div>
              ) : null}
            </div>

            <div className="react-card react-card-nested">
              <PanelHeader title="Severity & risk" subtitle="Technical severity, confidence, risk score and SOC priority." />
              {incidentRiskScore >= 80 ? <div className="react-inline-note react-inline-note-spaced">Высокий риск. Требуется приоритетная обработка инцидента.</div> : null}
              <DrawerFieldGrid>
                <KeyValue label="Severity" value={displayValue(incidentRisk.severity || incidentSeverity)} />
                <KeyValue label="Severity score" value={displayValue(incidentRisk.severity_score)} />
                <KeyValue label="Confidence" value={displayValue(incidentRisk.confidence)} />
                <KeyValue label="Risk score" value={displayValue(incidentRisk.risk_score)} />
                <KeyValue label="Impact" value={displayValue(incidentRisk.impact)} />
                <KeyValue label="Urgency" value={displayValue(incidentRisk.urgency)} />
                <KeyValue label="Priority" value={displayValue(incidentRisk.priority)} />
                <KeyValue label="Escalation reason" value={displayValue(incidentRisk.escalation_reason)} />
              </DrawerFieldGrid>
            </div>

            {entityUsers.length || entityHosts.length || entityIps.length || entityProcesses.length ? (
              <div className="react-card react-card-nested">
                <PanelHeader title="Affected entities" subtitle="Users, hosts, IP addresses and processes extracted from raw alerts and related events." />
                <DrawerFieldGrid>
                  <KeyValue label="Users" value={entityUsers.map((item) => displayValue(item["user.name"])).join(", ") || "Не определено"} />
                  <KeyValue label="Hosts" value={entityHosts.map((item) => displayValue(item["host.name"])).join(", ") || "Не определено"} />
                  <KeyValue label="IP addresses" value={entityIps.map((item) => displayValue(item.ip)).join(", ") || "Не определено"} />
                  <KeyValue label="Processes" value={entityProcesses.map((item) => displayValue(item["process.name"])).join(", ") || "Не определено"} />
                </DrawerFieldGrid>
              </div>
            ) : null}

            {shouldShowNetworkContext ? (
              <div className="react-card react-card-nested">
                <PanelHeader title="Network context" subtitle="Source/destination IPs, ports and log sources extracted for this incident." />
                <DrawerFieldGrid>
                  <KeyValue label="Source IPs" value={displayList(networkContext.source_ips)} />
                  <KeyValue label="Destination IPs" value={displayList(networkContext.destination_ips)} />
                  <KeyValue label="Destination ports" value={displayList(networkContext.destination_ports)} />
                  <KeyValue label="Log sources" value={displayList(networkContext.log_sources)} />
                  <KeyValue label="Unique source IPs" value={displayValue(networkContext.unique_source_ip_count)} />
                  <KeyValue label="Unique destination IPs" value={displayValue(networkContext.unique_destination_ip_count)} />
                  <KeyValue label="External source IPs" value={displayValue(networkContext.external_source_ip_count)} />
                  <KeyValue label="External destination IPs" value={displayValue(networkContext.external_destination_ip_count)} />
                </DrawerFieldGrid>
              </div>
            ) : null}

            {shouldShowAuthenticationContext ? (
              <details className="react-details">
                <summary>Authentication context</summary>
                <div className="react-card react-card-nested">
                  <DrawerFieldGrid>
                    <KeyValue label="Auth events" value={displayValue(authenticationContext.auth_event_count)} />
                    <KeyValue label="Failed logins" value={displayValue(authenticationContext.failed_login_count)} />
                    <KeyValue label="Successful logins" value={displayValue(authenticationContext.successful_login_count)} />
                    <KeyValue label="Unique source IPs" value={displayValue(authenticationContext.unique_source_ip_count)} />
                    <KeyValue label="Unique hosts" value={displayValue(authenticationContext.unique_host_count)} />
                    <KeyValue label="First auth event" value={formatIncidentTimestamp(authenticationContext.first_auth_event)} />
                    <KeyValue label="Last auth event" value={formatIncidentTimestamp(authenticationContext.last_auth_event)} />
                  </DrawerFieldGrid>
                </div>
              </details>
            ) : null}

            {shouldShowProcessContext ? (
              <div className="react-card react-card-nested">
                <PanelHeader title="Process context" subtitle="Process evidence extracted from related normalized events." />
                <div className="react-table-wrap">
                  <table className="react-table">
                    <thead>
                      <tr>
                        <th>Time</th>
                        <th>Host</th>
                        <th>User</th>
                        <th>Process</th>
                        <th>Command/message</th>
                      </tr>
                    </thead>
                    <tbody>
                      {processEventRows.map((row, index) => (
                        <tr key={`${row.event_id || index}-process-context`}>
                          <td>{formatIncidentTimestamp(row.ts)}</td>
                          <td>{displayValue(row.host_name)}</td>
                          <td>{displayValue(row.user_name)}</td>
                          <td>{displayValue(row.process_name || row.process_executable)}</td>
                          <td>{shortText(row.process_command || row.message, 320)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            ) : null}

            {shouldShowCommandEvidence ? (
              <details className="react-details">
                <summary>Executed commands ({commandEvidenceRows.length})</summary>
                <div className="react-card react-card-nested">
                  <div className="react-table-wrap">
                    <table className="react-table">
                      <thead>
                        <tr>
                          <th>Time</th>
                          <th>Host</th>
                          <th>User</th>
                          <th>Process</th>
                          <th>Command</th>
                        </tr>
                      </thead>
                      <tbody>
                        {commandEvidenceRows.map((row, index) => (
                          <tr key={`${row.event_id || index}-command`}>
                            <td>{formatIncidentTimestamp(row.ts)}</td>
                            <td>{displayValue(row.host_name)}</td>
                            <td>{displayValue(row.user_name)}</td>
                            <td>{displayValue(row.process_name || row.process_executable)}</td>
                            <td>
                              <pre style={{ whiteSpace: "pre-wrap", margin: 0, maxWidth: 760 }}>{displayValue(row.process_command)}</pre>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              </details>
            ) : null}

            {incidentTimeline.length ? (
              <div className="react-card react-card-nested">
                <PanelHeader title="Timeline" subtitle="Last timeline events from related events and correlation triggers." />
                <div className="react-table-wrap">
                  <table className="react-table">
                    <thead>
                      <tr>
                        <th>Time</th>
                        <th>Type</th>
                        <th>Source</th>
                        <th>Entity</th>
                        <th>Severity</th>
                        <th>Description</th>
                      </tr>
                    </thead>
                    <tbody>
                      {incidentTimeline.map((row, index) => (
                        <tr key={`${row.event_id || index}-timeline`}>
                          <td>{formatIncidentTimestamp(row.ts)}</td>
                          <td>{displayValue(row.type)}</td>
                          <td>{displayValue(row.source)}</td>
                          <td>{displayValue(row.entity)}</td>
                          <td><SeverityBadge value={String(row.severity || "info")} /></td>
                          <td>{shortText(row.description, 260)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            ) : null}

            {incidentRules.length ? (
              <div className="react-card react-card-nested">
                <PanelHeader title="Triggered rules" subtitle="Runtime rule metadata, grouping and threshold details." />
                <div className="react-table-wrap">
                  <table className="react-table">
                    <thead>
                      <tr>
                        <th>ID</th>
                        <th>Name</th>
                        <th>Type</th>
                        <th>Severity</th>
                        <th>Window</th>
                        <th>Threshold</th>
                        <th>Group by</th>
                        <th>Source</th>
                        <th>MITRE</th>
                        <th>Logic</th>
                      </tr>
                    </thead>
                    <tbody>
                      {incidentRules.map((row) => (
                        <tr key={`rule-${row.rule_id}`}>
                          <td>{displayValue(row.rule_id)}</td>
                          <td>{displayValue(row.rule_name)}</td>
                          <td>{displayValue(row.rule_type)}</td>
                          <td><SeverityBadge value={String(row.severity || "info")} /></td>
                          <td>{displayValue(row.window_s)}</td>
                          <td>{displayValue(row.threshold)}</td>
                          <td>{displayValue(row.group_by)}</td>
                          <td>{shortText(row.source_category || row.source_format, 140)}</td>
                          <td>{shortText([row.mitre_tactic, row.mitre_technique].map((item) => String(item || "").trim()).filter(Boolean).join(" / "), 180)}</td>
                          <td>{shortText(row.logic_summary, 220)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            ) : null}

            <details className="react-details">
              <summary>{t(lang, { en: "Host actions", ru: "Действия по хосту" })}</summary>
              <div className="react-card react-card-nested">
                <PanelHeader
                  title={t(lang, { en: "Host actions", ru: "Действия по хосту" })}
                  subtitle={t(lang, { en: "Manual snapshot and telemetry refresh for the source host.", ru: "Ручной сбор снимка и обновление телеметрии исходного хоста." })}
                />
                {canRunHostAction ? (
                  <div className="react-actions">
                    <button type="button" className="react-link-button" onClick={() => runHostAction("snapshot")}>{t(lang, { en: "Collect host snapshot", ru: "Собрать снимок хоста" })}</button>
                    <button type="button" className="react-link-button" onClick={() => runHostAction("refresh_telemetry")}>{t(lang, { en: "Refresh telemetry", ru: "Освежить телеметрию" })}</button>
                  </div>
                ) : null}
                {hostActionState ? <div className="react-inline-note">{hostActionState}</div> : null}
              </div>
            </details>

            <div className="react-card react-card-nested">
              <PanelHeader title={t(lang, { en: "Workflow", ru: "Рабочий процесс" })} subtitle={t(lang, { en: "Status and ownership update.", ru: "Обновление статуса и владения." })} />
              <div className="react-form-grid">
                <select className="react-select" value={statusValue} onChange={(event) => setStatusValue(event.target.value)}>
                  {allowedStatuses.map((status) => <option key={status} value={status}>{status}</option>)}
                </select>
                <input className="react-input" value={assigneeValue} onChange={(event) => setAssigneeValue(event.target.value)} placeholder={t(lang, { en: "Assignee", ru: "Ответственный" })} />
                <input className="react-input" value={noteValue} onChange={(event) => setNoteValue(event.target.value)} placeholder={t(lang, { en: "Note for history", ru: "Заметка для истории" })} />
              </div>
              {statusRequiresComment(statusValue) ? <div className="react-inline-note react-inline-note-spaced">Комментарий обязателен для этого статуса.</div> : null}
              <div className="react-actions">
                <button type="button" className="react-primary-button" onClick={updateIncident}>{t(lang, { en: "Save", ru: "Сохранить" })}</button>
                <Link className="react-link-button" to={`/events?q=${encodeURIComponent(selected.source_summary || selected.source || selected.entity_key || "")}`}>{t(lang, { en: "Related events", ru: "Связанные события" })}</Link>
                {selectedAssets[0] ? <Link className="react-link-button" to={`/assets?q=${encodeURIComponent(selectedAssets[0])}`}>{t(lang, { en: "Open asset", ru: "Открыть актив" })}</Link> : null}
              </div>
              {mutationState ? <div className="react-inline-note">{mutationState}</div> : null}
            </div>

            <details className="react-details">
              <summary>{t(lang, { en: "History", ru: "История" })} ({(detailData?.history || []).length})</summary>
              <div className="react-card react-card-nested">
                <div className="react-list react-list-compact">
                  {(detailData?.history || []).map((entry: IncidentHistoryEntry, index: number) => (
                    <div key={`${entry.changed_ts}-${index}`} className="react-history-item">
                      <strong>{formatIncidentTimestamp(entry.changed_ts)}</strong>
                      <span>{entry.changed_by || "system"}</span>
                      <span>{entry.previous_status || "n/a"} {"->"} {entry.next_status || "n/a"}</span>
                      <span>{entry.previous_assignee || "n/a"} {"->"} {entry.next_assignee || "n/a"}</span>
                      <span>{entry.note || ""}</span>
                    </div>
                  ))}
                </div>
              </div>
            </details>

            {recommendations.length ? (
              <div className="react-card react-card-nested">
                <PanelHeader title="Recommended response" subtitle="Deterministic response checklist for the analyst." />
                <ol className="react-list react-list-compact">
                  {recommendations.map((item) => <li key={item}>{item}</li>)}
                </ol>
              </div>
            ) : null}

            {rawAlertRows.length ? (
              <details className="react-details">
                <summary>Raw alerts ({totalRawAlerts})</summary>
                <div className="react-card react-card-nested">
                  <div className="react-table-wrap">
                    <table className="react-table">
                      <thead>
                        <tr>
                          <th>Alert ID</th>
                          <th>Time</th>
                          <th>Rule</th>
                          <th>Severity</th>
                          <th>Entity</th>
                          <th>Events</th>
                          <th>Status</th>
                          <th>Dedup</th>
                        </tr>
                      </thead>
                      <tbody>
                        {rawAlertRows.map((row) => (
                          <tr key={String(row.alert_id)}>
                            <td>{shortText(row.alert_id, 80)}</td>
                            <td>{formatIncidentTimestamp(row.ts_last || row.ts)}</td>
                            <td>{displayValue(row.rule_id)} / {displayValue(row.rule_name)}</td>
                            <td><SeverityBadge value={String(row.severity || "info")} /></td>
                            <td>{displayValue(row.entity || row.entity_key)}</td>
                            <td>{displayValue(row.source_event_count || row.hits)}</td>
                            <td><StatusBadge value={String(row.status || "new")} /></td>
                            <td>{shortText(row.dedup_key, 120)}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              </details>
            ) : null}

            {relatedEventRows.length ? (
              <details className="react-details">
                <summary>Related events ({totalRelatedEvents})</summary>
                <div className="react-card react-card-nested">
                  <div className="react-table-wrap">
                    <table className="react-table">
                      <thead>
                        <tr>
                          <th>Event ID</th>
                          <th>Time</th>
                          <th>Category</th>
                          <th>Action</th>
                          <th>Source IP</th>
                          <th>Destination</th>
                          <th>User</th>
                          <th>Host</th>
                          <th>Process / command</th>
                          <th>Message</th>
                        </tr>
                      </thead>
                      <tbody>
                        {relatedEventRows.map((row, index) => (
                          <tr key={`${row.event_id || index}-event`}>
                            <td>{shortText(row.event_id, 80)}</td>
                            <td>{formatIncidentTimestamp(row.ts)}</td>
                            <td>{displayValue(row.category || row.subcategory)}</td>
                            <td>{displayValue(row.event_action || row.event_outcome)}</td>
                            <td>{displayValue(row.src_ip)}</td>
                            <td>{[row.dst_ip, row.dst_port].map((item) => String(item || "").trim()).filter(Boolean).join(":") || "Не определено"}</td>
                            <td>{displayValue(row.user_name || row.target_user)}</td>
                            <td>{displayValue(row.host_name || row.log_source)}</td>
                            <td>{shortText(row.process_command || row.process_name || row.process_executable, 220)}</td>
                            <td>{shortText(row.message, 260)}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              </details>
            ) : null}

            <details className="react-details">
              <summary>Technical debug</summary>
              <JsonPreview value={detailData?.technical_debug || {}} />
            </details>

            <details className="react-details">
              <summary>JSON view</summary>
              <JsonPreview value={detailData?.json_view || detailData || {}} />
            </details>

          </div>
        ) : detailState.loading || detailState.error ? (
          <EmptyState
            message={
              detailState.error ? incidentEvidenceError(detailState.error, lang) :
              t(lang, { en: "Loading incident details...", ru: "Загрузка деталей инцидента..." })
            }
          />
        ) : (
          <EmptyState message={t(lang, { en: "Select an incident to open the drawer.", ru: "Выберите инцидент, чтобы открыть окно." })} />
        )}
      </DrawerOverlay>
    </div>
  );
}
