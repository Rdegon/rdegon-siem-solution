import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { api } from "../api";
import { useFeedback } from "../feedback";
import { readSessionJson, useAsyncData, useDebouncedValue, usePolledData, useWindowedRows, writeSessionJson } from "../hooks";
import {
  BreakdownBars,
  DrawerFieldGrid,
  DrawerOverlay,
  EmptyState,
  JsonPreview,
  InvestigationActionRail,
  InvestigationDrawerSection,
  InvestigationSummaryStrip,
  InvestigationTimeline,
  KeyValue,
  PanelHeader,
  SeverityBadge,
  SparklineChart,
  Icon,
} from "../ui";
import { NativeActionBar, NativePageHeader, NativePager } from "../native";
import { shiftTimeZoneInputValue, t, useShellContext } from "../context";
import { humanizeEventLabel, humanizeSourceName, humanizeTechnicalValue } from "../humanize";
import { refreshIntervalMs, refreshOptions } from "../timeControls";
import type { EventRow, EventsFacetsResponse, EventsQueryResponse, RuntimeBlob, SavedSearchRecord } from "../types";

type Column<TRow> = {
  key: string;
  label: string;
  render: (row: TRow) => ReactNode;
  className?: string;
};

const DEFAULT_COLUMNS = [
  "ts",
  "log_source",
  "collector",
  "severity",
  "category",
  "src_ip",
  "dst_ip",
  "dst_port",
  "user_name",
  "asset_id",
  "device_product",
  "message",
];

function toOffset(page: number, limit: number) {
  return Math.max(0, (Math.max(1, page) - 1) * limit);
}

function asObject(value: unknown): RuntimeBlob {
  if (value && typeof value === "object" && !Array.isArray(value)) return value as RuntimeBlob;
  if (typeof value === "string") {
    try {
      const parsed = JSON.parse(value) as unknown;
      if (parsed && typeof parsed === "object" && !Array.isArray(parsed)) return parsed as RuntimeBlob;
    } catch {
      return {};
    }
  }
  return {};
}

function nestedValue(source: unknown, path: string) {
  let current: unknown = source;
  for (const part of path.split(".")) {
    if (!current || typeof current !== "object") return "";
    current = (current as RuntimeBlob)[part];
  }
  return current;
}

function firstText(...values: unknown[]) {
  for (const value of values) {
    const text = String(value ?? "").trim();
    if (text && text.toLowerCase() !== "n/a") return text;
  }
  return "";
}

function formatTagList(value: unknown) {
  if (Array.isArray(value)) return value.map((item) => String(item || "").trim()).filter(Boolean);
  return String(value || "").split(",").map((item) => item.trim()).filter(Boolean);
}

function looksLikeIp(value: string) {
  const text = String(value || "").trim();
  if (!text) return false;
  return /^\d{1,3}(?:\.\d{1,3}){3}$/.test(text) || /^[a-f0-9:]+$/i.test(text);
}

function flattenDisplayValue(value: unknown): string {
  if (value === null || value === undefined) return "";
  if (Array.isArray(value)) {
    const items: string[] = value
      .map((item) => flattenDisplayValue(item))
      .filter(Boolean)
      .slice(0, 8);
    return items.join(", ");
  }
  if (typeof value === "object") return "";
  const text = String(value).trim();
  if (!text || text.toLowerCase() === "n/a") return "";
  if (text.length > 280) return "";
  return text;
}

function collectFlattenedFields(source: unknown, prefix = "", depth = 0, fields: Record<string, string> = {}) {
  if (!source || depth > 4) return fields;
  if (Array.isArray(source)) {
    const rendered = flattenDisplayValue(source);
    if (prefix && rendered) {
      fields[prefix] = rendered;
    }
    return fields;
  }
  if (typeof source !== "object") {
    const rendered = flattenDisplayValue(source);
    if (prefix && rendered) {
      fields[prefix] = rendered;
    }
    return fields;
  }
  for (const [key, value] of Object.entries(source as RuntimeBlob)) {
    const nextKey = prefix ? `${prefix}.${key}` : key;
    const rendered = flattenDisplayValue(value);
    if (rendered) {
      fields[nextKey] = rendered;
      continue;
    }
    if (value && typeof value === "object") {
      collectFlattenedFields(value, nextKey, depth + 1, fields);
    }
  }
  return fields;
}

export function parseStructuredMessage(message: string) {
  const fields: Record<string, string> = {};
  let section = "";
  for (const rawLine of String(message || "").split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line) continue;
    const sectionMatch = line.match(/^([A-Za-z][A-Za-z ]+):$/);
    if (sectionMatch) {
      section = sectionMatch[1].trim().toLowerCase().replace(/[^a-z0-9]+/g, "_");
      continue;
    }
    const keyValueMatch = line.match(/^([^:]+):\s*(.*)$/);
    if (!keyValueMatch) continue;
    const key = keyValueMatch[1].trim().toLowerCase().replace(/[^a-z0-9]+/g, "_");
    const value = keyValueMatch[2].trim();
    if (!value) continue;
    fields[key] = value;
    if (section) {
      fields[`${section}.${key}`] = value;
    }
  }
  return fields;
}

export function buildEventDetail(row: EventRow | null, lang: "en" | "ru") {
  if (!row) return null;
  const normalized = asObject(row.normalized_json);
  const payload = asObject((row as RuntimeBlob).payload);
  const metadata = asObject((row as RuntimeBlob).metadata);
  const sources = [row as RuntimeBlob, normalized, payload, metadata];
  const pick = (...paths: string[]) => firstText(...paths.flatMap((path) => sources.map((source) => nestedValue(source, path))));
  const message = firstText(
    row.message,
    pick("message", "event.original", "normalized.message", "raw.message", "winlog.event_data.Message", "winlog.event_data.ObjectName"),
  );
  const messageFields = parseStructuredMessage(message);
  const pickMessage = (...paths: string[]) => firstText(...paths.map((path) => messageFields[path]));
  const normalizedFields = {
    ...collectFlattenedFields(normalized),
    ...collectFlattenedFields(payload),
    ...collectFlattenedFields(metadata),
  };
  const rawCategory = String(row.category || "").trim();
  const rawSubcategory = String(row.subcategory || "").trim();
  const categoryLabel =
    rawCategory && rawSubcategory && rawCategory !== rawSubcategory
      ? `${rawCategory} / ${rawSubcategory}`
      : firstText(rawCategory, rawSubcategory, pick("category", "event.category", "type"));
  const rawSrcIp = pick("src_ip", "source.ip", "network.src_ip");
  const rawDstIp = pick("dst_ip", "destination.ip", "network.dst_ip");
  return {
    source: humanizeSourceName(
      pick("log_source", "host_name", "host.name", "source.name", "observer.name", "host", "winlog.computer_name", "computer_name"),
      lang,
    ),
    collector: pick("collector_profile", "observer_collector", "observer.profile", "observer.collector", "collector.profile", "collector.name", "collector"),
    host: humanizeSourceName(pick("host_name", "host.name", "observer.hostname", "computer_name", "host", "winlog.computer_name"), lang),
    category: humanizeEventLabel(categoryLabel, lang),
    severity: pick("severity"),
    asset: humanizeSourceName(
      firstText(
        pick("asset_id", "asset.id", "asset.name", "winlog.computer_name"),
        pickMessage("object.object_name"),
        pick("host_name", "host.name"),
      ),
      lang,
    ),
    assetOwner: pick("asset_owner", "asset.owner", "host.owner"),
    assetService: pick("asset_service", "service.name", "asset.service", "network.domain", "winlog.channel"),
    user: humanizeTechnicalValue(
      pickMessage("object.object_name"),
      lang,
    ) || humanizeTechnicalValue(
      pick(
        "user_name",
        "target_user",
        "user.name",
        "user.target.name",
        "subject.account.name",
        "account.name",
        "winlog.event_data.TargetUserName",
        "winlog.event_data.SubjectUserName",
      ) || pickMessage("subject.account_name"),
      lang,
    ),
    userDomain:
      pick(
        "account_domain",
        "user.domain",
        "subject.account.domain",
        "account.domain",
        "winlog.event_data.TargetDomainName",
        "winlog.event_data.SubjectDomainName",
      ) || pickMessage("subject.account_domain"),
    process: firstText(
      pick("process_name", "process.name", "winlog.event_data.ProcessName", "winlog.event_data.NewProcessName", "winlog.event_data.Image"),
      pickMessage("process_information.process_name"),
      [pick("process_executable", "process.executable"), pick("process_command", "process.command_line")].filter(Boolean).join(" "),
    ),
    processId: firstText(pick("winlog.event_data.ProcessId", "winlog.event_data.NewProcessId"), pickMessage("process_information.process_id")),
    srcIp: looksLikeIp(firstText(rawSrcIp, pick("winlog.event_data.IpAddress", "winlog.event_data.SourceAddress"))) ? firstText(rawSrcIp, pick("winlog.event_data.IpAddress", "winlog.event_data.SourceAddress")) : "",
    srcPort: pick("src_port", "source.port", "network.src_port", "winlog.event_data.IpPort", "winlog.event_data.SourcePort"),
    dstIp: looksLikeIp(firstText(rawDstIp, pick("winlog.event_data.DestinationIp", "winlog.event_data.DestAddress"))) ? firstText(rawDstIp, pick("winlog.event_data.DestinationIp", "winlog.event_data.DestAddress")) : "",
    dstPort: pick("dst_port", "destination.port", "network.dst_port", "winlog.event_data.DestinationPort", "winlog.event_data.DestPort"),
    eventId: pick("event_id", "event.id", "winlog.event_id"),
    eventCode: pick("event_code", "event.code", "winlog.event_id"),
    action: humanizeEventLabel(pick("event_action", "event.action", "action", "winlog.event_data.OperationType", "winlog.event_data.TaskContent"), lang),
    outcome: pick("event_outcome", "event.outcome", "outcome"),
    dataset: pick("event_dataset", "event.dataset", "winlog.channel"),
    device: firstText(
      [pick("device_vendor"), pick("device_product")].filter(Boolean).join(" / "),
      [pick("observer.vendor"), pick("observer.product")].filter(Boolean).join(" / "),
      pick("winlog.provider_name"),
    ),
    tiIndicator: pick("ti_indicator", "threat.indicator", "threat.indicator.ip"),
    tiProvider: pick("ti_provider", "threat.provider", "threat.feed.name"),
    tiSeverity: pick("ti_severity", "threat.severity"),
    objectName: firstText(pick("winlog.event_data.ObjectName"), pickMessage("object.object_name")),
    objectType: firstText(pick("winlog.event_data.ObjectType"), pickMessage("object.object_type")),
    objectServer: firstText(pick("winlog.event_data.ObjectServer"), pickMessage("object.object_server")),
    handleId: firstText(pick("winlog.event_data.HandleId"), pickMessage("object.handle_id")),
    subjectSid: firstText(pick("winlog.event_data.SubjectUserSid"), pickMessage("subject.security_id")),
    logonId: firstText(pick("winlog.event_data.SubjectLogonId", "winlog.event_data.LogonId"), pickMessage("subject.logon_id")),
    message,
    tags: formatTagList(firstText((row as RuntimeBlob).tags, nestedValue(normalized, "tags"), nestedValue(payload, "tags"))),
    messageFields,
    normalizedFields,
    normalized,
  };
}

export function EventsPage() {
  const { lang, formatTimestamp, timezone, toInputDateTime, toUtcQueryValue } = useShellContext();
  const { announce } = useFeedback();
  const location = useLocation();
  const navigate = useNavigate();
  const persistedState = readSessionJson("rdegon-events-view", {
    query: "",
    windowSize: "24h",
    fromTs: "",
    toTs: "",
    storage: "hot",
    limit: 100,
    offset: 0,
    visibleColumns: DEFAULT_COLUMNS,
    savedSearchId: "",
  });
  const [query, setQuery] = useState(() => String(persistedState.query || ""));
  const [windowSize, setWindowSize] = useState(() => String(persistedState.windowSize || "24h"));
  const [fromTs, setFromTs] = useState(() => String(persistedState.fromTs || ""));
  const [toTs, setToTs] = useState(() => String(persistedState.toTs || ""));
    const [storage, setStorage] = useState(() => String(persistedState.storage || "hot"));
    const [limit, setLimit] = useState(() => Number(persistedState.limit || 100));
    const [offset, setOffset] = useState(() => Math.max(0, Number(persistedState.offset || 0)));
    const [reloadToken, setReloadToken] = useState(0);
    const [refreshSeconds, setRefreshSeconds] = useState("0");
    const [drawerOpen, setDrawerOpen] = useState(false);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [selectedIndex, setSelectedIndex] = useState(0);
  const [visibleColumns, setVisibleColumns] = useState<string[]>(() =>
    Array.isArray(persistedState.visibleColumns) && persistedState.visibleColumns.length
      ? persistedState.visibleColumns.map((item) => String(item)).filter(Boolean)
      : DEFAULT_COLUMNS,
  );
  const [savedSearchId, setSavedSearchId] = useState(() => String(persistedState.savedSearchId || ""));
  const [savedSearchState, setSavedSearchState] = useState("");
  const [savedSearchRefresh, setSavedSearchRefresh] = useState(0);
  const debouncedQuery = useDebouncedValue(query, 350);
  const announcedSnapshotRef = useRef("");
  const loadSavedSearches = useCallback(() => {
    void savedSearchRefresh;
    return api.savedSearches();
  }, [savedSearchRefresh]);
  const savedSearches = useAsyncData<{ items: SavedSearchRecord[] }>(loadSavedSearches);
  const offsetResetReady = useRef(false);

  const loadEvents = useCallback(
    () => {
      void reloadToken;
      return api.eventsQuery({
        query: debouncedQuery,
        window: windowSize,
        from_ts: fromTs ? toUtcQueryValue(fromTs) : "",
        to_ts: toTs ? toUtcQueryValue(toTs) : "",
        storage,
        limit,
        offset,
      });
    },
    [debouncedQuery, windowSize, fromTs, toTs, storage, limit, offset, reloadToken, toUtcQueryValue],
  );

  const state = usePolledData<EventsQueryResponse>(loadEvents, refreshIntervalMs(refreshSeconds));
  const loadFacets = useCallback(
    () => {
      void reloadToken;
      return api.eventsFacets({
        query: debouncedQuery,
        window: windowSize,
        from_ts: fromTs ? toUtcQueryValue(fromTs) : "",
        to_ts: toTs ? toUtcQueryValue(toTs) : "",
        storage,
      });
    },
    [debouncedQuery, windowSize, fromTs, toTs, storage, reloadToken, toUtcQueryValue],
  );
  const facetsState = usePolledData<EventsFacetsResponse>(loadFacets, refreshIntervalMs(refreshSeconds));

  useEffect(() => {
    const params = new URLSearchParams(location.search || "");
    if (!params.toString()) return;
    if (params.has("q")) setQuery(String(params.get("q") || "").trim());
    if (params.has("window")) setWindowSize(String(params.get("window") || "24h").trim() || "24h");
    if (params.has("from")) setFromTs(toInputDateTime(String(params.get("from") || "").trim()));
    if (params.has("to")) setToTs(toInputDateTime(String(params.get("to") || "").trim()));
    if (params.has("storage")) setStorage(String(params.get("storage") || "hot").trim() || "hot");
    if (params.has("limit")) {
      const nextLimit = Number(params.get("limit") || 100);
      if (Number.isFinite(nextLimit) && nextLimit > 0) setLimit(nextLimit);
    }
    if (params.has("offset")) {
      const nextOffset = Number(params.get("offset") || 0);
      if (Number.isFinite(nextOffset) && nextOffset >= 0) setOffset(nextOffset);
    }
    if (params.has("saved")) setSavedSearchId(String(params.get("saved") || "").trim());
  }, [location.search, toInputDateTime]);

  useEffect(() => {
    const previousTimezone = window.sessionStorage.getItem("rdegon-events-timezone") || timezone;
    if (previousTimezone === timezone) {
      window.sessionStorage.setItem("rdegon-events-timezone", timezone);
      return;
    }
    setFromTs((current) => (current ? shiftTimeZoneInputValue(current, previousTimezone, timezone) : current));
    setToTs((current) => (current ? shiftTimeZoneInputValue(current, previousTimezone, timezone) : current));
    window.sessionStorage.setItem("rdegon-events-timezone", timezone);
  }, [timezone]);

  useEffect(() => {
    if (!offsetResetReady.current) {
      offsetResetReady.current = true;
      return;
    }
    setOffset(0);
  }, [debouncedQuery, windowSize, storage, limit, fromTs, toTs]);

  useEffect(() => {
    const params = new URLSearchParams();
    if (query.trim()) params.set("q", query.trim());
    if (windowSize && windowSize !== "24h") params.set("window", windowSize);
    if (fromTs) params.set("from", toUtcQueryValue(fromTs));
    if (toTs) params.set("to", toUtcQueryValue(toTs));
    if (storage !== "hot") params.set("storage", storage);
    if (limit !== 100) params.set("limit", String(limit));
    if (offset > 0) params.set("offset", String(offset));
    if (savedSearchId) params.set("saved", savedSearchId);
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
    writeSessionJson("rdegon-events-view", {
      query,
      windowSize,
      fromTs,
      toTs,
      storage,
      limit,
      offset,
      visibleColumns,
      savedSearchId,
    });
  }, [
    fromTs,
    limit,
    location.pathname,
    location.search,
    navigate,
    offset,
    query,
    savedSearchId,
    storage,
    toTs,
    toUtcQueryValue,
    visibleColumns,
    windowSize,
  ]);

  useEffect(() => {
    setSelectedIndex(0);
  }, [state.data?.offset, state.data?.row_count]);

  useEffect(() => {
    if (!(state.data?.rows || []).length) {
      setDrawerOpen(false);
    }
  }, [state.data?.rows]);

  const rows = state.data?.rows || [];
  const facets = facetsState.data || state.data || {};
  const savedSearchItems = savedSearches.data?.items || [];
  const selected = rows[selectedIndex] || null;
  const windowedRows = useWindowedRows(rows, {
    rowHeight: 48,
    overscan: 12,
    enabled: rows.length > 120,
    defaultHeight: 560,
  });

  const availableColumns = useMemo<Column<EventRow>[]>(
    () => [
      { key: "ts", label: t(lang, { en: "Time", ru: "Время" }), render: (row) => formatTimestamp(row.ts, "full") },
      { key: "log_source", label: t(lang, { en: "Source", ru: "Источник" }), render: (row) => <strong>{humanizeSourceName(row.log_source || "n/a", lang)}</strong> },
      { key: "collector", label: t(lang, { en: "Collector", ru: "Коллектор" }), render: (row) => row.collector_profile || row.observer_collector || "n/a" },
      { key: "severity", label: t(lang, { en: "Severity", ru: "Важность" }), render: (row) => <SeverityBadge value={row.severity || "info"} /> },
      { key: "category", label: t(lang, { en: "Category", ru: "Категория" }), render: (row) => humanizeEventLabel(`${row.category || "n/a"} / ${row.subcategory || "n/a"}`, lang) },
      { key: "src_ip", label: "Src IP", render: (row) => row.src_ip || "n/a" },
      { key: "dst_ip", label: "Dst IP", render: (row) => row.dst_ip || "n/a" },
      { key: "dst_port", label: t(lang, { en: "Dst port", ru: "Порт назначения" }), render: (row) => row.dst_port || "n/a" },
      { key: "user_name", label: t(lang, { en: "User", ru: "Пользователь" }), render: (row) => humanizeTechnicalValue(row.user_name || row.target_user || "n/a", lang) },
      { key: "asset_id", label: t(lang, { en: "Asset", ru: "Актив" }), render: (row) => humanizeSourceName(row.asset_id || "n/a", lang) },
      { key: "device_product", label: t(lang, { en: "Product", ru: "Продукт" }), render: (row) => row.device_product || "n/a" },
      { key: "message", label: t(lang, { en: "Message", ru: "Сообщение" }), render: (row) => row.message || "n/a", className: "react-cell-clamp" },
    ],
    [formatTimestamp, lang],
  );

  const activeColumns = useMemo(
    () => availableColumns.filter((column) => visibleColumns.includes(column.key)),
    [availableColumns, visibleColumns],
  );
  const selectedDetail = useMemo(() => buildEventDetail(selected, lang), [lang, selected]);
  const selectedEventSummary = useMemo(
    () =>
      selectedDetail
        ? [
            { label: t(lang, { en: "Time", ru: "Время" }), value: formatTimestamp(selected?.ts, "full"), tone: "info" as const },
            { label: t(lang, { en: "Source", ru: "Источник" }), value: selectedDetail.source || "n/a" },
            { label: t(lang, { en: "Severity", ru: "Важность" }), value: <SeverityBadge value={selectedDetail.severity || "info"} />, tone: String(selectedDetail.severity || "").toLowerCase() === "critical" ? ("critical" as const) : ("warning" as const) },
            { label: t(lang, { en: "User", ru: "Пользователь" }), value: selectedDetail.user || "n/a" },
            { label: t(lang, { en: "Asset", ru: "Актив" }), value: selectedDetail.asset || "n/a" },
            { label: "TI", value: selectedDetail.tiIndicator || "n/a", tone: selectedDetail.tiIndicator ? ("warning" as const) : ("default" as const) },
          ]
        : [],
    [formatTimestamp, lang, selected, selectedDetail],
  );
  const selectedEventActions = useMemo(() => {
    if (!selected || !selectedDetail) return [];
    const actions = [] as Array<{ label: string; href?: string; onClick?: () => void; tone?: "warning" }>;
    if (selected.log_source) {
      actions.push({
        label: `${t(lang, { en: "Source", ru: "Источник" })}: ${humanizeSourceName(selected.log_source, lang, { technicalSuffix: false })}`,
        onClick: () => applyQuickQuery(`log_source = '${String(selected.log_source).replace(/'/g, "''")}'`),
      });
    }
    if (selected.src_ip) {
      actions.push({
        label: `src:${selected.src_ip}`,
        onClick: () => applyQuickQuery(`src_ip = '${String(selected.src_ip).replace(/'/g, "''")}'`),
      });
    }
    if (selected.dst_ip) {
      actions.push({
        label: `dst:${selected.dst_ip}`,
        onClick: () => applyQuickQuery(`dst_ip = '${String(selected.dst_ip).replace(/'/g, "''")}'`),
      });
    }
    if (selected.user_name) {
      actions.push({
        label: `${t(lang, { en: "User", ru: "Пользователь" })}: ${humanizeTechnicalValue(selected.user_name, lang)}`,
        onClick: () => applyQuickQuery(`user_name = '${String(selected.user_name).replace(/'/g, "''")}'`),
      });
    }
    if (selected.asset_id) {
      actions.push({
        label: `${t(lang, { en: "Asset", ru: "Актив" })}: ${humanizeSourceName(selected.asset_id, lang, { technicalSuffix: false })}`,
        href: `/app/assets?focus=${encodeURIComponent(String(selected.asset_id))}`,
      });
    }
    if (selectedDetail.srcIp || selectedDetail.dstIp) {
      actions.push({
        label: t(lang, { en: "Open in TI", ru: "Открыть в TI" }),
        href: `/app/threat-intel?q=${encodeURIComponent(selectedDetail.srcIp || selectedDetail.dstIp || "")}`,
        tone: "warning",
      });
    }
    return actions;
  }, [lang, selected, selectedDetail]);
  const selectedEventTimeline = useMemo(() => {
    if (!selected || !selectedDetail) return [];
    const messageFields = Object.entries(selectedDetail.messageFields || {}).slice(0, 6);
    const normalizedFields = Object.entries(selectedDetail.normalizedFields || {}).slice(0, 8);
    return [
      {
        id: "event-envelope",
        title: t(lang, { en: "Observed event", ru: "Наблюдаемое событие" }),
        subtitle: `${selected.category || "event"} / ${selected.subcategory || "record"}${selected.device_product ? ` / ${selected.device_product}` : ""}`,
        meta: formatTimestamp(selected.ts, "compact"),
        tone: String(selected.severity || "").toLowerCase() === "critical" ? ("critical" as const) : ("info" as const),
        body: selectedDetail.message,
      },
      {
        id: "identity-context",
        title: t(lang, { en: "Identity and asset context", ru: "Контекст идентичности и актива" }),
        subtitle: [selectedDetail.user, selectedDetail.userDomain, selectedDetail.asset, selectedDetail.assetOwner].filter(Boolean).join(" · "),
        meta: selectedDetail.collector || "collector",
        body: [selectedDetail.assetService, selectedDetail.host, selectedDetail.device].filter(Boolean).join(" · ") || t(lang, { en: "No additional identity context.", ru: "Дополнительный контекст не найден." }),
      },
      {
        id: "network-path",
        title: t(lang, { en: "Network path", ru: "Сетевой путь" }),
        subtitle: [selectedDetail.srcIp || "n/a", selectedDetail.dstIp || "n/a"].join(" → "),
        meta: selectedDetail.dstPort ? `port ${selectedDetail.dstPort}` : "flow",
        tone: selectedDetail.dstIp ? ("warning" as const) : ("default" as const),
        body: [selectedDetail.srcPort ? `src:${selectedDetail.srcPort}` : "", selectedDetail.action || "", selectedDetail.outcome || ""].filter(Boolean).join(" · ") || t(lang, { en: "No network enrichment captured.", ru: "Сетевое обогащение отсутствует." }),
      },
      {
        id: "enrichment",
        title: t(lang, { en: "Parsed enrichment", ru: "Разобранное обогащение" }),
        subtitle: messageFields.length ? messageFields.map(([key]) => key).join(", ") : t(lang, { en: "Normalized payload fields", ru: "Поля нормализованного payload" }),
        meta: normalizedFields.length ? `${normalizedFields.length} fields` : "raw",
        body:
          (messageFields.length
            ? messageFields.map(([key, value]) => `${key}: ${value}`).join(" · ")
            : normalizedFields.map(([key, value]) => `${key}: ${value}`).join(" · ")) ||
          t(lang, { en: "No structured enrichment available.", ru: "Структурированное обогащение отсутствует." }),
      },
    ];
  }, [formatTimestamp, lang, selected, selectedDetail]);

  const pagination = useMemo(() => {
    const page = Number(state.data?.page || 1);
    const totalPages = Number(state.data?.total_pages || 1);
    return {
      page,
      totalPages,
      canPrev: page > 1,
      canNext: page < totalPages,
    };
  }, [state.data?.page, state.data?.total_pages]);
  const { scrollToIndex } = windowedRows;

  useEffect(() => {
    if (!rows.length) return;
    scrollToIndex(selectedIndex);
  }, [rows.length, scrollToIndex, selectedIndex]);

  useEffect(() => {
    if (state.loading || !state.data) return;
    const snapshot = `${state.data.row_count}:${state.data.total_count}:${state.data.page}:${storage}:${windowSize}`;
    if (announcedSnapshotRef.current === snapshot) return;
    announcedSnapshotRef.current = snapshot;
    announce(
      t(lang, {
        en: `Event results updated. ${state.data.total_count || state.data.row_count || 0} rows matched the current query.`,
        ru: `Результаты событий обновлены. Текущий запрос вернул ${state.data.total_count || state.data.row_count || 0} строк.`,
      }),
    );
  }, [announce, lang, state.data, state.loading, storage, windowSize]);

  function applyQuickQuery(next: string) {
    setSavedSearchId("");
    setQuery(next);
    setOffset(0);
    setReloadToken((value) => value + 1);
  }

  function applyPreset(next: string) {
    setSavedSearchId("");
    setWindowSize(next);
    if (next !== "custom") {
      setFromTs("");
      setToTs("");
    }
    setOffset(0);
  }

  function goToPage(nextPage: number) {
    setOffset(toOffset(nextPage, limit));
  }

  function toggleColumn(columnKey: string) {
    setVisibleColumns((current) =>
      current.includes(columnKey) ? current.filter((item) => item !== columnKey) : [...current, columnKey],
    );
  }

  function applySavedSearch(item: SavedSearchRecord) {
    setSavedSearchId(String(item.id || ""));
    setQuery(String(item.query || ""));
    setStorage(String(item.storage || "hot"));
    setWindowSize(String(item.window || "24h") || "24h");
    setFromTs("");
    setToTs("");
    setOffset(0);
    setSavedSearchState(
      `${t(lang, { en: "Applied saved view", ru: "Применен сохраненный вид" })}: ${item.title || item.id}`,
    );
  }

  function resetQueryState() {
    setSavedSearchId("");
    setQuery("");
    setWindowSize("24h");
    setFromTs("");
    setToTs("");
    setStorage("hot");
    setLimit(100);
    setOffset(0);
    setSavedSearchState(t(lang, { en: "Reset to default event view", ru: "Сброшено к базовому виду событий" }));
  }

  async function saveCurrentSearch() {
    const defaultTitle = query.trim()
      ? query.trim().slice(0, 48)
      : `events-${new Date().toISOString().slice(0, 16).replace("T", "-")}`;
    const title = window.prompt(
      t(lang, {
        en: "Saved search title",
        ru: "Название сохраненного поиска",
      }),
      defaultTitle,
    );
    if (!title || !title.trim()) return;
    setSavedSearchState(t(lang, { en: "Saving current view...", ru: "Сохраняю текущий вид..." }));
    try {
      const payload = await api.saveSavedSearch({
        title: title.trim(),
        description:
          fromTs || toTs
            ? `${t(lang, { en: "Custom range", ru: "Кастомный диапазон" })}: ${fromTs || "?"} -> ${toTs || "?"}`
            : t(lang, { en: "Events page saved view", ru: "Сохраненный вид страницы событий" }),
        query,
        storage,
        window: windowSize,
        tags: ["events", storage, windowSize],
      });
      setSavedSearchId(String(payload.id || ""));
      setSavedSearchRefresh((value) => value + 1);
      setSavedSearchState(`${t(lang, { en: "Saved view", ru: "Сохраненный вид" })}: ${payload.title || title.trim()}`);
    } catch (error: unknown) {
      setSavedSearchState(error instanceof Error ? error.message : "Unable to save current view");
    }
  }

  function exportCurrentRows() {
    if (!rows.length) return;
    const keys = activeColumns.map((column) => column.key);
    const escape = (value: unknown) => {
      const text = typeof value === "object" && value !== null ? JSON.stringify(value) : String(value ?? "");
      return `"${text.replace(/"/g, "\"\"")}"`;
    };
    const content = [
      keys.join("\t"),
      ...rows.map((row) => keys.map((key) => escape((row as RuntimeBlob)[key === "collector" ? "collector_profile" : key])).join("\t")),
    ].join("\n");
    const blob = new Blob([content], { type: "text/tab-separated-values;charset=utf-8" });
    const anchor = document.createElement("a");
    anchor.href = URL.createObjectURL(blob);
    anchor.download = `rdegon-events-${new Date().toISOString().replace(/[:.]/g, "-")}.tsv`;
    anchor.click();
    URL.revokeObjectURL(anchor.href);
  }

  return (
    <div className="react-page react-page-events native-page">
      <NativePageHeader
        title={t(lang, { en: "Events", ru: "События" })}
        icon="events"
        actions={(
          <>
            <button type="button" className="react-link-button" onClick={saveCurrentSearch}>{t(lang, { en: "Save query", ru: "Сохранить запрос" })}</button>
            <button type="button" className="react-icon-button" onClick={() => setSettingsOpen(true)} aria-label={t(lang, { en: "Event page settings", ru: "Настройки страницы событий" })}>
              <Icon name="control" size={15} />
            </button>
          </>
        )}
      />
      <section className="native-query-console">
        <div className="native-workspace-tabs" role="tablist" aria-label={t(lang, { en: "Event search mode", ru: "Режим поиска событий" })}>
          <button type="button" className="active" role="tab" aria-selected="true">SQL / field query</button>
          <span>{t(lang, { en: "Storage", ru: "Хранилище" })}: <strong>{storage}</strong></span>
        </div>
        <div className="react-events-console-body">
        <div className="react-query-stack react-query-stack-compact">
          <textarea
            className="react-query-editor react-query-editor-compact"
            value={query}
            onChange={(event) => {
              setSavedSearchId("");
              setOffset(0);
              setQuery(event.target.value);
            }}
            placeholder="message ILIKE '%auditd:%' OR SELECT ts, log_source, severity, category, subcategory, src_ip, dst_ip, user_name, message FROM events_view ORDER BY ts DESC LIMIT 100"
          />
          <div className="react-query-toolbar react-query-toolbar-compact">
            <div className="react-actions react-wrap">
              <button type="button" className="react-link-button" onClick={() => applyQuickQuery("message ILIKE '%auditd:%'")}>Auditd</button>
              <button type="button" className="react-link-button" onClick={() => applyQuickQuery("collector_profile = 'windows-security-http'")}>Windows security</button>
              <button type="button" className="react-link-button" onClick={() => applyQuickQuery("collector_profile = 'vpn-json-http'")}>VPN edge</button>
              <button type="button" className="react-primary-button" onClick={() => setReloadToken((value) => value + 1)}>
                {t(lang, { en: "Run query", ru: "Выполнить" })}
              </button>
            </div>
            <div className="react-query-controls react-query-controls-compact">
              <label>
                <span>{t(lang, { en: "Preset", ru: "Период" })}</span>
                <select className="react-select" value={windowSize} onChange={(event) => applyPreset(event.target.value)}>
                  {["1h", "6h", "24h", "72h", "7d", "custom"].map((item) => (
                    <option key={item} value={item}>{item}</option>
                  ))}
                </select>
              </label>
              <label className={windowSize !== "custom" && !fromTs ? "react-control-hidden" : ""}>
                <span>{t(lang, { en: "From", ru: "От" })}</span>
                <input className="react-input" type="datetime-local" value={fromTs} onChange={(event) => { setSavedSearchId(""); setWindowSize("custom"); setFromTs(event.target.value); }} />
              </label>
              <label className={windowSize !== "custom" && !toTs ? "react-control-hidden" : ""}>
                <span>{t(lang, { en: "To", ru: "До" })}</span>
                <input className="react-input" type="datetime-local" value={toTs} onChange={(event) => { setSavedSearchId(""); setWindowSize("custom"); setToTs(event.target.value); }} />
              </label>
              <label>
                <span>{t(lang, { en: "Storage", ru: "Хранилище" })}</span>
                <select className="react-select" value={storage} onChange={(event) => { setSavedSearchId(""); setStorage(event.target.value); }}>
                  {["hot", "cold", "all"].map((item) => (
                    <option key={item} value={item}>{item}</option>
                  ))}
                </select>
              </label>
              <label>
                <span>{t(lang, { en: "Rows", ru: "Строк" })}</span>
                <select className="react-select" value={limit} onChange={(event) => { setSavedSearchId(""); setLimit(Number(event.target.value)); }}>
                  {[50, 100, 250, 500].map((item) => (
                    <option key={item} value={item}>{item}</option>
                  ))}
                </select>
              </label>
              <label>
                <span>{t(lang, { en: "Refresh", ru: "Обновление" })}</span>
                <select className="react-select" value={refreshSeconds} onChange={(event) => setRefreshSeconds(event.target.value)}>
                  {refreshOptions(lang).map((item) => <option key={item.value} value={item.value}>{item.label}</option>)}
                </select>
              </label>
            </div>
          </div>
          <div className="react-query-saved-row">
            <label className="react-query-saved-picker">
              <span>{t(lang, { en: "Saved view", ru: "Сохраненный вид" })}</span>
              <select
                className="react-select react-select-inline"
                value={savedSearchId}
                onChange={(event) => {
                  const nextId = String(event.target.value || "");
                  setSavedSearchId(nextId);
                  const selectedSearch = savedSearchItems.find((item) => String(item.id || "") === nextId);
                  if (selectedSearch) {
                    applySavedSearch(selectedSearch);
                  }
                }}
              >
                <option value="">{t(lang, { en: "Current live query", ru: "Текущий живой поиск" })}</option>
                {savedSearchItems.map((item) => (
                  <option key={item.id} value={item.id}>
                    {item.title || item.id}
                  </option>
                ))}
              </select>
            </label>
            <div className="react-actions react-wrap">
              <button type="button" className="react-link-button" onClick={saveCurrentSearch}>
                {t(lang, { en: "Save current", ru: "Сохранить текущее" })}
              </button>
              <button type="button" className="react-link-button" onClick={resetQueryState}>
                {t(lang, { en: "Reset", ru: "Сбросить" })}
              </button>
            </div>
          </div>
          {savedSearchState ? <div className="react-inline-note">{savedSearchState}</div> : null}
          <div className="react-inline-note react-inline-note-spaced">
            {(fromTs || toTs)
              ? `${t(lang, { en: "Range", ru: "Диапазон" })}: ${fromTs || "?"} -> ${toTs || "?"}`
              : `${t(lang, { en: "Preset", ru: "Пресет" })}: ${windowSize}, ${t(lang, { en: "Storage", ru: "Хранилище" })}: ${storage}, ${t(lang, { en: "Rows", ru: "Строк" })}: ${limit}`}
          </div>
        </div>
        <details className="react-details">
          <summary>Resolved SQL</summary>
          <pre className="react-pre">{state.data?.base_sql || "No SQL yet."}</pre>
        </details>
        </div>
      </section>

      {state.loading ? (
        <EmptyState message="Running query..." />
      ) : state.error ? (
        <EmptyState message={state.error} />
      ) : (
        <>
          <div className="native-event-timeline" aria-label={t(lang, { en: "Event timeline", ru: "Таймлайн событий" })}>
            <SparklineChart items={facets.histogram || []} />
          </div>
          <NativeActionBar
            primary={(
              <>
                <button type="button" className="react-link-button" onClick={() => setSettingsOpen(true)}>{t(lang, { en: "Columns", ru: "Колонки" })}</button>
                <button type="button" className="react-link-button" onClick={() => setReloadToken((value) => value + 1)}>{t(lang, { en: "Refresh", ru: "Обновить" })}</button>
                <button type="button" className="react-link-button" disabled={!rows.length} onClick={exportCurrentRows}>TSV</button>
              </>
            )}
            meta={(
              <>
                <span>{t(lang, { en: "Found", ru: "Найдено" })}: <strong>{state.data?.total_count || 0}</strong></span>
                <span>{t(lang, { en: "Shown", ru: "Показано" })}: <strong>{state.data?.row_count || 0}</strong></span>
                <span>{state.data?.elapsed_ms || 0} ms</span>
                <span>{t(lang, { en: "Page", ru: "Страница" })} <strong>{pagination.page}</strong> / {pagination.totalPages}</span>
              </>
            )}
          />
          <section className="native-grid native-events-grid">
            <div className="react-results-window">
              <div
                ref={windowedRows.containerRef}
                className={`react-table-wrap react-table-window ${windowedRows.isWindowed ? "windowed" : ""}`}
              >
                <table className="react-table react-table-windowed" role="table" aria-label="Event result set" aria-rowcount={state.data?.total_count || rows.length} aria-colcount={activeColumns.length}>
                  <thead>
                    <tr role="row">
                      {activeColumns.map((column) => (
                        <th key={column.key} role="columnheader">{column.label}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {windowedRows.topSpacerHeight ? (
                      <tr className="react-table-spacer" aria-hidden="true">
                        <td colSpan={Math.max(1, activeColumns.length)} style={{ height: `${windowedRows.topSpacerHeight}px` }} />
                      </tr>
                    ) : null}
                    {windowedRows.visibleRows.map((row: EventRow, visibleIndex: number) => {
                      const index = windowedRows.startIndex + visibleIndex;
                      return (
                      <tr
                        key={`${row.ts}-${index}`}
                        role="row"
                        className={index === selectedIndex ? "selected" : ""}
                        onClick={() => {
                          setSelectedIndex(index);
                          setDrawerOpen(true);
                        }}
                      >
                        {activeColumns.map((column) => (
                          <td key={column.key} role="cell" className={column.className || ""}>{column.render(row)}</td>
                        ))}
                      </tr>
                      );
                    })}
                    {windowedRows.bottomSpacerHeight ? (
                      <tr className="react-table-spacer" aria-hidden="true">
                        <td colSpan={Math.max(1, activeColumns.length)} style={{ height: `${windowedRows.bottomSpacerHeight}px` }} />
                      </tr>
                    ) : null}
                  </tbody>
                </table>
              </div>
            </div>
          </section>
          <NativePager shown={state.data?.row_count || 0} total={state.data?.total_count || 0} lang={lang}>
            <button type="button" className="react-link-button" disabled={!pagination.canPrev} onClick={() => goToPage(1)}>{t(lang, { en: "First", ru: "Первая" })}</button>
            <button type="button" className="react-link-button" disabled={!pagination.canPrev} onClick={() => goToPage(pagination.page - 1)}>{t(lang, { en: "Previous", ru: "Назад" })}</button>
            <span>{pagination.page} / {pagination.totalPages}</span>
            <button type="button" className="react-link-button" disabled={!pagination.canNext} onClick={() => goToPage(pagination.page + 1)}>{t(lang, { en: "Next", ru: "Вперед" })}</button>
            <button type="button" className="react-link-button" disabled={!pagination.canNext} onClick={() => goToPage(pagination.totalPages)}>{t(lang, { en: "Last", ru: "Последняя" })}</button>
          </NativePager>

          <details className="react-details">
            <summary>{t(lang, { en: "Analytical helpers", ru: "Аналитические виджеты" })}</summary>
            {facetsState.loading ? (
              <div className="react-inline-note react-inline-note-spaced">
                {t(lang, { en: "Loading event facets separately; the result table remains available.", ru: "Агрегации событий грузятся отдельно, таблица остается доступной." })}
              </div>
            ) : null}
            {facetsState.error ? (
              <div className="react-inline-note react-inline-note-spaced">
                {t(lang, { en: "Facet widgets are temporarily unavailable.", ru: "Аналитические виджеты временно недоступны." })} {facetsState.error}
              </div>
            ) : null}
            <div className="react-grid react-grid-2">
              <section className="react-card react-card-nested">
                <PanelHeader
                  title={t(lang, { en: "Severity mix", ru: "Смешение по важности" })}
                  subtitle={t(lang, { en: "Aggregated over the filtered dataset.", ru: "Агрегировано по отфильтрованному набору." })}
                  icon="incidents"
                />
                <BreakdownBars items={facets.severity_stats || []} />
              </section>
              <section className="react-card react-card-nested">
                <PanelHeader
                  title={t(lang, { en: "Result timeline", ru: "Таймлайн результата" })}
                  subtitle={t(lang, { en: "Aggregated buckets for the full filtered dataset.", ru: "Агрегированные бакеты для полного набора результатов." })}
                  icon="dashboard"
                />
                <SparklineChart items={facets.histogram || []} />
              </section>
            </div>
          </details>

          <DrawerOverlay
            open={drawerOpen && !!selected}
            title={t(lang, { en: "Event details", ru: "Детали события" })}
            subtitle={t(lang, { en: "Pivot into related sources, users, assets and threat intelligence.", ru: "Переход к связанным источникам, пользователям, активам и TI." })}
            onClose={() => setDrawerOpen(false)}
          >
            {selected ? (
              <>
                <InvestigationSummaryStrip items={selectedEventSummary} />
                {selectedEventActions.length ? <InvestigationActionRail items={selectedEventActions} /> : null}
                <InvestigationTimeline
                  title={t(lang, { en: "Investigation chain", ru: "Цепочка расследования" })}
                  subtitle={t(lang, { en: "Envelope, identity, network path and parsed enrichment for the selected record.", ru: "Контур события, идентичность, сетевой путь и разобранное обогащение выбранной записи." })}
                  icon="events"
                  items={selectedEventTimeline}
                  emptyMessage={t(lang, { en: "No investigation timeline available.", ru: "Таймлайн расследования отсутствует." })}
                />
                <InvestigationDrawerSection
                  title={t(lang, { en: "Field matrix", ru: "Матрица полей" })}
                  subtitle={t(lang, { en: "Analyst-friendly facts that stay stable across the drawer.", ru: "Аналитические факты, которые остаются стабильными во всем drawer." })}
                  icon="dashboard"
                >
                <DrawerFieldGrid>
                  <KeyValue label={t(lang, { en: "Time", ru: "Время" })} value={formatTimestamp(selected.ts, "full")} />
                  <KeyValue label={t(lang, { en: "Source", ru: "Источник" })} value={humanizeSourceName(selected.log_source || "n/a", lang)} />
                  <KeyValue label={t(lang, { en: "Collector", ru: "Коллектор" })} value={selected.collector_profile || selected.observer_collector || "n/a"} />
                  <KeyValue label={t(lang, { en: "Category", ru: "Категория" })} value={humanizeEventLabel(`${selected.category} / ${selected.subcategory}`, lang)} />
                  <KeyValue label={t(lang, { en: "Severity", ru: "Важность" })} value={<SeverityBadge value={selected.severity || "info"} />} />
                  <KeyValue label={t(lang, { en: "Asset", ru: "Актив" })} value={humanizeSourceName(selected.asset_id || "n/a", lang)} />
                  <KeyValue label={t(lang, { en: "User", ru: "Пользователь" })} value={humanizeTechnicalValue(selected.user_name || selected.target_user || "n/a", lang)} />
                  <KeyValue label={t(lang, { en: "Process", ru: "Процесс" })} value={selected.process_name || selected.process_executable || "n/a"} />
                  <KeyValue label="Src IP" value={selected.src_ip || "n/a"} />
                  <KeyValue label="Dst IP" value={selected.dst_ip || "n/a"} />
                  <KeyValue label={t(lang, { en: "Dst port", ru: "Порт назначения" })} value={selected.dst_port || "n/a"} />
                  <KeyValue label="TI indicator" value={selected.ti_indicator || "n/a"} />
                </DrawerFieldGrid>
                </InvestigationDrawerSection>
                <div className="react-chip-row">
                  {selected.log_source ? <button type="button" className="react-chip" onClick={() => applyQuickQuery(`log_source = '${String(selected.log_source).replace(/'/g, "''")}'`)}>source:{humanizeSourceName(selected.log_source, lang, { technicalSuffix: false })}</button> : null}
                  {selected.src_ip ? <button type="button" className="react-chip" onClick={() => applyQuickQuery(`src_ip = '${String(selected.src_ip).replace(/'/g, "''")}'`)}>src:{selected.src_ip}</button> : null}
                  {selected.dst_ip ? <button type="button" className="react-chip" onClick={() => applyQuickQuery(`dst_ip = '${String(selected.dst_ip).replace(/'/g, "''")}'`)}>dst:{selected.dst_ip}</button> : null}
                  {selected.user_name ? <button type="button" className="react-chip" onClick={() => applyQuickQuery(`user_name = '${String(selected.user_name).replace(/'/g, "''")}'`)}>user:{humanizeTechnicalValue(selected.user_name, lang)}</button> : null}
                  {selected.asset_id ? <button type="button" className="react-chip" onClick={() => applyQuickQuery(`asset_id = '${String(selected.asset_id).replace(/'/g, "''")}'`)}>asset:{humanizeSourceName(selected.asset_id, lang, { technicalSuffix: false })}</button> : null}
                </div>
                <details className="react-details" open>
                  <summary>{t(lang, { en: "Message", ru: "Сообщение" })}</summary>
                  <pre className="react-pre">{selected.message}</pre>
                </details>
                <details className="react-details">
                  <summary>{t(lang, { en: "Raw row", ru: "Сырая строка" })}</summary>
                  <JsonPreview value={selected} />
                </details>
              </>
            ) : (
              <EmptyState message={t(lang, { en: "Select a row to open the drawer.", ru: "Выберите строку, чтобы открыть панель." })} />
            )}
          </DrawerOverlay>

          <DrawerOverlay
            open={settingsOpen}
            title={t(lang, { en: "Event page settings", ru: "Настройки страницы событий" })}
            subtitle={t(lang, { en: "Search defaults, visible columns and analyst pivots.", ru: "Параметры поиска, видимые колонки и переходы аналитика." })}
            onClose={() => setSettingsOpen(false)}
          >
            <section className="react-card react-card-nested">
              <PanelHeader title={t(lang, { en: "Quick pivots", ru: "Быстрые переходы" })} subtitle={t(lang, { en: "Open the most common investigative lanes.", ru: "Откройте самые частые расследовательские сценарии." })} icon="events" />
              <div className="react-actions react-wrap">
                <button type="button" className="react-link-button" onClick={() => { applyQuickQuery("message ILIKE '%auditd:%'"); setSettingsOpen(false); }}>Linux audit</button>
                <button type="button" className="react-link-button" onClick={() => { applyQuickQuery("collector_profile = 'windows-security-http'"); setSettingsOpen(false); }}>Windows Security</button>
                <button type="button" className="react-link-button" onClick={() => { applyQuickQuery("collector_profile = 'vpn-json-http'"); setSettingsOpen(false); }}>VPN</button>
                <button type="button" className="react-link-button" onClick={() => { applyPreset("72h"); setSettingsOpen(false); }}>72h</button>
              </div>
            </section>
            <section className="react-card react-card-nested">
              <PanelHeader title={t(lang, { en: "Visible columns", ru: "Видимые колонки" })} subtitle={t(lang, { en: "Choose which fields stay visible in the result window.", ru: "Выберите поля, которые должны быть видны в окне результатов." })} icon="dashboard" />
              <div className="react-chip-grid">
                {availableColumns.map((column) => (
                  <button
                    key={column.key}
                    type="button"
                    className={`react-chip-card react-chip-card-button ${visibleColumns.includes(column.key) ? "active" : ""}`}
                    onClick={() => toggleColumn(column.key)}
                  >
                    <div className="react-top-kicker">{visibleColumns.includes(column.key) ? "visible" : "hidden"}</div>
                    <strong>{column.label}</strong>
                    <span>{column.key}</span>
                  </button>
                ))}
              </div>
            </section>
          </DrawerOverlay>
        </>
      )}
    </div>
  );
}
