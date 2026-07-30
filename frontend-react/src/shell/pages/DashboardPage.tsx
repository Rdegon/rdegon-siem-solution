import { useCallback, useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../api";
import { DashboardCanvas, groupDashboardLayout } from "../DashboardCanvas";
import { useAsyncData, usePolledData } from "../hooks";
import { DrawerFieldGrid, DrawerOverlay, EmptyState, Icon, KeyValue, PanelHeader, TimeScopePickerButton } from "../ui";
import { NativePageHeader } from "../native";
import { shiftTimeZoneInputValue, t, useShellContext } from "../context";
import { localizeDashboardTitle, localizeRuleName } from "../runtimeLocalization";
import { refreshIntervalMs, refreshOptions, rowOptions, timeRangeOptions, timeScopeSummary } from "../timeControls";
import type { DashboardDefinition, DashboardSummaryResponse, GeoActivityRow, GeoCountryDetailResponse, ThreatIntelGeoDetailResponse } from "../types";

function normalizeCountry(value: string) {
  return String(value || "").trim().toLowerCase();
}

function buildCountryFallback(data: DashboardSummaryResponse, country: string, kind: "source" | "vpn"): GeoCountryDetailResponse {
  const normalizedTarget = normalizeCountry(country);
  const source = kind === "vpn" ? data?.geo_vpn_destinations : data?.geo_sources;
  const rows = source?.items || [];
  const items = rows
    .filter((row: GeoActivityRow) => normalizeCountry(String(row?.country || "")) === normalizedTarget)
    .map((row: GeoActivityRow) => ({
      label: String(row?.domain || row?.ip || ""),
      ip: String(row?.ip || ""),
      org: String(row?.org || "n/a"),
      events: Number(row?.visits ?? row?.events ?? 0),
      last_seen: String(row?.last_seen || ""),
      country: String(row?.country || country),
      country_code: String(row?.country_code || ""),
      ports: String(row?.target_ports || "").split(",").map((item) => item.trim()).filter(Boolean),
      sources: row?.ip ? [String(row.ip)] : [],
      incidents: [],
      assets: [],
    }));
  return {
    kind,
    country,
    summary: {
      items: items.length,
      events: items.reduce((sum, row) => sum + Number(row.events || 0), 0),
      organizations: new Set(items.map((row) => String(row.org || "n/a"))).size,
      incidents: 0,
      assets: 0,
    },
    items,
  };
}

function sectionCopy(lang: "en" | "ru", sectionId: string) {
  const copy: Record<string, { en: { title: string; subtitle: string }; ru: { title: string; subtitle: string } }> = {
    soc_overview: {
      en: { title: "SOC overview", subtitle: "Core events, alerts and category analytics." },
      ru: { title: "SOC-обзор", subtitle: "События, алерты и аналитика категорий." },
    },
    threat_geography: {
      en: { title: "Threat geography", subtitle: "Source countries and VPN destinations." },
      ru: { title: "География угроз", subtitle: "Страны-источники и VPN-направления." },
    },
    threat_intel: {
      en: { title: "Threat intelligence", subtitle: "IOC matches and malicious IP context." },
      ru: { title: "Threat intelligence", subtitle: "IOC и контекст вредоносных IP." },
    },
    collector_health: {
      en: { title: "Collector health", subtitle: "Source activity and ingest visibility." },
      ru: { title: "Состояние коллекторов", subtitle: "Активность источников и видимость ingest." },
    },
    incident_operations: {
      en: { title: "Incident operations", subtitle: "Queue posture and analyst pivots." },
      ru: { title: "Операции с инцидентами", subtitle: "Очередь и переходы для аналитика." },
    },
    external_traffic: {
      en: { title: "External traffic", subtitle: "VPN browsing activity and destinations." },
      ru: { title: "Внешний трафик", subtitle: "VPN-активность и внешние направления." },
    },
  };
  return copy[sectionId]?.[lang] || { title: sectionId, subtitle: "" };
}

function sectionIcon(sectionId: string) {
  if (sectionId === "threat_geography") return "map";
  if (sectionId === "incident_operations") return "incidents";
  if (sectionId === "collector_health") return "collectors";
  if (sectionId === "threat_intel") return "intel";
  if (sectionId === "external_traffic") return "globe";
  return "dashboard";
}

function formatTimelineWindowLabel(value: string, lang: "en" | "ru") {
  const normalized = String(value || "").trim().toLowerCase();
  const localized: Record<string, { en: string; ru: string }> = {
    "15m": { en: "15 minutes", ru: "15 минут" },
    "1h": { en: "1 hour", ru: "1 час" },
    "6h": { en: "6 hours", ru: "6 часов" },
    "24h": { en: "24 hours", ru: "24 часа" },
    "72h": { en: "72 hours", ru: "72 часа" },
    "7d": { en: "7 days", ru: "7 дней" },
    "30d": { en: "30 days", ru: "30 дней" },
    all: { en: "All available", ru: "Всё доступное" },
    custom: { en: "Custom range", ru: "Свой диапазон" },
  };
  return localized[normalized]?.[lang] || value;
}

export function DashboardPage() {
  const { lang, formatTimestamp, timezone, toUtcQueryValue } = useShellContext();
  const [timelineWindow, setTimelineWindow] = useState("24h");
  const [timelineFrom, setTimelineFrom] = useState("");
  const [timelineTo, setTimelineTo] = useState("");
  const [timelineBucketMinutes, setTimelineBucketMinutes] = useState(60);
  const [recentLimit, setRecentLimit] = useState(25);
  const [refreshSeconds, setRefreshSeconds] = useState("30");
  const loadSummary = useCallback(
    () =>
      api.dashboard({
        window: timelineWindow === "custom" ? "24h" : timelineWindow,
        from_ts: timelineFrom ? toUtcQueryValue(timelineFrom) : "",
        to_ts: timelineTo ? toUtcQueryValue(timelineTo) : "",
        bucket_minutes: timelineBucketMinutes,
        recent_limit: recentLimit,
      }),
    [recentLimit, timelineBucketMinutes, timelineFrom, timelineTo, timelineWindow, toUtcQueryValue],
  );
  const summary = usePolledData(loadSummary, refreshIntervalMs(refreshSeconds));
  const loadRegistry = useCallback(() => api.dashboards(), []);
  const registry = usePolledData(loadRegistry, 45000);
  const [selectedDashboardId, setSelectedDashboardId] = useState("");
  const [focusedIp, setFocusedIp] = useState("");
  const [focusedCountry, setFocusedCountry] = useState("");
  const [focusedCountryKind, setFocusedCountryKind] = useState<"source" | "vpn">("source");
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [countryCache, setCountryCache] = useState<Record<string, GeoCountryDetailResponse>>({});
  const [countryLoading, setCountryLoading] = useState(false);
  const [countryError, setCountryError] = useState("");

  useEffect(() => {
    const previousTimezone = window.sessionStorage.getItem("rdegon-dashboard-timezone") || timezone;
    if (previousTimezone === timezone) {
      window.sessionStorage.setItem("rdegon-dashboard-timezone", timezone);
      return;
    }
    setTimelineFrom((current) => (current ? shiftTimeZoneInputValue(current, previousTimezone, timezone) : current));
    setTimelineTo((current) => (current ? shiftTimeZoneInputValue(current, previousTimezone, timezone) : current));
    window.sessionStorage.setItem("rdegon-dashboard-timezone", timezone);
  }, [timezone]);

  const dashboards = useMemo(() => registry.data?.dashboards || [], [registry.data?.dashboards]);
  const selected: DashboardDefinition | undefined = dashboards.find((item) => item.id === selectedDashboardId) || dashboards[0];
  const groupedLayout = useMemo(() => groupDashboardLayout(selected?.layout || []), [selected?.layout]);
  const countryCacheKey = useMemo(() => `${focusedCountryKind}:${normalizeCountry(focusedCountry)}`, [focusedCountry, focusedCountryKind]);
  const fallbackCountryDetail = useMemo(
    () => (focusedCountry && summary.data ? buildCountryFallback(summary.data, focusedCountry, focusedCountryKind) : null),
    [focusedCountry, focusedCountryKind, summary.data],
  );
  const loadIpDetail = useCallback<() => Promise<ThreatIntelGeoDetailResponse | null>>(
    () => (focusedIp ? api.geoIpDetail(focusedIp, { hours: 72 }) : Promise.resolve(null)),
    [focusedIp],
  );
  const ipDetail = useAsyncData<ThreatIntelGeoDetailResponse | null>(loadIpDetail);
  const remoteCountryDetail = countryCache[countryCacheKey] || null;

  useEffect(() => {
    if (!selectedDashboardId && dashboards.length) {
      setSelectedDashboardId(String(dashboards[0].id || ""));
    }
  }, [dashboards, selectedDashboardId]);

  useEffect(() => {
    let cancelled = false;
    if (!focusedCountry) {
      setCountryLoading(false);
      setCountryError("");
      return;
    }
    if (countryCache[countryCacheKey]) {
      setCountryLoading(false);
      setCountryError("");
      return;
    }
    setCountryLoading(true);
    setCountryError("");
    api.geoCountryDetail(focusedCountry, { kind: focusedCountryKind, hours: 72, limit: 40 })
      .then((payload) => {
        if (cancelled) return;
        setCountryCache((current) => ({ ...current, [countryCacheKey]: payload }));
        setCountryLoading(false);
      })
      .catch((error: unknown) => {
        if (cancelled) return;
        setCountryError(error instanceof Error ? error.message : "Country detail unavailable");
        setCountryLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [countryCache, countryCacheKey, focusedCountry, focusedCountryKind]);

  const countryDetail = useMemo(() => {
    if (!fallbackCountryDetail && !remoteCountryDetail) return null;
    if (!fallbackCountryDetail) return remoteCountryDetail;
    if (!remoteCountryDetail) return fallbackCountryDetail;
    return {
      ...fallbackCountryDetail,
      ...remoteCountryDetail,
      summary: {
        ...fallbackCountryDetail.summary,
        ...(remoteCountryDetail?.summary || {}),
      },
      items: (remoteCountryDetail?.items || fallbackCountryDetail.items || []).map((item: NonNullable<GeoCountryDetailResponse["items"]>[number]) => ({
        ...item,
        ports:
          item.ports ||
          String(item.target_ports || "")
            .split(",")
            .map((port: string) => port.trim())
            .filter(Boolean),
      })),
    };
  }, [fallbackCountryDetail, remoteCountryDetail]);

  if (summary.loading || registry.loading) return <EmptyState message={t(lang, { en: "Loading overview...", ru: "Загрузка обзора..." })} />;
  if (summary.error || !summary.data) return <EmptyState message={summary.error || "No dashboard data"} />;
  if (registry.error || !registry.data) return <EmptyState message={registry.error || "No dashboard registry"} />;
  const summaryData = summary.data;

  const activeWindow = summaryData.timeline_window || {};
  const currentFrom = String(activeWindow.from_ts || "");
  const currentTo = String(activeWindow.to_ts || "");
  const currentRangeQuery =
    currentFrom || currentTo
      ? `from=${encodeURIComponent(currentFrom)}${currentTo ? `&to=${encodeURIComponent(currentTo)}` : ""}`
      : "";
  const metrics = summaryData.metrics || {};
  const overviewLiveText = t(lang, {
    en: `Overview refreshed. Events in the last hour: ${Number(metrics.events_1h || 0).toLocaleString()}. Open incidents: ${Number(metrics.open_incidents_24h || 0).toLocaleString()}. Threat intel hits: ${Number(metrics.ti_hits_24h || 0).toLocaleString()}.`,
    ru: `Обзор обновлен. События за последний час: ${Number(metrics.events_1h || 0).toLocaleString()}. Открытые инциденты: ${Number(metrics.open_incidents_24h || 0).toLocaleString()}. Совпадения TI: ${Number(metrics.ti_hits_24h || 0).toLocaleString()}.`,
  });
  const overviewStats = [
    {
      label: t(lang, { en: "Events 1h", ru: "События 1ч" }),
      value: Number(metrics.events_1h || 0).toLocaleString(),
      hint: t(lang, { en: "Current normalized flow.", ru: "Текущий нормализованный поток." }),
    },
    {
      label: t(lang, { en: "Open incidents", ru: "Открытые инциденты" }),
      value: Number(metrics.open_incidents_24h || 0).toLocaleString(),
      hint: t(lang, { en: "Analyst queue waiting for action.", ru: "Очередь аналитика, ждущая разбора." }),
    },
    {
      label: t(lang, { en: "TI hits", ru: "Совпадения TI" }),
      value: Number(metrics.ti_hits_24h || 0).toLocaleString(),
      hint: t(lang, { en: "Matched intelligence signals.", ru: "Совпавшие TI-сигналы." }),
    },
    {
      label: t(lang, { en: "Active sources", ru: "Активные источники" }),
      value: Number(metrics.active_sources_24h || 0).toLocaleString(),
      hint: t(lang, { en: "Reporting sources in the current window.", ru: "Источники, которые сейчас отправляют события." }),
    },
  ];
  const overviewPressureItems = [
    {
      label: t(lang, { en: "Queue pressure", ru: "Давление очереди" }),
      value: Number(metrics.open_incidents_24h || 0).toLocaleString(),
      hint: t(lang, { en: "Open incident queue for the active window.", ru: "Очередь открытых инцидентов для активного окна." }),
      tone: Number(metrics.open_incidents_24h || 0) > 10 ? "critical" : "warning",
    },
    {
      label: t(lang, { en: "Top source", ru: "Топ-источник" }),
      value: String(summaryData.top_sources?.[0]?.log_source || summaryData.top_sources?.[0]?.source_name || "n/a"),
      hint: t(lang, { en: "Highest-volume source right now.", ru: "Источник с самым высоким объемом прямо сейчас." }),
      tone: "info",
    },
    {
      label: t(lang, { en: "Lead alert", ru: "Ключевой алерт" }),
      value: localizeRuleName(summaryData.recent_alerts?.[0]?.rule_name || "n/a", lang),
      hint: t(lang, { en: "Freshest alert worth pivoting into.", ru: "Самый свежий алерт, в который стоит провалиться." }),
      tone: summaryData.recent_alerts?.[0]?.severity === "critical" ? "critical" : "warning",
    },
  ] as const;
  const overviewOperatingLanes = [
    { title: t(lang, { en: "Triage queue", ru: "Триаж-очередь" }), href: currentRangeQuery ? `/incidents?${currentRangeQuery}` : "/incidents", hint: t(lang, { en: "Read ownership, severity and workflow state.", ru: "Смотреть ответственного, важность и состояние процесса." }) },
    { title: t(lang, { en: "Event explorer", ru: "Эксплорер событий" }), href: currentRangeQuery ? `/events?${currentRangeQuery}` : "/events", hint: t(lang, { en: "Pivot from pressure into evidence.", ru: "Переходить от давления к доказательствам." }) },
    { title: t(lang, { en: "Source health", ru: "Состояние источников" }), href: "/sources?view=freshness", hint: t(lang, { en: "Check freshness, drift and onboarding gaps.", ru: "Проверять актуальность данных, рассинхронизацию и пробелы подключения." }) },
    { title: t(lang, { en: "Exposure queue", ru: "Очередь экспозиции" }), href: "/vuln", hint: t(lang, { en: "See what requires action now.", ru: "Смотреть, что требует действий сейчас." }) },
  ];
  const activeWindowLabel =
    currentFrom || currentTo
      ? `${formatTimestamp(currentFrom || currentTo, "full")} -> ${formatTimestamp(currentTo || currentFrom, "full")}`
      : t(lang, {
          en: `${formatTimelineWindowLabel(activeWindow.window || timelineWindow, lang)} | ${activeWindow.bucket_minutes || timelineBucketMinutes}m interval`,
          ru: `${formatTimelineWindowLabel(activeWindow.window || timelineWindow, lang)} | ${activeWindow.bucket_minutes || timelineBucketMinutes} м интервал`,
        });

  const dashboardRangeOptions = timeRangeOptions(lang);
  const dashboardRefreshOptions = refreshOptions(lang);
  const dashboardRowOptions = rowOptions();
  const dashboardScopeSummary = timeScopeSummary(lang, {
    rangeLabel: activeWindowLabel,
    refreshSeconds,
    rows: recentLimit,
    fromTs: timelineFrom,
    toTs: timelineTo,
  });
  const activeRangeOption = dashboardRangeOptions.find((item) => item.value === timelineWindow) || dashboardRangeOptions[0];
  const handleTimelineWindowChange = (next: string) => {
    setTimelineWindow(next);
    if (next !== "custom") {
      setTimelineFrom("");
      setTimelineTo("");
    }
  };
  const overviewFocusButtonLabel = (
    <span className="react-time-focus-button-content">
      <span className="react-time-focus-button-badge">{activeRangeOption?.label || timelineWindow}</span>
      <span className="react-time-focus-button-text">{activeWindowLabel}</span>
    </span>
  );
  const overviewFocusFooter = (
    <div className="react-time-focus-footer">
      <div className="react-time-focus-footer-controls">
        <label className="react-time-inline-select">
          <span>{t(lang, { en: "Queue rows", ru: "Строк в очереди" })}</span>
          <select className="react-select" value={recentLimit} onChange={(event) => setRecentLimit(Number(event.target.value))}>
            {dashboardRowOptions.map((item) => (
              <option key={item.value} value={item.value}>
                {item.label}
              </option>
            ))}
          </select>
        </label>
        <label className="react-time-inline-select">
          <span>{t(lang, { en: "Bucket", ru: "Интервал" })}</span>
          <select className="react-select" value={timelineBucketMinutes} onChange={(event) => setTimelineBucketMinutes(Number(event.target.value))}>
            {[5, 15, 30, 60, 180, 360].map((item) => (
              <option key={item} value={item}>
                {lang === "ru" ? `${item} м` : `${item}m`}
              </option>
            ))}
          </select>
        </label>
      </div>
      <div className="react-inline-note react-overview-heading-note">{dashboardScopeSummary}</div>
    </div>
  );
  const compactTimeline = (summaryData.timeline || []).slice(-18);
  const compactTimelineMax = Math.max(
    1,
    ...compactTimeline.map((row) => Number(row.count ?? row.cnt ?? row.__value ?? 0)),
  );
  const compactSeverities = (summaryData.alert_severity_breakdown || summaryData.severity_breakdown || []).slice(0, 5);
  const compactSeverityMax = Math.max(
    1,
    ...compactSeverities.map((row) => Number(row.count ?? row.cnt ?? row.events ?? 0)),
  );
  const compactAlerts = (summaryData.recent_alerts || []).slice(0, 6);
  const compactSources = (summaryData.top_sources || []).slice(0, 7);
  const compactCategories = (summaryData.top_categories || []).slice(0, 6);

  return (
    <div className="react-page react-page-dashboard native-page native-dashboard-page">
      <div className="react-sr-only" aria-live="polite">{overviewLiveText}</div>
      <NativePageHeader
        title={t(lang, { en: "Dashboard", ru: "Панель мониторинга" })}
        icon="dashboard"
        actions={(
          <>
            <Link className="react-link-button" to="/control">{t(lang, { en: "Edit layout", ru: "Изменить макет" })}</Link>
            <button type="button" className="react-primary-button" onClick={() => setSettingsOpen(true)}>{t(lang, { en: "Add widget", ru: "Добавить виджет" })}</button>
          </>
        )}
      />
      <div className="native-dashboard-controls">
        <label>
          <span>{t(lang, { en: "Layout", ru: "Макет" })}</span>
          <select value={selected?.id || ""} onChange={(event) => setSelectedDashboardId(event.target.value)}>
            {dashboards.map((item) => <option key={item.id} value={item.id}>{localizeDashboardTitle(item.title, lang)}</option>)}
          </select>
        </label>
        <label>
          <span>{t(lang, { en: "Period", ru: "Период" })}</span>
          <select value={timelineWindow} onChange={(event) => handleTimelineWindowChange(event.target.value)}>
            {dashboardRangeOptions.map((item) => <option key={item.value} value={item.value}>{item.label}</option>)}
          </select>
        </label>
        <label>
          <span>{t(lang, { en: "Refresh", ru: "Обновление" })}</span>
          <select value={refreshSeconds} onChange={(event) => setRefreshSeconds(event.target.value)}>
            {dashboardRefreshOptions.map((item) => <option key={item.value} value={item.value}>{item.label}</option>)}
          </select>
        </label>
        <label>
          <span>{t(lang, { en: "Bucket", ru: "Интервал" })}</span>
          <select value={timelineBucketMinutes} onChange={(event) => setTimelineBucketMinutes(Number(event.target.value))}>
            {[5, 15, 30, 60, 180, 360].map((item) => <option key={item} value={item}>{item}m</option>)}
          </select>
        </label>
      </div>
      {timelineWindow === "custom" ? (
        <div className="native-custom-range">
          <label><span>{t(lang, { en: "From", ru: "От" })}</span><input type="datetime-local" value={timelineFrom} onChange={(event) => setTimelineFrom(event.target.value)} /></label>
          <label><span>{t(lang, { en: "To", ru: "До" })}</span><input type="datetime-local" value={timelineTo} onChange={(event) => setTimelineTo(event.target.value)} /></label>
        </div>
      ) : null}
      <div className="native-dashboard-kpis">
        {overviewStats.map((item, index) => (
          <Link key={item.label} className="native-dashboard-kpi" to={index === 1 ? "/incidents" : index === 2 ? "/threat-intel" : index === 3 ? "/sources" : "/events"}>
            <span>{item.label}</span>
            <strong>{item.value}</strong>
            <small>{item.hint}</small>
          </Link>
        ))}
      </div>
      <div className="native-dashboard-workspace">
        <section className="native-dashboard-panel native-dashboard-panel-wide">
          <header>
            <div>
              <h2><Icon name="incidents" size={17} />{t(lang, { en: "Recent detections", ru: "Последние сработки" })}</h2>
              <p>{t(lang, { en: "Live alert queue from the selected analytical window.", ru: "Живая очередь алертов за выбранный период." })}</p>
            </div>
            <Link to={currentRangeQuery ? `/alerts?${currentRangeQuery}` : "/alerts"}>
              {t(lang, { en: "Open queue", ru: "Открыть очередь" })}
            </Link>
          </header>
          <div className="native-table-scroll">
            <table className="native-data-table">
              <thead>
                <tr>
                  <th>{t(lang, { en: "Severity", ru: "Важность" })}</th>
                  <th>{t(lang, { en: "Rule", ru: "Правило" })}</th>
                  <th>{t(lang, { en: "Source", ru: "Источник" })}</th>
                  <th>{t(lang, { en: "Status", ru: "Статус" })}</th>
                  <th>{t(lang, { en: "Last seen", ru: "Последнее событие" })}</th>
                </tr>
              </thead>
              <tbody>
                {compactAlerts.map((row, index) => {
                  const focusId = String(row.agg_id || row.alert_id || "");
                  return (
                    <tr key={focusId || `${row.rule_id}-${index}`}>
                      <td><span className={`react-badge severity-${String(row.severity || "info").toLowerCase()}`}>{row.severity || "info"}</span></td>
                      <td>
                        <Link className="native-row-link" to={focusId ? `/alerts?focus=${encodeURIComponent(focusId)}` : "/alerts"}>
                          {localizeRuleName(row.rule_name || row.rule_id || "n/a", lang)}
                        </Link>
                      </td>
                      <td>{row.source || "n/a"}</td>
                      <td>{row.status || "open"}</td>
                      <td>{formatTimestamp(row.ts_last || row.ts || row.ts_first, "compact")}</td>
                    </tr>
                  );
                })}
                {!compactAlerts.length ? (
                  <tr><td colSpan={5}>{t(lang, { en: "No detections in the current window.", ru: "За выбранный период сработок нет." })}</td></tr>
                ) : null}
              </tbody>
            </table>
          </div>
        </section>

        <section className="native-dashboard-panel">
          <header>
            <div>
              <h2><Icon name="dashboard" size={17} />{t(lang, { en: "Event flow", ru: "Поток событий" })}</h2>
              <p>{activeWindowLabel}</p>
            </div>
            <Link to={currentRangeQuery ? `/events?${currentRangeQuery}` : "/events"}>{t(lang, { en: "Explore", ru: "Исследовать" })}</Link>
          </header>
          <div className="native-dashboard-timeline" aria-label={t(lang, { en: "Event volume timeline", ru: "Динамика объема событий" })}>
            {compactTimeline.map((row, index) => {
              const count = Number(row.count ?? row.cnt ?? row.__value ?? 0);
              return (
                <div className="native-dashboard-timeline-bar" key={`${row.bucket_start || row.ts || row.bucket}-${index}`}>
                  <span style={{ height: `${Math.max(4, (count / compactTimelineMax) * 100)}%` }} />
                  <strong>{count.toLocaleString()}</strong>
                  <small>{formatTimestamp(row.bucket_start || row.ts || row.bucket, "time")}</small>
                </div>
              );
            })}
          </div>
        </section>

        <section className="native-dashboard-panel">
          <header>
            <div>
              <h2><Icon name="incidents" size={17} />{t(lang, { en: "Severity posture", ru: "Распределение важности" })}</h2>
              <p>{t(lang, { en: "Alert volume by normalized severity.", ru: "Объем алертов по нормализованной важности." })}</p>
            </div>
          </header>
          <div className="native-dashboard-breakdown">
            {compactSeverities.map((row, index) => {
              const label = String(row.severity || row.label || "unknown");
              const count = Number(row.count ?? row.cnt ?? row.events ?? 0);
              return (
                <div key={`${label}-${index}`}>
                  <span>{label}</span>
                  <i><b style={{ width: `${Math.max(2, (count / compactSeverityMax) * 100)}%` }} /></i>
                  <strong>{count.toLocaleString()}</strong>
                </div>
              );
            })}
          </div>
        </section>

        <section className="native-dashboard-panel">
          <header>
            <div>
              <h2><Icon name="collectors" size={17} />{t(lang, { en: "Top sources", ru: "Основные источники" })}</h2>
              <p>{t(lang, { en: "Current event contribution and freshness.", ru: "Текущий вклад источников и актуальность данных." })}</p>
            </div>
            <Link to="/sources">{t(lang, { en: "All sources", ru: "Все источники" })}</Link>
          </header>
          <div className="native-dashboard-list">
            {compactSources.map((row, index) => (
              <Link key={`${row.log_source}-${index}`} to={`/events?q=${encodeURIComponent(String(row.log_source || ""))}`}>
                <span><strong>{row.log_source || "n/a"}</strong><small>{formatTimestamp(row.last_seen, "compact")}</small></span>
                <b>{Number(row.events || 0).toLocaleString()}</b>
              </Link>
            ))}
          </div>
        </section>

        <section className="native-dashboard-panel">
          <header>
            <div>
              <h2><Icon name="builders" size={17} />{t(lang, { en: "Detection categories", ru: "Категории детектирования" })}</h2>
              <p>{t(lang, { en: "Normalized category mix across the event stream.", ru: "Структура нормализованных категорий в потоке." })}</p>
            </div>
            <Link to="/rules">{t(lang, { en: "Rules", ru: "Правила" })}</Link>
          </header>
          <div className="native-dashboard-list">
            {compactCategories.map((row, index) => {
              const label = String(row.label || row.category || row.severity || row.status || "unknown");
              const count = Number(row.count ?? row.cnt ?? row.events ?? 0);
              return (
                <Link key={`${label}-${index}`} to={`/events?q=${encodeURIComponent(label)}`}>
                  <span><strong>{label}</strong></span>
                  <b>{count.toLocaleString()}</b>
                </Link>
              );
            })}
          </div>
        </section>
      </div>
      <section className="react-card react-overview-hero-shell react-overview-legacy-shell">
        <div className="react-overview-hero-top react-overview-heading-bar">
          <div className="react-overview-heading-controls">
            <label className="react-time-inline-select">
              <span>{t(lang, { en: "Refresh", ru: "Обновление" })}</span>
              <select className="react-select" value={refreshSeconds} onChange={(event) => setRefreshSeconds(event.target.value)}>
                {dashboardRefreshOptions.map((item) => (
                  <option key={item.value} value={item.value}>
                    {item.label}
                  </option>
                ))}
              </select>
            </label>
            <TimeScopePickerButton
              label={t(lang, { en: "Time focus", ru: "Фокус по времени" })}
              value={timelineWindow}
              options={dashboardRangeOptions}
              onChange={handleTimelineWindowChange}
              buttonLabel={overviewFocusButtonLabel}
              customContent={
                <>
                  <label className="react-time-scope-item">
                    <span>{t(lang, { en: "Range from", ru: "Начало диапазона" })}</span>
                    <input
                      className="react-input"
                      type="datetime-local"
                      value={timelineFrom}
                      onChange={(event) => {
                        setTimelineWindow("custom");
                        setTimelineFrom(event.target.value);
                      }}
                    />
                  </label>
                  <label className="react-time-scope-item">
                    <span>{t(lang, { en: "Range to", ru: "Конец диапазона" })}</span>
                    <input
                      className="react-input"
                      type="datetime-local"
                      value={timelineTo}
                      onChange={(event) => {
                        setTimelineWindow("custom");
                        setTimelineTo(event.target.value);
                      }}
                    />
                  </label>
                </>
              }
              footerContent={overviewFocusFooter}
            />
          </div>
          <div className="react-overview-hero-copy react-overview-heading-copy">
            <div className="react-top-kicker">{t(lang, { en: "Overview", ru: "Обзор" })}</div>
            <h2 className="react-title-with-icon react-title-with-icon-hero">
              <Icon name="dashboard" size={20} />
              <span>{t(lang, { en: "Security overview", ru: "Обзор безопасности" })}</span>
            </h2>
            <p className="react-muted">
              {t(lang, {
                en: "Live SOC posture, time focus and direct pivots for the current operating window.",
                ru: "Живая SOC-картина, фокус по времени и быстрые переходы по текущему окну.",
              })}
            </p>
            <div className="react-overview-heading-links">
              <Link className="react-link-button" to={currentRangeQuery ? `/events?${currentRangeQuery}` : "/events"}>
                {t(lang, { en: "Open events", ru: "Открыть события" })}
              </Link>
              <Link className="react-link-button" to={currentRangeQuery ? `/incidents?${currentRangeQuery}` : "/incidents"}>
                {t(lang, { en: "Open incidents", ru: "Открыть инциденты" })}
              </Link>
            </div>
            <div className="react-inline-note react-overview-heading-note">{dashboardScopeSummary}</div>
          </div>
          <div className="react-overview-hero-actions">
            {selected?.title ? <span className="react-badge soft">{localizeDashboardTitle(selected.title, lang)}</span> : null}
            <span className="react-badge soft">{activeWindowLabel}</span>
            <button
              type="button"
              className="react-icon-button"
              onClick={() => setSettingsOpen(true)}
              aria-label={t(lang, { en: "Overview settings", ru: "Настройки обзора" })}
            >
              <Icon name="control" size={15} />
            </button>
          </div>
        </div>
        <div className="react-overview-hero-grid">
          <section className="react-overview-kpi-panel">
            <div className="react-overview-summary-row">
              <div>
                <div className="react-top-kicker">{t(lang, { en: "SOC snapshot", ru: "SOC-снимок" })}</div>
                <p className="react-muted">
                  {t(lang, {
                    en: "The most important platform counters for the same analytical window.",
                    ru: "Главные метрики платформы в том же аналитическом окне.",
                  })}
                </p>
              </div>
            </div>
            <div className="react-overview-kpi-grid">
              {overviewStats.map((item) => (
                <div key={item.label} className="react-overview-kpi-item">
                  <div className="react-stat-label">{item.label}</div>
                  <div className="react-overview-kpi-value">{item.value}</div>
                  <div className="react-stat-hint">{item.hint}</div>
                </div>
              ))}
            </div>
            <div className="react-overview-pressure-grid">
              {overviewPressureItems.map((item) => (
                <div key={item.label} className={`react-overview-pressure-item tone-${item.tone}`}>
                  <div className="react-stat-label">{item.label}</div>
                  <strong>{item.value}</strong>
                  <span>{item.hint}</span>
                </div>
              ))}
            </div>
            <div className="react-overview-lane-grid">
              {overviewOperatingLanes.map((item) => (
                <Link key={item.title} className="react-overview-lane-card" to={item.href}>
                  <div className="react-top-kicker">{t(lang, { en: "Operating lane", ru: "Рабочий маршрут" })}</div>
                  <strong>{item.title}</strong>
                  <span>{item.hint}</span>
                </Link>
              ))}
            </div>
          </section>
        </div>
      </section>

      {groupedLayout.map((section) => {
        const copy = sectionCopy(lang, section.id);
        return (
          <section key={section.id} className="react-section-stack react-overview-section-stack">
            <div className={`react-overview-section-head ${section.id === "soc_overview" ? "primary" : ""}`}>
              <h3 className="react-title-with-icon">
                <Icon name={sectionIcon(section.id)} size={18} />
                <span>{copy.title}</span>
              </h3>
              <p>{copy.subtitle}</p>
            </div>
            <DashboardCanvas
              layout={section.items}
              data={summaryData}
              onFocusIncident={(incidentId) => {
                window.location.assign(`/app/incidents?focus=${encodeURIComponent(incidentId)}`);
              }}
              onFocusIp={(ip) => setFocusedIp(ip)}
              onFocusCountry={(country, kind) => {
                setFocusedCountry(country);
                setFocusedCountryKind(kind);
              }}
              onFocusTimeRange={({ kind, from, to }) => {
                const params = new URLSearchParams();
                if (from) params.set("from", from);
                if (to) params.set("to", to);
                window.location.assign(kind === "alerts" ? `/app/incidents?${params.toString()}` : `/app/events?${params.toString()}`);
              }}
            />
          </section>
        );
      })}
      <DrawerOverlay
        open={settingsOpen}
        title={t(lang, { en: "Overview settings", ru: "Настройки обзора" })}
        subtitle={t(lang, {
          en: "Switch overview templates or open the dashboard composer only when you need to edit layout.",
          ru: "Переключайте шаблоны обзора или открывайте композер только когда нужно менять макет.",
        })}
        onClose={() => setSettingsOpen(false)}
      >
        <section className="react-card react-card-nested">
          <PanelHeader title={t(lang, { en: "Dashboards", ru: "Дашборды" })} subtitle={t(lang, { en: "Switch between analyst overview templates.", ru: "Переключайтесь между аналитическими шаблонами." })} icon="dashboard" />
          <div className="react-list react-list-compact">
            {dashboards.map((item: DashboardDefinition) => (
              <button
                type="button"
                key={item.id}
                className={`react-list-item ${selected?.id === item.id ? "active" : ""}`}
                onClick={() => {
                  setSelectedDashboardId(String(item.id || ""));
                  setSettingsOpen(false);
                }}
              >
                <strong>{item.title}</strong>
                <span>{item.description || ""}</span>
              </button>
            ))}
          </div>
        </section>
        <section className="react-card react-card-nested">
          <PanelHeader title={t(lang, { en: "Workspace actions", ru: "Действия рабочего пространства" })} subtitle={t(lang, { en: "Open the composer only when you need to edit templates or widget placement.", ru: "Открывайте композер только когда нужно менять шаблоны или расположение виджетов." })} icon="control" />
          <div className="react-actions react-wrap">
            <Link className="react-link-button" to="/control" onClick={() => setSettingsOpen(false)}>
              {t(lang, { en: "Open dashboard composer", ru: "Открыть композер дашбордов" })}
            </Link>
          </div>
        </section>
      </DrawerOverlay>

      <DrawerOverlay
        open={Boolean(focusedIp)}
        title={t(lang, { en: `IP detail: ${focusedIp}`, ru: `Детали IP: ${focusedIp}` })}
        subtitle={t(lang, {
          en: "GeoIP, reputation, incidents and recent evidence for the selected address.",
          ru: "GeoIP, репутация, инциденты и связанные события для выбранного адреса.",
        })}
        onClose={() => setFocusedIp("")}
      >
        {ipDetail.loading ? (
          <EmptyState message={t(lang, { en: "Loading IP detail...", ru: "Загрузка деталей IP..." })} />
        ) : ipDetail.error ? (
          <EmptyState message={ipDetail.error} />
        ) : ipDetail.data ? (
          <>
            <div className="react-card react-card-nested">
              <DrawerFieldGrid>
                <KeyValue label={t(lang, { en: "Country", ru: "Страна" })} value={ipDetail.data.geo?.country || "Unknown"} />
                <KeyValue label={t(lang, { en: "City", ru: "Город" })} value={ipDetail.data.geo?.city || "n/a"} />
                <KeyValue label={t(lang, { en: "Organization", ru: "Организация" })} value={ipDetail.data.geo?.org || "n/a"} />
                <KeyValue label={t(lang, { en: "Reputation", ru: "Репутация" })} value={ipDetail.data.reputation?.label || "unknown"} />
                <KeyValue label={t(lang, { en: "Signals", ru: "Сигналы" })} value={(ipDetail.data.reputation?.sources || []).join(", ") || "n/a"} />
                <KeyValue label={t(lang, { en: "Events 72h", ru: "События 72ч" })} value={ipDetail.data.summary?.events || 0} />
                <KeyValue label={t(lang, { en: "As source", ru: "Как источник" })} value={ipDetail.data.summary?.as_source || 0} />
                <KeyValue label={t(lang, { en: "As destination", ru: "Как назначение" })} value={ipDetail.data.summary?.as_destination || 0} />
                <KeyValue label={t(lang, { en: "Auth events", ru: "Auth-события" })} value={ipDetail.data.summary?.auth_events || 0} />
                <KeyValue label="Threat intel" value={ipDetail.data.summary?.ti_events || 0} />
                <KeyValue label={t(lang, { en: "Notable", ru: "Значимые" })} value={ipDetail.data.summary?.notable_events || 0} />
                <KeyValue label={t(lang, { en: "Last seen", ru: "Последняя активность" })} value={ipDetail.data.summary?.last_seen || "n/a"} />
              </DrawerFieldGrid>
            </div>
            <section className="react-card react-card-nested">
              <PanelHeader title={t(lang, { en: "Recent incidents", ru: "Свежие инциденты" })} subtitle={t(lang, { en: "Aggregated incidents referencing this address.", ru: "Агрегированные инциденты, связанные с этим адресом." })} icon="incidents" />
              <div className="react-table-wrap">
                <table className="react-table">
                  <thead>
                    <tr>
                      <th>{t(lang, { en: "Rule", ru: "Правило" })}</th>
                      <th>{t(lang, { en: "Status", ru: "Статус" })}</th>
                      <th>{t(lang, { en: "Severity", ru: "Важность" })}</th>
                      <th>{t(lang, { en: "Last seen", ru: "Последняя активность" })}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(ipDetail.data.incidents || []).map((row: NonNullable<ThreatIntelGeoDetailResponse["incidents"]>[number], index: number) => (
                      <tr key={`${row.agg_id}-${index}`}>
                        <td>{localizeRuleName(row.rule_name, lang)}</td>
                        <td>{row.status}</td>
                        <td>{row.severity}</td>
                        <td>{row.last_seen}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>
          </>
        ) : (
          <EmptyState message={t(lang, { en: "No IP detail loaded.", ru: "Нет данных по IP." })} />
        )}
      </DrawerOverlay>

      <DrawerOverlay
        open={Boolean(focusedCountry)}
        title={focusedCountry || t(lang, { en: "Country detail", ru: "Страна" })}
        subtitle={t(lang, {
          en: "IP addresses, organizations and related activity for the selected country.",
          ru: "IP-адреса, организации и связанная активность для выбранной страны.",
        })}
        onClose={() => setFocusedCountry("")}
      >
        {countryDetail ? (
          <div className="react-page">
            <DrawerFieldGrid>
              <KeyValue label={t(lang, { en: "Kind", ru: "Тип" })} value={focusedCountryKind === "source" ? t(lang, { en: "Source traffic", ru: "Входящий трафик" }) : t(lang, { en: "VPN destinations", ru: "VPN-направления" })} />
              <KeyValue label={t(lang, { en: "Events", ru: "События" })} value={countryDetail.summary?.events || 0} />
              <KeyValue label="IPs" value={countryDetail.summary?.items || countryDetail.items?.length || 0} />
              <KeyValue label={t(lang, { en: "Organizations", ru: "Организации" })} value={countryDetail.summary?.organizations || 0} />
            </DrawerFieldGrid>
            {countryLoading ? <div className="react-inline-note">{t(lang, { en: "Loading extended detail...", ru: "Загрузка расширенных деталей..." })}</div> : null}
            {countryError ? <div className="react-inline-note">{countryError}</div> : null}
            <section className="react-card react-card-nested">
              <PanelHeader title={t(lang, { en: "Address register", ru: "Реестр адресов" })} subtitle={t(lang, { en: "Top IPs/domains and their organizations.", ru: "Топ IP/доменов и соответствующих организаций." })} icon="map" />
              <div className="react-table-wrap">
                <table className="react-table">
                  <thead>
                    <tr>
                      <th>IP / Domain</th>
                      <th>{t(lang, { en: "Organization", ru: "Организация" })}</th>
                      <th>{t(lang, { en: "Events", ru: "События" })}</th>
                      <th>{t(lang, { en: "Ports", ru: "Порты" })}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(countryDetail.items || []).map((row: NonNullable<GeoCountryDetailResponse["items"]>[number], index: number) => (
                      <tr key={`${row.ip || row.label}-${index}`}>
                        <td>
                          {row.ip ? (
                            <button type="button" className="react-inline-action" onClick={() => setFocusedIp(String(row.ip))}>
                              {row.ip}
                            </button>
                          ) : (
                            row.label || "n/a"
                          )}
                        </td>
                        <td>{row.org || "n/a"}</td>
                        <td>{row.events ?? row.visits ?? 0}</td>
                        <td>{(row.ports || []).join(", ") || "n/a"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>
          </div>
        ) : (
          <EmptyState message={t(lang, { en: "No country detail loaded.", ru: "Нет данных по стране." })} />
        )}
      </DrawerOverlay>
    </div>
  );
}
