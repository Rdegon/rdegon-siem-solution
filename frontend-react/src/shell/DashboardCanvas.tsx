import type { DragEvent, ReactNode } from "react";
import {
  BreakdownBars,
  DonutChart,
  EmptyState,
  GeoDotMap,
  PanelHeader,
  ReactErrorBoundary,
  SeverityBadge,
  SparklineChart,
  StatCard,
  StatusBadge,
} from "./ui";
import { t, useShellContext } from "./context";
import { localizeRuleName } from "./runtimeLocalization";
import type { BreakdownRecord, DashboardSummaryResponse, GeoActivityRow, GeoCountrySummaryRow, IncidentRecord, ThreatIntelMaliciousSource, ThreatIntelMatchRecord, TimeBucketRecord } from "./types";

export type LayoutItem = {
  widget: string;
  span?: number;
};

type LocalizedCopy = {
  en: string;
  ru: string;
};

type WidgetMeta = {
  title: LocalizedCopy;
  subtitle: LocalizedCopy;
  section: string;
};

type DashboardSourceRow = NonNullable<DashboardSummaryResponse["top_sources"]>[number];
type DashboardPortRow = NonNullable<DashboardSummaryResponse["top_target_ports"]>[number];
type DashboardVpnSiteRow = NonNullable<DashboardSummaryResponse["top_vpn_sites"]>[number];

function withDisplayLabel(items: BreakdownRecord[], fallbackKey: "severity" | "status") {
  return items.map((item) => ({
    ...item,
    label: item.label || item[fallbackKey] || "unknown",
  }));
}

function normalizeBuckets(items: TimeBucketRecord[]) {
  return items.map((item) => ({
    ...item,
    count: item.cnt ?? item.count ?? 0,
  }));
}

function geoWindowHint(
  summary: { observed_window_hours?: number; requested_window_hours?: number; fallback_applied?: boolean; [key: string]: unknown } | undefined,
  lang: "en" | "ru",
) {
  const observed = Number(summary?.observed_window_hours || 0);
  const requested = Number(summary?.requested_window_hours || 0);
  if (!summary?.fallback_applied || !observed || !requested || observed <= requested) return "";
  return t(lang, {
    en: ` Showing last non-empty ${observed}h window.`,
    ru: ` Показано по последнему непустому окну ${observed}ч.`,
  });
}

export const DASHBOARD_SECTIONS: Array<{ id: string; title: string; subtitle: string }> = [
  { id: "soc_overview", title: "SOC Overview", subtitle: "Core queue, severity, volume and category analytics." },
  { id: "threat_geography", title: "Threat Geography", subtitle: "Where source traffic and VPN egress destinations are concentrated." },
  { id: "threat_intel", title: "Threat Intelligence", subtitle: "Reputation, IOC matches and malicious source prioritization." },
  { id: "collector_health", title: "Collector Health", subtitle: "Sources, ports and transport activity across pipelines." },
  { id: "incident_operations", title: "Incident Operations", subtitle: "Current queue state, recent incidents and analyst pivots." },
  { id: "external_traffic", title: "External Traffic", subtitle: "VPN browsing and external network activity." },
];

const WIDGET_META: Record<string, WidgetMeta> = {
  kpis: {
    title: { en: "Platform KPIs", ru: "Ключевые метрики" },
    subtitle: { en: "Core counters and operational pulse.", ru: "Базовые счетчики и оперативный пульс платформы." },
    section: "soc_overview",
  },
  severity_breakdown: {
    title: { en: "Severity overview", ru: "Распределение важности" },
    subtitle: { en: "Event and alert distributions by severity and status.", ru: "События и алерты по важности и статусу." },
    section: "soc_overview",
  },
  timelines: {
    title: { en: "Time-series", ru: "Динамика по времени" },
    subtitle: { en: "Event and alert volume over time.", ru: "Объем событий и алертов по времени." },
    section: "soc_overview",
  },
  categories: {
    title: { en: "Top categories", ru: "Топ категорий" },
    subtitle: { en: "Normalized category mix across the event stream.", ru: "Нормализованные категории в потоке событий." },
    section: "soc_overview",
  },
  geo_sources: {
    title: { en: "Attack geography", ru: "География атак" },
    subtitle: { en: "GeoIP map and country breakdown for source IPs.", ru: "Карта GeoIP и страны-источники для входящих IP." },
    section: "threat_geography",
  },
  geo_vpn_destinations: {
    title: { en: "VPN destination map", ru: "Карта VPN-направлений" },
    subtitle: { en: "Where users behind the VPN egress connect.", ru: "Куда выходят пользователи через VPN." },
    section: "threat_geography",
  },
  threat_intel: {
    title: { en: "Threat intelligence", ru: "Киберразведка" },
    subtitle: { en: "IOC matches, malicious IPs and provider summary.", ru: "IOC, вредоносные IP и сводка по провайдерам TI." },
    section: "threat_intel",
  },
  sources: {
    title: { en: "Top sources", ru: "Топ источников" },
    subtitle: { en: "Most active monitored sources in the recent window.", ru: "Самые активные источники в текущем окне." },
    section: "collector_health",
  },
  ports: {
    title: { en: "Targeted ports", ru: "Целевые порты" },
    subtitle: { en: "Services and ports most frequently probed or hit.", ru: "Сервисы и порты, которые чаще всего пробуют." },
    section: "collector_health",
  },
  vpn_sites: {
    title: { en: "VPN top sites", ru: "Топ сайтов через VPN" },
    subtitle: { en: "Most active domains observed in VPN access logs.", ru: "Домены, которые чаще всего встречаются в VPN-логах." },
    section: "external_traffic",
  },
  incidents_preview: {
    title: { en: "Recent incidents", ru: "Свежие инциденты" },
    subtitle: { en: "Fresh incident queue preview with pivots into incidents.", ru: "Превью очереди инцидентов с быстрыми переходами." },
    section: "incident_operations",
  },
  incident_queue: {
    title: { en: "Incident queue", ru: "Очередь инцидентов" },
    subtitle: { en: "Analyst-facing queue widget for triage.", ru: "Рабочая очередь аналитика для triage." },
    section: "incident_operations",
  },
};

function label(lang: "en" | "ru", values: LocalizedCopy) {
  return t(lang, values);
}

function Section({
  title,
  subtitle,
  actions,
  children,
  span = 1,
  draggable,
  onDragStart,
  onDragOver,
  onDrop,
}: {
  title: string;
  subtitle: string;
  actions?: ReactNode;
  children: ReactNode;
  span?: number;
  draggable?: boolean;
  onDragStart?: () => void;
  onDragOver?: (event: DragEvent<HTMLElement>) => void;
  onDrop?: () => void;
}) {
  return (
    <section
      className={`react-card react-widget-card react-widget-span-${span >= 2 ? 2 : 1}`}
      draggable={draggable}
      onDragStart={onDragStart}
      onDragOver={onDragOver}
      onDrop={onDrop}
    >
      <PanelHeader title={title} subtitle={subtitle} actions={actions} />
      {children}
    </section>
  );
}

export function widgetMeta(widgetId: string): WidgetMeta {
  return WIDGET_META[widgetId] || {
    title: { en: widgetId.replaceAll("_", " "), ru: widgetId.replaceAll("_", " ") },
    subtitle: { en: "Interactive widget", ru: "Интерактивный виджет" },
    section: "soc_overview",
  };
}

export function groupDashboardLayout(layout: LayoutItem[]) {
  const groups = new Map<string, LayoutItem[]>();
  for (const item of layout || []) {
    const meta = widgetMeta(String(item.widget || ""));
    const current = groups.get(meta.section) || [];
    current.push(item);
    groups.set(meta.section, current);
  }
  return DASHBOARD_SECTIONS
    .map((section) => ({
      ...section,
      items: groups.get(section.id) || [],
    }))
    .filter((section) => section.items.length > 0);
}

export function renderDashboardWidget(
  widgetId: string,
  data: DashboardSummaryResponse,
  options: {
    lang?: "en" | "ru";
    compact?: boolean;
    formatTimestamp?: (value: unknown, style?: "full" | "compact" | "date" | "time") => string;
    onFocusIncident?: (incidentId: string) => void;
    onFocusIp?: (ip: string) => void;
    onFocusCountry?: (country: string, kind: "source" | "vpn") => void;
    onFocusTimeRange?: (selection: { kind: "events" | "alerts"; from: string; to: string; count: number }) => void;
  } = {},
) {
  const lang = options.lang || "en";
  const formatTimestamp = options.formatTimestamp || ((value: unknown) => String(value || "n/a"));
  const recentAlerts: IncidentRecord[] = data?.recent_alerts || [];

  switch (widgetId) {
    case "kpis":
      return (
        <div className="react-grid react-grid-5 react-grid-tight">
          <StatCard label={t(lang, { en: "Events 1h", ru: "События 1ч" })} value={data?.metrics?.events_1h || 0} hint={t(lang, { en: "Current flow in the last hour.", ru: "Текущий поток за последний час." })} />
          <StatCard label={t(lang, { en: "Events 24h", ru: "События 24ч" })} value={data?.metrics?.events_24h || 0} hint={t(lang, { en: "Normalized events for the last day.", ru: "Нормализованные события за последние сутки." })} />
          <StatCard label={t(lang, { en: "Open incidents", ru: "Открытые инциденты" })} value={data?.metrics?.open_incidents_24h || 0} hint={t(lang, { en: "Queue waiting for analyst action.", ru: "Очередь, ожидающая действий аналитика." })} />
          <StatCard label={t(lang, { en: "TI hits", ru: "Совпадения TI" })} value={data?.metrics?.ti_hits_24h || 0} hint={t(lang, { en: "Threat-intelligence matches in 24h.", ru: "Совпадения с киберразведкой за 24 часа." })} />
          <StatCard label={t(lang, { en: "Active sources", ru: "Активные источники" })} value={data?.metrics?.active_sources_24h || 0} hint={t(lang, { en: "Reporting sources across the platform.", ru: "Источники, которые сейчас отчитываются в систему." })} />
        </div>
      );
    case "severity_breakdown":
      return (
        <div className="react-severity-matrix">
          <div className="react-severity-panel">
            <PanelHeader title={t(lang, { en: "Events by severity", ru: "События по важности" })} subtitle={t(lang, { en: "Normalized event distribution.", ru: "Распределение нормализованных событий." })} />
            <DonutChart items={withDisplayLabel(data?.severity_breakdown || [], "severity")} />
          </div>
          <div className="react-severity-panel">
            <PanelHeader title={t(lang, { en: "Alerts by severity", ru: "Алерты по важности" })} subtitle={t(lang, { en: "Queue concentration by alert level.", ru: "Концентрация очереди по уровню алертов." })} />
            <DonutChart items={withDisplayLabel(data?.alert_severity_breakdown || [], "severity")} />
          </div>
          <div className="react-severity-panel">
            <PanelHeader title={t(lang, { en: "Alerts by status", ru: "Алерты по статусу" })} subtitle={t(lang, { en: "Lifecycle stage distribution.", ru: "Распределение стадий жизненного цикла." })} />
            <DonutChart items={withDisplayLabel(data?.alert_status_breakdown || [], "status")} />
          </div>
        </div>
      );
    case "timelines":
      return (
        <div className="react-grid react-grid-2">
          <div className="react-card react-card-nested">
            <PanelHeader title={t(lang, { en: "Event volume", ru: "Объем событий" })} subtitle={t(lang, { en: "Hourly buckets for normalized events.", ru: "Почасовые бакеты для нормализованных событий." })} />
            <SparklineChart
              items={normalizeBuckets(data?.timeline || [])}
              onSelect={(item) =>
                options.onFocusTimeRange?.({
                  kind: "events",
                  from: String(item.bucket_start || item.bucket || ""),
                  to: String(item.bucket_end || item.bucket || ""),
                  count: Number(item.__value ?? item.cnt ?? item.count ?? 0),
                })
              }
            />
          </div>
          <div className="react-card react-card-nested">
            <PanelHeader title={t(lang, { en: "Alert volume", ru: "Объем алертов" })} subtitle={t(lang, { en: "Hourly buckets for generated alerts.", ru: "Почасовые бакеты для сгенерированных алертов." })} />
            <SparklineChart
              items={normalizeBuckets(data?.alert_timeline || [])}
              onSelect={(item) =>
                options.onFocusTimeRange?.({
                  kind: "alerts",
                  from: String(item.bucket_start || item.bucket || ""),
                  to: String(item.bucket_end || item.bucket || ""),
                  count: Number(item.__value ?? item.cnt ?? item.count ?? 0),
                })
              }
            />
          </div>
        </div>
      );
    case "geo_sources":
      return (
        <div className="react-grid react-grid-2">
          <div className="react-card react-card-nested">
            <PanelHeader
              title={t(lang, { en: "GeoIP: source countries", ru: "GeoIP: страны-источники" })}
              subtitle={t(lang, {
                en: `Countries: ${data?.geo_sources?.summary?.countries || 0}, IPs: ${data?.geo_sources?.summary?.ips || 0}`,
                ru: `Стран: ${data?.geo_sources?.summary?.countries || 0}, IP: ${data?.geo_sources?.summary?.ips || 0}`,
              }) + geoWindowHint(data?.geo_sources?.summary, lang)}
            />
            <GeoDotMap
              points={data?.geo_sources?.items || []}
              valueKey="events"
              labelKey="country"
              titleKey="ip"
              metricLabel={t(lang, { en: "events", ru: "событий" })}
              onCountryClick={(country) => options.onFocusCountry?.(country, "source")}
            />
          </div>
          <div className="react-card react-card-nested">
            <PanelHeader title={t(lang, { en: "Country breakdown", ru: "Разбивка по странам" })} subtitle={t(lang, { en: "External sources grouped by country and source count.", ru: "Внешние источники по странам и числу адресов." })} />
            <div className="react-table-wrap">
              <table className="react-table">
                <thead>
                  <tr>
                    <th>{t(lang, { en: "Country", ru: "Страна" })}</th>
                    <th>{t(lang, { en: "Events", ru: "События" })}</th>
                    <th>IPs</th>
                  </tr>
                </thead>
                <tbody>
                  {(data?.geo_sources?.countries || []).map((row: GeoCountrySummaryRow, index: number) => (
                    <tr key={`${row.country}-${index}`} onClick={() => options.onFocusCountry?.(String(row.country || ""), "source")}>
                      <td>
                        <button type="button" className="react-inline-action">
                          {row.country}
                        </button>
                      </td>
                      <td>{row.events}</td>
                      <td>{row.ips}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      );
    case "geo_vpn_destinations":
      return (
        <div className="react-grid react-grid-2">
          <div className="react-card react-card-nested">
            <PanelHeader title={t(lang, { en: "VPN destination map", ru: "Карта VPN-направлений" })} subtitle={t(lang, { en: "Resolved destination geography for VPN browsing.", ru: "География назначений для VPN-трафика." })} />
            <GeoDotMap
              points={data?.geo_vpn_destinations?.items || []}
              valueKey="visits"
              labelKey="country"
              titleKey="domain"
              metricLabel={t(lang, { en: "visits", ru: "визитов" })}
              onCountryClick={(country) => options.onFocusCountry?.(country, "vpn")}
            />
          </div>
          <div className="react-card react-card-nested">
            <PanelHeader title={t(lang, { en: "VPN destination countries", ru: "Страны VPN-направлений" })} subtitle={t(lang, { en: "Country and destination summary for VPN egress.", ru: "Страны и назначения для VPN-egress." })} />
            <div className="react-table-wrap">
              <table className="react-table">
                <thead>
                  <tr>
                    <th>{t(lang, { en: "Domain", ru: "Домен" })}</th>
                    <th>{t(lang, { en: "Country", ru: "Страна" })}</th>
                    <th>{t(lang, { en: "Visits", ru: "Визиты" })}</th>
                  </tr>
                </thead>
                <tbody>
                  {(data?.geo_vpn_destinations?.items || []).map((row: GeoActivityRow, index: number) => (
                    <tr key={`${row.domain}-${index}`} onClick={() => row.country && options.onFocusCountry?.(String(row.country), "vpn")}>
                      <td>{row.domain}</td>
                      <td>{row.country}</td>
                      <td>{row.visits}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      );
    case "threat_intel":
      return (
        <div className="react-grid react-grid-2">
          <div className="react-card react-card-nested">
            <PanelHeader title={t(lang, { en: "Malicious sources", ru: "Подозрительные источники" })} subtitle={t(lang, { en: "Public source IPs flagged by TI or deny/watch lists.", ru: "Публичные IP-источники, отмеченные TI или списками." })} />
            <div className="react-table-wrap">
              <table className="react-table">
                <thead>
                  <tr>
                    <th>IP</th>
                    <th>{t(lang, { en: "Country", ru: "Страна" })}</th>
                    <th>{t(lang, { en: "Reputation", ru: "Репутация" })}</th>
                    <th>{t(lang, { en: "Events", ru: "События" })}</th>
                    <th>TI</th>
                  </tr>
                </thead>
                <tbody>
                  {(data?.threat_intel?.malicious_sources || []).slice(0, 8).map((row: ThreatIntelMaliciousSource, index: number) => (
                    <tr key={`${row.ip}-${index}`}>
                      <td>
                        <button type="button" className="react-inline-action" onClick={() => options.onFocusIp?.(String(row.ip))}>
                          {row.ip}
                        </button>
                      </td>
                      <td>{row.country}</td>
                      <td>{row.reputation}</td>
                      <td>{row.events}</td>
                      <td>{row.ti_hits}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
          <div className="react-card react-card-nested">
            <PanelHeader title={t(lang, { en: "Indicator matches", ru: "Совпадения индикаторов" })} subtitle={t(lang, { en: "Recent IOC matches grouped by indicator.", ru: "Недавние IOC-совпадения по индикаторам." })} />
            <div className="react-table-wrap">
              <table className="react-table">
                <thead>
                  <tr>
                    <th>{t(lang, { en: "Indicator", ru: "Индикатор" })}</th>
                    <th>{t(lang, { en: "Provider", ru: "Провайдер" })}</th>
                    <th>{t(lang, { en: "Events", ru: "События" })}</th>
                    <th>IP</th>
                  </tr>
                </thead>
                <tbody>
                  {(data?.threat_intel?.recent_matches || []).slice(0, 8).map((row: ThreatIntelMatchRecord, index: number) => (
                    <tr key={`${row.indicator}-${index}`}>
                      <td>{row.indicator}</td>
                      <td>{row.provider || "n/a"}</td>
                      <td>{row.events}</td>
                      <td>
                        {row.sample_ip ? (
                          <button type="button" className="react-inline-action" onClick={() => options.onFocusIp?.(String(row.sample_ip))}>
                            {row.sample_ip}
                          </button>
                        ) : (
                          "n/a"
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <BreakdownBars items={data?.threat_intel?.providers || []} valueKey="count" labelKey="provider" />
          </div>
        </div>
      );
    case "sources":
      return (
        <div className="react-table-wrap">
          <table className="react-table">
            <thead>
              <tr>
                <th>{t(lang, { en: "Source", ru: "Источник" })}</th>
                <th>{t(lang, { en: "Events", ru: "События" })}</th>
                <th>{t(lang, { en: "Last seen", ru: "Последняя активность" })}</th>
              </tr>
            </thead>
            <tbody>
              {(data?.top_sources || []).map((row: DashboardSourceRow) => (
                <tr key={row.log_source}>
                  <td>{row.log_source}</td>
                  <td>{row.events}</td>
                  <td>{formatTimestamp(row.last_seen, "compact")}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      );
    case "ports":
      return (
        <div className="react-table-wrap">
          <table className="react-table">
            <thead>
              <tr>
                <th>{t(lang, { en: "Port", ru: "Порт" })}</th>
                <th>{t(lang, { en: "Service", ru: "Сервис" })}</th>
                <th>{t(lang, { en: "Attempts", ru: "Попытки" })}</th>
                <th>{t(lang, { en: "Sources", ru: "Источники" })}</th>
                <th>{t(lang, { en: "Signal", ru: "Сигнал" })}</th>
              </tr>
            </thead>
            <tbody>
              {(data?.top_target_ports || []).map((row: DashboardPortRow, index: number) => (
                <tr key={`${row.dst_port}-${index}`}>
                  <td>{row.dst_port}</td>
                  <td>{row.service}</td>
                  <td>{row.attempts}</td>
                  <td>{row.unique_sources}</td>
                  <td>{row.signal || "probe"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      );
    case "vpn_sites":
      return (
        <div className="react-table-wrap">
          <table className="react-table">
            <thead>
              <tr>
                <th>{t(lang, { en: "Domain", ru: "Домен" })}</th>
                <th>{t(lang, { en: "Visits", ru: "Визиты" })}</th>
                <th>{t(lang, { en: "Client", ru: "Клиент" })}</th>
                <th>{t(lang, { en: "Last seen", ru: "Последняя активность" })}</th>
              </tr>
            </thead>
            <tbody>
              {(data?.top_vpn_sites || []).map((row: DashboardVpnSiteRow, index: number) => (
                <tr key={`${row.domain}-${index}`}>
                  <td>{row.domain}</td>
                  <td>{row.visits}</td>
                  <td>{row.client_id || "default"}</td>
                  <td>{formatTimestamp(row.last_seen, "compact")}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      );
    case "categories":
      return <BreakdownBars items={data?.top_categories || []} valueKey="events" labelKey="category" />;
    case "incidents_preview":
    case "incident_queue":
      return recentAlerts.length ? (
        <div className="react-table-wrap">
          <table className="react-table">
            <thead>
              <tr>
                <th>{t(lang, { en: "Rule", ru: "Правило" })}</th>
                <th>{t(lang, { en: "Severity", ru: "Важность" })}</th>
                <th>{t(lang, { en: "Source", ru: "Источник" })}</th>
                <th>{t(lang, { en: "Status", ru: "Статус" })}</th>
                <th>{t(lang, { en: "Last seen", ru: "Последняя активность" })}</th>
              </tr>
            </thead>
            <tbody>
              {recentAlerts.map((row) => (
                <tr key={row.agg_id}>
                  <td>
                    <button type="button" className="react-inline-action" onClick={() => options.onFocusIncident?.(String(row.agg_id || ""))}>
                      {localizeRuleName(row.rule_name, lang)}
                    </button>
                  </td>
                  <td>
                    <SeverityBadge value={row.severity_agg || row.severity || "info"} />
                  </td>
                  <td>{row.source_summary || row.source || "n/a"}</td>
                  <td>
                    <StatusBadge value={row.status || "new"} />
                  </td>
                  <td>{formatTimestamp(row.ts_last || row.ts, "compact")}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <EmptyState message={t(lang, { en: "No incidents in the selected queue.", ru: "В выбранной очереди нет инцидентов." })} />
      );
    default:
      return <EmptyState message={`${t(lang, { en: "Unknown widget", ru: "Неизвестный виджет" })}: ${widgetId}`} />;
  }
}

export function DashboardCanvas({
  layout,
  data,
  editable = false,
  onDragStartItem,
  onDropItem,
  onRemove,
  onToggleSpan,
  onFocusIncident,
  onFocusIp,
  onFocusCountry,
  onFocusTimeRange,
}: {
  layout: LayoutItem[];
  data: DashboardSummaryResponse;
  editable?: boolean;
  onDragStartItem?: (index: number) => void;
  onDropItem?: (index: number) => void;
  onRemove?: (widgetId: string) => void;
  onToggleSpan?: (widgetId: string) => void;
  onFocusIncident?: (incidentId: string) => void;
  onFocusIp?: (ip: string) => void;
  onFocusCountry?: (country: string, kind: "source" | "vpn") => void;
  onFocusTimeRange?: (selection: { kind: "events" | "alerts"; from: string; to: string; count: number }) => void;
}) {
  const { lang, formatTimestamp } = useShellContext();

  if (!layout?.length) return <EmptyState message={t(lang, { en: "No widgets configured for this dashboard.", ru: "Для этого дашборда не настроены виджеты." })} />;
  return (
    <div className="react-grid react-dashboard-canvas">
      {layout.map((item, index) => {
        const widgetId = String(item.widget || "");
        const span = Number(item.span || 1) >= 2 ? 2 : 1;
        const meta = widgetMeta(widgetId);
        const actions = editable ? (
          <>
            <button type="button" className="react-link-button" onClick={() => onToggleSpan?.(widgetId)}>
              {t(lang, { en: "Span", ru: "Размер" })} {span === 2 ? "1" : "2"}
            </button>
            <button type="button" className="react-link-button" onClick={() => onRemove?.(widgetId)}>
              {t(lang, { en: "Remove", ru: "Убрать" })}
            </button>
          </>
        ) : undefined;
        return (
          <Section
            key={`${widgetId}-${index}`}
            title={label(lang, meta.title)}
            subtitle={label(lang, meta.subtitle)}
            actions={actions}
            span={span}
            draggable={editable}
            onDragStart={() => onDragStartItem?.(index)}
            onDragOver={(event) => {
              if (editable) event.preventDefault();
            }}
            onDrop={() => onDropItem?.(index)}
          >
            <ReactErrorBoundary title={`${t(lang, { en: "Widget failed", ru: "Ошибка виджета" })}: ${label(lang, meta.title)}`}>
              {renderDashboardWidget(widgetId, data, { lang, formatTimestamp, onFocusIncident, onFocusIp, onFocusCountry, onFocusTimeRange })}
            </ReactErrorBoundary>
          </Section>
        );
      })}
    </div>
  );
}
