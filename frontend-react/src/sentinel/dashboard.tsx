import { useMemo } from "react";
import { geoNaturalEarth1, geoPath } from "d3-geo";
import { feature } from "topojson-client";
import type { FeatureCollection } from "geojson";
import worldAtlas from "world-atlas/countries-110m.json";
import { api } from "./runtime/api";
import type { DashboardSummaryResponse, IncidentRecord } from "./runtime/types";
import { formatTime, number, severityTone, text, useQuery } from "./runtime/query";
import type { View } from "./model";
import { Badge, Button, EmptyState, ErrorState, IconButton, LoadingState, PageHeader, StatusCell } from "./ui";

type Row = Record<string, unknown>;
type Navigate = (view: View) => void;

const SLA_MINUTES: Record<string, number> = { critical: 15, high: 60, medium: 240, low: 1440, info: 1440 };
const TERMINAL_STATUSES = new Set(["closed", "resolved", "false_positive", "suppressed"]);

export function incidentSla(row: IncidentRecord, now = Date.now()) {
  const severity = text(row.severity_agg ?? row.severity, "info").toLowerCase();
  const targetMinutes = SLA_MINUTES[severity] ?? SLA_MINUTES.info;
  const openedAt = new Date(text(row.ts_first ?? row.ts, "")).getTime();
  const ageMinutes = Number.isFinite(openedAt) ? Math.max(0, Math.floor((now - openedAt) / 60_000)) : 0;
  const terminal = TERMINAL_STATUSES.has(text(row.status, "open").toLowerCase());
  return {
    targetMinutes,
    ageMinutes,
    remainingMinutes: targetMinutes - ageMinutes,
    breached: !terminal && ageMinutes > targetMinutes,
    terminal,
  };
}

function compactDuration(minutes: number) {
  const absolute = Math.abs(Math.round(minutes));
  if (absolute < 60) return `${absolute} мин`;
  if (absolute < 1440) return `${Math.floor(absolute / 60)} ч ${absolute % 60} мин`;
  return `${Math.floor(absolute / 1440)} д ${Math.floor((absolute % 1440) / 60)} ч`;
}

function Metric({ label, value, detail, tone = "" }: { label: string; value: string | number; detail: string; tone?: string }) {
  return <div className={`metric sentinel-dashboard-metric ${tone ? `metric-${tone}` : ""}`}><span>{label}</span><strong>{value}</strong><small>{detail}</small></div>;
}

function Panel({ title, subtitle, action, children, className = "" }: { title: string; subtitle: string; action?: React.ReactNode; children: React.ReactNode; className?: string }) {
  return <section className={`panel sentinel-dashboard-panel ${className}`}><header className="panel-header"><div className="panel-title"><h2>{title}</h2><span>{subtitle}</span></div>{action}</header><div className="sentinel-panel-body">{children}</div></section>;
}

function Bars({ rows, labelKey = "label", valueKeys = ["count", "cnt", "events"] }: { rows: Row[]; labelKey?: string; valueKeys?: string[] }) {
  const prepared = rows.map((row) => ({
    label: labelKey === "service" && row.dst_port
      ? `${text(row[labelKey], "port")} · ${text(row.dst_port)}`
      : text(row[labelKey] ?? row.category ?? row.subcategory ?? row.severity ?? row.status ?? row.log_source ?? row.dst_port, "Неизвестно"),
    value: valueKeys.reduce((result, key) => result || number(row[key]), 0),
  }));
  const max = Math.max(1, ...prepared.map((item) => item.value));
  if (!prepared.length) return <EmptyState detail="За выбранный период распределение отсутствует" />;
  return <div className="sentinel-bars">{prepared.map((item) => <div className="sentinel-bar-row" key={item.label}><span>{item.label}</span><div><i style={{ width: `${Math.max(2, item.value / max * 100)}%` }} /></div><b>{item.value.toLocaleString("ru-RU")}</b></div>)}</div>;
}

function Timeline({ events, alerts }: { events: Row[]; alerts: Row[] }) {
  const alertIndex = new Map(alerts.map((row) => [text(row.bucket ?? row.bucket_start, ""), number(row.cnt ?? row.count)]));
  const points = events.map((row) => ({
    key: text(row.bucket ?? row.bucket_start, ""),
    label: formatTime(row.bucket ?? row.bucket_start),
    events: number(row.cnt ?? row.count),
    alerts: alertIndex.get(text(row.bucket ?? row.bucket_start, "")) ?? 0,
  }));
  const max = Math.max(1, ...points.map((point) => point.events));
  if (!points.length) return <EmptyState detail="Временной ряд еще не сформирован" />;
  return <div className="sentinel-timeline" aria-label="Динамика событий и алертов">{points.map((point) => <div className="sentinel-timeline-column" key={point.key} title={`${point.label}: ${point.events.toLocaleString("ru-RU")} событий, ${point.alerts} алертов`}><div className="sentinel-timeline-bars"><i style={{ height: `${Math.max(3, point.events / max * 100)}%` }} /><b style={{ height: `${Math.max(2, Math.min(100, point.alerts * 12))}%` }} /></div><span>{new Date(point.key).getHours().toString().padStart(2, "0")}</span></div>)}</div>;
}

function WorldActivityMap({ rows }: { rows: Row[] }) {
  const map = useMemo(() => {
    const atlas = worldAtlas as unknown as { objects: { countries: unknown } };
    const collection = feature(worldAtlas as never, atlas.objects.countries as never) as unknown as FeatureCollection;
    const projection = geoNaturalEarth1().fitExtent([[8, 8], [892, 392]], collection);
    const path = geoPath(projection);
    return { collection, projection, path };
  }, []);
  const points = rows.filter((row) => Number.isFinite(Number(row.lat)) && Number.isFinite(Number(row.lon)));
  const max = Math.max(1, ...points.map((row) => number(row.events ?? row.count)));
  return <div className="sentinel-world-map"><svg aria-label="Карта источников сетевой активности" role="img" viewBox="0 0 900 400"><g className="sentinel-world-land">{map.collection.features.map((shape, index) => <path d={map.path(shape) ?? ""} key={String(shape.id ?? index)} />)}</g><g>{points.map((row, index) => {
    const coordinates = map.projection([number(row.lon), number(row.lat)]);
    if (!coordinates) return null;
    const radius = 3.5 + Math.sqrt(number(row.events ?? row.count) / max) * 8;
    return <g className="sentinel-map-point" key={`${text(row.ip ?? row.country)}-${index}`} transform={`translate(${coordinates[0]} ${coordinates[1]})`}><circle className="pulse" r={radius + 6} /><circle r={radius}><title>{`${text(row.country)} · ${text(row.ip)} · ${number(row.events).toLocaleString("ru-RU")} событий`}</title></circle></g>;
  })}</g></svg><div className="sentinel-map-legend"><span><i /> внешний источник</span><b>{points.length} геоточек</b></div></div>;
}

function SlaPanel({ incidents }: { incidents: IncidentRecord[] }) {
  const active = incidents.filter((row) => !incidentSla(row).terminal);
  const breached = active.filter((row) => incidentSla(row).breached);
  const compliance = active.length ? Math.round((active.length - breached.length) / active.length * 100) : 100;
  const urgent = [...active].sort((left, right) => incidentSla(left).remainingMinutes - incidentSla(right).remainingMinutes).slice(0, 5);
  return <><div className="sentinel-sla-summary"><div className={`sentinel-sla-gauge ${breached.length ? "warning" : "healthy"}`} style={{ "--sla": `${compliance}%` } as React.CSSProperties}><strong>{compliance}%</strong><span>в пределах SLA</span></div><div><b>{breached.length}</b><span>нарушено</span></div><div><b>{active.length - breached.length}</b><span>в работе</span></div></div><div className="sentinel-compact-list">{urgent.map((row) => {
    const sla = incidentSla(row);
    return <div key={text(row.agg_id ?? row.alert_id)}><Badge tone={severityTone(row.severity_agg ?? row.severity)}>{text(row.severity_agg ?? row.severity)}</Badge><span><strong>{text(row.rule_name)}</strong><small>{sla.breached ? `просрочено на ${compactDuration(-sla.remainingMinutes)}` : `осталось ${compactDuration(sla.remainingMinutes)}`}</small></span></div>;
  })}</div></>;
}

function IncidentPreview({ rows, navigate }: { rows: IncidentRecord[]; navigate: Navigate }) {
  if (!rows.length) return <EmptyState detail="Открытых инцидентов нет" />;
  return <div className="sentinel-incident-preview">{rows.slice(0, 8).map((row) => <button key={text(row.agg_id ?? row.alert_id)} onClick={() => navigate("incidents")} type="button"><Badge tone={severityTone(row.severity_agg ?? row.severity)}>{text(row.severity_agg ?? row.severity)}</Badge><span><strong>{text(row.rule_name)}</strong><small>{text(row.source_summary ?? row.source ?? row.entity_key)} · {formatTime(row.ts_last ?? row.ts)}</small></span><StatusCell value={text(row.status)} /></button>)}</div>;
}

export function OverviewDashboard({ navigate }: { navigate: Navigate }) {
  const dashboard = useQuery("dashboard:24h", () => api.dashboard({ window: "24h", bucket_minutes: 60, recent_limit: 12 }), 60_000);
  const incidents = useQuery("dashboard:incidents", () => api.incidents({ view: "agg", window: "30d", limit: 50 }), 30_000);
  const sources = useQuery("dashboard:sources", () => api.sourcesInventory({ hours: 24, limit: 500 }), 60_000);
  const security = useQuery("dashboard:security", () => api.securityServices(), 60_000);
  const data: DashboardSummaryResponse = dashboard.data ?? {};
  const incidentRows = incidents.data?.items ?? [];
  const sourceRows = sources.data?.items ?? [];
  const unhealthySources = sourceRows.filter((row) => !/active|healthy|online|норма/i.test(text(row.status, "")));
  const partialErrors = [dashboard.error, incidents.error, sources.error, security.error].filter(Boolean);
  return <div className="native-page sentinel-dashboard"><PageHeader eyebrow="SOC · production telemetry" title="Панель мониторинга" actions={<IconButton icon="refresh" label="Обновить все виджеты" onClick={() => { dashboard.reload(); incidents.reload(); sources.reload(); security.reload(); }} />} />
    {partialErrors.length ? <div className="sentinel-partial-warning"><Badge tone="warning">Частичные данные</Badge><span>{partialErrors.map((error) => error?.message).join(" · ")}</span></div> : null}
    <section className="metric-grid sentinel-dashboard-metrics">
      <Metric detail="нормализованный поток" label="События за 1 час" value={number(data.metrics?.events_1h).toLocaleString("ru-RU")} />
      <Metric detail="горячее хранилище" label="События за 24 часа" value={number(data.metrics?.events_24h).toLocaleString("ru-RU")} />
      <Metric detail="ожидают triage" label="Открытые инциденты" tone={incidentRows.length ? "warning" : ""} value={incidentRows.length} />
      <Metric detail={`${unhealthySources.length} с отклонениями`} label="Активные источники" value={number(data.metrics?.active_sources_24h) || sourceRows.length} />
      <Metric detail="совпадения с TI" label="Threat Intelligence" tone={number(data.metrics?.ti_hits_24h) ? "warning" : ""} value={number(data.metrics?.ti_hits_24h).toLocaleString("ru-RU")} />
      <Metric detail={`${number(security.data?.total)} интеграций`} label="Средства защиты" value={`${number(security.data?.healthy)}/${number(security.data?.total)}`} />
    </section>
    {dashboard.loading && !dashboard.data ? <LoadingState label="Формирование аналитических виджетов..." /> : dashboard.error && !dashboard.data ? <ErrorState error={dashboard.error} retry={dashboard.reload} /> : <>
      <div className="sentinel-dashboard-grid sentinel-dashboard-grid-main">
        <Panel className="span-2" subtitle="Почасовая нагрузка production transport" title="Поток событий и алертов"><Timeline alerts={(data.alert_timeline ?? []) as Row[]} events={(data.timeline ?? []) as Row[]} /></Panel>
        <Panel subtitle="Triage: critical 15 мин, high 1 ч, medium 4 ч" title="SLA инцидентов"><SlaPanel incidents={incidentRows} /></Panel>
        <Panel className="span-2" subtitle="GeoIP внешних адресов, зафиксированных источниками" title="Карта сетевой активности"><WorldActivityMap rows={(data.geo_sources?.items ?? []) as Row[]} /></Panel>
        <Panel subtitle="Нормализованные события за 24 часа" title="Важность событий"><Bars rows={(data.severity_breakdown ?? []) as Row[]} /></Panel>
      </div>
      <div className="sentinel-dashboard-grid">
        <Panel action={<Button onClick={() => navigate("incidents")} tone="ghost">Вся очередь</Button>} className="span-2" subtitle="Текущие агрегированные срабатывания" title="Открытые инциденты"><IncidentPreview navigate={navigate} rows={incidentRows} /></Panel>
        <Panel subtitle="Распределение нормализованного потока" title="Категории событий"><Bars rows={(data.top_categories ?? []) as Row[]} /></Panel>
        <Panel subtitle="Наиболее активные подключенные источники" title="Источники"><Bars labelKey="log_source" rows={(data.top_sources ?? []) as Row[]} valueKeys={["events"]} /></Panel>
        <Panel subtitle="Адреса назначения и сервисы" title="Целевые порты"><Bars labelKey="service" rows={(data.top_target_ports ?? []) as Row[]} valueKeys={["attempts"]} /></Panel>
      </div>
    </>}
  </div>;
}
