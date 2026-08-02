import { useEffect, useMemo, useRef, useState } from "react";
import { geoNaturalEarth1, geoPath } from "d3-geo";
import { feature } from "topojson-client";
import type { FeatureCollection } from "geojson";
import worldAtlas from "world-atlas/countries-110m.json";
import ReactGridLayout, {
  type Layout,
  verticalCompactor,
} from "react-grid-layout";
import "react-grid-layout/css/styles.css";
import "react-resizable/css/styles.css";
import { api } from "./runtime/api";
import type {
  DashboardDefinition,
  DashboardSummaryResponse,
  IncidentRecord,
} from "./runtime/types";
import {
  formatTime,
  number,
  severityTone,
  text,
  useQuery,
} from "./runtime/query";
import type { View } from "./model";
import {
  Badge,
  Button,
  EmptyState,
  ErrorState,
  Icon,
  IconButton,
  LoadingState,
  Modal,
  PageHeader,
  StatusCell,
} from "./ui";

type Row = Record<string, unknown>;
type Navigate = (view: View) => void;

const SLA_MINUTES: Record<string, number> = {
  critical: 15,
  high: 60,
  medium: 240,
  low: 1440,
  info: 1440,
};
const TERMINAL_STATUSES = new Set([
  "closed",
  "resolved",
  "false_positive",
  "suppressed",
]);

export function incidentSla(row: IncidentRecord, now = Date.now()) {
  const severity = text(row.severity_agg ?? row.severity, "info").toLowerCase();
  const targetMinutes = SLA_MINUTES[severity] ?? SLA_MINUTES.info;
  const openedAt = new Date(text(row.ts_first ?? row.ts, "")).getTime();
  const ageMinutes = Number.isFinite(openedAt)
    ? Math.max(0, Math.floor((now - openedAt) / 60_000))
    : 0;
  const terminal = TERMINAL_STATUSES.has(
    text(row.status, "open").toLowerCase(),
  );
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
  if (absolute < 1440)
    return `${Math.floor(absolute / 60)} ч ${absolute % 60} мин`;
  return `${Math.floor(absolute / 1440)} д ${Math.floor((absolute % 1440) / 60)} ч`;
}

function Metric({
  label,
  value,
  detail,
  tone = "",
}: {
  label: string;
  value: string | number;
  detail: string;
  tone?: string;
}) {
  return (
    <div
      className={`metric sentinel-dashboard-metric ${tone ? `metric-${tone}` : ""}`}
    >
      <span>{label}</span>
      <strong>{value}</strong>
      <small>{detail}</small>
    </div>
  );
}

function Panel({
  title,
  subtitle,
  action,
  children,
  className = "",
}: {
  title: string;
  subtitle: string;
  action?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <section className={`panel sentinel-dashboard-panel ${className}`}>
      <header className="panel-header">
        <div className="panel-title">
          <h2>{title}</h2>
          <span>{subtitle}</span>
        </div>
        {action}
      </header>
      <div className="sentinel-panel-body">{children}</div>
    </section>
  );
}

function Bars({
  rows,
  labelKey = "label",
  valueKeys = ["count", "cnt", "events"],
}: {
  rows: Row[];
  labelKey?: string;
  valueKeys?: string[];
}) {
  const prepared = rows.map((row) => ({
    label:
      labelKey === "service" && row.dst_port
        ? `${text(row[labelKey], "port")} · ${text(row.dst_port)}`
        : text(
            row[labelKey] ??
              row.category ??
              row.subcategory ??
              row.severity ??
              row.status ??
              row.log_source ??
              row.dst_port,
            "Неизвестно",
          ),
    value: valueKeys.reduce((result, key) => result || number(row[key]), 0),
  }));
  const max = Math.max(1, ...prepared.map((item) => item.value));
  if (!prepared.length)
    return (
      <EmptyState detail="За выбранный период распределение отсутствует" />
    );
  return (
    <div className="sentinel-bars">
      {prepared.map((item) => (
        <div className="sentinel-bar-row" key={item.label}>
          <span>{item.label}</span>
          <div>
            <i style={{ width: `${Math.max(2, (item.value / max) * 100)}%` }} />
          </div>
          <b>{item.value.toLocaleString("ru-RU")}</b>
        </div>
      ))}
    </div>
  );
}

function Timeline({ events, alerts }: { events: Row[]; alerts: Row[] }) {
  const alertIndex = new Map(
    alerts.map((row) => [
      text(row.bucket ?? row.bucket_start, ""),
      number(row.cnt ?? row.count),
    ]),
  );
  const points = events.map((row) => ({
    key: text(row.bucket ?? row.bucket_start, ""),
    label: formatTime(row.bucket ?? row.bucket_start),
    events: number(row.cnt ?? row.count),
    alerts: alertIndex.get(text(row.bucket ?? row.bucket_start, "")) ?? 0,
  }));
  const max = Math.max(1, ...points.map((point) => point.events));
  if (!points.length)
    return <EmptyState detail="Временной ряд еще не сформирован" />;
  return (
    <div className="sentinel-timeline" aria-label="Динамика событий и алертов">
      {points.map((point) => (
        <div
          className="sentinel-timeline-column"
          key={point.key}
          title={`${point.label}: ${point.events.toLocaleString("ru-RU")} событий, ${point.alerts} алертов`}
        >
          <div className="sentinel-timeline-bars">
            <i
              style={{ height: `${Math.max(3, (point.events / max) * 100)}%` }}
            />
            <b
              style={{
                height: `${Math.max(2, Math.min(100, point.alerts * 12))}%`,
              }}
            />
          </div>
          <span>
            {new Date(point.key).getHours().toString().padStart(2, "0")}
          </span>
        </div>
      ))}
    </div>
  );
}

function WorldActivityMap({ rows }: { rows: Row[] }) {
  const map = useMemo(() => {
    const atlas = worldAtlas as unknown as { objects: { countries: unknown } };
    const collection = feature(
      worldAtlas as never,
      atlas.objects.countries as never,
    ) as unknown as FeatureCollection;
    const projection = geoNaturalEarth1().fitExtent(
      [
        [8, 8],
        [892, 392],
      ],
      collection,
    );
    const path = geoPath(projection);
    return { collection, projection, path };
  }, []);
  const points = rows.filter(
    (row) =>
      Number.isFinite(Number(row.lat)) && Number.isFinite(Number(row.lon)),
  );
  const max = Math.max(
    1,
    ...points.map((row) => number(row.events ?? row.count)),
  );
  return (
    <div className="sentinel-world-map">
      <svg
        aria-label="Карта источников сетевой активности"
        role="img"
        viewBox="0 0 900 400"
      >
        <g className="sentinel-world-land">
          {map.collection.features.map((shape, index) => (
            <path d={map.path(shape) ?? ""} key={String(shape.id ?? index)} />
          ))}
        </g>
        <g>
          {points.map((row, index) => {
            const coordinates = map.projection([
              number(row.lon),
              number(row.lat),
            ]);
            if (!coordinates) return null;
            const radius =
              3.5 + Math.sqrt(number(row.events ?? row.count) / max) * 8;
            return (
              <g
                className="sentinel-map-point"
                key={`${text(row.ip ?? row.country)}-${index}`}
                transform={`translate(${coordinates[0]} ${coordinates[1]})`}
              >
                <circle className="pulse" r={radius + 6} />
                <circle r={radius}>
                  <title>{`${text(row.country)} · ${text(row.ip)} · ${number(row.events).toLocaleString("ru-RU")} событий`}</title>
                </circle>
              </g>
            );
          })}
        </g>
      </svg>
      <div className="sentinel-map-legend">
        <span>
          <i /> внешний источник
        </span>
        <b>{points.length} геоточек</b>
      </div>
    </div>
  );
}

function SlaPanel({ incidents }: { incidents: IncidentRecord[] }) {
  const active = incidents.filter((row) => !incidentSla(row).terminal);
  const breached = active.filter((row) => incidentSla(row).breached);
  const compliance = active.length
    ? Math.round(((active.length - breached.length) / active.length) * 100)
    : 100;
  const urgent = [...active]
    .sort(
      (left, right) =>
        incidentSla(left).remainingMinutes -
        incidentSla(right).remainingMinutes,
    )
    .slice(0, 5);
  return (
    <>
      <div className="sentinel-sla-summary">
        <div
          className={`sentinel-sla-gauge ${breached.length ? "warning" : "healthy"}`}
          style={{ "--sla": `${compliance}%` } as React.CSSProperties}
        >
          <strong>{compliance}%</strong>
          <span>в пределах SLA</span>
        </div>
        <div>
          <b>{breached.length}</b>
          <span>нарушено</span>
        </div>
        <div>
          <b>{active.length - breached.length}</b>
          <span>в работе</span>
        </div>
      </div>
      <div className="sentinel-compact-list">
        {urgent.map((row) => {
          const sla = incidentSla(row);
          return (
            <div key={text(row.agg_id ?? row.alert_id)}>
              <Badge tone={severityTone(row.severity_agg ?? row.severity)}>
                {text(row.severity_agg ?? row.severity)}
              </Badge>
              <span>
                <strong>{text(row.rule_name)}</strong>
                <small>
                  {sla.breached
                    ? `просрочено на ${compactDuration(-sla.remainingMinutes)}`
                    : `осталось ${compactDuration(sla.remainingMinutes)}`}
                </small>
              </span>
            </div>
          );
        })}
      </div>
    </>
  );
}

function IncidentPreview({
  rows,
  navigate,
}: {
  rows: IncidentRecord[];
  navigate: Navigate;
}) {
  if (!rows.length) return <EmptyState detail="Открытых инцидентов нет" />;
  return (
    <div className="sentinel-incident-preview">
      {rows.slice(0, 8).map((row) => (
        <button
          key={text(row.agg_id ?? row.alert_id)}
          onClick={() => navigate("incidents")}
          type="button"
        >
          <Badge tone={severityTone(row.severity_agg ?? row.severity)}>
            {text(row.severity_agg ?? row.severity)}
          </Badge>
          <span>
            <strong>{text(row.rule_name)}</strong>
            <small>
              {text(row.source_summary ?? row.source ?? row.entity_key)} ·{" "}
              {formatTime(row.ts_last ?? row.ts)}
            </small>
          </span>
          <StatusCell value={text(row.status)} />
        </button>
      ))}
    </div>
  );
}

function DashboardEditor({
  open,
  dashboard,
  catalog,
  onClose,
  onSaved,
}: {
  open: boolean;
  dashboard: DashboardDefinition | null;
  catalog: Array<{
    id: string;
    title: string;
    description?: string;
    default_span?: number;
  }>;
  onClose: () => void;
  onSaved: (dashboard: DashboardDefinition) => void;
}) {
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [widgets, setWidgets] = useState<string[]>([]);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  useEffect(() => {
    if (!open) return;
    setTitle(
      dashboard?.built_in
        ? `${dashboard.title} — копия`
        : (dashboard?.title ?? "Новый макет SOC"),
    );
    setDescription(dashboard?.description ?? "");
    setWidgets(
      dashboard?.widgets ??
        dashboard?.layout?.map((item) => item.widget) ?? [
          "kpis",
          "timelines",
          "incident_queue",
        ],
    );
    setError("");
  }, [dashboard, open]);
  async function save() {
    setSaving(true);
    setError("");
    try {
      const result = await api.saveDashboard({
        id: dashboard?.built_in ? "" : (dashboard?.id ?? ""),
        title,
        description,
        widgets,
        layout: widgets.map(
          (widget, index) =>
            dashboard?.layout?.find((item) => item.widget === widget) ?? {
              widget,
              span:
                catalog.find((item) => item.id === widget)?.default_span ?? 1,
              x: 0,
              y: index * 7,
              w: 12,
              h: 7,
            },
        ),
      });
      onSaved(result);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason));
    } finally {
      setSaving(false);
    }
  }
  return (
    <Modal
      footer={
        <>
          <Button onClick={onClose}>Отмена</Button>
          <Button
            disabled={saving || !title.trim() || !widgets.length}
            onClick={() => void save()}
            tone="primary"
          >
            {saving ? "Сохранение..." : "Сохранить макет"}
          </Button>
        </>
      }
      onClose={onClose}
      open={open}
      title={dashboard ? "Редактирование макета" : "Новый макет"}
    >
      <div className="dashboard-editor-form">
        <label>
          <span>Название</span>
          <input
            onChange={(event) => setTitle(event.target.value)}
            value={title}
          />
        </label>
        <label>
          <span>Описание</span>
          <textarea
            onChange={(event) => setDescription(event.target.value)}
            rows={3}
            value={description}
          />
        </label>
        <fieldset>
          <legend>Виджеты</legend>
          <div className="kuma-widget-catalog">
            {catalog.map((item) => (
              <button
                aria-pressed={widgets.includes(item.id)}
                className={widgets.includes(item.id) ? "selected" : ""}
                key={item.id}
                onClick={() =>
                  setWidgets((current) =>
                    current.includes(item.id)
                      ? current.filter((id) => id !== item.id)
                      : [...current, item.id],
                  )
                }
                type="button"
              >
                <Icon name={widgets.includes(item.id) ? "check" : "plus"} />
                <span>
                  <strong>{item.title}</strong>
                  <small>{item.description}</small>
                </span>
                <Badge tone={widgets.includes(item.id) ? "healthy" : "info"}>
                  {item.default_span === 2 ? "широкий" : "обычный"}
                </Badge>
              </button>
            ))}
          </div>
        </fieldset>
        {error ? (
          <div className="sentinel-partial-warning">
            <Badge tone="critical">Ошибка</Badge>
            <span>{error}</span>
          </div>
        ) : null}
      </div>
    </Modal>
  );
}

export function LegacyOverviewDashboard({ navigate }: { navigate: Navigate }) {
  const [window, setWindow] = useState("24h");
  const [refreshMs, setRefreshMs] = useState(60_000);
  const [selectedDashboardId, setSelectedDashboardId] = useState(
    () => localStorage.getItem("sentinel-dashboard") || "security-overview",
  );
  const [editorOpen, setEditorOpen] = useState(false);
  const [editorDashboard, setEditorDashboard] =
    useState<DashboardDefinition | null>(null);
  const registry = useQuery("dashboard:registry", api.dashboards, 60_000);
  const dashboard = useQuery(
    `dashboard:${window}`,
    () =>
      api.dashboard({
        window,
        bucket_minutes: window === "24h" ? 60 : window === "7d" ? 360 : 30,
        recent_limit: 12,
      }),
    refreshMs,
  );
  const incidents = useQuery(
    "dashboard:incidents",
    () => api.incidents({ view: "agg", window: "30d", limit: 50 }),
    30_000,
  );
  const sources = useQuery(
    "dashboard:sources",
    () => api.sourcesInventory({ hours: 24, limit: 500 }),
    60_000,
  );
  const security = useQuery(
    "dashboard:security",
    () => api.securityServices(),
    60_000,
  );
  const selectedDashboard =
    registry.data?.dashboards.find((item) => item.id === selectedDashboardId) ??
    registry.data?.dashboards[0] ??
    null;
  const selectedWidgets = new Set(
    selectedDashboard?.widgets ??
      selectedDashboard?.layout?.map((item) => item.widget) ?? [
        "kpis",
        "timelines",
        "geo_sources",
        "severity_breakdown",
        "incident_queue",
        "incidents_preview",
        "categories",
        "sources",
        "ports",
      ],
  );
  const show = (widget: string) => selectedWidgets.has(widget);
  useEffect(() => {
    if (selectedDashboard) {
      setSelectedDashboardId(selectedDashboard.id);
      localStorage.setItem("sentinel-dashboard", selectedDashboard.id);
    }
  }, [selectedDashboard]);
  const data: DashboardSummaryResponse = dashboard.data ?? {};
  const incidentRows = incidents.data?.items ?? [];
  const sourceRows = sources.data?.items ?? [];
  const unhealthySources = sourceRows.filter(
    (row) => !/active|healthy|online|норма/i.test(text(row.status, "")),
  );
  const partialErrors = [
    dashboard.error,
    incidents.error,
    sources.error,
    security.error,
  ].filter(Boolean);
  return (
    <div className="native-page sentinel-dashboard">
      <PageHeader
        eyebrow="SOC · production telemetry"
        title="Панель мониторинга"
        actions={
          <>
            <Button
              icon="settings"
              onClick={() => {
                setEditorDashboard(selectedDashboard);
                setEditorOpen(true);
              }}
            >
              Редактировать макет
            </Button>
            <Button
              icon="plus"
              onClick={() => {
                setEditorDashboard(null);
                setEditorOpen(true);
              }}
              tone="primary"
            >
              Новый макет
            </Button>
            <IconButton
              icon="refresh"
              label="Обновить все виджеты"
              onClick={() => {
                dashboard.reload();
                incidents.reload();
                sources.reload();
                security.reload();
                registry.reload();
              }}
            />
          </>
        }
      />
      <div className="dashboard-toolbar">
        <div className="dashboard-layouts">
          {registry.data?.dashboards.map((item) => (
            <button
              className={selectedDashboard?.id === item.id ? "active" : ""}
              key={item.id}
              onClick={() => setSelectedDashboardId(item.id)}
              type="button"
            >
              {item.title.split("/")[0].trim()}
              {item.built_in ? "" : " · custom"}
            </button>
          ))}
        </div>
        <div className="dashboard-scope">
          <label>
            <span>Период</span>
            <select
              aria-label="Период дашборда"
              onChange={(event) => setWindow(event.target.value)}
              value={window}
            >
              <option value="1h">1 час</option>
              <option value="24h">24 часа</option>
              <option value="7d">7 дней</option>
              <option value="30d">30 дней</option>
            </select>
          </label>
          <label>
            <span>Обновление</span>
            <select
              aria-label="Интервал обновления"
              onChange={(event) => setRefreshMs(Number(event.target.value))}
              value={refreshMs}
            >
              <option value={0}>Вручную</option>
              <option value={30000}>30 секунд</option>
              <option value={60000}>1 минута</option>
              <option value={300000}>5 минут</option>
            </select>
          </label>
        </div>
      </div>
      {registry.error ? (
        <div className="sentinel-partial-warning">
          <Badge tone="warning">Макеты недоступны</Badge>
          <span>{registry.error.message}</span>
        </div>
      ) : null}
      {partialErrors.length ? (
        <div className="sentinel-partial-warning">
          <Badge tone="warning">Частичные данные</Badge>
          <span>
            {partialErrors.map((error) => error?.message).join(" · ")}
          </span>
        </div>
      ) : null}
      {show("kpis") ? (
        <section className="metric-grid sentinel-dashboard-metrics">
          <Metric
            detail="нормализованный поток"
            label="События за 1 час"
            value={number(data.metrics?.events_1h).toLocaleString("ru-RU")}
          />
          <Metric
            detail="горячее хранилище"
            label="События за 24 часа"
            value={number(data.metrics?.events_24h).toLocaleString("ru-RU")}
          />
          <Metric
            detail="ожидают triage"
            label="Открытые инциденты"
            tone={incidentRows.length ? "warning" : ""}
            value={incidentRows.length}
          />
          <Metric
            detail={`${unhealthySources.length} с отклонениями`}
            label="Активные источники"
            value={
              number(data.metrics?.active_sources_24h) || sourceRows.length
            }
          />
          <Metric
            detail="совпадения с TI"
            label="Threat Intelligence"
            tone={number(data.metrics?.ti_hits_24h) ? "warning" : ""}
            value={number(data.metrics?.ti_hits_24h).toLocaleString("ru-RU")}
          />
          <Metric
            detail={`${number(security.data?.total)} интеграций`}
            label="Средства защиты"
            value={`${number(security.data?.healthy)}/${number(security.data?.total)}`}
          />
        </section>
      ) : null}
      {dashboard.loading && !dashboard.data ? (
        <LoadingState label="Формирование аналитических виджетов..." />
      ) : dashboard.error && !dashboard.data ? (
        <ErrorState error={dashboard.error} retry={dashboard.reload} />
      ) : (
        <>
          <div className="sentinel-dashboard-grid sentinel-dashboard-grid-main">
            {show("timelines") ? (
              <Panel
                className="span-2"
                subtitle="Нагрузка production transport за выбранный период"
                title="Поток событий и алертов"
              >
                <Timeline
                  alerts={(data.alert_timeline ?? []) as Row[]}
                  events={(data.timeline ?? []) as Row[]}
                />
              </Panel>
            ) : null}
            {show("incident_queue") ? (
              <Panel
                subtitle="Triage: critical 15 мин, high 1 ч, medium 4 ч"
                title="SLA инцидентов"
              >
                <SlaPanel incidents={incidentRows} />
              </Panel>
            ) : null}
            {show("geo_sources") ? (
              <Panel
                className="span-2"
                subtitle="GeoIP внешних адресов, зафиксированных источниками"
                title="Карта сетевой активности"
              >
                <WorldActivityMap
                  rows={(data.geo_sources?.items ?? []) as Row[]}
                />
              </Panel>
            ) : null}
            {show("geo_vpn_destinations") ? (
              <Panel
                className="span-2"
                subtitle="Назначения, наблюдаемые за VPN egress"
                title="География VPN"
              >
                <WorldActivityMap
                  rows={(data.geo_vpn_destinations?.items ?? []) as Row[]}
                />
              </Panel>
            ) : null}
            {show("severity_breakdown") ? (
              <Panel
                subtitle="Нормализованные события за выбранный период"
                title="Важность событий"
              >
                <Bars rows={(data.severity_breakdown ?? []) as Row[]} />
              </Panel>
            ) : null}
            {show("threat_intel") ? (
              <Panel
                subtitle="Провайдеры совпадений и индикаторов"
                title="Threat Intelligence"
              >
                <Bars
                  labelKey="provider"
                  rows={(data.threat_intel?.providers ?? []) as Row[]}
                />
              </Panel>
            ) : null}
          </div>
          <div className="sentinel-dashboard-grid">
            {show("incidents_preview") ? (
              <Panel
                action={
                  <Button onClick={() => navigate("incidents")} tone="ghost">
                    Вся очередь
                  </Button>
                }
                className="span-2"
                subtitle="Текущие агрегированные срабатывания"
                title="Открытые инциденты"
              >
                <IncidentPreview navigate={navigate} rows={incidentRows} />
              </Panel>
            ) : null}
            {show("categories") ? (
              <Panel
                subtitle="Распределение нормализованного потока"
                title="Категории событий"
              >
                <Bars rows={(data.top_categories ?? []) as Row[]} />
              </Panel>
            ) : null}
            {show("sources") ? (
              <Panel
                subtitle="Наиболее активные подключенные источники"
                title="Источники"
              >
                <Bars
                  labelKey="log_source"
                  rows={(data.top_sources ?? []) as Row[]}
                  valueKeys={["events"]}
                />
              </Panel>
            ) : null}
            {show("ports") ? (
              <Panel
                subtitle="Адреса назначения и сервисы"
                title="Целевые порты"
              >
                <Bars
                  labelKey="service"
                  rows={(data.top_target_ports ?? []) as Row[]}
                  valueKeys={["attempts"]}
                />
              </Panel>
            ) : null}
            {show("vpn_sites") ? (
              <Panel
                subtitle="Домены, наблюдаемые за VPN egress"
                title="VPN: посещаемые сайты"
              >
                <Bars
                  labelKey="domain"
                  rows={(data.top_vpn_sites ?? []) as Row[]}
                  valueKeys={["visits"]}
                />
              </Panel>
            ) : null}
          </div>
        </>
      )}
      <DashboardEditor
        catalog={registry.data?.widget_catalog ?? []}
        dashboard={editorDashboard}
        onClose={() => setEditorOpen(false)}
        onSaved={(saved) => {
          setEditorOpen(false);
          setSelectedDashboardId(saved.id);
          registry.reload();
        }}
        open={editorOpen}
      />
    </div>
  );
}

function dashboardGridLayout(dashboard: DashboardDefinition | null): Layout {
  const widgets =
    dashboard?.widgets ?? dashboard?.layout?.map((item) => item.widget) ?? [];
  let fallbackY = 0;
  return widgets.map((widget, index) => {
    const saved = dashboard?.layout?.find((item) => item.widget === widget);
    const wide = saved?.span === 2;
    const item = {
      i: widget,
      x: saved?.x ?? 0,
      y: saved?.y ?? fallbackY,
      w: saved?.w ?? (widget === "kpis" ? 12 : wide ? 8 : 4),
      h:
        saved?.h ??
        (widget.startsWith("geo_") ? 11 : widget === "kpis" ? 4 : 7),
      minW: saved?.minW ?? 3,
      minH: saved?.minH ?? 4,
    };
    fallbackY = Math.max(fallbackY, item.y + item.h + (index % 2));
    return item;
  });
}

export function OverviewDashboard({ navigate }: { navigate: Navigate }) {
  const [windowSize, setWindowSize] = useState("24h");
  const [refreshMs, setRefreshMs] = useState(60_000);
  const [selectedDashboardId, setSelectedDashboardId] = useState(
    () => localStorage.getItem("sentinel-dashboard") || "security-overview",
  );
  const [editorOpen, setEditorOpen] = useState(false);
  const [editorDashboard, setEditorDashboard] =
    useState<DashboardDefinition | null>(null);
  const [layoutMode, setLayoutMode] = useState(false);
  const [layout, setLayout] = useState<Layout>([]);
  const [layoutBusy, setLayoutBusy] = useState(false);
  const [layoutError, setLayoutError] = useState("");
  const containerRef = useRef<HTMLDivElement | null>(null);
  const [gridWidth, setGridWidth] = useState(0);
  const registry = useQuery("dashboard:registry", api.dashboards, 60_000);
  const dashboard = useQuery(
    `dashboard:${windowSize}`,
    () =>
      api.dashboard({
        window: windowSize,
        bucket_minutes:
          windowSize === "24h" ? 60 : windowSize === "7d" ? 360 : 30,
        recent_limit: 12,
      }),
    refreshMs || undefined,
  );
  const incidents = useQuery(
    "dashboard:incidents",
    () => api.incidents({ view: "agg", window: "30d", limit: 50 }),
    30_000,
  );
  const sources = useQuery(
    "dashboard:sources",
    () => api.sourcesInventory({ hours: 24, limit: 500 }),
    60_000,
  );
  const security = useQuery(
    "dashboard:security",
    () => api.securityServices(),
    60_000,
  );
  const selectedDashboard =
    registry.data?.dashboards.find((item) => item.id === selectedDashboardId) ??
    registry.data?.dashboards[0] ??
    null;
  const widgets =
    selectedDashboard?.widgets ??
    selectedDashboard?.layout?.map((item) => item.widget) ??
    [];
  const data: DashboardSummaryResponse = dashboard.data ?? {};
  const incidentRows = incidents.data?.items ?? [];
  const sourceRows = sources.data?.items ?? [];
  const unhealthySources = sourceRows.filter(
    (row) => !/active|healthy|online|норма/i.test(text(row.status, "")),
  );
  const partialErrors = [
    dashboard.error,
    incidents.error,
    sources.error,
    security.error,
  ].filter(Boolean);

  useEffect(() => {
    if (!selectedDashboard) return;
    setSelectedDashboardId(selectedDashboard.id);
    localStorage.setItem("sentinel-dashboard", selectedDashboard.id);
    setLayout(dashboardGridLayout(selectedDashboard));
    setLayoutMode(false);
  }, [selectedDashboard]);

  useEffect(() => {
    const element = containerRef.current;
    if (!element) return undefined;
    const measure = () => setGridWidth(Math.max(0, Math.floor(element.getBoundingClientRect().width)));
    measure();
    const observer = new ResizeObserver(measure);
    observer.observe(element);
    window.addEventListener("resize", measure);
    return () => { observer.disconnect(); window.removeEventListener("resize", measure); };
  }, [dashboard.data, dashboard.loading]);

  async function saveLayout() {
    if (!selectedDashboard) return;
    setLayoutBusy(true);
    setLayoutError("");
    try {
      const saved = await api.saveDashboard({
        id: selectedDashboard.built_in ? "" : selectedDashboard.id,
        title: selectedDashboard.built_in
          ? `${selectedDashboard.title.split("/")[0].trim()} · мой макет`
          : selectedDashboard.title,
        description: selectedDashboard.description ?? "",
        widgets,
        layout: layout.map((item) => ({
          widget: item.i,
          x: item.x,
          y: item.y,
          w: item.w,
          h: item.h,
          minW: item.minW,
          minH: item.minH,
          span: item.w >= 7 ? 2 : 1,
        })),
      });
      setSelectedDashboardId(saved.id);
      setLayoutMode(false);
      registry.reload();
    } catch (error) {
      setLayoutError(error instanceof Error ? error.message : String(error));
    } finally {
      setLayoutBusy(false);
    }
  }

  function renderWidget(widget: string) {
    if (widget === "kpis")
      return (
        <section className="metric-grid sentinel-dashboard-metrics">
          <Metric
            detail="нормализованный поток"
            label="События за 1 час"
            value={number(data.metrics?.events_1h).toLocaleString("ru-RU")}
          />
          <Metric
            detail="горячее хранилище"
            label="События за 24 часа"
            value={number(data.metrics?.events_24h).toLocaleString("ru-RU")}
          />
          <Metric
            detail="ожидают triage"
            label="Открытые инциденты"
            tone={incidentRows.length ? "warning" : ""}
            value={incidentRows.length}
          />
          <Metric
            detail={`${unhealthySources.length} с отклонениями`}
            label="Активные источники"
            value={
              number(data.metrics?.active_sources_24h) || sourceRows.length
            }
          />
          <Metric
            detail="совпадения с TI"
            label="Threat Intelligence"
            tone={number(data.metrics?.ti_hits_24h) ? "warning" : ""}
            value={number(data.metrics?.ti_hits_24h).toLocaleString("ru-RU")}
          />
          <Metric
            detail={`${number(security.data?.total)} интеграций`}
            label="Средства защиты"
            value={`${number(security.data?.healthy)}/${number(security.data?.total)}`}
          />
        </section>
      );
    if (widget === "timelines")
      return (
        <Panel
          subtitle="Production transport за выбранный период"
          title="Поток событий и алертов"
        >
          <Timeline
            alerts={(data.alert_timeline ?? []) as Row[]}
            events={(data.timeline ?? []) as Row[]}
          />
        </Panel>
      );
    if (widget === "incident_queue")
      return (
        <Panel
          subtitle="Critical 15 мин, high 1 ч, medium 4 ч"
          title="SLA инцидентов"
        >
          <SlaPanel incidents={incidentRows} />
        </Panel>
      );
    if (widget === "geo_sources")
      return (
        <Panel
          subtitle="GeoIP внешних адресов из реальных событий"
          title="Карта сетевой активности"
        >
          <WorldActivityMap rows={(data.geo_sources?.items ?? []) as Row[]} />
        </Panel>
      );
    if (widget === "geo_vpn_destinations")
      return (
        <Panel
          subtitle="Назначения, наблюдаемые за VPN egress"
          title="География VPN"
        >
          <WorldActivityMap
            rows={(data.geo_vpn_destinations?.items ?? []) as Row[]}
          />
        </Panel>
      );
    if (widget === "severity_breakdown")
      return (
        <Panel subtitle="Нормализованные события и алерты" title="Важность">
          <div className="dashboard-split-bars">
            <Bars rows={(data.severity_breakdown ?? []) as Row[]} />
            <Bars rows={(data.alert_severity_breakdown ?? []) as Row[]} />
          </div>
        </Panel>
      );
    if (widget === "threat_intel")
      return (
        <Panel
          subtitle="Провайдеры совпадений и индикаторов"
          title="Threat Intelligence"
        >
          <Bars
            labelKey="provider"
            rows={(data.threat_intel?.providers ?? []) as Row[]}
          />
        </Panel>
      );
    if (widget === "incidents_preview")
      return (
        <Panel
          action={
            <Button onClick={() => navigate("incidents")} tone="ghost">
              Вся очередь
            </Button>
          }
          subtitle="Текущие агрегированные срабатывания"
          title="Открытые инциденты"
        >
          <IncidentPreview navigate={navigate} rows={incidentRows} />
        </Panel>
      );
    if (widget === "categories")
      return (
        <Panel
          subtitle="Распределение нормализованного потока"
          title="Категории событий"
        >
          <Bars rows={(data.top_categories ?? []) as Row[]} />
        </Panel>
      );
    if (widget === "sources")
      return (
        <Panel
          subtitle="Наиболее активные подключенные источники"
          title="Источники"
        >
          <Bars
            labelKey="log_source"
            rows={(data.top_sources ?? []) as Row[]}
            valueKeys={["events"]}
          />
        </Panel>
      );
    if (widget === "ports")
      return (
        <Panel subtitle="Адреса назначения и сервисы" title="Целевые порты">
          <Bars
            labelKey="service"
            rows={(data.top_target_ports ?? []) as Row[]}
            valueKeys={["attempts"]}
          />
        </Panel>
      );
    if (widget === "vpn_sites")
      return (
        <Panel subtitle="Домены за VPN egress" title="VPN: посещаемые сайты">
          <Bars
            labelKey="domain"
            rows={(data.top_vpn_sites ?? []) as Row[]}
            valueKeys={["visits"]}
          />
        </Panel>
      );
    if (widget === "source_health")
      return (
        <Panel
          action={
            <Button onClick={() => navigate("sources")} tone="ghost">
              Источники
            </Button>
          }
          subtitle="Машины, контейнеры и приложения"
          title="Состояние источников"
        >
          <Bars
            rows={[
              {
                label: "Активны",
                count: Math.max(0, sourceRows.length - unhealthySources.length),
              },
              { label: "Требуют внимания", count: unhealthySources.length },
            ]}
          />
        </Panel>
      );
    if (widget === "security_coverage")
      return (
        <Panel
          action={
            <Button onClick={() => navigate("coverage")} tone="ghost">
              Покрытие
            </Button>
          }
          subtitle="Реальный health подключенных систем"
          title="Средства защиты"
        >
          <Bars
            rows={[
              { label: "Исправны", count: number(security.data?.healthy) },
              {
                label: "Недоступны",
                count: Math.max(
                  0,
                  number(security.data?.total) - number(security.data?.healthy),
                ),
              },
            ]}
          />
        </Panel>
      );
    if (widget === "alert_status")
      return (
        <Panel
          action={
            <Button onClick={() => navigate("alerts")} tone="ghost">
              Алерты
            </Button>
          }
          subtitle="Состояния за выбранный период"
          title="Workflow алертов"
        >
          <Bars rows={(data.alert_status_breakdown ?? []) as Row[]} />
        </Panel>
      );
    return (
      <Panel subtitle="Виджет не поддерживается текущей версией" title={widget}>
        <EmptyState />
      </Panel>
    );
  }

  return (
    <div className="native-page sentinel-dashboard">
      <PageHeader
        eyebrow="SOC · production telemetry"
        title="Панель мониторинга"
        actions={
          <>
            {layoutMode ? (
              <>
                <Button
                  disabled={layoutBusy}
                  onClick={() => {
                    setLayout(dashboardGridLayout(selectedDashboard));
                    setLayoutMode(false);
                  }}
                >
                  Отмена
                </Button>
                <Button
                  disabled={layoutBusy}
                  icon="check"
                  onClick={() => void saveLayout()}
                  tone="primary"
                >
                  {layoutBusy ? "Сохранение..." : "Сохранить расположение"}
                </Button>
              </>
            ) : (
              <Button icon="move" onClick={() => setLayoutMode(true)}>
                Настроить расположение
              </Button>
            )}
            <Button
              icon="settings"
              onClick={() => {
                setEditorDashboard(selectedDashboard);
                setEditorOpen(true);
              }}
            >
              Виджеты
            </Button>
            <Button
              icon="plus"
              onClick={() => {
                setEditorDashboard(null);
                setEditorOpen(true);
              }}
              tone="primary"
            >
              Новый макет
            </Button>
            <IconButton
              icon="refresh"
              label="Обновить все виджеты"
              onClick={() => {
                dashboard.reload();
                incidents.reload();
                sources.reload();
                security.reload();
                registry.reload();
              }}
            />
          </>
        }
      />
      <div className="dashboard-toolbar">
        <div className="dashboard-layouts">
          {registry.data?.dashboards.map((item) => (
            <button
              className={selectedDashboard?.id === item.id ? "active" : ""}
              key={item.id}
              onClick={() => setSelectedDashboardId(item.id)}
              type="button"
            >
              {item.title.split("/")[0].trim()}
              {item.built_in ? "" : " · custom"}
            </button>
          ))}
        </div>
        <div className="dashboard-scope">
          <label>
            <span>Период</span>
            <select
              aria-label="Период дашборда"
              onChange={(event) => setWindowSize(event.target.value)}
              value={windowSize}
            >
              <option value="1h">1 час</option>
              <option value="24h">24 часа</option>
              <option value="7d">7 дней</option>
              <option value="30d">30 дней</option>
            </select>
          </label>
          <label>
            <span>Обновление</span>
            <select
              aria-label="Интервал обновления"
              onChange={(event) => setRefreshMs(Number(event.target.value))}
              value={refreshMs}
            >
              <option value={0}>Вручную</option>
              <option value={30000}>30 секунд</option>
              <option value={60000}>1 минута</option>
              <option value={300000}>5 минут</option>
            </select>
          </label>
        </div>
      </div>
      {layoutMode ? (
        <div className="dashboard-layout-hint">
          <Icon name="move" />
          <span>
            Перетаскивайте виджеты за заголовок и меняйте размер за правый
            нижний угол.
          </span>
        </div>
      ) : null}
      {layoutError ? (
        <div className="sentinel-partial-warning">
          <Badge tone="critical">Ошибка макета</Badge>
          <span>{layoutError}</span>
        </div>
      ) : null}
      {partialErrors.length ? (
        <div className="sentinel-partial-warning">
          <Badge tone="warning">Частичные данные</Badge>
          <span>
            {partialErrors.map((error) => error?.message).join(" · ")}
          </span>
        </div>
      ) : null}
      {dashboard.loading && !dashboard.data ? (
        <LoadingState label="Формирование аналитических виджетов..." />
      ) : dashboard.error && !dashboard.data ? (
        <ErrorState error={dashboard.error} retry={dashboard.reload} />
      ) : (
        <div
          className={`dashboard-grid-workspace ${layoutMode ? "editing" : ""}`}
          ref={containerRef}
        >
          {gridWidth > 0 && layout.length ? (
            <ReactGridLayout
              compactor={verticalCompactor}
              dragConfig={{
                enabled: layoutMode,
                handle: ".panel-header",
                cancel: "button,a,input,select",
              }}
              gridConfig={{
                cols: 12,
                rowHeight: 34,
                margin: [12, 12],
                containerPadding: [0, 0],
              }}
              layout={layout}
              onLayoutChange={(next) => {
                if (layoutMode) setLayout([...next]);
              }}
              resizeConfig={{ enabled: layoutMode, handles: ["se"] }}
              width={gridWidth}
            >
              {layout.map((item) => (
                <div className="dashboard-grid-item" key={item.i}>
                  {renderWidget(item.i)}
                </div>
              ))}
            </ReactGridLayout>
          ) : (
            <EmptyState detail="Добавьте виджеты в макет" />
          )}
        </div>
      )}
      <DashboardEditor
        catalog={registry.data?.widget_catalog ?? []}
        dashboard={editorDashboard}
        onClose={() => setEditorOpen(false)}
        onSaved={(saved) => {
          setEditorOpen(false);
          setSelectedDashboardId(saved.id);
          registry.reload();
        }}
        open={editorOpen}
      />
    </div>
  );
}
