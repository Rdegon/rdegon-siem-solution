import { useEffect, useRef, useState, type ReactNode } from "react";
import { api } from "./runtime/api";
import type {
  ActiveListImportResponse,
  ActiveListRecord,
  IncidentDetailResponse,
  ResourceCatalogRecord,
  ResourcePackageImportResponse,
  ResourceVersionCompareResponse,
  ResourceVersionsResponse,
  UnifiedRuleRecord,
} from "./runtime/types";
import {
  formatTime,
  number,
  severityTone,
  text,
  useQuery,
} from "./runtime/query";
import { EventDetailContent, IncidentDetailContent } from "./incident-details";
import {
  Badge,
  Button,
  DetailDrawer,
  EmptyState,
  ErrorState,
  Icon,
  IconButton,
  LoadingState,
  Modal,
  PageHeader,
  SearchField,
  StatusCell,
} from "./ui";
import { RecordDetails } from "./record-details";
export { EventsHuntingWorkspace as EventsQueryWorkspace } from "./events-hunting-workspace";

type Notify = (message: string, tone?: string) => void;
type Row = Record<string, unknown>;
type Column = { key: string; title: string; render?: (row: Row) => ReactNode };

function rows(value: unknown): Row[] {
  return Array.isArray(value)
    ? value.filter(
        (item): item is Row => Boolean(item) && typeof item === "object",
      )
    : [];
}

function Grid({
  columns,
  data,
  onOpen,
  empty = "Данные не найдены",
}: {
  columns: Column[];
  data: Row[];
  onOpen?: (row: Row) => void;
  empty?: string;
}) {
  if (!data.length) return <EmptyState detail={empty} />;
  return (
    <div className="native-grid kuma-dense-grid">
      <table>
        <thead>
          <tr>
            {columns.map((column) => (
              <th key={column.key}>{column.title}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {data.map((row, index) => (
            <tr
              className={onOpen ? "sentinel-clickable-row" : ""}
              key={text(
                row.id ?? row.alert_id ?? row.agg_id ?? row.pack_id ?? row.name,
                String(index),
              )}
              onClick={onOpen ? () => onOpen(row) : undefined}
              onKeyDown={
                onOpen
                  ? (event) => {
                      if (event.key === "Enter" || event.key === " ")
                        onOpen(row);
                    }
                  : undefined
              }
              tabIndex={onOpen ? 0 : undefined}
            >
              {columns.map((column) => (
                <td key={column.key}>
                  {column.render ? column.render(row) : text(row[column.key])}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function Boundary<T>({
  state,
  children,
}: {
  state: { data?: T; error?: Error; loading: boolean; reload: () => void };
  children: (data: T) => ReactNode;
}) {
  if (state.loading && !state.data) return <LoadingState />;
  if (state.error)
    return <ErrorState error={state.error} retry={state.reload} />;
  if (!state.data) return <EmptyState />;
  return <>{children(state.data)}</>;
}

function Field({
  label,
  children,
  wide = false,
  hint,
}: {
  label: string;
  children: ReactNode;
  wide?: boolean;
  hint?: string;
}) {
  return (
    <label className={`kuma-editor-field ${wide ? "wide" : ""}`}>
      <span>{label}</span>
      {children}
      {hint ? <small>{hint}</small> : null}
    </label>
  );
}

function objectValue(value: unknown): Row {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Row)
    : {};
}

function incidentId(row: Row) {
  return text(row.agg_id ?? row.alert_id ?? row.id, "");
}

const activeIncidentStatuses = new Set([
  "new",
  "open",
  "assigned",
  "triaged",
  "reopened",
  "in_progress",
  "escalated",
]);

export function IncidentQueueWorkspace({
  mode,
  notify,
}: {
  mode: "agg" | "raw";
  notify: Notify;
}) {
  const [queryInput, setQueryInput] = useState("");
  const [query, setQuery] = useState("");
  const [status, setStatus] = useState(mode === "agg" ? "active" : "all");
  const [severity, setSeverity] = useState("all");
  const [windowSize, setWindowSize] = useState(mode === "raw" ? "24h" : "30d");
  const [rowLimit, setRowLimit] = useState(mode === "raw" ? 100 : 200);
  const [filterOpen, setFilterOpen] = useState(false);
  const [selected, setSelected] = useState<Row | null>(null);
  const [detail, setDetail] = useState<IncidentDetailResponse | null>(null);
  const [detailError, setDetailError] = useState("");
  const includeTerminal = mode === "agg" && status !== "active";
  useEffect(() => {
    const timer = window.setTimeout(() => setQuery(queryInput.trim()), 400);
    return () => window.clearTimeout(timer);
  }, [queryInput]);
  const state = useQuery(
    `kuma-queue:${mode}:${status}:${query}:${windowSize}:${rowLimit}`,
    () =>
      api.incidents({
        view: mode,
        q: query,
        window: windowSize,
        limit: rowLimit,
        include_terminal: includeTerminal,
      }),
    30_000,
  );

  async function open(row: Row) {
    setSelected(row);
    setDetail(null);
    setDetailError("");
    try {
      setDetail(
        await api.incidentDetail(mode, incidentId(row), {
          window: windowSize,
          event_limit: 100,
          alert_limit: 100,
          include_evidence: true,
        }),
      );
    } catch (error) {
      setDetailError(error instanceof Error ? error.message : String(error));
    }
  }

  async function update(body: Row) {
    if (!selected) return;
    try {
      await api.updateIncident(mode, incidentId(selected), body);
      notify("Карточка обновлена", "healthy");
      setSelected(null);
      state.reload();
    } catch (error) {
      notify(
        error instanceof Error ? error.message : String(error),
        "critical",
      );
    }
  }

  const visible = rows(state.data?.items).filter((row) => {
    const rowStatus = text(row.status, "open").toLowerCase();
    const rowSeverity = text(
      row.severity_agg ?? row.severity,
      "unknown",
    ).toLowerCase();
    const statusMatches =
      status === "all" ||
      (status === "active"
        ? activeIncidentStatuses.has(rowStatus)
        : status === "resolved"
          ? ["closed", "resolved"].includes(rowStatus)
          : ["false_positive", "suppressed"].includes(rowStatus));
    return statusMatches && (severity === "all" || rowSeverity === severity);
  });

  const alertColumns: Column[] = [
    {
      key: "severity",
      title: "Важность",
      render: (row) => (
        <Badge tone={severityTone(row.severity)}>{text(row.severity)}</Badge>
      ),
    },
    {
      key: "rule_name",
      title: "Название",
      render: (row) => <strong>{text(row.rule_name, "Без названия")}</strong>,
    },
    {
      key: "status",
      title: "Статус",
      render: (row) => <StatusCell value={text(row.status)} />,
    },
    {
      key: "assignee",
      title: "Исполнитель",
      render: (row) => text(row.assignee, "Не назначен"),
    },
    {
      key: "incident",
      title: "Инцидент",
      render: (row) => text(row.incident_id ?? row.agg_id, "—"),
    },
    {
      key: "ts_first",
      title: "Первое событие",
      render: (row) => formatTime(row.ts_first ?? row.ts),
    },
    {
      key: "ts_last",
      title: "Последнее событие",
      render: (row) => formatTime(row.ts_last ?? row.ts),
    },
    { key: "entity_key", title: "Затронутый актив" },
  ];
  const incidentColumns: Column[] = [
    {
      key: "rule_name",
      title: "Название",
      render: (row) => <strong>{text(row.rule_name, "Без названия")}</strong>,
    },
    {
      key: "duration",
      title: "Длительность",
      render: (row) => text(row.duration, "—"),
    },
    {
      key: "assignee",
      title: "Исполнитель",
      render: (row) => text(row.assignee, "Не назначен"),
    },
    {
      key: "ts_first",
      title: "Создан",
      render: (row) => formatTime(row.ts_first ?? row.ts),
    },
    {
      key: "tenant",
      title: "Tenant",
      render: (row) => text(row.tenant_id ?? row.tenant, "main"),
    },
    {
      key: "status",
      title: "Статус",
      render: (row) => <StatusCell value={text(row.status)} />,
    },
    {
      key: "hits",
      title: "Алерты",
      render: (row) =>
        number(
          row.raw_alerts_total ?? row.alert_count ?? row.hits,
        ).toLocaleString("ru-RU"),
    },
    {
      key: "severity",
      title: "Важность",
      render: (row) => (
        <Badge tone={severityTone(row.severity_agg ?? row.severity)}>
          {text(row.severity_agg ?? row.severity)}
        </Badge>
      ),
    },
    { key: "entity_key", title: "Затронутый актив" },
  ];
  const selectedStatus = selected
    ? text(selected.status, "open").toLowerCase()
    : "";
  const selectedActive = activeIncidentStatuses.has(selectedStatus);
  const selectedTerminal = [
    "closed",
    "resolved",
    "false_positive",
    "suppressed",
  ].includes(selectedStatus);

  return (
    <div className="native-page kuma-queue-page">
      <PageHeader
        title={mode === "agg" ? "Инциденты" : "Алерты"}
        actions={
          <IconButton icon="refresh" label="Обновить" onClick={state.reload} />
        }
      />
      <div className="kuma-commandbar">
        <SearchField
          onChange={setQueryInput}
          placeholder="Поиск по названию, активу, источнику или исполнителю..."
          value={queryInput}
        />
        <div className="kuma-commandbar-actions">
          <span className="kuma-found">
            Показано: <b>{visible.length.toLocaleString("ru-RU")}</b>
            {number(state.data?.available_count) > visible.length
              ? ` из ${number(state.data?.available_count).toLocaleString("ru-RU")}`
              : ""}
          </span>
          <Button
            icon="filter"
            onClick={() => setFilterOpen((value) => !value)}
          >
            Фильтры{status !== "all" || severity !== "all" ? " · активны" : ""}
          </Button>
        </div>
      </div>
      {filterOpen ? (
        <div className="kuma-filter-strip">
          <Field label="Состояние">
            <select
              onChange={(event) => setStatus(event.target.value)}
              value={status}
            >
              <option value="all">Все</option>
              <option value="active">Открытые</option>
              <option value="resolved">Закрытые</option>
              <option value="false_positive">False positive</option>
            </select>
          </Field>
          <Field label="Важность">
            <select
              onChange={(event) => setSeverity(event.target.value)}
              value={severity}
            >
              <option value="all">Все</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </Field>
          <Field label="Период">
            <select
              onChange={(event) => setWindowSize(event.target.value)}
              value={windowSize}
            >
              <option value="24h">24 часа</option>
              <option value="7d">7 дней</option>
              <option value="30d">30 дней</option>
            </select>
          </Field>
          <Field label="Строк">
            <select
              onChange={(event) => setRowLimit(Number(event.target.value))}
              value={rowLimit}
            >
              <option value={100}>100</option>
              <option value={200}>200</option>
              <option value={250}>250</option>
              <option value={500}>500</option>
            </select>
          </Field>
          <Button
            onClick={() => {
              setStatus(mode === "agg" ? "active" : "all");
              setSeverity("all");
              setWindowSize(mode === "raw" ? "24h" : "30d");
              setRowLimit(mode === "raw" ? 100 : 200);
              setQueryInput("");
            }}
          >
            Сбросить
          </Button>
        </div>
      ) : null}
      <Boundary state={state}>
        {() => (
          <Grid
            columns={mode === "agg" ? incidentColumns : alertColumns}
            data={visible}
            onOpen={open}
          />
        )}
      </Boundary>
      <DetailDrawer
        actions={
          selectedActive ? (
            <>
              <Button
                icon="user"
                onClick={() => update({ assignee: "current_user" })}
              >
                Назначить мне
              </Button>
              <Button
                icon="check"
                onClick={() =>
                  update({ status: "closed", note: "Closed from Sentinel UI" })
                }
                tone="primary"
              >
                Закрыть
              </Button>
              <Button
                onClick={() =>
                  update({
                    status: "false_positive",
                    note: "Marked as false positive from Sentinel UI",
                  })
                }
                tone="danger"
              >
                False positive
              </Button>
            </>
          ) : selectedTerminal ? (
            <Button
              icon="refresh"
              onClick={() =>
                update({
                  status: "reopened",
                  note: "Reopened from Sentinel UI",
                })
              }
              tone="primary"
            >
              Вернуть в работу
            </Button>
          ) : null
        }
        eyebrow={
          selected
            ? text(selected.severity_agg ?? selected.severity)
            : undefined
        }
        onClose={() => setSelected(null)}
        open={Boolean(selected)}
        title={
          selected ? text(selected.rule_name, incidentId(selected)) : "Детали"
        }
      >
        {selected ? (
          detailError ? (
            <ErrorState
              error={new Error(detailError)}
              retry={() => open(selected)}
            />
          ) : detail ? (
            <IncidentDetailContent detail={detail} />
          ) : (
            <LoadingState label="Загрузка evidence..." />
          )
        ) : null}
      </DetailDrawer>
    </div>
  );
}

export const DEFAULT_EVENT_QUERY = "";

const eventColumns: Column[] = [
  { key: "ts", title: "Время", render: (row) => formatTime(row.ts) },
  {
    key: "severity",
    title: "Важность",
    render: (row) => (
      <Badge tone={severityTone(row.severity)}>{text(row.severity)}</Badge>
    ),
  },
  { key: "log_source", title: "Источник" },
  { key: "category", title: "Категория" },
  { key: "event_code", title: "Код" },
  { key: "src_ip", title: "Источник IP" },
  { key: "dst_ip", title: "Назначение IP" },
  {
    key: "user_name",
    title: "Пользователь",
    render: (row) => text(row.user_name ?? row.target_user),
  },
  {
    key: "message",
    title: "Сообщение",
    render: (row) => (
      <span className="sentinel-truncate">{text(row.message)}</span>
    ),
  },
];

function downloadTsv(data: Row[], columns: Column[]) {
  const escape = (value: unknown) =>
    text(value).replace(/\t/g, " ").replace(/\r?\n/g, " ");
  const body = [
    columns.map((column) => column.title).join("\t"),
    ...data.map((row) =>
      columns.map((column) => escape(row[column.key])).join("\t"),
    ),
  ].join("\n");
  const url = URL.createObjectURL(
    new Blob([body], { type: "text/tab-separated-values;charset=utf-8" }),
  );
  const link = document.createElement("a");
  link.href = url;
  link.download = `sentinel-events-${new Date().toISOString().slice(0, 19).replace(/:/g, "-")}.tsv`;
  link.click();
  URL.revokeObjectURL(url);
}

export function LegacyEventsQueryWorkspace({ notify }: { notify: Notify }) {
  const [draft, setDraft] = useState(DEFAULT_EVENT_QUERY);
  const [executed, setExecuted] = useState(DEFAULT_EVENT_QUERY);
  const [windowSize, setWindowSize] = useState("24h");
  const [autoRefresh, setAutoRefresh] = useState(false);
  const [selected, setSelected] = useState<Row | null>(null);
  const [columnPicker, setColumnPicker] = useState(false);
  const [visibleKeys, setVisibleKeys] = useState(
    eventColumns.map((column) => column.key),
  );
  const state = useQuery(
    `kuma-events:${executed}:${windowSize}`,
    () =>
      api.eventsQuery({
        query: executed,
        window: windowSize,
        storage: "auto",
        limit: 250,
        offset: 0,
        include_count: true,
      }),
    autoRefresh ? 30_000 : undefined,
  );
  const visibleColumns = eventColumns.filter((column) =>
    visibleKeys.includes(column.key),
  );
  const data = rows(state.data?.rows);
  const lines = Array.from(
    { length: Math.max(5, draft.split("\n").length) },
    (_, index) => index + 1,
  ).join("\n");

  return (
    <div className="native-page kuma-events-page">
      <PageHeader
        title="События"
        actions={
          <>
            <label className="kuma-auto-refresh">
              <input
                checked={autoRefresh}
                onChange={(event) => setAutoRefresh(event.target.checked)}
                type="checkbox"
              />
              <span>Автообновление</span>
            </label>
            <select
              aria-label="Временной диапазон"
              onChange={(event) => setWindowSize(event.target.value)}
              value={windowSize}
            >
              <option value="1h">1 час</option>
              <option value="24h">24 часа</option>
              <option value="7d">7 дней</option>
              <option value="30d">30 дней</option>
            </select>
          </>
        }
      />
      <section className="kuma-query-workspace">
        <div className="kuma-query-topline">
          <div>
            <strong>Запрос</strong>
            <span>ClickHouse SQL · только чтение</span>
          </div>
          <select
            aria-label="Готовый запрос"
            onChange={(event) =>
              event.target.value && setDraft(event.target.value)
            }
            value=""
          >
            <option value="">Сохраненные запросы</option>
            <option value={DEFAULT_EVENT_QUERY}>Последние события</option>
            <option value="SELECT *\nFROM events_view\nWHERE severity IN ('high', 'critical')\nORDER BY ts DESC\nLIMIT 250">
              High и Critical
            </option>
            <option value="SELECT *\nFROM events_view\nWHERE category = 'authentication'\nORDER BY ts DESC\nLIMIT 250">
              Аутентификация
            </option>
          </select>
        </div>
        <div className="kuma-query-editor">
          <pre className="kuma-query-lines">{lines}</pre>
          <textarea
            aria-label="Запрос событий"
            onChange={(event) => setDraft(event.target.value)}
            spellCheck={false}
            value={draft}
          />
        </div>
        <div className="kuma-query-actions">
          <div>
            <span className="kuma-query-chip">events_view</span>
            <span className="kuma-query-chip">{windowSize}</span>
          </div>
          <div>
            <IconButton
              icon="refresh"
              label="Повторить запрос"
              onClick={state.reload}
            />
            <Button
              icon="play"
              onClick={() => setExecuted(draft.trim() || DEFAULT_EVENT_QUERY)}
              tone="primary"
            >
              Выполнить запрос
            </Button>
          </div>
        </div>
      </section>
      <div className="kuma-results-toolbar">
        <div>
          <h2>Результаты</h2>
          <span>
            {number(
              state.data?.total_count ?? state.data?.row_count,
            ).toLocaleString("ru-RU")}{" "}
            событий · {number(state.data?.elapsed_ms)} мс
          </span>
        </div>
        <div>
          <Button
            onClick={() => {
              downloadTsv(data, visibleColumns);
              notify("Результат экспортирован в TSV", "healthy");
            }}
          >
            Экспорт TSV
          </Button>
          <IconButton
            active={columnPicker}
            icon="settings"
            label="Настроить столбцы"
            onClick={() => setColumnPicker((value) => !value)}
          />
        </div>
      </div>
      {columnPicker ? (
        <div className="kuma-column-picker">
          {eventColumns.map((column) => (
            <label key={column.key}>
              <input
                checked={visibleKeys.includes(column.key)}
                onChange={(event) =>
                  setVisibleKeys((current) =>
                    event.target.checked
                      ? [...current, column.key]
                      : current.length > 1
                        ? current.filter((key) => key !== column.key)
                        : current,
                  )
                }
                type="checkbox"
              />
              {column.title}
            </label>
          ))}
        </div>
      ) : null}
      <Boundary state={state}>
        {() => (
          <Grid columns={visibleColumns} data={data} onOpen={setSelected} />
        )}
      </Boundary>
      <DetailDrawer
        actions={
          selected ? (
            <Button
              onClick={() => {
                void navigator.clipboard.writeText(
                  JSON.stringify(selected, null, 2),
                );
                notify("Данные события скопированы", "healthy");
              }}
            >
              Копировать данные
            </Button>
          ) : null
        }
        onClose={() => setSelected(null)}
        open={Boolean(selected)}
        title={
          selected
            ? `${text(selected.log_source)} · ${formatTime(selected.ts)}`
            : "Событие"
        }
      >
        {selected ? <EventDetailContent event={selected} /> : null}
      </DetailDrawer>
    </div>
  );
}

export type ResourceFieldDefinition = {
  key: string;
  label: string;
  type?: "text" | "textarea" | "number" | "select" | "csv" | "boolean";
  target?: "config" | "bindings";
  placeholder?: string;
  hint?: string;
  wide?: boolean;
  rows?: number;
  min?: number;
  defaultValue?: string | number | boolean | string[];
  options?: { value: string; label: string }[];
};

export type ResourceStepDefinition = {
  id: string;
  label: string;
  fields?: ResourceFieldDefinition[];
  editor?: "mapping" | "active-list" | "validation";
};

type ResourceDefinition = {
  kind: string;
  label: string;
  description: string;
  icon: string;
  steps: ResourceStepDefinition[];
};

const resourceField = (
  key: string,
  label: string,
  settings: Omit<ResourceFieldDefinition, "key" | "label"> = {},
): ResourceFieldDefinition => ({ key, label, ...settings });
const resourceStep = (
  id: string,
  label: string,
  fields: ResourceFieldDefinition[],
): ResourceStepDefinition => ({ id, label, fields });
const resourceValidation = (label = "Проверка и публикация"): ResourceStepDefinition => ({
  id: "validation",
  label,
  editor: "validation",
});
const resourceOptions = (...items: [string, string][]) =>
  items.map(([value, label]) => ({ value, label }));

const RESOURCE_SCHEMAS: Record<string, ResourceStepDefinition[]> = {
  collector: [
    resourceStep("main", "Подключение источников", [
      resourceField("enabled", "Ресурс активен", { type: "boolean", defaultValue: true }),
      resourceField("asset_group", "Группа активов", { placeholder: "linux_common" }),
    ]),
    resourceStep("transport", "Транспорт", [
      resourceField("collector_profile", "Профиль коллектора", { wide: true, placeholder: "linux-auth" }),
      resourceField("transport", "Транспорт", { type: "select", defaultValue: "http", options: resourceOptions(["http", "HTTP"], ["syslog_tcp", "Syslog TCP"], ["syslog_udp", "Syslog UDP"], ["kafka", "Kafka"]) }),
      resourceField("endpoint", "Endpoint / topic", { placeholder: "/ingest/http или topic" }),
      resourceField("listen_address", "Адрес прослушивания", { defaultValue: "0.0.0.0" }),
      resourceField("port", "Порт", { type: "number", min: 1 }),
      resourceField("workers", "Workers", { type: "number", min: 1, defaultValue: 2 }),
      resourceField("batch_size", "Batch size", { type: "number", min: 1, defaultValue: 500 }),
      resourceField("tls_secret_ref", "Ссылка на TLS-секрет", { placeholder: "vault:secret/data/siem/collector" }),
    ]),
    resourceStep("parsing", "Парсинг событий", [
      resourceField("source_types", "Типы источников", { type: "csv", wide: true, hint: "Через запятую" }),
      resourceField("normalizer", "Нормализатор", { target: "bindings", placeholder: "linux-auth-normalizer" }),
      resourceField("framing", "Разделение сообщений", { type: "select", defaultValue: "line", options: resourceOptions(["line", "Одна строка — одно событие"], ["octet_counting", "Octet counting"], ["json", "JSON stream"]) }),
    ]),
    resourceStep("filtering", "Фильтрация событий", [
      resourceField("filters", "Фильтры", { type: "csv", target: "bindings", wide: true }),
      resourceField("unknown_events", "Неизвестные события", { type: "select", defaultValue: "pass", options: resourceOptions(["pass", "Пропускать"], ["tag", "Помечать"], ["drop", "Отбрасывать"]) }),
    ]),
    resourceStep("collector_aggregation", "Агрегация событий", [
      resourceField("aggregation_rules", "Правила агрегации", { type: "csv", target: "bindings", wide: true }),
      resourceField("aggregation_window_s", "Окно, секунд", { type: "number", min: 1, defaultValue: 60 }),
      resourceField("aggregation_key", "Поля группировки", { type: "csv", placeholder: "host.name, event.code" }),
    ]),
    resourceStep("enrichment", "Обогащение", [
      resourceField("enrichment_rules", "Правила обогащения", { type: "csv", target: "bindings", wide: true }),
      resourceField("context_sources", "Активные листы и словари", { type: "csv", target: "bindings" }),
      resourceField("ldap_mapping", "LDAP mapping"),
    ]),
    resourceStep("routing", "Маршрутизация", [
      resourceField("destinations", "Точки назначения", { type: "csv", target: "bindings", wide: true }),
      resourceField("topic", "Kafka topic", { defaultValue: "siem.raw" }),
    ]),
    resourceValidation("Проверка параметров"),
  ],
  correlator: [
    resourceStep("main", "Основные параметры", [resourceField("enabled", "Ресурс активен", { type: "boolean", defaultValue: true }), resourceField("asset_group", "Группа активов")]),
    resourceStep("engine", "Движок", [resourceField("engine", "Режим обработки", { type: "select", defaultValue: "stream", options: resourceOptions(["stream", "Потоковый"], ["batch", "Пакетный"]) }), resourceField("workers", "Workers", { type: "number", min: 1, defaultValue: 2 }), resourceField("shard_key", "Ключ шардирования", { defaultValue: "asset_group" }), resourceField("input_topic", "Входной topic", { defaultValue: "siem.normalized" })]),
    resourceStep("bindings", "Привязка ресурсов", [resourceField("correlation_rules", "Правила корреляции", { type: "csv", target: "bindings", wide: true }), resourceField("enrichment_rules", "Правила обогащения", { type: "csv", target: "bindings" }), resourceField("response_rules", "Правила реагирования", { type: "csv", target: "bindings" }), resourceField("destinations", "Точки назначения", { type: "csv", target: "bindings" })]),
    resourceValidation("Проверка параметров"),
  ],
  storage: [
    resourceStep("main", "Политика хранения", [resourceField("storage_type", "Тип хранилища", { type: "select", defaultValue: "clickhouse", options: resourceOptions(["clickhouse", "ClickHouse"], ["elasticsearch", "Elasticsearch"], ["archive", "Архив"]) }), resourceField("retention_days", "Срок хранения, дней", { type: "number", min: 1, defaultValue: 30 }), resourceField("hot_days", "Горячий слой, дней", { type: "number", min: 1, defaultValue: 7 })]),
    resourceStep("connection", "Подключение", [resourceField("endpoint", "Endpoint", { wide: true, placeholder: "clickhouse://siem-storage:9000" }), resourceField("database", "База данных", { defaultValue: "siem" }), resourceField("events_table", "Таблица событий", { defaultValue: "events" }), resourceField("secret_ref", "Ссылка на секрет")]),
    resourceStep("performance", "Производительность", [resourceField("replicas", "Реплики", { type: "number", min: 1, defaultValue: 1 }), resourceField("shards", "Шарды", { type: "number", min: 1, defaultValue: 1 }), resourceField("insert_batch_size", "Размер пакета записи", { type: "number", min: 1, defaultValue: 1000 }), resourceField("flush_interval_ms", "Интервал flush, мс", { type: "number", min: 1, defaultValue: 250 })]),
    resourceStep("bindings", "Маршрутизация", [resourceField("event_routers", "Маршрутизаторы событий", { type: "csv", target: "bindings", wide: true }), resourceField("tenant_scope", "Tenant scope", { type: "csv" })]),
    resourceValidation(),
  ],
  activeList: [
    resourceStep("main", "Основные параметры", [resourceField("list_kind", "Назначение", { type: "select", defaultValue: "watch", options: resourceOptions(["watch", "Наблюдение"], ["allow", "Разрешающий лист"], ["deny", "Блокирующий лист"]) }), resourceField("ttl_seconds", "TTL, секунд", { type: "number", min: 0, defaultValue: 0, hint: "0 — без срока" })]),
    resourceStep("schema", "Структура записей", [resourceField("key_fields", "Ключевые поля", { type: "csv", wide: true, defaultValue: ["value"] }), resourceField("context_fields", "Контекстные поля", { type: "csv", wide: true })]),
    { id: "entries", label: "Содержимое листа", editor: "active-list" },
    resourceValidation(),
  ],
  aggregationRule: [
    resourceStep("main", "Основные параметры", [resourceField("enabled", "Правило активно", { type: "boolean", defaultValue: true }), resourceField("priority", "Приоритет", { type: "number", min: 1, defaultValue: 100 })]),
    resourceStep("selector", "Условие отбора", [resourceField("expr", "Выражение отбора", { type: "textarea", wide: true, rows: 7 })]),
    resourceStep("aggregation", "Окно и группировка", [resourceField("group_fields", "Поля группировки", { type: "csv", wide: true }), resourceField("window_s", "Окно, секунд", { type: "number", min: 1, defaultValue: 60 }), resourceField("threshold", "Минимум событий", { type: "number", min: 1, defaultValue: 2 }), resourceField("emit_count_field", "Поле счетчика", { defaultValue: "event.count" })]),
    resourceValidation(),
  ],
  connector: [
    resourceStep("main", "Тип интеграции", [resourceField("connector_type", "Тип коннектора", { type: "select", defaultValue: "http", options: resourceOptions(["http", "HTTP API"], ["webhook", "Webhook"], ["kafka", "Kafka"], ["email", "Email"], ["telegram", "Telegram"]) }), resourceField("enabled", "Коннектор активен", { type: "boolean", defaultValue: true })]),
    resourceStep("connection", "Подключение", [resourceField("endpoint", "Endpoint", { wide: true }), resourceField("protocol", "Протокол", { defaultValue: "https" }), resourceField("method", "HTTP-метод", { type: "select", defaultValue: "POST", options: resourceOptions(["GET", "GET"], ["POST", "POST"], ["PUT", "PUT"]) }), resourceField("secret_ref", "Ссылка на секрет")]),
    resourceStep("delivery", "Доставка", [resourceField("timeout_s", "Timeout, секунд", { type: "number", min: 1, defaultValue: 10 }), resourceField("retries", "Повторные попытки", { type: "number", min: 0, defaultValue: 3 }), resourceField("verify_tls", "Проверять TLS", { type: "boolean", defaultValue: true })]),
    resourceStep("bindings", "Привязки", [resourceField("destinations", "Точки назначения", { type: "csv", target: "bindings" }), resourceField("resources", "Связанные ресурсы", { type: "csv", target: "bindings" })]),
    resourceValidation(),
  ],
  correlationRule: [
    resourceStep("main", "Общие параметры", [resourceField("enabled", "Правило активно", { type: "boolean", defaultValue: true }), resourceField("rule_id", "Rule ID", { type: "number", min: 1 }), resourceField("rule_type", "Тип правила", { type: "select", defaultValue: "standard", options: resourceOptions(["simple", "Простое"], ["standard", "Стандартное"], ["operational", "Операционное"]) })]),
    resourceStep("selector", "Селекторы", [resourceField("expr", "Выражение корреляции", { type: "textarea", wide: true, rows: 8 }), resourceField("mitre", "Техники MITRE", { type: "csv", placeholder: "T1110, T1021.004" })]),
    resourceStep("aggregation", "Окно и агрегация", [resourceField("threshold", "Порог", { type: "number", min: 1, defaultValue: 1 }), resourceField("window_s", "Окно, секунд", { type: "number", min: 1, defaultValue: 300 }), resourceField("entity_field", "Поле сущности", { defaultValue: "host.name" }), resourceField("suppression_key", "Ключ дедупликации", { defaultValue: "host.name" })]),
    resourceStep("actions", "Создание алерта", [resourceField("severity", "Важность", { type: "select", defaultValue: "medium", options: resourceOptions(["low", "Низкая"], ["medium", "Средняя"], ["high", "Высокая"], ["critical", "Критическая"]) }), resourceField("tags", "Теги", { type: "csv", wide: true }), resourceField("response_rules", "Правила реагирования", { type: "csv", target: "bindings" })]),
    resourceValidation(),
  ],
  dictionary: [
    resourceStep("main", "Назначение словаря", [resourceField("dictionary_type", "Тип словаря", { type: "select", defaultValue: "static", options: resourceOptions(["static", "Статический"], ["http", "HTTP"], ["file", "Файл"], ["ldap", "LDAP"]) }), resourceField("refresh_interval_s", "Интервал обновления, секунд", { type: "number", min: 0, defaultValue: 3600 })]),
    resourceStep("schema", "Структура данных", [resourceField("key_fields", "Ключевые поля", { type: "csv", wide: true, defaultValue: ["key"] }), resourceField("value_fields", "Поля значений", { type: "csv", wide: true, defaultValue: ["value"] }), resourceField("format", "Формат", { type: "select", defaultValue: "csv", options: resourceOptions(["csv", "CSV"], ["json", "JSON"], ["tsv", "TSV"]) })]),
    resourceStep("source", "Источник данных", [resourceField("endpoint", "URL или путь", { wide: true }), resourceField("secret_ref", "Ссылка на секрет"), resourceField("verify_tls", "Проверять TLS", { type: "boolean", defaultValue: true })]),
    resourceStep("bindings", "Использование", [resourceField("normalizers", "Нормализаторы", { type: "csv", target: "bindings" }), resourceField("enrichment_rules", "Правила обогащения", { type: "csv", target: "bindings" })]),
    resourceValidation(),
  ],
  enrichmentRule: [
    resourceStep("main", "Основные параметры", [resourceField("enabled", "Правило активно", { type: "boolean", defaultValue: true }), resourceField("priority", "Приоритет", { type: "number", min: 1, defaultValue: 100 })]),
    resourceStep("selector", "Условие применения", [resourceField("expr", "Выражение отбора", { type: "textarea", wide: true, rows: 7 })]),
    resourceStep("lookup", "Поиск контекста", [resourceField("source_ref", "Словарь, лист или таблица", { wide: true }), resourceField("lookup_field", "Поле события для поиска"), resourceField("source_key", "Ключ источника", { defaultValue: "key" }), resourceField("target_field", "Целевое поле UEM"), resourceField("on_miss", "Если значение не найдено", { type: "select", defaultValue: "pass", options: resourceOptions(["pass", "Продолжить"], ["tag", "Добавить тег"], ["drop", "Отбросить событие"]) })]),
    resourceStep("bindings", "Привязки", [resourceField("context_sources", "Источники контекста", { type: "csv", target: "bindings" }), resourceField("collectors", "Коллекторы", { type: "csv", target: "bindings" })]),
    resourceValidation(),
  ],
  destination: [
    resourceStep("main", "Тип назначения", [resourceField("destination_type", "Тип", { type: "select", defaultValue: "kafka", options: resourceOptions(["kafka", "Kafka"], ["clickhouse", "ClickHouse"], ["syslog", "Syslog"], ["http", "HTTP"], ["file", "Файл"]) }), resourceField("enabled", "Назначение активно", { type: "boolean", defaultValue: true })]),
    resourceStep("connection", "Подключение", [resourceField("endpoint", "Endpoint", { wide: true }), resourceField("protocol", "Протокол"), resourceField("secret_ref", "Ссылка на секрет")]),
    resourceStep("delivery", "Параметры доставки", [resourceField("topic", "Topic / таблица / путь", { wide: true }), resourceField("batch_size", "Размер пакета", { type: "number", min: 1, defaultValue: 500 }), resourceField("compression", "Сжатие", { type: "select", defaultValue: "none", options: resourceOptions(["none", "Без сжатия"], ["gzip", "Gzip"], ["lz4", "LZ4"]) }), resourceField("retries", "Повторные попытки", { type: "number", min: 0, defaultValue: 3 })]),
    resourceValidation(),
  ],
  filter: [
    resourceStep("main", "Основные параметры", [resourceField("enabled", "Фильтр активен", { type: "boolean", defaultValue: true }), resourceField("priority", "Приоритет", { type: "number", min: 1, defaultValue: 100 })]),
    resourceStep("selector", "Условие", [resourceField("expr", "Условие фильтра", { type: "textarea", wide: true, rows: 8 })]),
    resourceStep("actions", "Действие", [resourceField("action", "Действие", { type: "select", defaultValue: "tag", options: resourceOptions(["drop", "Отбросить"], ["tag", "Добавить тег"], ["pass", "Пропустить"]) }), resourceField("tags", "Теги", { type: "csv", wide: true }), resourceField("route", "Маршрут назначения", { target: "bindings" })]),
    resourceValidation("Проверка параметров"),
  ],
  normalizer: [
    resourceStep("main", "Схема нормализации", [resourceField("source_type", "Тип источника"), resourceField("event_matcher", "Matcher события", { type: "textarea", wide: true, rows: 4 }), resourceField("priority", "Приоритет", { type: "number", min: 1, defaultValue: 100 })]),
    resourceStep("parser", "Парсер", [resourceField("parser_type", "Тип парсера", { type: "select", defaultValue: "regex", options: resourceOptions(["regex", "Регулярное выражение"], ["json", "JSON"], ["cef", "CEF"], ["leef", "LEEF"], ["syslog", "Syslog"]) }), resourceField("message_field", "Поле сообщения", { defaultValue: "message" }), resourceField("timezone", "Часовой пояс", { defaultValue: "UTC" }), resourceField("pattern", "Шаблон парсинга", { type: "textarea", wide: true, rows: 6 })]),
    { id: "mapping", label: "Сопоставление полей", editor: "mapping" },
    resourceStep("examples", "Примеры событий", [resourceField("examples", "Обезличенные raw-события", { type: "textarea", wide: true, rows: 14 })]),
    resourceValidation("Проверка параметров"),
  ],
  responseRule: [
    resourceStep("main", "Основные параметры", [resourceField("enabled", "Правило активно", { type: "boolean", defaultValue: true }), resourceField("severity_scope", "Минимальная важность", { type: "select", defaultValue: "high", options: resourceOptions(["low", "Низкая"], ["medium", "Средняя"], ["high", "Высокая"], ["critical", "Критическая"]) })]),
    resourceStep("trigger", "Условие запуска", [resourceField("expr", "Условие", { type: "textarea", wide: true, rows: 7 })]),
    resourceStep("action", "Действие", [resourceField("action_type", "Тип действия", { type: "select", defaultValue: "webhook", options: resourceOptions(["webhook", "Webhook"], ["block_ip", "Блокировка IP"], ["isolate_host", "Изоляция хоста"], ["notify", "Уведомление"], ["script", "Сценарий"]) }), resourceField("target", "Целевой сервис или endpoint", { wide: true }), resourceField("parameter_template", "Шаблон параметров", { type: "textarea", wide: true, rows: 5, hint: "Используйте поля события, например {{src.ip}}" }), resourceField("secret_ref", "Ссылка на секрет")]),
    resourceStep("approval", "Контроль выполнения", [resourceField("requires_approval", "Требуется подтверждение", { type: "boolean", defaultValue: true }), resourceField("timeout_s", "Timeout, секунд", { type: "number", min: 1, defaultValue: 30 }), resourceField("max_retries", "Повторные попытки", { type: "number", min: 0, defaultValue: 2 })]),
    resourceValidation(),
  ],
  search: [
    resourceStep("main", "Запрос", [resourceField("language", "Язык запроса", { type: "select", defaultValue: "sql", options: resourceOptions(["sql", "SQL"], ["filter", "Конструктор фильтров"]) }), resourceField("query", "Поисковый запрос", { type: "textarea", wide: true, rows: 10 }), resourceField("time_range", "Временной диапазон", { defaultValue: "24h" })]),
    resourceStep("presentation", "Представление", [resourceField("columns", "Колонки результата", { type: "csv", wide: true }), resourceField("sort_field", "Поле сортировки", { defaultValue: "ts" }), resourceField("sort_order", "Порядок", { type: "select", defaultValue: "desc", options: resourceOptions(["desc", "Сначала новые"], ["asc", "Сначала старые"]) })]),
    resourceStep("sharing", "Доступ", [resourceField("visibility", "Видимость", { type: "select", defaultValue: "tenant", options: resourceOptions(["private", "Только владелец"], ["tenant", "Tenant"], ["global", "Все tenants"]) }), resourceField("tags", "Теги", { type: "csv" })]),
    resourceValidation(),
  ],
  agent: [
    resourceStep("main", "Платформа агента", [resourceField("platform", "ОС", { type: "select", defaultValue: "linux", options: resourceOptions(["linux", "Linux"], ["windows", "Windows"], ["macos", "macOS"]) }), resourceField("architecture", "Архитектура", { type: "select", defaultValue: "amd64", options: resourceOptions(["amd64", "AMD64"], ["arm64", "ARM64"]) })]),
    resourceStep("connection", "Управляющий канал", [resourceField("manager_url", "URL управляющего сервиса", { wide: true }), resourceField("secret_ref", "Ссылка на bootstrap-секрет"), resourceField("verify_tls", "Проверять TLS", { type: "boolean", defaultValue: true })]),
    resourceStep("deployment", "Развертывание", [resourceField("labels", "Метки", { type: "csv", wide: true }), resourceField("poll_interval_s", "Интервал опроса, секунд", { type: "number", min: 5, defaultValue: 30 }), resourceField("auto_update", "Автоматически обновлять", { type: "boolean", defaultValue: false })]),
    resourceStep("bindings", "Назначение", [resourceField("collectors", "Коллекторы", { type: "csv", target: "bindings", wide: true }), resourceField("asset_groups", "Группы активов", { type: "csv", target: "bindings" })]),
    resourceValidation(),
  ],
  proxy: [
    resourceStep("main", "Тип прокси", [resourceField("proxy_type", "Тип", { type: "select", defaultValue: "http", options: resourceOptions(["http", "HTTP CONNECT"], ["socks5", "SOCKS5"], ["reverse", "Reverse proxy"]) }), resourceField("enabled", "Прокси активен", { type: "boolean", defaultValue: true })]),
    resourceStep("connection", "Подключение", [resourceField("listen_address", "Адрес прослушивания", { defaultValue: "0.0.0.0" }), resourceField("listen_port", "Порт", { type: "number", min: 1 }), resourceField("upstream", "Upstream", { wide: true }), resourceField("secret_ref", "Ссылка на секрет")]),
    resourceStep("network", "Сетевая политика", [resourceField("allowed_networks", "Разрешенные сети", { type: "csv", wide: true }), resourceField("verify_tls", "Проверять TLS upstream", { type: "boolean", defaultValue: true })]),
    resourceValidation(),
  ],
  secret: [
    resourceStep("main", "Ссылка на секрет", [resourceField("secret_ref", "Secret reference", { wide: true, placeholder: "vault:secret/data/siem/service" }), resourceField("provider", "Провайдер", { type: "select", defaultValue: "vault", options: resourceOptions(["vault", "HashiCorp Vault"], ["environment", "Переменная окружения"], ["file", "Защищенный файл"]) }), resourceField("purpose", "Назначение", { type: "textarea", wide: true, rows: 4 }), resourceField("rotation_days", "Период ротации, дней", { type: "number", min: 0, defaultValue: 90 })]),
    resourceValidation(),
  ],
  segmentationRule: [
    resourceStep("main", "Основные параметры", [resourceField("enabled", "Правило активно", { type: "boolean", defaultValue: true }), resourceField("priority", "Приоритет", { type: "number", min: 1, defaultValue: 100 })]),
    resourceStep("selector", "Условие сегментации", [resourceField("expr", "Условие", { type: "textarea", wide: true, rows: 7 })]),
    resourceStep("assignment", "Назначение", [resourceField("segment", "Сегмент"), resourceField("asset_group", "Группа активов"), resourceField("tenant_id", "Tenant"), resourceField("tags", "Теги", { type: "csv", wide: true })]),
    resourceValidation(),
  ],
  emailTemplate: [
    resourceStep("main", "Параметры письма", [resourceField("sender_name", "Имя отправителя"), resourceField("sender_address", "Адрес отправителя"), resourceField("locale", "Язык", { type: "select", defaultValue: "ru", options: resourceOptions(["ru", "Русский"], ["en", "English"]) })]),
    resourceStep("content", "Содержимое", [resourceField("subject", "Тема", { wide: true }), resourceField("body", "Текст шаблона", { type: "textarea", wide: true, rows: 14 }), resourceField("content_type", "Формат", { type: "select", defaultValue: "html", options: resourceOptions(["html", "HTML"], ["text", "Обычный текст"]) })]),
    resourceStep("bindings", "Доставка", [resourceField("connector", "Email-коннектор", { target: "bindings" }), resourceField("reports", "Шаблоны отчетов", { type: "csv", target: "bindings" })]),
    resourceValidation(),
  ],
  contextTable: [
    resourceStep("main", "Назначение таблицы", [resourceField("table_kind", "Тип данных", { type: "select", defaultValue: "asset", options: resourceOptions(["asset", "Активы"], ["identity", "Учетные записи"], ["threat", "Индикаторы угроз"], ["custom", "Пользовательские данные"]) }), resourceField("ttl_seconds", "TTL, секунд", { type: "number", min: 0, defaultValue: 0 })]),
    resourceStep("schema", "Структура", [resourceField("key_fields", "Ключевые поля", { type: "csv", wide: true }), resourceField("value_fields", "Поля контекста", { type: "csv", wide: true })]),
    resourceStep("source", "Источник и обновление", [resourceField("source_ref", "Активный лист или словарь", { wide: true }), resourceField("refresh_mode", "Режим обновления", { type: "select", defaultValue: "interval", options: resourceOptions(["interval", "По интервалу"], ["event", "По событиям"], ["manual", "Вручную"]) }), resourceField("refresh_interval_s", "Интервал, секунд", { type: "number", min: 0, defaultValue: 300 })]),
    resourceStep("bindings", "Использование", [resourceField("correlators", "Корреляторы", { type: "csv", target: "bindings" }), resourceField("enrichment_rules", "Правила обогащения", { type: "csv", target: "bindings" })]),
    resourceValidation(),
  ],
  eventRouter: [
    resourceStep("main", "Основные параметры", [resourceField("enabled", "Маршрутизатор активен", { type: "boolean", defaultValue: true }), resourceField("priority", "Приоритет", { type: "number", min: 1, defaultValue: 100 })]),
    resourceStep("selector", "Условие маршрута", [resourceField("expr", "Выражение отбора", { type: "textarea", wide: true, rows: 7 })]),
    resourceStep("routes", "Направления", [resourceField("destinations", "Точки назначения", { type: "csv", target: "bindings", wide: true }), resourceField("fallback_destination", "Резервная точка", { target: "bindings" }), resourceField("continue_routing", "Продолжить проверку маршрутов", { type: "boolean", defaultValue: false })]),
    resourceStep("performance", "Производительность", [resourceField("workers", "Workers", { type: "number", min: 1, defaultValue: 2 }), resourceField("batch_size", "Размер пакета", { type: "number", min: 1, defaultValue: 500 }), resourceField("queue_limit", "Лимит очереди", { type: "number", min: 1, defaultValue: 10000 })]),
    resourceValidation(),
  ],
};

export const RESOURCE_DEFINITIONS: ResourceDefinition[] = [
  { kind: "collector", label: "Коллекторы", description: "Прием и обработка входящих событий", icon: "sources", steps: RESOURCE_SCHEMAS.collector },
  { kind: "correlator", label: "Корреляторы", description: "Потоковые и пакетные обработчики", icon: "runtime", steps: RESOURCE_SCHEMAS.correlator },
  { kind: "storage", label: "Хранилища", description: "Хранение, ретенция и производительность", icon: "storage", steps: RESOURCE_SCHEMAS.storage },
  { kind: "activeList", label: "Активные листы", description: "Динамические наборы значений и TTL", icon: "list", steps: RESOURCE_SCHEMAS.activeList },
  { kind: "aggregationRule", label: "Правила агрегации", description: "Свертка повторяющихся событий", icon: "rules", steps: RESOURCE_SCHEMAS.aggregationRule },
  { kind: "connector", label: "Коннекторы", description: "Интеграции с внешними системами", icon: "resources", steps: RESOURCE_SCHEMAS.connector },
  { kind: "correlationRule", label: "Правила корреляции", description: "Условия, окна, пороги и алерты", icon: "rules", steps: RESOURCE_SCHEMAS.correlationRule },
  { kind: "dictionary", label: "Словари", description: "Статические и внешние справочники", icon: "list", steps: RESOURCE_SCHEMAS.dictionary },
  { kind: "enrichmentRule", label: "Правила обогащения", description: "Контекст и справочники", icon: "plus", steps: RESOURCE_SCHEMAS.enrichmentRule },
  { kind: "destination", label: "Точки назначения", description: "Маршрутизация выходного потока", icon: "next", steps: RESOURCE_SCHEMAS.destination },
  { kind: "filter", label: "Фильтры", description: "Drop, tag и pass политики", icon: "filter", steps: RESOURCE_SCHEMAS.filter },
  { kind: "normalizer", label: "Нормализаторы", description: "Разбор и UEM-сопоставление", icon: "list", steps: RESOURCE_SCHEMAS.normalizer },
  { kind: "responseRule", label: "Правила реагирования", description: "Автоматические и подтверждаемые действия", icon: "response", steps: RESOURCE_SCHEMAS.responseRule },
  { kind: "search", label: "Поисковые запросы", description: "Сохраненные запросы и представления", icon: "search", steps: RESOURCE_SCHEMAS.search },
  { kind: "agent", label: "Агенты", description: "Управляемые агенты на конечных узлах", icon: "runtime", steps: RESOURCE_SCHEMAS.agent },
  { kind: "proxy", label: "Прокси", description: "Промежуточные сетевые соединения", icon: "resources", steps: RESOURCE_SCHEMAS.proxy },
  { kind: "secret", label: "Ссылки на секреты", description: "Ссылки на внешнее хранилище секретов", icon: "settings", steps: RESOURCE_SCHEMAS.secret },
  { kind: "segmentationRule", label: "Правила сегментации", description: "Автораспределение активов и событий", icon: "filter", steps: RESOURCE_SCHEMAS.segmentationRule },
  { kind: "emailTemplate", label: "Шаблоны Email", description: "Оформление уведомлений и отчетов", icon: "response", steps: RESOURCE_SCHEMAS.emailTemplate },
  { kind: "contextTable", label: "Контекстные таблицы", description: "Табличный контекст для корреляции", icon: "list", steps: RESOURCE_SCHEMAS.contextTable },
  { kind: "eventRouter", label: "Маршрутизаторы событий", description: "Условная доставка потоков событий", icon: "next", steps: RESOURCE_SCHEMAS.eventRouter },
];

function resourceLabel(kind: string) {
  return RESOURCE_DEFINITIONS.find((item) => item.kind === kind)?.label ?? kind;
}

export function resourceSteps(kind: string): ResourceStepDefinition[] {
  return RESOURCE_DEFINITIONS.find((item) => item.kind === kind)?.steps ?? [
    resourceStep("main", "Основные параметры", []),
    resourceValidation(),
  ];
}

export function resourceDefaults(
  kind: string,
  target: "config" | "bindings",
): Row {
  const result: Row = {};
  for (const stepDefinition of resourceSteps(kind)) {
    for (const fieldDefinition of stepDefinition.fields ?? []) {
      if ((fieldDefinition.target ?? "config") !== target) continue;
      if (fieldDefinition.defaultValue !== undefined)
        result[fieldDefinition.key] = fieldDefinition.defaultValue;
    }
  }
  return result;
}

export function sanitizeResourceConfig(kind: string, config: Row): Row {
  if (kind !== "secret") return config;
  const allowed = new Set(["secret_ref", "provider", "purpose", "rotation_days"]);
  return Object.fromEntries(
    Object.entries(config).filter(([key]) => allowed.has(key)),
  );
}

function initialResource(resource: Row): {
  id: string;
  name: string;
  kind: string;
  tenant: string;
  description: string;
  config: Row;
  bindings: Row;
} {
  const readOnly = Boolean(resource.read_only);
  const kind = text(resource.kind, "collector");
  return {
    id: readOnly ? "" : text(resource.id, ""),
    name: readOnly ? `${text(resource.name)} managed` : text(resource.name, ""),
    kind,
    tenant: text(resource.tenant_id, "main"),
    description: text(resource.description, ""),
    config: sanitizeResourceConfig(kind, {
      ...resourceDefaults(kind, "config"),
      ...objectValue(resource.config),
    }),
    bindings: {
      ...resourceDefaults(kind, "bindings"),
      ...objectValue(resource.bindings),
    },
  };
}

function MappingEditor({
  value,
  onChange,
}: {
  value: Row;
  onChange: (value: Row) => void;
}) {
  const entries = Object.entries(value);
  return (
    <div className="kuma-mapping-editor">
      <div className="kuma-mapping-head">
        <span>Исходное поле</span>
        <span>Поле UEM</span>
        <span />
      </div>
      {entries.map(([source, target], index) => (
        <div className="kuma-mapping-row" key={`${source}-${index}`}>
          <input
            aria-label="Исходное поле"
            onChange={(event) => {
              const next = { ...value };
              delete next[source];
              next[event.target.value] = target;
              onChange(next);
            }}
            value={source}
          />
          <input
            aria-label="Поле UEM"
            onChange={(event) =>
              onChange({ ...value, [source]: event.target.value })
            }
            value={text(target, "")}
          />
          <IconButton
            icon="delete"
            label="Удалить сопоставление"
            onClick={() => {
              const next = { ...value };
              delete next[source];
              onChange(next);
            }}
          />
        </div>
      ))}
      <Button
        icon="plus"
        onClick={() => {
          let index = entries.length + 1;
          while (`source_field_${index}` in value) index += 1;
          onChange({ ...value, [`source_field_${index}`]: "event.field" });
        }}
      >
        Добавить строку
      </Button>
    </div>
  );
}

function activeListMutationPayload(
  item: ActiveListRecord,
  fallbackListName: string,
  fallbackListKind: string,
) {
  return {
    list_name: text(item.list_name, fallbackListName),
    list_kind: text(item.list_kind, fallbackListKind || "watch"),
    item_type: text(item.item_type, "string"),
    item_value: text(item.item_value),
    item_label: text(item.item_label),
    tags: item.tags ?? [],
  };
}

export function ActiveListEntries({
  listName,
  listKind,
  notify,
}: {
  listName: string;
  listKind: string;
  notify: Notify;
}) {
  const state = useQuery(
    `active-list:${listName}`,
    () => api.activeLists({ list_name: listName, limit: 5_000 }),
    30_000,
  );
  const [itemType, setItemType] = useState("ip");
  const [itemValue, setItemValue] = useState("");
  const [itemLabel, setItemLabel] = useState("");
  const [bulkValues, setBulkValues] = useState("");
  const [bulkLabel, setBulkLabel] = useState("");
  const [bulkTags, setBulkTags] = useState("");
  const [bulkEnabled, setBulkEnabled] = useState(true);
  const [validatedImport, setValidatedImport] = useState<{
    signature: string;
    result: ActiveListImportResponse;
  } | null>(null);
  const [busy, setBusy] = useState("");
  const visible = state.data?.items ?? [];
  const importSignature = [
    listName,
    listKind,
    itemType,
    bulkValues,
    bulkLabel,
    bulkTags,
    bulkEnabled,
  ].join("\u001f");
  const importItems = bulkValues
    .split(/\r?\n/)
    .map((value) => value.trim())
    .filter(Boolean)
    .map((value) => ({
      list_name: listName,
      list_kind: listKind || "watch",
      item_type: itemType,
      item_value: value,
      item_label: bulkLabel,
      tags: bulkTags.split(",").map((tag) => tag.trim()).filter(Boolean),
      enabled: bulkEnabled,
    }));

  async function add() {
    if (!listName.trim() || !itemValue.trim()) {
      notify("Сначала укажите название листа и значение", "critical");
      return;
    }
    try {
      await api.saveActiveList({
        list_name: listName,
        list_kind: listKind || "watch",
        type: itemType,
        value: itemValue,
        label: itemLabel,
      });
      setItemValue("");
      setItemLabel("");
      state.reload();
      notify("Значение добавлено в активный лист", "healthy");
    } catch (error) {
      notify(
        error instanceof Error ? error.message : String(error),
        "critical",
      );
    }
  }

  async function toggle(item: ActiveListRecord) {
    const enabled = item.enabled === false;
    setBusy(`toggle:${text(item.item_value)}`);
    try {
      await api.toggleActiveList({
        ...activeListMutationPayload(item, listName, listKind),
        enabled,
      });
      await state.reload();
      notify(enabled ? "Запись активного листа включена" : "Запись активного листа отключена", "healthy");
    } catch (error) {
      notify(error instanceof Error ? error.message : String(error), "critical");
    } finally {
      setBusy("");
    }
  }

  async function remove(item: ActiveListRecord) {
    if (!window.confirm(`Удалить ${text(item.item_value)} из ${listName}?`)) return;
    setBusy(`delete:${text(item.item_value)}`);
    try {
      await api.deleteActiveList(activeListMutationPayload(item, listName, listKind));
      await state.reload();
      notify("Запись удалена из активного листа", "healthy");
    } catch (error) {
      notify(error instanceof Error ? error.message : String(error), "critical");
    } finally {
      setBusy("");
    }
  }

  async function runImport(dryRun: boolean) {
    if (!listName.trim() || !importItems.length) {
      notify("Укажите название листа и значения для импорта", "critical");
      return;
    }
    if (!dryRun && validatedImport?.signature !== importSignature) {
      notify("Повторите проверку изменённого набора", "critical");
      return;
    }
    setBusy(dryRun ? "validate-import" : "apply-import");
    try {
      const result = await api.importActiveLists({ items: importItems, dry_run: dryRun });
      if (dryRun) {
        setValidatedImport({ signature: importSignature, result });
        notify(`Проверено записей: ${result.rows}`, "healthy");
      } else {
        setBulkValues("");
        setValidatedImport(null);
        await state.reload();
        notify(`Импортировано записей: ${result.rows}`, "healthy");
      }
    } catch (error) {
      notify(error instanceof Error ? error.message : String(error), "critical");
    } finally {
      setBusy("");
    }
  }

  async function exportList(format: "csv" | "json") {
    try {
      const result = await api.exportActiveLists(listName, format);
      notify(`Выгружен файл ${result.filename}`, "healthy");
    } catch (error) {
      notify(error instanceof Error ? error.message : String(error), "critical");
    }
  }

  return (
    <div className="kuma-active-list-editor">
      <div className="kuma-editor-form">
        <Field label="Тип значения">
          <select
            onChange={(event) => setItemType(event.target.value)}
            value={itemType}
          >
            <option value="ip">IP-адрес</option>
            <option value="domain">Домен</option>
            <option value="hash">Hash</option>
            <option value="user">Пользователь</option>
            <option value="string">Строка</option>
          </select>
        </Field>
        <Field label="Значение" wide>
          <input
            onChange={(event) => setItemValue(event.target.value)}
            placeholder="10.20.30.40"
            value={itemValue}
          />
        </Field>
        <Field label="Контекст" wide>
          <input
            onChange={(event) => setItemLabel(event.target.value)}
            placeholder="Причина добавления или владелец"
            value={itemLabel}
          />
        </Field>
        <Button icon="plus" onClick={() => void add()} tone="primary">
          Добавить запись
        </Button>
      </div>
      <div className="kuma-catalog-toolbar">
        <strong>{listName || "Активный лист"}</strong>
        <span>Записей: {visible.length}</span>
        <Button disabled={!listName} onClick={() => void exportList("csv")}>CSV</Button>
        <Button disabled={!listName} onClick={() => void exportList("json")}>JSON</Button>
      </div>
      <div className="native-grid">
        <table>
          <thead>
            <tr>
              <th>Тип</th>
              <th>Значение</th>
              <th>Контекст</th>
              <th>Статус</th>
              <th>Обновлено</th>
              <th aria-label="Действия" />
            </tr>
          </thead>
          <tbody>
            {visible.map((item, index) => (
              <tr
                key={`${text(item.item_type)}-${text(item.item_value)}-${index}`}
              >
                <td>{text(item.item_type)}</td>
                <td>
                  <code>{text(item.item_value)}</code>
                </td>
                <td>{text(item.item_label, "—")}</td>
                <td>
                  <StatusCell value={item.enabled === false ? "Отключено" : "Включено"} />
                </td>
                <td>{formatTime(item.updated_ts)}</td>
                <td>
                  <div className="table-actions">
                    <label title={item.enabled === false ? "Включить" : "Отключить"}>
                      <input
                        aria-label={`${item.enabled === false ? "Включить" : "Отключить"} ${text(item.item_value)}`}
                        checked={item.enabled !== false}
                        disabled={Boolean(busy)}
                        onChange={() => void toggle(item)}
                        type="checkbox"
                      />
                    </label>
                    <IconButton
                      disabled={Boolean(busy)}
                      icon="delete"
                      label={`Удалить ${text(item.item_value)}`}
                      onClick={() => void remove(item)}
                    />
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        {!visible.length ? (
          <EmptyState detail="В листе пока нет значений" />
        ) : null}
      </div>
      <section className="kuma-editor-section">
        <div className="kuma-editor-section-head">
          <div>
            <h3>Пакетный импорт</h3>
          </div>
          {validatedImport?.signature === importSignature ? (
            <StatusCell value={`Проверено: ${validatedImport.result.rows}`} />
          ) : null}
        </div>
        <div className="kuma-editor-form">
          <Field label="Тип значений">
            <select
              onChange={(event) => {
                setItemType(event.target.value);
                setValidatedImport(null);
              }}
              value={itemType}
            >
              <option value="ip">IP-адрес</option>
              <option value="domain">Домен</option>
              <option value="hash">Hash</option>
              <option value="user">Пользователь</option>
              <option value="host">Хост</option>
              <option value="process">Процесс</option>
              <option value="string">Строка</option>
            </select>
          </Field>
          <Field label="Общий контекст" wide>
            <input
              onChange={(event) => {
                setBulkLabel(event.target.value);
                setValidatedImport(null);
              }}
              value={bulkLabel}
            />
          </Field>
          <Field label="Теги" wide>
            <input
              onChange={(event) => {
                setBulkTags(event.target.value);
                setValidatedImport(null);
              }}
              value={bulkTags}
            />
          </Field>
          <Field label="Начальный статус">
            <label>
              <input
                checked={bulkEnabled}
                onChange={(event) => {
                  setBulkEnabled(event.target.checked);
                  setValidatedImport(null);
                }}
                type="checkbox"
              />
              Включено
            </label>
          </Field>
          <Field label="Значения импорта" wide>
            <textarea
              aria-label="Значения импорта"
              onChange={(event) => {
                setBulkValues(event.target.value);
                setValidatedImport(null);
              }}
              rows={6}
              value={bulkValues}
            />
          </Field>
          <Button
            disabled={Boolean(busy) || !importItems.length}
            onClick={() => void runImport(true)}
          >
            Проверить импорт
          </Button>
          <Button
            disabled={Boolean(busy) || validatedImport?.signature !== importSignature}
            onClick={() => void runImport(false)}
            tone="primary"
          >
            Применить импорт
          </Button>
        </div>
      </section>
    </div>
  );
}

function ResourceEditor({
  resource,
  onClose,
  onSaved,
  notify,
}: {
  resource: Row;
  onClose: () => void;
  onSaved: () => void;
  notify: Notify;
}) {
  const initial = initialResource(resource);
  const [id, setId] = useState(initial.id);
  const [name, setName] = useState(initial.name);
  const [kind] = useState(initial.kind);
  const [tenant, setTenant] = useState(initial.tenant);
  const [description, setDescription] = useState(initial.description);
  const [config, setConfig] = useState<Row>(initial.config);
  const [bindings, setBindings] = useState<Row>(initial.bindings);
  const [step, setStep] = useState<string>(resourceSteps(initial.kind)[0].id);
  const [validation, setValidation] = useState<Row | null>(null);
  const [deployment, setDeployment] = useState<Row | null>(null);
  const [busy, setBusy] = useState("");
  const steps = resourceSteps(kind);
  const setConfigValue = (key: string, value: unknown) =>
    setConfig((current) => ({ ...current, [key]: value }));
  const setBindingValue = (key: string, value: unknown) =>
    setBindings((current) => ({ ...current, [key]: value }));

  async function save() {
    if (!name.trim()) throw new Error("Укажите название ресурса");
    const saved = await api.saveResource({
      id,
      name: name.trim(),
      kind,
      description,
      tenant_id: tenant || "main",
      config: sanitizeResourceConfig(kind, config),
      bindings,
    });
    setId(saved.id);
    return saved;
  }

  async function operation(action: "save" | "validate" | "publish") {
    setBusy(action);
    setValidation(null);
    try {
      const saved = await save();
      if (action === "save") {
        notify("Черновик ресурса сохранен", "healthy");
        onSaved();
        return;
      }
      const result = await api.validateResource(saved.id);
      setValidation(result as unknown as Row);
      setStep("validation");
      if (!result.valid) {
        notify(`Проверка не пройдена: ${result.errors.join("; ")}`, "critical");
        return;
      }
      if (kind === "collector")
        setDeployment(
          (await api.resourceDeployment(saved.id)) as unknown as Row,
        );
      if (action === "validate") {
        notify("Параметры ресурса проверены", "healthy");
        onSaved();
        return;
      }
      await api.publishResource(saved.id);
      notify("Ресурс опубликован в runtime", "healthy");
      onSaved();
      onClose();
    } catch (error) {
      notify(
        error instanceof Error ? error.message : String(error),
        "critical",
      );
    } finally {
      setBusy("");
    }
  }

  function commonFields() {
    return (
      <div className="kuma-editor-form">
        <Field label="Название" wide>
          <input
            onChange={(event) => setName(event.target.value)}
            required
            value={name}
          />
        </Field>
        <Field label="Tenant">
          <input
            onChange={(event) => setTenant(event.target.value)}
            value={tenant}
          />
        </Field>
        <Field label="Тип">
          <input disabled value={resourceLabel(kind)} />
        </Field>
        <Field label="Описание" wide>
          <textarea
            onChange={(event) => setDescription(event.target.value)}
            rows={4}
            value={description}
          />
        </Field>
      </div>
    );
  }

  const selectedStep = steps.find((item) => item.id === step) ?? steps[0];
  const variants = Array.isArray(deployment?.variants)
    ? (deployment.variants as Row[])
    : [];

  function updateSchemaField(
    definition: ResourceFieldDefinition,
    value: unknown,
  ) {
    if ((definition.target ?? "config") === "bindings")
      setBindingValue(definition.key, value);
    else setConfigValue(definition.key, value);
  }

  function schemaFieldValue(definition: ResourceFieldDefinition): unknown {
    const source =
      (definition.target ?? "config") === "bindings" ? bindings : config;
    return source[definition.key] ?? definition.defaultValue ?? "";
  }

  function renderSchemaField(definition: ResourceFieldDefinition) {
    const value = schemaFieldValue(definition);
    let control: ReactNode;
    if (definition.type === "select") {
      control = (
        <select
          aria-label={definition.label}
          onChange={(event) => updateSchemaField(definition, event.target.value)}
          value={text(value, "")}
        >
          {(definition.options ?? []).map((item) => (
            <option key={item.value} value={item.value}>
              {item.label}
            </option>
          ))}
        </select>
      );
    } else if (definition.type === "textarea") {
      control = (
        <textarea
          aria-label={definition.label}
          className="sentinel-code-input"
          onChange={(event) => updateSchemaField(definition, event.target.value)}
          placeholder={definition.placeholder}
          rows={definition.rows ?? 6}
          value={text(value, "")}
        />
      );
    } else if (definition.type === "boolean") {
      control = (
        <input
          aria-label={definition.label}
          checked={Boolean(value)}
          onChange={(event) =>
            updateSchemaField(definition, event.target.checked)
          }
          type="checkbox"
        />
      );
    } else if (definition.type === "number") {
      control = (
        <input
          aria-label={definition.label}
          min={definition.min}
          onChange={(event) =>
            updateSchemaField(definition, Number(event.target.value))
          }
          type="number"
          value={number(value)}
        />
      );
    } else if (definition.type === "csv") {
      control = (
        <input
          aria-label={definition.label}
          onChange={(event) =>
            updateSchemaField(
              definition,
              event.target.value
                .split(",")
                .map((item) => item.trim())
                .filter(Boolean),
            )
          }
          placeholder={definition.placeholder}
          value={Array.isArray(value) ? value.join(", ") : text(value, "")}
        />
      );
    } else {
      control = (
        <input
          aria-label={definition.label}
          onChange={(event) => updateSchemaField(definition, event.target.value)}
          placeholder={definition.placeholder}
          value={text(value, "")}
        />
      );
    }
    return (
      <Field
        hint={definition.hint}
        key={`${definition.target ?? "config"}:${definition.key}`}
        label={definition.label}
        wide={definition.wide}
      >
        {control}
      </Field>
    );
  }

  function validationContent() {
    return (
      <div className="kuma-validation-screen">
        <Icon name={validation?.valid ? "check" : "settings"} size={30} />
        <h3>
          {validation
            ? validation.valid
              ? "Параметры корректны"
              : "Найдены ошибки"
            : "Ресурс готов к серверной проверке"}
        </h3>
        {validation ? (
          <>
            {Array.isArray(validation.errors)
              ? (validation.errors as unknown[]).map((item, index) => (
                  <p className="kuma-validation-error" key={`e-${index}`}>
                    {text(item)}
                  </p>
                ))
              : null}
            {Array.isArray(validation.warnings)
              ? (validation.warnings as unknown[]).map((item, index) => (
                  <p className="kuma-validation-warning" key={`w-${index}`}>
                    {text(item)}
                  </p>
                ))
              : null}
          </>
        ) : (
          <p>
            Сохраните черновик и запустите проверку. Публикация доступна только
            после успешной валидации.
          </p>
        )}
        {variants.length ? (
          <div className="collector-deployment-grid">
            {variants.map((variant) => (
              <article key={text(variant.id)}>
                <header>
                  <div>
                    <strong>{text(variant.title)}</strong>
                    <small>{text(variant.description)}</small>
                  </div>
                  <Button
                    icon="copy"
                    onClick={() => {
                      void navigator.clipboard.writeText(
                        (variant.commands as unknown[])
                          .map((command) => text(command))
                          .join("\n\n"),
                      );
                      notify("Команды скопированы", "healthy");
                    }}
                  >
                    Копировать
                  </Button>
                </header>
                {(variant.commands as unknown[]).map((command, index) => (
                  <pre key={index}>{text(command)}</pre>
                ))}
                <p>
                  <b>Проверка:</b> {text(variant.verification)}
                </p>
              </article>
            ))}
          </div>
        ) : null}
      </div>
    );
  }

  function stepContent() {
    if (selectedStep.editor === "mapping")
      return (
        <MappingEditor
          onChange={(value) => setConfigValue("uem_mapping", value)}
          value={objectValue(config.uem_mapping)}
        />
      );
    if (selectedStep.editor === "active-list")
      return (
        <ActiveListEntries
          listKind={text(config.list_kind, "watch")}
          listName={name.trim()}
          notify={notify}
        />
      );
    if (selectedStep.editor === "validation") return validationContent();
    return (
      <>
        {selectedStep.id === "main" ? commonFields() : null}
        {(selectedStep.fields ?? []).length ? (
          <div className="kuma-editor-form">
            {(selectedStep.fields ?? []).map(renderSchemaField)}
          </div>
        ) : null}
      </>
    );
  }
  return (
    <div aria-modal="true" className="kuma-full-editor" role="dialog">
      <header>
        <div>
          <span>Ресурсы и сервисы / {resourceLabel(kind)}</span>
          <h2>
            {id ? "Редактирование" : "Создание"}: {name || resourceLabel(kind)}
          </h2>
        </div>
        <IconButton icon="close" label="Закрыть редактор" onClick={onClose} />
      </header>
      <div className="kuma-editor-body">
        <aside>
          <strong>{resourceLabel(kind)}</strong>
          {steps.map((stepDefinition, index) => (
            <button
              className={step === stepDefinition.id ? "active" : ""}
              key={stepDefinition.id}
              onClick={() => setStep(stepDefinition.id)}
              type="button"
            >
              <span>{index + 1}</span>
              {stepDefinition.label}
            </button>
          ))}
        </aside>
        <main>
          <div className="kuma-editor-section-head">
            <div>
              <h3>{selectedStep.label}</h3>
              <p>
                Изменения сохраняются как управляемый production-ресурс
                Sentinel.
              </p>
            </div>
            <StatusCell value={id ? "draft" : "new"} />
          </div>
          {stepContent()}
        </main>
      </div>
      <footer>
        <div>
          <Button onClick={onClose}>Отмена</Button>
        </div>
        <div>
          <Button
            disabled={Boolean(busy)}
            onClick={() => void operation("save")}
          >
            {busy === "save" ? "Сохранение..." : "Сохранить черновик"}
          </Button>
          <Button
            disabled={Boolean(busy)}
            onClick={() => void operation("validate")}
          >
            Проверить
          </Button>
          <Button
            disabled={Boolean(busy)}
            icon="play"
            onClick={() => void operation("publish")}
            tone="primary"
          >
            Опубликовать
          </Button>
        </div>
      </footer>
    </div>
  );
}

function LifecycleValue({ value }: { value: unknown }) {
  if (value === undefined) return <span>Отсутствует</span>;
  if (value === null) return <span>NULL</span>;
  if (Array.isArray(value)) {
    return value.length ? (
      <ul>{value.slice(0, 20).map((item, index) => <li key={index}><LifecycleValue value={item} /></li>)}</ul>
    ) : <span>Пустой список</span>;
  }
  if (typeof value === "object") {
    const entries = Object.entries(value as Row).slice(0, 20);
    return entries.length ? (
      <dl className="kuma-kv">
        {entries.map(([key, item]) => <div key={key}><dt>{key}</dt><dd><LifecycleValue value={item} /></dd></div>)}
      </dl>
    ) : <span>Пустой объект</span>;
  }
  if (typeof value === "boolean") return <span>{value ? "true" : "false"}</span>;
  return <code>{String(value)}</code>;
}

function ResourceLifecyclePanel({
  resource,
  notify,
  onChanged,
}: {
  resource: ResourceCatalogRecord;
  notify: Notify;
  onChanged: () => void;
}) {
  const managed = resource.origin === "sentinel-managed" && !resource.read_only;
  const versions = useQuery<ResourceVersionsResponse>(
    `resource-versions:${resource.id}:${managed}`,
    () => managed
      ? api.resourceVersions(resource.id)
      : Promise.resolve({
        resource_id: resource.id,
        tenant_id: resource.tenant_id,
        current_version: null,
        current_revision: null,
        deleted: false,
        items: [],
        total: 0,
      }),
  );
  const [fromVersion, setFromVersion] = useState(0);
  const [toVersion, setToVersion] = useState(0);
  const [comparison, setComparison] = useState<ResourceVersionCompareResponse | null>(null);
  const [busy, setBusy] = useState("");

  useEffect(() => {
    const items = versions.data?.items ?? [];
    const current = number(versions.data?.current_version ?? items[0]?.version);
    const previous = number(items.find((item) => item.version !== current)?.version ?? current);
    setFromVersion(previous);
    setToVersion(current);
    setComparison(null);
  }, [versions.data]);

  if (!managed) {
    return (
      <section className="kuma-editor-section">
        <div className="kuma-editor-section-head">
          <div><h3>Управляемый lifecycle</h3><p>Runtime и read-only ресурс необходимо дублировать в managed draft.</p></div>
          <StatusCell value="Только чтение" />
        </div>
      </section>
    );
  }
  if (versions.loading && !versions.data) return <LoadingState label="Загрузка версий..." />;
  if (versions.error) return <ErrorState error={versions.error} retry={versions.reload} />;
  const items = versions.data?.items ?? [];

  async function compare() {
    if (!fromVersion || !toVersion) return;
    setBusy("compare");
    try {
      setComparison(await api.compareResourceVersions(resource.id, fromVersion, toVersion));
    } catch (error) {
      notify(error instanceof Error ? error.message : String(error), "critical");
    } finally {
      setBusy("");
    }
  }

  async function rollback(targetVersion: number) {
    const expectedRevision = number(versions.data?.current_revision ?? resource.revision ?? resource.version);
    if (!expectedRevision || !window.confirm(`Создать новую версию из v${targetVersion}?`)) return;
    setBusy(`rollback:${targetVersion}`);
    try {
      await api.rollbackResource(resource.id, {
        target_version: targetVersion,
        expected_revision: expectedRevision,
      });
      notify(`Rollback v${targetVersion} сохранен новой версией`, "healthy");
      versions.reload();
      onChanged();
    } catch (error) {
      notify(error instanceof Error ? error.message : String(error), "critical");
    } finally {
      setBusy("");
    }
  }

  return (
    <section className="kuma-editor-section">
      <div className="kuma-editor-section-head">
        <div><h3>Версии managed resource</h3><p>Текущая версия v{versions.data?.current_version ?? resource.version}, revision {versions.data?.current_revision ?? resource.revision ?? resource.version}</p></div>
        <StatusCell value={`${items.length} версий`} />
      </div>
      <div className="native-grid">
        <table>
          <thead><tr><th>Версия</th><th>Операция</th><th>Автор</th><th>Создано</th><th /></tr></thead>
          <tbody>{items.map((item) => <tr key={item.id}>
            <td><strong>v{item.version}</strong>{item.version === versions.data?.current_version ? <Badge tone="healthy">Текущая</Badge> : null}</td>
            <td>{item.action}</td>
            <td>{item.created_by}</td>
            <td>{formatTime(item.created_ts)}</td>
            <td>{item.version !== versions.data?.current_version ? <Button disabled={Boolean(busy)} onClick={() => void rollback(item.version)}>Откатить к v{item.version}</Button> : null}</td>
          </tr>)}</tbody>
        </table>
      </div>
      {items.length >= 2 ? (
        <>
          <div className="kuma-editor-form">
            <Field label="Версия до">
              <select aria-label="Версия до" onChange={(event) => { setFromVersion(number(event.target.value)); setComparison(null); }} value={fromVersion}>
                {items.map((item) => <option key={item.version} value={item.version}>v{item.version}</option>)}
              </select>
            </Field>
            <Field label="Версия после">
              <select aria-label="Версия после" onChange={(event) => { setToVersion(number(event.target.value)); setComparison(null); }} value={toVersion}>
                {items.map((item) => <option key={item.version} value={item.version}>v{item.version}</option>)}
              </select>
            </Field>
            <Button disabled={Boolean(busy) || fromVersion === toVersion} onClick={() => void compare()}>Сравнить версии</Button>
          </div>
          {comparison ? (
            <div className="native-grid">
              <table>
                <thead><tr><th>Операция</th><th>JSON Pointer</th><th>До</th><th>После</th></tr></thead>
                <tbody>{comparison.changes.map((change, index) => <tr key={`${change.path}:${index}`}>
                  <td><StatusCell value={change.op} /></td>
                  <td><code>{change.path}</code></td>
                  <td><LifecycleValue value={change.before} /></td>
                  <td><LifecycleValue value={change.after} /></td>
                </tr>)}</tbody>
              </table>
              {comparison.identical ? <EmptyState detail="Версии идентичны" /> : null}
              {comparison.truncated ? <Badge tone="warning">Список ограничен backend-лимитом</Badge> : null}
            </div>
          ) : null}
        </>
      ) : null}
    </section>
  );
}

export function ResourcesWorkspace({ notify }: { notify: Notify }) {
  const [display, setDisplay] = useState<"tiles" | "list">("tiles");
  const [kind, setKind] = useState("");
  const [query, setQuery] = useState("");
  const [scope, setScope] = useState<"all" | "mine">("all");
  const [selected, setSelected] = useState<Row | null>(null);
  const [editing, setEditing] = useState<Row | null>(null);
  const [packageSelection, setPackageSelection] = useState<string[]>([]);
  const [importSummary, setImportSummary] = useState<ResourcePackageImportResponse | null>(null);
  const [lifecycleBusy, setLifecycleBusy] = useState("");
  const importInput = useRef<HTMLInputElement>(null);
  const state = useQuery(
    "kuma-resources",
    () => api.resourceCatalog({ include_runtime: true }),
    60_000,
  );
  const allRows = rows(state.data?.items);
  const filtered = allRows.filter(
    (row) =>
      (!kind || row.kind === kind) &&
      (scope === "all" || row.origin === "sentinel-managed") &&
      JSON.stringify(row).toLowerCase().includes(query.toLowerCase()),
  );
  const selectedDefinition = RESOURCE_DEFINITIONS.find(
    (item) => item.kind === kind,
  );
  const selectedResource = selected as unknown as ResourceCatalogRecord | null;
  const openKind = (nextKind: string) => {
    setKind(nextKind);
    setDisplay("list");
    setSelected(null);
  };

  async function duplicate(resource: ResourceCatalogRecord) {
    setLifecycleBusy("duplicate");
    try {
      const result = await api.duplicateResource(resource.id, { name: `${resource.name} managed` });
      notify(`Создан managed draft ${result.resource?.name || result.resource?.id || ""}`, "healthy");
      setSelected(null);
      state.reload();
    } catch (error) {
      notify(error instanceof Error ? error.message : String(error), "critical");
    } finally {
      setLifecycleBusy("");
    }
  }

  async function deleteDraft(resource: ResourceCatalogRecord) {
    const revision = number(resource.revision ?? resource.version);
    if (!revision || !window.confirm(`Удалить неопубликованный draft ${resource.name}?`)) return;
    setLifecycleBusy("delete");
    try {
      await api.deleteResourceDraft(resource.id, revision);
      notify("Неопубликованный draft удален, история версий сохранена", "healthy");
      setSelected(null);
      state.reload();
    } catch (error) {
      notify(error instanceof Error ? error.message : String(error), "critical");
    } finally {
      setLifecycleBusy("");
    }
  }

  async function exportPackage(resourceIds: string[]) {
    setLifecycleBusy("export");
    try {
      const result = await api.exportResourcePackage(resourceIds);
      notify(`Выгружен пакет ${result.filename}`, "healthy");
    } catch (error) {
      notify(error instanceof Error ? error.message : String(error), "critical");
    } finally {
      setLifecycleBusy("");
    }
  }

  async function importPackage(file: File) {
    setLifecycleBusy("import");
    try {
      const result = await api.importResourcePackage(file);
      setImportSummary(result);
      notify(`Импортировано managed drafts: ${result.total}`, "healthy");
      state.reload();
    } catch (error) {
      notify(error instanceof Error ? error.message : String(error), "critical");
    } finally {
      setLifecycleBusy("");
      if (importInput.current) importInput.current.value = "";
    }
  }

  return (
    <div className="native-page kuma-resources-page">
      <PageHeader
        eyebrow={kind ? "Ресурсы и сервисы" : undefined}
        title={selectedDefinition?.label ?? "Ресурсы и сервисы"}
        actions={
          <>
            <div className="kuma-view-toggle">
              <button
                className={display === "tiles" ? "active" : ""}
                onClick={() => {
                  setDisplay("tiles");
                  setKind("");
                }}
                type="button"
              >
                Плитка
              </button>
              <button
                className={display === "list" ? "active" : ""}
                onClick={() => setDisplay("list")}
                type="button"
              >
                Список
              </button>
            </div>
            <IconButton
              icon="refresh"
              label="Обновить"
              onClick={state.reload}
            />
          </>
        }
      />
      <Boundary state={state}>
        {() =>
          display === "tiles" ? (
            <div className="kuma-resource-home">
              <section>
                <h2>Конфигурация сервисов</h2>
                <div className="kuma-resource-tiles">
                  {RESOURCE_DEFINITIONS.slice(0, 2).map((definition) => (
                    <button
                      key={definition.kind}
                      onClick={() => openKind(definition.kind)}
                      type="button"
                    >
                      <Icon name={definition.icon} size={22} />
                      <span>
                        <strong>{definition.label}</strong>
                        <small>{definition.description}</small>
                      </span>
                      <b>
                        {
                          allRows.filter((row) => row.kind === definition.kind)
                            .length
                        }
                      </b>
                    </button>
                  ))}
                </div>
              </section>
              <section>
                <h2>Конфигурация ресурсов</h2>
                <div className="kuma-resource-tiles">
                  {RESOURCE_DEFINITIONS.slice(2).map((definition) => (
                    <button
                      key={definition.kind}
                      onClick={() => openKind(definition.kind)}
                      type="button"
                    >
                      <Icon name={definition.icon} size={22} />
                      <span>
                        <strong>{definition.label}</strong>
                        <small>{definition.description}</small>
                      </span>
                      <b>
                        {
                          allRows.filter((row) => row.kind === definition.kind)
                            .length
                        }
                      </b>
                    </button>
                  ))}
                </div>
              </section>
            </div>
          ) : (
            <div className="kuma-resource-catalog">
              <aside>
                <SearchField
                  onChange={setQuery}
                  placeholder="Поиск..."
                  value={query}
                />
                <div className="kuma-scope-toggle">
                  <button
                    className={scope === "all" ? "active" : ""}
                    onClick={() => setScope("all")}
                    type="button"
                  >
                    Все
                  </button>
                  <button
                    className={scope === "mine" ? "active" : ""}
                    onClick={() => setScope("mine")}
                    type="button"
                  >
                    Мои
                  </button>
                </div>
                <nav>
                  <button
                    className={!kind ? "active" : ""}
                    onClick={() => setKind("")}
                    type="button"
                  >
                    <Icon name="resources" />
                    Все ресурсы <b>{allRows.length}</b>
                  </button>
                  {RESOURCE_DEFINITIONS.map((definition) => (
                    <button
                      className={kind === definition.kind ? "active" : ""}
                      key={definition.kind}
                      onClick={() => setKind(definition.kind)}
                      type="button"
                    >
                      <Icon name={definition.icon} />
                      {definition.label}
                      <b>
                        {
                          allRows.filter((row) => row.kind === definition.kind)
                            .length
                        }
                      </b>
                    </button>
                  ))}
                </nav>
              </aside>
              <section>
                <div className="kuma-catalog-toolbar">
                  <Button
                    icon="plus"
                    onClick={() =>
                      setEditing({
                        kind: kind || "collector",
                        tenant_id: "main",
                        config:
                          kind === "collector" || !kind
                            ? { transport: "http", collector_profile: "" }
                            : {},
                        bindings: {},
                      })
                    }
                    tone="primary"
                  >
                    Добавить
                  </Button>
                  <SearchField
                    onChange={setQuery}
                    placeholder="Поиск по названию..."
                    value={query}
                  />
                  <span>Всего {filtered.length}</span>
                  <Button
                    disabled={Boolean(lifecycleBusy) || !packageSelection.length}
                    onClick={() => void exportPackage(packageSelection)}
                  >
                    Выгрузить выбранные ({packageSelection.length})
                  </Button>
                  <Button disabled={Boolean(lifecycleBusy)} onClick={() => importInput.current?.click()}>
                    Импорт пакета
                  </Button>
                  <input
                    accept=".json,application/json,application/vnd.rdegon-sentinel.resources+json"
                    aria-label="Файл пакета ресурсов"
                    hidden
                    onChange={(event) => {
                      const file = event.target.files?.[0];
                      if (file) void importPackage(file);
                    }}
                    ref={importInput}
                    type="file"
                  />
                </div>
                <Grid
                  columns={[
                    {
                      key: "package_selection",
                      title: "Пакет",
                      render: (row) => {
                        const resourceId = text(row.id, "");
                        const canExport = row.origin === "sentinel-managed" && !row.read_only && row.kind !== "secret";
                        return <input
                          aria-label={`Выбрать ${text(row.name)} для пакета`}
                          checked={packageSelection.includes(resourceId)}
                          disabled={!canExport}
                          onChange={(event) => setPackageSelection((current) => event.target.checked
                            ? [...new Set([...current, resourceId])]
                            : current.filter((item) => item !== resourceId))}
                          onClick={(event) => event.stopPropagation()}
                          type="checkbox"
                        />;
                      },
                    },
                    {
                      key: "name",
                      title: "Название",
                      render: (row) => <strong>{text(row.name)}</strong>,
                    },
                    {
                      key: "kind",
                      title: "Тип",
                      render: (row) => resourceLabel(text(row.kind)),
                    },
                    {
                      key: "status",
                      title: "Статус",
                      render: (row) => <StatusCell value={text(row.status)} />,
                    },
                    { key: "origin", title: "Источник" },
                    { key: "tenant_id", title: "Tenant" },
                    {
                      key: "updated_ts",
                      title: "Последнее обновление",
                      render: (row) => formatTime(row.updated_ts),
                    },
                    { key: "description", title: "Описание" },
                  ]}
                  data={filtered}
                  onOpen={setSelected}
                />
              </section>
            </div>
          )
        }
      </Boundary>
      <DetailDrawer
        actions={
          selectedResource ? (
            <>
              {selectedResource.read_only || selectedResource.origin !== "sentinel-managed" ? (
                <Button disabled={Boolean(lifecycleBusy)} icon="copy" onClick={() => void duplicate(selectedResource)} tone="primary">
                  Создать managed draft
                </Button>
              ) : (
                <Button icon="settings" onClick={() => setEditing(selectedResource as unknown as Row)}>
                  Редактировать
                </Button>
              )}
              {!selectedResource.read_only && selectedResource.origin === "sentinel-managed" ? (
                <Button
                  onClick={async () => {
                    try {
                      const result = await api.validateResource(
                        selectedResource.id,
                      );
                      notify(
                        result.valid
                          ? "Ресурс прошел проверку"
                          : result.errors.join("; "),
                        result.valid ? "healthy" : "critical",
                      );
                    } catch (error) {
                      notify(
                        error instanceof Error ? error.message : String(error),
                        "critical",
                      );
                    }
                  }}
                >
                  Проверить
                </Button>
              ) : null}
              {!selectedResource.read_only && selectedResource.origin === "sentinel-managed" && selectedResource.kind !== "secret" ? (
                <Button disabled={Boolean(lifecycleBusy)} onClick={() => void exportPackage([selectedResource.id])}>
                  Выгрузить пакет
                </Button>
              ) : null}
              {!selectedResource.read_only && selectedResource.origin === "sentinel-managed" && selectedResource.status === "draft" && !selectedResource.published_ts ? (
                <Button disabled={Boolean(lifecycleBusy)} onClick={() => void deleteDraft(selectedResource)} tone="danger">
                  Удалить draft
                </Button>
              ) : null}
            </>
          ) : null
        }
        onClose={() => setSelected(null)}
        open={Boolean(selected)}
        title={selected ? text(selected.name) : "Ресурс"}
      >
        {selectedResource ? <>
          <RecordDetails kind="resource" value={selectedResource as unknown as Row} />
          <ResourceLifecyclePanel
            notify={notify}
            onChanged={() => state.reload()}
            resource={selectedResource}
          />
        </> : null}
      </DetailDrawer>
      <Modal
        footer={<Button onClick={() => setImportSummary(null)} tone="primary">Закрыть</Button>}
        onClose={() => setImportSummary(null)}
        open={Boolean(importSummary)}
        title="Импорт ресурсов завершен"
      >
        {importSummary ? <div className="record-details">
          <dl className="kuma-kv">
            <div><dt>Статус</dt><dd><StatusCell value={importSummary.status} /></dd></div>
            <div><dt>Package ID</dt><dd><code>{importSummary.package_id}</code></dd></div>
            <div><dt>Tenant</dt><dd>{importSummary.tenant_id}</dd></div>
            <div><dt>Создано drafts</dt><dd>{importSummary.total}</dd></div>
          </dl>
          <div className="native-grid">
            <table><thead><tr><th>Исходный ID</th><th>Managed ID</th><th>Версия</th><th>Статус</th></tr></thead>
              <tbody>{importSummary.items.map((item) => <tr key={`${item.source_id}:${item.resource_id}`}>
                <td><code>{item.source_id}</code></td><td><code>{item.resource_id}</code></td><td>v{item.version}</td><td><StatusCell value={item.status} /></td>
              </tr>)}</tbody>
            </table>
          </div>
        </div> : null}
      </Modal>
      {editing ? (
        <ResourceEditor
          key={`${text(editing.id, "new")}-${text(editing.kind)}`}
          notify={notify}
          onClose={() => setEditing(null)}
          onSaved={() => {
            state.reload();
            setSelected(null);
          }}
          resource={editing}
        />
      ) : null}
    </div>
  );
}

export type RuleEditorState = {
  title: string;
  description: string;
  kind: string;
  sourceProfile: string;
  sourceQuery: string;
  expression: string;
  threshold: number;
  windowS: number;
  entityField: string;
  severity: string;
  suppressionKey: string;
  target: string;
};

export function buildRuleBlocks(value: RuleEditorState): Row[] {
  return [
    {
      id: "source-1",
      type: "source",
      stage: "ingest",
      label: value.sourceProfile || "Production events",
      config: {
        profile: value.sourceProfile || "all",
        query: value.sourceQuery,
      },
    },
    {
      id: "rule-1",
      type: "detection",
      stage: "detect",
      label: value.title || "Detection",
      config: {
        expr: value.expression,
        threshold: value.threshold,
        window_s: value.windowS,
        entity_field: value.entityField,
      },
    },
    {
      id: "incident-1",
      type: "incident",
      stage: "incident",
      label: "Create incident",
      config: {
        severity: value.severity,
        suppression_key: value.suppressionKey,
      },
    },
    {
      id: "publish-1",
      type: "publish",
      stage: "publish",
      label: "Publish runtime",
      config: { target: value.target },
    },
  ];
}

function ruleState(row: Row): RuleEditorState {
  const blocks = rows(row.blocks);
  const source = blocks.find((block) => block.type === "source") ?? {};
  const detection = blocks.find((block) => block.type === "detection") ?? {};
  const incident = blocks.find((block) => block.type === "incident") ?? {};
  const publish = blocks.find((block) => block.type === "publish") ?? {};
  const sourceConfig = objectValue(source.config);
  const detectionConfig = objectValue(detection.config);
  const incidentConfig = objectValue(incident.config);
  const publishConfig = objectValue(publish.config);
  return {
    title: text(row.title, ""),
    description: text(row.description, ""),
    kind: text(row.kind, "detection"),
    sourceProfile: text(sourceConfig.profile, "all"),
    sourceQuery: text(sourceConfig.query, ""),
    expression: text(detectionConfig.expr, ""),
    threshold: number(detectionConfig.threshold || 1),
    windowS: number(detectionConfig.window_s || 300),
    entityField: text(detectionConfig.entity_field, "host.name"),
    severity: text(incidentConfig.severity, "medium"),
    suppressionKey: text(incidentConfig.suppression_key, "host.name"),
    target: text(publishConfig.target, "stream-correlation"),
  };
}

function RuleEditor({
  draft,
  notify,
  onClose,
  onSaved,
}: {
  draft: Row;
  notify: Notify;
  onClose: () => void;
  onSaved: () => void;
}) {
  const [id, setId] = useState(text(draft.id, ""));
  const [value, setValue] = useState<RuleEditorState>(() => ruleState(draft));
  const [tab, setTab] = useState("general");
  const [advanced, setAdvanced] = useState(false);
  const [result, setResult] = useState<Row | null>(null);
  const [busy, setBusy] = useState("");
  const change = <K extends keyof RuleEditorState>(
    key: K,
    next: RuleEditorState[K],
  ) => setValue((current) => ({ ...current, [key]: next }));
  const payload = () => ({
    id,
    title: value.title.trim(),
    description: value.description,
    kind: value.kind || "detection",
    blocks: buildRuleBlocks(value),
  });

  async function save() {
    if (!value.title.trim()) throw new Error("Укажите название правила");
    const saved = await api.saveBuilderDraft(payload());
    setId(saved.id);
    return saved;
  }
  async function action(operation: "save" | "validate" | "test" | "publish") {
    setBusy(operation);
    setResult(null);
    try {
      const saved = await save();
      if (operation === "save") {
        notify("Черновик правила сохранен", "healthy");
        onSaved();
        return;
      }
      const response =
        operation === "validate"
          ? await api.validateBuilder(saved)
          : operation === "test"
            ? await api.testBuilder(saved)
            : await api.publishBuilder(saved.id);
      setResult(response as unknown as Row);
      setTab("test");
      notify(
        `${operation}: ${text((response as unknown as Row).status ?? (response as unknown as Row).valid, "готово")}`,
        "healthy",
      );
      onSaved();
      if (operation === "publish") onClose();
    } catch (error) {
      notify(
        error instanceof Error ? error.message : String(error),
        "critical",
      );
    } finally {
      setBusy("");
    }
  }

  return (
    <div aria-modal="true" className="kuma-full-editor" role="dialog">
      <header>
        <div>
          <span>Ресурсы и сервисы / Правила корреляции</span>
          <h2>
            {id ? "Редактирование правила" : "Создание правила корреляции"}
          </h2>
        </div>
        <IconButton icon="close" label="Закрыть редактор" onClick={onClose} />
      </header>
      <div className="kuma-rule-tabs">
        <button
          className={tab === "general" ? "active" : ""}
          onClick={() => setTab("general")}
          type="button"
        >
          Общие
        </button>
        <button
          className={tab === "selectors" ? "active" : ""}
          onClick={() => setTab("selectors")}
          type="button"
        >
          Селекторы
        </button>
        <button
          className={tab === "actions" ? "active" : ""}
          onClick={() => setTab("actions")}
          type="button"
        >
          Действия
        </button>
        <button
          className={tab === "test" ? "active" : ""}
          onClick={() => setTab("test")}
          type="button"
        >
          Проверка и публикация
        </button>
        <button
          className={advanced ? "active" : ""}
          onClick={() => setAdvanced((current) => !current)}
          type="button"
        >
          JSON
        </button>
      </div>
      <div className="kuma-rule-editor-body">
        <main>
          {advanced ? (
            <div className="kuma-editor-form">
              <Field label="Pipeline blocks JSON" wide>
                <textarea
                  className="sentinel-code-input"
                  readOnly
                  rows={24}
                  value={JSON.stringify(buildRuleBlocks(value), null, 2)}
                />
              </Field>
            </div>
          ) : tab === "general" ? (
            <div className="kuma-editor-form">
              <Field label="Название" wide>
                <input
                  onChange={(event) => change("title", event.target.value)}
                  value={value.title}
                />
              </Field>
              <Field label="Tenant">
                <input disabled value="main" />
              </Field>
              <Field label="Тип">
                <select
                  onChange={(event) => change("kind", event.target.value)}
                  value={value.kind}
                >
                  <option value="detection">Detection</option>
                  <option value="normalizer">Normalizer pipeline</option>
                  <option value="threat-intel">Threat intelligence</option>
                </select>
              </Field>
              <Field label="Описание" wide>
                <textarea
                  onChange={(event) =>
                    change("description", event.target.value)
                  }
                  rows={5}
                  value={value.description}
                />
              </Field>
            </div>
          ) : tab === "selectors" ? (
            <div className="kuma-editor-form">
              <Field label="Профиль источника">
                <input
                  onChange={(event) =>
                    change("sourceProfile", event.target.value)
                  }
                  value={value.sourceProfile}
                />
              </Field>
              <Field label="Предварительный фильтр">
                <input
                  onChange={(event) =>
                    change("sourceQuery", event.target.value)
                  }
                  placeholder="source_type = 'linux'"
                  value={value.sourceQuery}
                />
              </Field>
              <Field label="Условие корреляции" wide>
                <textarea
                  className="sentinel-code-input"
                  onChange={(event) => change("expression", event.target.value)}
                  placeholder="category = 'authentication' AND event_outcome = 'failure'"
                  rows={10}
                  value={value.expression}
                />
              </Field>
              <Field label="Порог">
                <input
                  min="1"
                  onChange={(event) =>
                    change("threshold", Number(event.target.value))
                  }
                  type="number"
                  value={value.threshold}
                />
              </Field>
              <Field label="Окно, секунд">
                <input
                  min="60"
                  onChange={(event) =>
                    change("windowS", Number(event.target.value))
                  }
                  type="number"
                  value={value.windowS}
                />
              </Field>
              <Field label="Поле сущности">
                <input
                  onChange={(event) =>
                    change("entityField", event.target.value)
                  }
                  value={value.entityField}
                />
              </Field>
            </div>
          ) : tab === "actions" ? (
            <div className="kuma-editor-form">
              <Field label="Важность">
                <select
                  onChange={(event) => change("severity", event.target.value)}
                  value={value.severity}
                >
                  <option value="low">Low</option>
                  <option value="medium">Medium</option>
                  <option value="high">High</option>
                  <option value="critical">Critical</option>
                </select>
              </Field>
              <Field label="Ключ дедупликации">
                <input
                  onChange={(event) =>
                    change("suppressionKey", event.target.value)
                  }
                  value={value.suppressionKey}
                />
              </Field>
              <Field label="Runtime target">
                <select
                  onChange={(event) => change("target", event.target.value)}
                  value={value.target}
                >
                  <option value="stream-correlation">Stream correlation</option>
                  <option value="batch-correlation">Batch correlation</option>
                </select>
              </Field>
            </div>
          ) : (
            <div className="kuma-validation-screen">
              <Icon name={result ? "check" : "settings"} size={30} />
              <h3>
                {result
                  ? "Операция завершена"
                  : "Проверка на production contract"}
              </h3>
              <p>
                Validate проверяет структуру pipeline. Test выполняет
                shadow-проверку без публикации. Publish переводит проверенный
                черновик в runtime.
              </p>
              {result ? <RecordDetails kind="rule" value={result} /> : null}
              <div className="kuma-validation-actions">
                <Button
                  disabled={Boolean(busy)}
                  onClick={() => void action("validate")}
                >
                  Validate
                </Button>
                <Button
                  disabled={Boolean(busy)}
                  icon="play"
                  onClick={() => void action("test")}
                >
                  Shadow test
                </Button>
              </div>
            </div>
          )}
        </main>
      </div>
      <footer>
        <Button onClick={onClose}>Отмена</Button>
        <div>
          <Button disabled={Boolean(busy)} onClick={() => void action("save")}>
            Сохранить черновик
          </Button>
          <Button
            disabled={Boolean(busy)}
            icon="play"
            onClick={() => void action("publish")}
            tone="primary"
          >
            Опубликовать
          </Button>
        </div>
      </footer>
    </div>
  );
}

function unifiedStatusLabel(status: string) {
  return ({
    active: "Активно",
    drift: "Расхождение",
    retired: "Выведено",
    disabled: "Отключено",
    unpublished: "Не опубликовано",
    unknown: "Неизвестно",
  } as Record<string, string>)[status] || status;
}

function unifiedIssueLabel(issue: string) {
  return ({
    pack_provenance_conflict: "Конфликт владельцев пакета",
    catalog_runtime_enabled_drift: "Статус каталога расходится с runtime",
    authored_runtime_status_drift: "Статус пакета расходится с runtime",
    shared_runtime_id_collapsed: "Один ID используется stream и batch",
  } as Record<string, string>)[issue] || issue;
}

function RuntimeRuleDetails({ rule }: { rule: UnifiedRuleRecord }) {
  const noise = rule.noise ?? {};
  return (
    <div className="record-details">
      <dl className="kuma-kv">
        <div><dt>Runtime ID</dt><dd><code>{rule.identity}</code></dd></div>
        <div><dt>Движок</dt><dd>{rule.kind}</dd></div>
        <div><dt>Статус</dt><dd><StatusCell value={unifiedStatusLabel(rule.status)} /></dd></div>
        <div><dt>Важность</dt><dd><Badge tone={severityTone(rule.severity)}>{rule.severity || "info"}</Badge></dd></div>
        <div><dt>Пакет</dt><dd>{rule.pack?.title || rule.pack?.id || "—"}</dd></div>
        <div><dt>Владелец</dt><dd>{rule.pack?.owner || "—"}</dd></div>
        <div><dt>Алертов, 30 дней</dt><dd>{number(noise.alert_count).toLocaleString("ru-RU")}</dd></div>
        <div><dt>False positive</dt><dd>{number(noise.false_positive_count).toLocaleString("ru-RU")} ({(number(noise.false_positive_ratio) * 100).toFixed(1)}%)</dd></div>
        <div><dt>Подавлено</dt><dd>{number(noise.suppressed_count).toLocaleString("ru-RU")} ({(number(noise.suppressed_ratio) * 100).toFixed(1)}%)</dd></div>
        <div><dt>Обновлено</dt><dd>{formatTime(rule.updated_ts)}</dd></div>
      </dl>
      {rule.description ? <section><h3>Описание</h3><p>{rule.description}</p></section> : null}
      {rule.issues.length ? (
        <section>
          <h3>Расхождения</h3>
          <div className="badge-row">
            {rule.issues.map((issue) => <Badge key={issue} tone="warning">{unifiedIssueLabel(issue)}</Badge>)}
          </div>
        </section>
      ) : null}
      {rule.replacement?.replacement_identity ? (
        <section>
          <h3>Замена</h3>
          <p><code>{rule.replacement.replacement_identity}</code> · {rule.replacement.reason || "—"}</p>
        </section>
      ) : null}
    </div>
  );
}

export function RulesWorkspace({ notify }: { notify: Notify }) {
  const [tab, setTab] = useState<"drafts" | "packs" | "runtime">("drafts");
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState<Row | null>(null);
  const [editing, setEditing] = useState<Row | null>(null);
  const [runtimeBusy, setRuntimeBusy] = useState("");
  const [disableTarget, setDisableTarget] = useState<UnifiedRuleRecord | null>(null);
  const [disableReason, setDisableReason] = useState("");
  const [replacementIdentity, setReplacementIdentity] = useState("");
  const state = useQuery(
    "kuma-rules",
    async () => {
      const [drafts, packs] = await Promise.all([
        api.builderDrafts(),
        api.correlationPacks(),
      ]);
      return { drafts, packs };
    },
    60_000,
  );
  const runtimeState = useQuery(
    "kuma-rules-runtime",
    () => api.unifiedRules({ limit: 5_000, noise_days: 30 }),
    60_000,
  );
  const needle = query.trim().toLowerCase();
  const draftRows = rows(state.data?.drafts.items).filter((row) =>
    JSON.stringify(row).toLowerCase().includes(needle),
  );
  const packRows = rows(state.data?.packs.items).filter((row) =>
    JSON.stringify(row).toLowerCase().includes(needle),
  );
  const runtimeRules = runtimeState.data?.items ?? [];
  const runtimeRows = runtimeRules.filter((rule) =>
    `${rule.identity} ${rule.title} ${rule.description || ""} ${rule.pack?.id || ""}`.toLowerCase().includes(needle),
  );
  const activeReplacements = runtimeRules.filter((rule) =>
    rule.enabled && rule.identity !== disableTarget?.identity,
  );
  const selectedRuntime = tab === "runtime" && selected
    ? selected as UnifiedRuleRecord
    : null;

  function reloadAll() {
    state.reload();
    runtimeState.reload();
  }

  async function packAction(
    operation: "validate" | "test" | "publish",
    row: Row,
  ) {
    const id = text(row.pack_id);
    try {
      const result =
        operation === "validate"
          ? await api.validateCorrelationPack(id, row)
          : operation === "test"
            ? await api.testCorrelationPack(id, { include_runtime: true })
            : await api.publishCorrelationPack(id);
      notify(
        `${operation}: ${text((result as unknown as Row).status ?? (result as unknown as Row).valid, "готово")}`,
        "healthy",
      );
      reloadAll();
    } catch (error) {
      notify(error instanceof Error ? error.message : String(error), "critical");
    }
  }

  async function runtimeAction(operation: "publish" | "enable", rule: UnifiedRuleRecord) {
    setRuntimeBusy(`${operation}:${rule.identity}`);
    try {
      const result = operation === "publish"
        ? await api.publishUnifiedRule(rule.identity)
        : await api.setUnifiedRuleEnabled(rule.identity, { enabled: true });
      notify(`Правило ${rule.identity}: ${text(result.status, "готово")}`, "healthy");
      setSelected(null);
      runtimeState.reload();
    } catch (error) {
      notify(error instanceof Error ? error.message : String(error), "critical");
    } finally {
      setRuntimeBusy("");
    }
  }

  async function retireRule() {
    if (!disableTarget || disableReason.trim().length < 8 || !replacementIdentity) return;
    setRuntimeBusy(`disable:${disableTarget.identity}`);
    try {
      const result = await api.setUnifiedRuleEnabled(disableTarget.identity, {
        enabled: false,
        reason: disableReason.trim(),
        replacement_identity: replacementIdentity,
      });
      notify(`Правило ${disableTarget.identity}: ${text(result.status, "выведено")}`, "healthy");
      setDisableTarget(null);
      setDisableReason("");
      setReplacementIdentity("");
      setSelected(null);
      runtimeState.reload();
    } catch (error) {
      notify(error instanceof Error ? error.message : String(error), "critical");
    } finally {
      setRuntimeBusy("");
    }
  }

  return (
    <div className="native-page kuma-rules-page">
      <PageHeader
        title="Правила корреляции"
        actions={<IconButton icon="refresh" label="Обновить" onClick={reloadAll} />}
      />
      <Boundary state={state}>
        {() => (
          <div className="kuma-rule-catalog">
            <aside>
              <SearchField onChange={setQuery} placeholder="Поиск..." value={query} />
              <nav>
                <button className={tab === "drafts" ? "active" : ""} onClick={() => { setTab("drafts"); setSelected(null); }} type="button">
                  <Icon name="rules" />
                  Черновики <b>{draftRows.length}</b>
                </button>
                <button className={tab === "packs" ? "active" : ""} onClick={() => { setTab("packs"); setSelected(null); }} type="button">
                  <Icon name="resources" />
                  Пакеты правил <b>{packRows.length}</b>
                </button>
                <button className={tab === "runtime" ? "active" : ""} onClick={() => { setTab("runtime"); setSelected(null); }} type="button">
                  <Icon name="runtime" />
                  Runtime <b>{runtimeState.data?.total ?? runtimeRows.length}</b>
                </button>
              </nav>
            </aside>
            <section>
              <div className="kuma-catalog-toolbar">
                {tab !== "runtime" ? (
                  <Button icon="plus" onClick={() => setEditing({ kind: "detection", blocks: [] })} tone="primary">
                    Добавить
                  </Button>
                ) : null}
                <SearchField onChange={setQuery} placeholder="Поиск по названию..." value={query} />
                <span>Всего {tab === "drafts" ? draftRows.length : tab === "packs" ? packRows.length : runtimeRows.length}</span>
                {tab === "runtime" ? <span>Активно {runtimeState.data?.summary?.enabled_rule_count ?? 0}</span> : null}
              </div>
              {tab === "drafts" ? (
                <Grid
                  columns={[
                    { key: "title", title: "Название", render: (row) => <strong>{text(row.title)}</strong> },
                    { key: "kind", title: "Тип" },
                    { key: "status", title: "Статус", render: (row) => <StatusCell value={text(row.status)} /> },
                    { key: "version", title: "Версия" },
                    { key: "updated_ts", title: "Последнее обновление", render: (row) => formatTime(row.updated_ts) },
                    { key: "published_ts", title: "Опубликован", render: (row) => formatTime(row.published_ts) },
                  ]}
                  data={draftRows}
                  onOpen={setSelected}
                />
              ) : tab === "packs" ? (
                <Grid
                  columns={[
                    { key: "title", title: "Название", render: (row) => <strong>{text(row.title)}</strong> },
                    { key: "status", title: "Статус", render: (row) => <StatusCell value={text(row.status)} /> },
                    { key: "version", title: "Версия" },
                    { key: "rule_count", title: "Правил" },
                    { key: "active_stream_rules", title: "Активных stream" },
                    { key: "owner", title: "Владелец" },
                    { key: "updated_ts", title: "Изменен", render: (row) => formatTime(row.updated_ts) },
                  ]}
                  data={packRows}
                  onOpen={setSelected}
                />
              ) : (
                <Boundary state={runtimeState}>
                  {() => (
                    <Grid
                      columns={[
                        {
                          key: "title",
                          title: "Правило",
                          render: (row) => <><strong>{text(row.title)}</strong><span className="table-secondary">{text(row.identity)}</span></>,
                        },
                        { key: "kind", title: "Контур" },
                        { key: "status", title: "Статус", render: (row) => <StatusCell value={unifiedStatusLabel(text(row.status))} /> },
                        { key: "severity", title: "Важность", render: (row) => <Badge tone={severityTone(row.severity)}>{text(row.severity, "info")}</Badge> },
                        { key: "alerts", title: "Алерты 30д", render: (row) => number((row.noise as Row | undefined)?.alert_count).toLocaleString("ru-RU") },
                        { key: "fp", title: "FP", render: (row) => `${number((row.noise as Row | undefined)?.false_positive_count).toLocaleString("ru-RU")} · ${(number((row.noise as Row | undefined)?.false_positive_ratio) * 100).toFixed(1)}%` },
                        { key: "suppressed", title: "Подавлено", render: (row) => number((row.noise as Row | undefined)?.suppressed_count).toLocaleString("ru-RU") },
                        { key: "pack", title: "Пакет / владелец", render: (row) => { const pack = row.pack as Row | undefined; return <><strong>{text(pack?.id, "—")}</strong><span className="table-secondary">{text(pack?.owner, "—")}</span></>; } },
                        { key: "issues", title: "Проблемы", render: (row) => { const issues = Array.isArray(row.issues) ? row.issues : []; return issues.length ? <Badge tone="warning">{issues.length}</Badge> : <StatusCell value="Норма" />; } },
                      ]}
                      data={runtimeRows}
                      empty="Runtime-правила не найдены"
                      onOpen={setSelected}
                    />
                  )}
                </Boundary>
              )}
            </section>
          </div>
        )}
      </Boundary>
      <DetailDrawer
        actions={selected ? (
          tab === "drafts" ? (
            <Button icon="settings" onClick={() => setEditing(selected)}>Редактировать</Button>
          ) : tab === "packs" ? (
            <>
              <Button onClick={() => void packAction("validate", selected)}>Validate</Button>
              <Button icon="play" onClick={() => void packAction("test", selected)}>Shadow test</Button>
              <Button onClick={() => void packAction("publish", selected)} tone="primary">Publish</Button>
            </>
          ) : selectedRuntime ? (
            <>
              {selectedRuntime.capabilities.publish ? (
                <Button disabled={Boolean(runtimeBusy)} onClick={() => void runtimeAction("publish", selectedRuntime)}>Опубликовать</Button>
              ) : null}
              {!selectedRuntime.enabled && selectedRuntime.capabilities.enable ? (
                <Button disabled={Boolean(runtimeBusy)} onClick={() => void runtimeAction("enable", selectedRuntime)} tone="primary">Включить</Button>
              ) : null}
              {selectedRuntime.enabled && selectedRuntime.capabilities.disable ? (
                <Button disabled={Boolean(runtimeBusy)} onClick={() => { setDisableTarget(selectedRuntime); setDisableReason(""); setReplacementIdentity(""); }} tone="danger">Вывести правило</Button>
              ) : null}
            </>
          ) : null
        ) : null}
        onClose={() => setSelected(null)}
        open={Boolean(selected)}
        title={selected ? text(selected.title) : "Правило"}
      >
        {selected ? (selectedRuntime ? <RuntimeRuleDetails rule={selectedRuntime} /> : <RecordDetails kind="rule" value={selected} />) : null}
      </DetailDrawer>
      <Modal
        footer={<>
          <Button onClick={() => setDisableTarget(null)}>Отмена</Button>
          <Button disabled={Boolean(runtimeBusy) || disableReason.trim().length < 8 || !replacementIdentity} onClick={() => void retireRule()} tone="danger">Подтвердить отключение</Button>
        </>}
        onClose={() => setDisableTarget(null)}
        open={Boolean(disableTarget)}
        title="Вывод правила из runtime"
      >
        <div className="kuma-editor-form">
          <Field label="Причина" wide>
            <textarea aria-label="Причина" onChange={(event) => setDisableReason(event.target.value)} rows={4} value={disableReason} />
          </Field>
          <Field label="Активное правило-замена" wide>
            <select aria-label="Активное правило-замена" onChange={(event) => setReplacementIdentity(event.target.value)} value={replacementIdentity}>
              <option value="">Не выбрано</option>
              {activeReplacements.map((rule) => <option key={rule.identity} value={rule.identity}>{rule.identity} · {rule.title}</option>)}
            </select>
          </Field>
        </div>
      </Modal>
      {editing ? (
        <RuleEditor
          draft={editing}
          key={text(editing.id, "new")}
          notify={notify}
          onClose={() => setEditing(null)}
          onSaved={() => { reloadAll(); setSelected(null); }}
        />
      ) : null}
    </div>
  );
}
