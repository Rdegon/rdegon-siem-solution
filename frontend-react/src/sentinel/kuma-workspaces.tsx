import { useEffect, useState, type ReactNode } from "react";
import { api } from "./runtime/api";
import type { IncidentDetailResponse } from "./runtime/types";
import { formatTime, number, severityTone, text, useQuery } from "./runtime/query";
import { EventDetailContent, IncidentDetailContent } from "./incident-details";
import { Badge, Button, DetailDrawer, EmptyState, ErrorState, Icon, IconButton, LoadingState, PageHeader, SearchField, StatusCell } from "./ui";
import { RecordDetails } from "./record-details";

type Notify = (message: string, tone?: string) => void;
type Row = Record<string, unknown>;
type Column = { key: string; title: string; render?: (row: Row) => ReactNode };

function rows(value: unknown): Row[] {
  return Array.isArray(value) ? value.filter((item): item is Row => Boolean(item) && typeof item === "object") : [];
}

function Grid({ columns, data, onOpen, empty = "Данные не найдены" }: { columns: Column[]; data: Row[]; onOpen?: (row: Row) => void; empty?: string }) {
  if (!data.length) return <EmptyState detail={empty} />;
  return <div className="native-grid kuma-dense-grid"><table><thead><tr>{columns.map((column) => <th key={column.key}>{column.title}</th>)}</tr></thead><tbody>{data.map((row, index) => <tr className={onOpen ? "sentinel-clickable-row" : ""} key={text(row.id ?? row.alert_id ?? row.agg_id ?? row.pack_id ?? row.name, String(index))} onClick={onOpen ? () => onOpen(row) : undefined} onKeyDown={onOpen ? (event) => { if (event.key === "Enter" || event.key === " ") onOpen(row); } : undefined} tabIndex={onOpen ? 0 : undefined}>{columns.map((column) => <td key={column.key}>{column.render ? column.render(row) : text(row[column.key])}</td>)}</tr>)}</tbody></table></div>;
}

function Boundary<T>({ state, children }: { state: { data?: T; error?: Error; loading: boolean; reload: () => void }; children: (data: T) => ReactNode }) {
  if (state.loading && !state.data) return <LoadingState />;
  if (state.error) return <ErrorState error={state.error} retry={state.reload} />;
  if (!state.data) return <EmptyState />;
  return <>{children(state.data)}</>;
}

function Field({ label, children, wide = false, hint }: { label: string; children: ReactNode; wide?: boolean; hint?: string }) {
  return <label className={`kuma-editor-field ${wide ? "wide" : ""}`}><span>{label}</span>{children}{hint ? <small>{hint}</small> : null}</label>;
}

function objectValue(value: unknown): Row {
  return value && typeof value === "object" && !Array.isArray(value) ? value as Row : {};
}

function incidentId(row: Row) {
  return text(row.agg_id ?? row.alert_id ?? row.id, "");
}

const activeIncidentStatuses = new Set(["new", "open", "assigned", "triaged", "reopened", "in_progress", "escalated"]);

export function IncidentQueueWorkspace({ mode, notify }: { mode: "agg" | "raw"; notify: Notify }) {
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
  useEffect(() => { const timer = window.setTimeout(() => setQuery(queryInput.trim()), 400); return () => window.clearTimeout(timer); }, [queryInput]);
  const state = useQuery(`kuma-queue:${mode}:${status}:${query}:${windowSize}:${rowLimit}`, () => api.incidents({ view: mode, q: query, window: windowSize, limit: rowLimit, include_terminal: includeTerminal }), 30_000);

  async function open(row: Row) {
    setSelected(row); setDetail(null); setDetailError("");
    try { setDetail(await api.incidentDetail(mode, incidentId(row), { window: windowSize, event_limit: 100, alert_limit: 100, include_evidence: true })); }
    catch (error) { setDetailError(error instanceof Error ? error.message : String(error)); }
  }

  async function update(body: Row) {
    if (!selected) return;
    try {
      await api.updateIncident(mode, incidentId(selected), body);
      notify("Карточка обновлена", "healthy");
      setSelected(null);
      state.reload();
    } catch (error) { notify(error instanceof Error ? error.message : String(error), "critical"); }
  }

  const visible = rows(state.data?.items).filter((row) => {
    const rowStatus = text(row.status, "open").toLowerCase();
    const rowSeverity = text(row.severity_agg ?? row.severity, "unknown").toLowerCase();
    const statusMatches = status === "all" || (status === "active" ? activeIncidentStatuses.has(rowStatus) : status === "resolved" ? ["closed", "resolved"].includes(rowStatus) : ["false_positive", "suppressed"].includes(rowStatus));
    return statusMatches && (severity === "all" || rowSeverity === severity);
  });

  const alertColumns: Column[] = [
    { key: "severity", title: "Важность", render: (row) => <Badge tone={severityTone(row.severity)}>{text(row.severity)}</Badge> },
    { key: "rule_name", title: "Название", render: (row) => <strong>{text(row.rule_name, "Без названия")}</strong> },
    { key: "status", title: "Статус", render: (row) => <StatusCell value={text(row.status)} /> },
    { key: "assignee", title: "Исполнитель", render: (row) => text(row.assignee, "Не назначен") },
    { key: "incident", title: "Инцидент", render: (row) => text(row.incident_id ?? row.agg_id, "—") },
    { key: "ts_first", title: "Первое событие", render: (row) => formatTime(row.ts_first ?? row.ts) },
    { key: "ts_last", title: "Последнее событие", render: (row) => formatTime(row.ts_last ?? row.ts) },
    { key: "entity_key", title: "Затронутый актив" },
  ];
  const incidentColumns: Column[] = [
    { key: "rule_name", title: "Название", render: (row) => <strong>{text(row.rule_name, "Без названия")}</strong> },
    { key: "duration", title: "Длительность", render: (row) => text(row.duration, "—") },
    { key: "assignee", title: "Исполнитель", render: (row) => text(row.assignee, "Не назначен") },
    { key: "ts_first", title: "Создан", render: (row) => formatTime(row.ts_first ?? row.ts) },
    { key: "tenant", title: "Tenant", render: (row) => text(row.tenant_id ?? row.tenant, "main") },
    { key: "status", title: "Статус", render: (row) => <StatusCell value={text(row.status)} /> },
    { key: "hits", title: "Алерты", render: (row) => number(row.raw_alerts_total ?? row.alert_count ?? row.hits).toLocaleString("ru-RU") },
    { key: "severity", title: "Важность", render: (row) => <Badge tone={severityTone(row.severity_agg ?? row.severity)}>{text(row.severity_agg ?? row.severity)}</Badge> },
    { key: "entity_key", title: "Затронутый актив" },
  ];
  const selectedStatus = selected ? text(selected.status, "open").toLowerCase() : "";
  const selectedActive = activeIncidentStatuses.has(selectedStatus);
  const selectedTerminal = ["closed", "resolved", "false_positive", "suppressed"].includes(selectedStatus);

  return <div className="native-page kuma-queue-page">
    <PageHeader title={mode === "agg" ? "Инциденты" : "Алерты"} actions={<IconButton icon="refresh" label="Обновить" onClick={state.reload} />} />
    <div className="kuma-commandbar">
      <SearchField onChange={setQueryInput} placeholder="Поиск по названию, активу, источнику или исполнителю..." value={queryInput} />
      <div className="kuma-commandbar-actions">
        <span className="kuma-found">Показано: <b>{visible.length.toLocaleString("ru-RU")}</b>{number(state.data?.available_count) > visible.length ? ` из ${number(state.data?.available_count).toLocaleString("ru-RU")}` : ""}</span>
        <Button icon="filter" onClick={() => setFilterOpen((value) => !value)}>Фильтры{status !== "all" || severity !== "all" ? " · активны" : ""}</Button>
      </div>
    </div>
    {filterOpen ? <div className="kuma-filter-strip"><Field label="Состояние"><select onChange={(event) => setStatus(event.target.value)} value={status}><option value="all">Все</option><option value="active">Открытые</option><option value="resolved">Закрытые</option><option value="false_positive">False positive</option></select></Field><Field label="Важность"><select onChange={(event) => setSeverity(event.target.value)} value={severity}><option value="all">Все</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select></Field><Field label="Период"><select onChange={(event) => setWindowSize(event.target.value)} value={windowSize}><option value="24h">24 часа</option><option value="7d">7 дней</option><option value="30d">30 дней</option></select></Field><Field label="Строк"><select onChange={(event) => setRowLimit(Number(event.target.value))} value={rowLimit}><option value={100}>100</option><option value={200}>200</option><option value={250}>250</option><option value={500}>500</option></select></Field><Button onClick={() => { setStatus(mode === "agg" ? "active" : "all"); setSeverity("all"); setWindowSize(mode === "raw" ? "24h" : "30d"); setRowLimit(mode === "raw" ? 100 : 200); setQueryInput(""); }}>Сбросить</Button></div> : null}
    <Boundary state={state}>{() => <Grid columns={mode === "agg" ? incidentColumns : alertColumns} data={visible} onOpen={open} />}</Boundary>
    <DetailDrawer actions={selectedActive ? <><Button icon="user" onClick={() => update({ assignee: "current_user" })}>Назначить мне</Button><Button icon="check" onClick={() => update({ status: "closed", note: "Closed from Sentinel UI" })} tone="primary">Закрыть</Button><Button onClick={() => update({ status: "false_positive", note: "Marked as false positive from Sentinel UI" })} tone="danger">False positive</Button></> : selectedTerminal ? <Button icon="refresh" onClick={() => update({ status: "reopened", note: "Reopened from Sentinel UI" })} tone="primary">Вернуть в работу</Button> : null} eyebrow={selected ? text(selected.severity_agg ?? selected.severity) : undefined} onClose={() => setSelected(null)} open={Boolean(selected)} title={selected ? text(selected.rule_name, incidentId(selected)) : "Детали"}>
      {selected ? detailError ? <ErrorState error={new Error(detailError)} retry={() => open(selected)} /> : detail ? <IncidentDetailContent detail={detail} /> : <LoadingState label="Загрузка evidence..." /> : null}
    </DetailDrawer>
  </div>;
}

export const DEFAULT_EVENT_QUERY = "SELECT *\nFROM events_view\nORDER BY ts DESC\nLIMIT 250";

const eventColumns: Column[] = [
  { key: "ts", title: "Время", render: (row) => formatTime(row.ts) },
  { key: "severity", title: "Важность", render: (row) => <Badge tone={severityTone(row.severity)}>{text(row.severity)}</Badge> },
  { key: "log_source", title: "Источник" },
  { key: "category", title: "Категория" },
  { key: "event_code", title: "Код" },
  { key: "src_ip", title: "Источник IP" },
  { key: "dst_ip", title: "Назначение IP" },
  { key: "user_name", title: "Пользователь", render: (row) => text(row.user_name ?? row.target_user) },
  { key: "message", title: "Сообщение", render: (row) => <span className="sentinel-truncate">{text(row.message)}</span> },
];

function downloadTsv(data: Row[], columns: Column[]) {
  const escape = (value: unknown) => text(value).replace(/\t/g, " ").replace(/\r?\n/g, " ");
  const body = [columns.map((column) => column.title).join("\t"), ...data.map((row) => columns.map((column) => escape(row[column.key])).join("\t"))].join("\n");
  const url = URL.createObjectURL(new Blob([body], { type: "text/tab-separated-values;charset=utf-8" }));
  const link = document.createElement("a");
  link.href = url; link.download = `sentinel-events-${new Date().toISOString().slice(0, 19).replace(/:/g, "-")}.tsv`; link.click();
  URL.revokeObjectURL(url);
}

export function EventsQueryWorkspace({ notify }: { notify: Notify }) {
  const [draft, setDraft] = useState(DEFAULT_EVENT_QUERY);
  const [executed, setExecuted] = useState(DEFAULT_EVENT_QUERY);
  const [windowSize, setWindowSize] = useState("24h");
  const [autoRefresh, setAutoRefresh] = useState(false);
  const [selected, setSelected] = useState<Row | null>(null);
  const [columnPicker, setColumnPicker] = useState(false);
  const [visibleKeys, setVisibleKeys] = useState(eventColumns.map((column) => column.key));
  const state = useQuery(`kuma-events:${executed}:${windowSize}`, () => api.eventsQuery({ query: executed, window: windowSize, storage: "auto", limit: 250, offset: 0, include_count: true }), autoRefresh ? 30_000 : undefined);
  const visibleColumns = eventColumns.filter((column) => visibleKeys.includes(column.key));
  const data = rows(state.data?.rows);
  const lines = Array.from({ length: Math.max(5, draft.split("\n").length) }, (_, index) => index + 1).join("\n");

  return <div className="native-page kuma-events-page">
    <PageHeader title="События" actions={<><label className="kuma-auto-refresh"><input checked={autoRefresh} onChange={(event) => setAutoRefresh(event.target.checked)} type="checkbox" /><span>Автообновление</span></label><select aria-label="Временной диапазон" onChange={(event) => setWindowSize(event.target.value)} value={windowSize}><option value="1h">1 час</option><option value="24h">24 часа</option><option value="7d">7 дней</option><option value="30d">30 дней</option></select></>} />
    <section className="kuma-query-workspace">
      <div className="kuma-query-topline"><div><strong>Запрос</strong><span>ClickHouse SQL · только чтение</span></div><select aria-label="Готовый запрос" onChange={(event) => event.target.value && setDraft(event.target.value)} value=""><option value="">Сохраненные запросы</option><option value={DEFAULT_EVENT_QUERY}>Последние события</option><option value="SELECT *\nFROM events_view\nWHERE severity IN ('high', 'critical')\nORDER BY ts DESC\nLIMIT 250">High и Critical</option><option value="SELECT *\nFROM events_view\nWHERE category = 'authentication'\nORDER BY ts DESC\nLIMIT 250">Аутентификация</option></select></div>
      <div className="kuma-query-editor"><pre className="kuma-query-lines">{lines}</pre><textarea aria-label="Запрос событий" onChange={(event) => setDraft(event.target.value)} spellCheck={false} value={draft} /></div>
      <div className="kuma-query-actions"><div><span className="kuma-query-chip">events_view</span><span className="kuma-query-chip">{windowSize}</span></div><div><IconButton icon="refresh" label="Повторить запрос" onClick={state.reload} /><Button icon="play" onClick={() => setExecuted(draft.trim() || DEFAULT_EVENT_QUERY)} tone="primary">Выполнить запрос</Button></div></div>
    </section>
    <div className="kuma-results-toolbar"><div><h2>Результаты</h2><span>{number(state.data?.total_count ?? state.data?.row_count).toLocaleString("ru-RU")} событий · {number(state.data?.elapsed_ms)} мс</span></div><div><Button onClick={() => { downloadTsv(data, visibleColumns); notify("Результат экспортирован в TSV", "healthy"); }}>Экспорт TSV</Button><IconButton active={columnPicker} icon="settings" label="Настроить столбцы" onClick={() => setColumnPicker((value) => !value)} /></div></div>
    {columnPicker ? <div className="kuma-column-picker">{eventColumns.map((column) => <label key={column.key}><input checked={visibleKeys.includes(column.key)} onChange={(event) => setVisibleKeys((current) => event.target.checked ? [...current, column.key] : current.length > 1 ? current.filter((key) => key !== column.key) : current)} type="checkbox" />{column.title}</label>)}</div> : null}
    <Boundary state={state}>{() => <Grid columns={visibleColumns} data={data} onOpen={setSelected} />}</Boundary>
    <DetailDrawer actions={selected ? <Button onClick={() => { void navigator.clipboard.writeText(JSON.stringify(selected, null, 2)); notify("Данные события скопированы", "healthy"); }}>Копировать данные</Button> : null} onClose={() => setSelected(null)} open={Boolean(selected)} title={selected ? `${text(selected.log_source)} · ${formatTime(selected.ts)}` : "Событие"}>{selected ? <EventDetailContent event={selected} /> : null}</DetailDrawer>
  </div>;
}

type ResourceDefinition = { kind: string; label: string; description: string; icon: string };

export const RESOURCE_DEFINITIONS: ResourceDefinition[] = [
  { kind: "collector", label: "Коллекторы", description: "Прием событий и transport profiles", icon: "sources" },
  { kind: "correlator", label: "Корреляторы", description: "Stream и batch обработчики", icon: "runtime" },
  { kind: "correlationRule", label: "Правила корреляции", description: "Условия, окна и пороги", icon: "rules" },
  { kind: "normalizer", label: "Нормализаторы", description: "Разбор и UEM-сопоставление", icon: "list" },
  { kind: "connector", label: "Коннекторы", description: "Интеграции внешних систем", icon: "resources" },
  { kind: "destination", label: "Точки назначения", description: "Маршрутизация выходного потока", icon: "next" },
  { kind: "filter", label: "Фильтры", description: "Drop, tag и pass политики", icon: "filter" },
  { kind: "enrichmentRule", label: "Правила обогащения", description: "Контекст и справочники", icon: "plus" },
  { kind: "activeList", label: "Активные листы", description: "Динамические наборы значений", icon: "list" },
  { kind: "responseRule", label: "Правила реагирования", description: "Автоматические действия", icon: "response" },
];

function resourceLabel(kind: string) {
  return RESOURCE_DEFINITIONS.find((item) => item.kind === kind)?.label ?? kind;
}

function resourceSteps(kind: string) {
  if (kind === "collector") return [["main", "Источник"], ["transport", "Транспорт"], ["parsing", "Разбор событий"], ["filtering", "Фильтрация"], ["routing", "Маршрутизация"], ["validation", "Проверка параметров"]] as const;
  if (kind === "normalizer") return [["main", "Схема нормализации"], ["mapping", "Сопоставление полей"], ["examples", "Примеры событий"], ["validation", "Проверка параметров"]] as const;
  if (kind === "correlationRule") return [["main", "Общие"], ["selector", "Селекторы"], ["aggregation", "Окно и агрегация"], ["actions", "Действия"], ["validation", "Проверка и публикация"]] as const;
  if (kind === "correlator") return [["main", "Основные параметры"], ["engine", "Движок"], ["bindings", "Привязка правил"], ["validation", "Проверка параметров"]] as const;
  if (kind === "filter") return [["main", "Основные параметры"], ["selector", "Условие"], ["actions", "Действие"], ["validation", "Проверка параметров"]] as const;
  return [["main", "Основные параметры"], ["connection", "Конфигурация"], ["bindings", "Привязки"], ["validation", "Проверка параметров"]] as const;
}

function initialResource(resource: Row): { id: string; name: string; kind: string; tenant: string; description: string; config: Row; bindings: Row } {
  const readOnly = Boolean(resource.read_only);
  const kind = text(resource.kind, "collector");
  return {
    id: readOnly ? "" : text(resource.id, ""),
    name: readOnly ? `${text(resource.name)} managed` : text(resource.name, ""),
    kind,
    tenant: text(resource.tenant_id, "main"),
    description: text(resource.description, ""),
    config: { ...objectValue(resource.config), ...(kind === "collector" && !resource.config ? { transport: "http", collector_profile: "" } : {}) },
    bindings: { ...objectValue(resource.bindings) },
  };
}

function MappingEditor({ value, onChange }: { value: Row; onChange: (value: Row) => void }) {
  const entries = Object.entries(value);
  return <div className="kuma-mapping-editor"><div className="kuma-mapping-head"><span>Исходное поле</span><span>Поле UEM</span><span /></div>{entries.map(([source, target], index) => <div className="kuma-mapping-row" key={`${source}-${index}`}><input aria-label="Исходное поле" onChange={(event) => { const next = { ...value }; delete next[source]; next[event.target.value] = target; onChange(next); }} value={source} /><input aria-label="Поле UEM" onChange={(event) => onChange({ ...value, [source]: event.target.value })} value={text(target, "")} /><IconButton icon="delete" label="Удалить сопоставление" onClick={() => { const next = { ...value }; delete next[source]; onChange(next); }} /></div>)}<Button icon="plus" onClick={() => { let index = entries.length + 1; while (`source_field_${index}` in value) index += 1; onChange({ ...value, [`source_field_${index}`]: "event.field" }); }}>Добавить строку</Button></div>;
}

function ResourceEditor({ resource, onClose, onSaved, notify }: { resource: Row; onClose: () => void; onSaved: () => void; notify: Notify }) {
  const initial = initialResource(resource);
  const [id, setId] = useState(initial.id);
  const [name, setName] = useState(initial.name);
  const [kind] = useState(initial.kind);
  const [tenant, setTenant] = useState(initial.tenant);
  const [description, setDescription] = useState(initial.description);
  const [config, setConfig] = useState<Row>(initial.config);
  const [bindings, setBindings] = useState<Row>(initial.bindings);
  const [step, setStep] = useState<string>(resourceSteps(initial.kind)[0][0]);
  const [advanced, setAdvanced] = useState(false);
  const [validation, setValidation] = useState<Row | null>(null);
  const [busy, setBusy] = useState("");
  const steps = resourceSteps(kind);
  const setConfigValue = (key: string, value: unknown) => setConfig((current) => ({ ...current, [key]: value }));
  const setBindingValue = (key: string, value: unknown) => setBindings((current) => ({ ...current, [key]: value }));

  async function save() {
    if (!name.trim()) throw new Error("Укажите название ресурса");
    const saved = await api.saveResource({ id, name: name.trim(), kind, description, tenant_id: tenant || "main", config, bindings });
    setId(saved.id);
    return saved;
  }

  async function operation(action: "save" | "validate" | "publish") {
    setBusy(action); setValidation(null);
    try {
      const saved = await save();
      if (action === "save") {
        notify("Черновик ресурса сохранен", "healthy"); onSaved(); return;
      }
      const result = await api.validateResource(saved.id);
      setValidation(result as unknown as Row);
      setStep("validation");
      if (!result.valid) { notify(`Проверка не пройдена: ${result.errors.join("; ")}`, "critical"); return; }
      if (action === "validate") { notify("Параметры ресурса проверены", "healthy"); onSaved(); return; }
      await api.publishResource(saved.id);
      notify("Ресурс опубликован в runtime", "healthy"); onSaved(); onClose();
    } catch (error) { notify(error instanceof Error ? error.message : String(error), "critical"); }
    finally { setBusy(""); }
  }

  function commonFields() {
    return <div className="kuma-editor-form"><Field label="Название" wide><input onChange={(event) => setName(event.target.value)} required value={name} /></Field><Field label="Tenant"><input onChange={(event) => setTenant(event.target.value)} value={tenant} /></Field><Field label="Тип"><input disabled value={resourceLabel(kind)} /></Field><Field label="Описание" wide><textarea onChange={(event) => setDescription(event.target.value)} rows={4} value={description} /></Field></div>;
  }

  function stepContent() {
    if (step === "main") return <>{commonFields()}{kind === "normalizer" ? <div className="kuma-editor-form"><Field label="Тип источника"><input onChange={(event) => setConfigValue("source_type", event.target.value)} placeholder="linux, windows, suricata..." value={text(config.source_type, "")} /></Field><Field label="Matcher события" wide><textarea onChange={(event) => setConfigValue("event_matcher", event.target.value)} placeholder="event.module == 'linux'" rows={4} value={text(config.event_matcher, "")} /></Field><Field label="Приоритет"><input min="1" onChange={(event) => setConfigValue("priority", Number(event.target.value))} type="number" value={number(config.priority || 100)} /></Field></div> : null}</>;
    if (step === "transport") return <div className="kuma-editor-form"><Field label="Профиль коллектора" wide><input onChange={(event) => setConfigValue("collector_profile", event.target.value)} placeholder="linux-auth" value={text(config.collector_profile, "")} /></Field><Field label="Транспорт"><select onChange={(event) => setConfigValue("transport", event.target.value)} value={text(config.transport, "http")}><option value="http">HTTP</option><option value="syslog_tcp">Syslog TCP</option><option value="syslog_udp">Syslog UDP</option><option value="kafka">Kafka</option></select></Field><Field label="Endpoint / topic"><input onChange={(event) => setConfigValue("endpoint", event.target.value)} placeholder="/ingest/http или topic" value={text(config.endpoint, "")} /></Field><Field label="Workers"><input min="1" onChange={(event) => setConfigValue("workers", Number(event.target.value))} type="number" value={number(config.workers || 2)} /></Field><Field label="Batch size"><input min="1" onChange={(event) => setConfigValue("batch_size", Number(event.target.value))} type="number" value={number(config.batch_size || 500)} /></Field></div>;
    if (step === "parsing") return <div className="kuma-editor-form"><Field label="Типы источников" wide hint="Через запятую"><input onChange={(event) => setConfigValue("source_types", event.target.value.split(",").map((item) => item.trim()).filter(Boolean))} value={text(config.source_types, "")} /></Field><Field label="Нормализатор"><input onChange={(event) => setBindingValue("normalizer", event.target.value)} placeholder="linux-auth-normalizer" value={text(bindings.normalizer, "")} /></Field><Field label="Framing"><select onChange={(event) => setConfigValue("framing", event.target.value)} value={text(config.framing, "line")}><option value="line">Одна строка — одно событие</option><option value="octet_counting">Octet counting</option><option value="json">JSON stream</option></select></Field></div>;
    if (step === "filtering") return <div className="kuma-editor-form"><Field label="Фильтры" wide hint="Идентификаторы через запятую"><input onChange={(event) => setBindingValue("filters", event.target.value.split(",").map((item) => item.trim()).filter(Boolean))} value={text(bindings.filters, "")} /></Field><Field label="Неизвестные события"><select onChange={(event) => setConfigValue("unknown_events", event.target.value)} value={text(config.unknown_events, "pass")}><option value="pass">Пропускать</option><option value="tag">Помечать</option><option value="drop">Отбрасывать</option></select></Field></div>;
    if (step === "routing") return <div className="kuma-editor-form"><Field label="Точки назначения" wide hint="Идентификаторы через запятую"><input onChange={(event) => setBindingValue("destinations", event.target.value.split(",").map((item) => item.trim()).filter(Boolean))} value={text(bindings.destinations, "")} /></Field><Field label="Kafka topic"><input onChange={(event) => setConfigValue("topic", event.target.value)} value={text(config.topic, "siem.raw")} /></Field></div>;
    if (step === "mapping") return <MappingEditor onChange={(value) => setConfigValue("uem_mapping", value)} value={objectValue(config.uem_mapping)} />;
    if (step === "examples") return <div className="kuma-editor-form"><Field label="Примеры событий" wide><textarea className="sentinel-code-input" onChange={(event) => setConfigValue("examples", event.target.value)} placeholder="Вставьте обезличенные raw-события для проверки парсинга" rows={14} value={text(config.examples, "")} /></Field></div>;
    if (step === "selector") return <div className="kuma-editor-form"><Field label={kind === "filter" ? "Условие фильтра" : "Выражение корреляции"} wide><textarea className="sentinel-code-input" onChange={(event) => setConfigValue("expr", event.target.value)} placeholder="category = 'authentication' AND event_outcome = 'failure'" rows={8} value={text(config.expr ?? config.event_matcher, "")} /></Field>{kind === "correlationRule" ? <><Field label="Rule ID"><input min="1" onChange={(event) => setConfigValue("rule_id", Number(event.target.value))} type="number" value={number(config.rule_id)} /></Field><Field label="Техники MITRE"><input onChange={(event) => setConfigValue("mitre", event.target.value.split(",").map((item) => item.trim()).filter(Boolean))} placeholder="T1110, T1021.004" value={text(config.mitre, "")} /></Field></> : null}</div>;
    if (step === "aggregation") return <div className="kuma-editor-form"><Field label="Порог"><input min="1" onChange={(event) => setConfigValue("threshold", Number(event.target.value))} type="number" value={number(config.threshold || 1)} /></Field><Field label="Окно, секунд"><input min="60" onChange={(event) => setConfigValue("window_s", Number(event.target.value))} type="number" value={number(config.window_s || 300)} /></Field><Field label="Поле сущности"><input onChange={(event) => setConfigValue("entity_field", event.target.value)} value={text(config.entity_field, "host.name")} /></Field><Field label="Ключ дедупликации"><input onChange={(event) => setConfigValue("suppression_key", event.target.value)} value={text(config.suppression_key, "host.name")} /></Field></div>;
    if (step === "actions") return <div className="kuma-editor-form"><Field label={kind === "filter" ? "Действие" : "Важность"}><select onChange={(event) => setConfigValue(kind === "filter" ? "action" : "severity", event.target.value)} value={text(config[kind === "filter" ? "action" : "severity"], kind === "filter" ? "tag" : "medium")}>{kind === "filter" ? <><option value="drop">Drop</option><option value="tag">Tag</option><option value="pass">Pass</option></> : <><option value="low">Low</option><option value="medium">Medium</option><option value="high">High</option><option value="critical">Critical</option></>}</select></Field><Field label="Теги" wide><input onChange={(event) => setConfigValue("tags", event.target.value.split(",").map((item) => item.trim()).filter(Boolean))} value={text(config.tags, "")} /></Field></div>;
    if (step === "engine") return <div className="kuma-editor-form"><Field label="Движок"><select onChange={(event) => setConfigValue("engine", event.target.value)} value={text(config.engine, "stream")}><option value="stream">Stream</option><option value="batch">Batch</option></select></Field><Field label="Workers"><input min="1" onChange={(event) => setConfigValue("workers", Number(event.target.value))} type="number" value={number(config.workers || 2)} /></Field><Field label="Shard key"><input onChange={(event) => setConfigValue("shard_key", event.target.value)} value={text(config.shard_key, "asset_group")} /></Field></div>;
    if (step === "bindings") return <div className="kuma-editor-form"><Field label={kind === "correlator" ? "Правила корреляции" : "Привязанные ресурсы"} wide hint="Идентификаторы через запятую"><input onChange={(event) => setBindingValue(kind === "correlator" ? "correlation_rules" : "resources", event.target.value.split(",").map((item) => item.trim()).filter(Boolean))} value={text(bindings[kind === "correlator" ? "correlation_rules" : "resources"], "")} /></Field></div>;
    if (step === "connection") return <div className="kuma-editor-form"><Field label="URL / endpoint" wide><input onChange={(event) => setConfigValue("endpoint", event.target.value)} value={text(config.endpoint, "")} /></Field><Field label="Протокол"><input onChange={(event) => setConfigValue("protocol", event.target.value)} value={text(config.protocol, "")} /></Field><Field label="Secret reference"><input onChange={(event) => setConfigValue("secret_ref", event.target.value)} value={text(config.secret_ref, "")} /></Field></div>;
    return <div className="kuma-validation-screen"><Icon name={validation?.valid ? "check" : "settings"} size={30} /><h3>{validation ? validation.valid ? "Параметры корректны" : "Найдены ошибки" : "Ресурс готов к серверной проверке"}</h3>{validation ? <>{Array.isArray(validation.errors) ? (validation.errors as unknown[]).map((item, index) => <p className="kuma-validation-error" key={`e-${index}`}>{text(item)}</p>) : null}{Array.isArray(validation.warnings) ? (validation.warnings as unknown[]).map((item, index) => <p className="kuma-validation-warning" key={`w-${index}`}>{text(item)}</p>) : null}</> : <p>Сохраните черновик и запустите проверку. Публикация доступна только после успешной валидации.</p>}</div>;
  }

  return <div aria-modal="true" className="kuma-full-editor" role="dialog"><header><div><span>Ресурсы и сервисы / {resourceLabel(kind)}</span><h2>{id ? "Редактирование" : "Создание"}: {name || resourceLabel(kind)}</h2></div><IconButton icon="close" label="Закрыть редактор" onClick={onClose} /></header><div className="kuma-editor-body"><aside><strong>{resourceLabel(kind)}</strong>{steps.map(([idValue, label], index) => <button className={step === idValue ? "active" : ""} key={idValue} onClick={() => setStep(idValue)} type="button"><span>{index + 1}</span>{label}</button>)}<button className={advanced ? "active" : ""} onClick={() => setAdvanced((value) => !value)} type="button"><span><Icon name="settings" size={13} /></span>Расширенный JSON</button></aside><main><div className="kuma-editor-section-head"><div><h3>{advanced ? "Расширенная конфигурация" : steps.find(([idValue]) => idValue === step)?.[1]}</h3><p>Изменения сохраняются как управляемый production-ресурс Sentinel.</p></div><StatusCell value={id ? "draft" : "new"} /></div>{advanced ? <div className="kuma-editor-form"><Field label="Config JSON" wide><textarea className="sentinel-code-input" onBlur={(event) => { try { setConfig(JSON.parse(event.target.value)); } catch { notify("Config содержит невалидный JSON", "critical"); } }} defaultValue={JSON.stringify(config, null, 2)} rows={18} /></Field><Field label="Bindings JSON" wide><textarea className="sentinel-code-input" onBlur={(event) => { try { setBindings(JSON.parse(event.target.value)); } catch { notify("Bindings содержит невалидный JSON", "critical"); } }} defaultValue={JSON.stringify(bindings, null, 2)} rows={10} /></Field></div> : stepContent()}</main></div><footer><div><Button onClick={onClose}>Отмена</Button></div><div><Button disabled={Boolean(busy)} onClick={() => void operation("save")}>{busy === "save" ? "Сохранение..." : "Сохранить черновик"}</Button><Button disabled={Boolean(busy)} onClick={() => void operation("validate")}>Проверить</Button><Button disabled={Boolean(busy)} icon="play" onClick={() => void operation("publish")} tone="primary">Опубликовать</Button></div></footer></div>;
}

export function ResourcesWorkspace({ notify }: { notify: Notify }) {
  const [display, setDisplay] = useState<"tiles" | "list">("tiles");
  const [kind, setKind] = useState("");
  const [query, setQuery] = useState("");
  const [scope, setScope] = useState<"all" | "mine">("all");
  const [selected, setSelected] = useState<Row | null>(null);
  const [editing, setEditing] = useState<Row | null>(null);
  const state = useQuery("kuma-resources", () => api.resourceCatalog({ include_runtime: true }), 60_000);
  const allRows = rows(state.data?.items);
  const filtered = allRows.filter((row) => (!kind || row.kind === kind) && (scope === "all" || row.origin === "sentinel-managed") && JSON.stringify(row).toLowerCase().includes(query.toLowerCase()));
  const selectedDefinition = RESOURCE_DEFINITIONS.find((item) => item.kind === kind);
  const openKind = (nextKind: string) => { setKind(nextKind); setDisplay("list"); setSelected(null); };

  return <div className="native-page kuma-resources-page">
    <PageHeader eyebrow={kind ? "Ресурсы и сервисы" : undefined} title={selectedDefinition?.label ?? "Ресурсы и сервисы"} actions={<><div className="kuma-view-toggle"><button className={display === "tiles" ? "active" : ""} onClick={() => { setDisplay("tiles"); setKind(""); }} type="button">Плитка</button><button className={display === "list" ? "active" : ""} onClick={() => setDisplay("list")} type="button">Список</button></div><IconButton icon="refresh" label="Обновить" onClick={state.reload} /></>} />
    <Boundary state={state}>{() => display === "tiles" ? <div className="kuma-resource-home"><section><h2>Конфигурация сервисов</h2><div className="kuma-resource-tiles">{RESOURCE_DEFINITIONS.slice(0, 2).map((definition) => <button key={definition.kind} onClick={() => openKind(definition.kind)} type="button"><Icon name={definition.icon} size={22} /><span><strong>{definition.label}</strong><small>{definition.description}</small></span><b>{allRows.filter((row) => row.kind === definition.kind).length}</b></button>)}</div></section><section><h2>Конфигурация ресурсов</h2><div className="kuma-resource-tiles">{RESOURCE_DEFINITIONS.slice(2).map((definition) => <button key={definition.kind} onClick={() => openKind(definition.kind)} type="button"><Icon name={definition.icon} size={22} /><span><strong>{definition.label}</strong><small>{definition.description}</small></span><b>{allRows.filter((row) => row.kind === definition.kind).length}</b></button>)}</div></section></div> : <div className="kuma-resource-catalog"><aside><SearchField onChange={setQuery} placeholder="Поиск..." value={query} /><div className="kuma-scope-toggle"><button className={scope === "all" ? "active" : ""} onClick={() => setScope("all")} type="button">Все</button><button className={scope === "mine" ? "active" : ""} onClick={() => setScope("mine")} type="button">Мои</button></div><nav><button className={!kind ? "active" : ""} onClick={() => setKind("")} type="button"><Icon name="resources" />Все ресурсы <b>{allRows.length}</b></button>{RESOURCE_DEFINITIONS.map((definition) => <button className={kind === definition.kind ? "active" : ""} key={definition.kind} onClick={() => setKind(definition.kind)} type="button"><Icon name={definition.icon} />{definition.label}<b>{allRows.filter((row) => row.kind === definition.kind).length}</b></button>)}</nav></aside><section><div className="kuma-catalog-toolbar"><Button icon="plus" onClick={() => setEditing({ kind: kind || "collector", tenant_id: "main", config: kind === "collector" || !kind ? { transport: "http", collector_profile: "" } : {}, bindings: {} })} tone="primary">Добавить</Button><SearchField onChange={setQuery} placeholder="Поиск по названию..." value={query} /><span>Всего {filtered.length}</span></div><Grid columns={[{ key: "name", title: "Название", render: (row) => <strong>{text(row.name)}</strong> }, { key: "kind", title: "Тип", render: (row) => resourceLabel(text(row.kind)) }, { key: "status", title: "Статус", render: (row) => <StatusCell value={text(row.status)} /> }, { key: "origin", title: "Источник" }, { key: "tenant_id", title: "Tenant" }, { key: "updated_ts", title: "Последнее обновление", render: (row) => formatTime(row.updated_ts) }, { key: "description", title: "Описание" }]} data={filtered} onOpen={setSelected} /></section></div>}</Boundary>
    <DetailDrawer actions={selected ? <><Button icon="settings" onClick={() => setEditing(selected)}>{selected.read_only ? "Создать управляемую копию" : "Редактировать"}</Button>{!selected.read_only ? <Button onClick={async () => { try { const result = await api.validateResource(text(selected.id)); notify(result.valid ? "Ресурс прошел проверку" : result.errors.join("; "), result.valid ? "healthy" : "critical"); } catch (error) { notify(error instanceof Error ? error.message : String(error), "critical"); } }}>Проверить</Button> : null}</> : null} onClose={() => setSelected(null)} open={Boolean(selected)} title={selected ? text(selected.name) : "Ресурс"}>{selected ? <RecordDetails kind="resource" value={selected} /> : null}</DetailDrawer>
    {editing ? <ResourceEditor key={`${text(editing.id, "new")}-${text(editing.kind)}`} notify={notify} onClose={() => setEditing(null)} onSaved={() => { state.reload(); setSelected(null); }} resource={editing} /> : null}
  </div>;
}

export type RuleEditorState = {
  title: string; description: string; kind: string; sourceProfile: string; sourceQuery: string;
  expression: string; threshold: number; windowS: number; entityField: string; severity: string;
  suppressionKey: string; target: string;
};

export function buildRuleBlocks(value: RuleEditorState): Row[] {
  return [
    { id: "source-1", type: "source", stage: "ingest", label: value.sourceProfile || "Production events", config: { profile: value.sourceProfile || "all", query: value.sourceQuery } },
    { id: "rule-1", type: "detection", stage: "detect", label: value.title || "Detection", config: { expr: value.expression, threshold: value.threshold, window_s: value.windowS, entity_field: value.entityField } },
    { id: "incident-1", type: "incident", stage: "incident", label: "Create incident", config: { severity: value.severity, suppression_key: value.suppressionKey } },
    { id: "publish-1", type: "publish", stage: "publish", label: "Publish runtime", config: { target: value.target } },
  ];
}

function ruleState(row: Row): RuleEditorState {
  const blocks = rows(row.blocks);
  const source = blocks.find((block) => block.type === "source") ?? {};
  const detection = blocks.find((block) => block.type === "detection") ?? {};
  const incident = blocks.find((block) => block.type === "incident") ?? {};
  const publish = blocks.find((block) => block.type === "publish") ?? {};
  const sourceConfig = objectValue(source.config); const detectionConfig = objectValue(detection.config); const incidentConfig = objectValue(incident.config); const publishConfig = objectValue(publish.config);
  return {
    title: text(row.title, ""), description: text(row.description, ""), kind: text(row.kind, "detection"),
    sourceProfile: text(sourceConfig.profile, "all"), sourceQuery: text(sourceConfig.query, ""), expression: text(detectionConfig.expr, ""),
    threshold: number(detectionConfig.threshold || 1), windowS: number(detectionConfig.window_s || 300), entityField: text(detectionConfig.entity_field, "host.name"),
    severity: text(incidentConfig.severity, "medium"), suppressionKey: text(incidentConfig.suppression_key, "host.name"), target: text(publishConfig.target, "stream-correlation"),
  };
}

function RuleEditor({ draft, notify, onClose, onSaved }: { draft: Row; notify: Notify; onClose: () => void; onSaved: () => void }) {
  const [id, setId] = useState(text(draft.id, ""));
  const [value, setValue] = useState<RuleEditorState>(() => ruleState(draft));
  const [tab, setTab] = useState("general");
  const [advanced, setAdvanced] = useState(false);
  const [result, setResult] = useState<Row | null>(null);
  const [busy, setBusy] = useState("");
  const change = <K extends keyof RuleEditorState>(key: K, next: RuleEditorState[K]) => setValue((current) => ({ ...current, [key]: next }));
  const payload = () => ({ id, title: value.title.trim(), description: value.description, kind: value.kind || "detection", blocks: buildRuleBlocks(value) });

  async function save() {
    if (!value.title.trim()) throw new Error("Укажите название правила");
    const saved = await api.saveBuilderDraft(payload()); setId(saved.id); return saved;
  }
  async function action(operation: "save" | "validate" | "test" | "publish") {
    setBusy(operation); setResult(null);
    try {
      const saved = await save();
      if (operation === "save") { notify("Черновик правила сохранен", "healthy"); onSaved(); return; }
      const response = operation === "validate" ? await api.validateBuilder(saved) : operation === "test" ? await api.testBuilder(saved) : await api.publishBuilder(saved.id);
      setResult(response as unknown as Row); setTab("test");
      notify(`${operation}: ${text((response as unknown as Row).status ?? (response as unknown as Row).valid, "готово")}`, "healthy"); onSaved();
      if (operation === "publish") onClose();
    } catch (error) { notify(error instanceof Error ? error.message : String(error), "critical"); }
    finally { setBusy(""); }
  }

  return <div aria-modal="true" className="kuma-full-editor" role="dialog"><header><div><span>Ресурсы и сервисы / Правила корреляции</span><h2>{id ? "Редактирование правила" : "Создание правила корреляции"}</h2></div><IconButton icon="close" label="Закрыть редактор" onClick={onClose} /></header><div className="kuma-rule-tabs"><button className={tab === "general" ? "active" : ""} onClick={() => setTab("general")} type="button">Общие</button><button className={tab === "selectors" ? "active" : ""} onClick={() => setTab("selectors")} type="button">Селекторы</button><button className={tab === "actions" ? "active" : ""} onClick={() => setTab("actions")} type="button">Действия</button><button className={tab === "test" ? "active" : ""} onClick={() => setTab("test")} type="button">Проверка и публикация</button><button className={advanced ? "active" : ""} onClick={() => setAdvanced((current) => !current)} type="button">JSON</button></div><div className="kuma-rule-editor-body"><main>{advanced ? <div className="kuma-editor-form"><Field label="Pipeline blocks JSON" wide><textarea className="sentinel-code-input" readOnly rows={24} value={JSON.stringify(buildRuleBlocks(value), null, 2)} /></Field></div> : tab === "general" ? <div className="kuma-editor-form"><Field label="Название" wide><input onChange={(event) => change("title", event.target.value)} value={value.title} /></Field><Field label="Tenant"><input disabled value="main" /></Field><Field label="Тип"><select onChange={(event) => change("kind", event.target.value)} value={value.kind}><option value="detection">Detection</option><option value="normalizer">Normalizer pipeline</option><option value="threat-intel">Threat intelligence</option></select></Field><Field label="Описание" wide><textarea onChange={(event) => change("description", event.target.value)} rows={5} value={value.description} /></Field></div> : tab === "selectors" ? <div className="kuma-editor-form"><Field label="Профиль источника"><input onChange={(event) => change("sourceProfile", event.target.value)} value={value.sourceProfile} /></Field><Field label="Предварительный фильтр"><input onChange={(event) => change("sourceQuery", event.target.value)} placeholder="source_type = 'linux'" value={value.sourceQuery} /></Field><Field label="Условие корреляции" wide><textarea className="sentinel-code-input" onChange={(event) => change("expression", event.target.value)} placeholder="category = 'authentication' AND event_outcome = 'failure'" rows={10} value={value.expression} /></Field><Field label="Порог"><input min="1" onChange={(event) => change("threshold", Number(event.target.value))} type="number" value={value.threshold} /></Field><Field label="Окно, секунд"><input min="60" onChange={(event) => change("windowS", Number(event.target.value))} type="number" value={value.windowS} /></Field><Field label="Поле сущности"><input onChange={(event) => change("entityField", event.target.value)} value={value.entityField} /></Field></div> : tab === "actions" ? <div className="kuma-editor-form"><Field label="Важность"><select onChange={(event) => change("severity", event.target.value)} value={value.severity}><option value="low">Low</option><option value="medium">Medium</option><option value="high">High</option><option value="critical">Critical</option></select></Field><Field label="Ключ дедупликации"><input onChange={(event) => change("suppressionKey", event.target.value)} value={value.suppressionKey} /></Field><Field label="Runtime target"><select onChange={(event) => change("target", event.target.value)} value={value.target}><option value="stream-correlation">Stream correlation</option><option value="batch-correlation">Batch correlation</option></select></Field></div> : <div className="kuma-validation-screen"><Icon name={result ? "check" : "settings"} size={30} /><h3>{result ? "Операция завершена" : "Проверка на production contract"}</h3><p>Validate проверяет структуру pipeline. Test выполняет shadow-проверку без публикации. Publish переводит проверенный черновик в runtime.</p>{result ? <RecordDetails kind="rule" value={result} /> : null}<div className="kuma-validation-actions"><Button disabled={Boolean(busy)} onClick={() => void action("validate")}>Validate</Button><Button disabled={Boolean(busy)} icon="play" onClick={() => void action("test")}>Shadow test</Button></div></div>}</main></div><footer><Button onClick={onClose}>Отмена</Button><div><Button disabled={Boolean(busy)} onClick={() => void action("save")}>Сохранить черновик</Button><Button disabled={Boolean(busy)} icon="play" onClick={() => void action("publish")} tone="primary">Опубликовать</Button></div></footer></div>;
}

export function RulesWorkspace({ notify }: { notify: Notify }) {
  const [tab, setTab] = useState("drafts");
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState<Row | null>(null);
  const [editing, setEditing] = useState<Row | null>(null);
  const state = useQuery("kuma-rules", async () => { const [drafts, packs] = await Promise.all([api.builderDrafts(), api.correlationPacks()]); return { drafts, packs }; }, 60_000);
  const draftRows = rows(state.data?.drafts.items).filter((row) => JSON.stringify(row).toLowerCase().includes(query.toLowerCase()));
  const packRows = rows(state.data?.packs.items).filter((row) => JSON.stringify(row).toLowerCase().includes(query.toLowerCase()));

  async function packAction(operation: "validate" | "test" | "publish", row: Row) {
    const id = text(row.pack_id);
    try { const result = operation === "validate" ? await api.validateCorrelationPack(id, row) : operation === "test" ? await api.testCorrelationPack(id, { include_runtime: true }) : await api.publishCorrelationPack(id); notify(`${operation}: ${text((result as unknown as Row).status ?? (result as unknown as Row).valid, "готово")}`, "healthy"); state.reload(); }
    catch (error) { notify(error instanceof Error ? error.message : String(error), "critical"); }
  }

  return <div className="native-page kuma-rules-page"><PageHeader title="Правила корреляции" actions={<IconButton icon="refresh" label="Обновить" onClick={state.reload} />} /><Boundary state={state}>{() => <div className="kuma-rule-catalog"><aside><SearchField onChange={setQuery} placeholder="Поиск..." value={query} /><nav><button className={tab === "drafts" ? "active" : ""} onClick={() => { setTab("drafts"); setSelected(null); }} type="button"><Icon name="rules" />Черновики <b>{draftRows.length}</b></button><button className={tab === "packs" ? "active" : ""} onClick={() => { setTab("packs"); setSelected(null); }} type="button"><Icon name="resources" />Пакеты правил <b>{packRows.length}</b></button></nav></aside><section><div className="kuma-catalog-toolbar"><Button icon="plus" onClick={() => setEditing({ kind: "detection", blocks: [] })} tone="primary">Добавить</Button><SearchField onChange={setQuery} placeholder="Поиск по названию..." value={query} /><span>Всего {tab === "drafts" ? draftRows.length : packRows.length}</span></div>{tab === "drafts" ? <Grid columns={[{ key: "title", title: "Название", render: (row) => <strong>{text(row.title)}</strong> }, { key: "kind", title: "Тип" }, { key: "status", title: "Статус", render: (row) => <StatusCell value={text(row.status)} /> }, { key: "version", title: "Версия" }, { key: "updated_ts", title: "Последнее обновление", render: (row) => formatTime(row.updated_ts) }, { key: "published_ts", title: "Опубликован", render: (row) => formatTime(row.published_ts) }]} data={draftRows} onOpen={setSelected} /> : <Grid columns={[{ key: "title", title: "Название", render: (row) => <strong>{text(row.title)}</strong> }, { key: "status", title: "Статус", render: (row) => <StatusCell value={text(row.status)} /> }, { key: "version", title: "Версия" }, { key: "rule_count", title: "Правил" }, { key: "active_stream_rules", title: "Активных stream" }, { key: "owner", title: "Владелец" }, { key: "updated_ts", title: "Изменен", render: (row) => formatTime(row.updated_ts) }]} data={packRows} onOpen={setSelected} />}</section></div>}</Boundary><DetailDrawer actions={selected ? tab === "drafts" ? <Button icon="settings" onClick={() => setEditing(selected)}>Редактировать</Button> : <><Button onClick={() => void packAction("validate", selected)}>Validate</Button><Button icon="play" onClick={() => void packAction("test", selected)}>Shadow test</Button><Button onClick={() => void packAction("publish", selected)} tone="primary">Publish</Button></> : null} onClose={() => setSelected(null)} open={Boolean(selected)} title={selected ? text(selected.title) : "Правило"}>{selected ? <RecordDetails kind="rule" value={selected} /> : null}</DetailDrawer>{editing ? <RuleEditor draft={editing} key={text(editing.id, "new")} notify={notify} onClose={() => setEditing(null)} onSaved={() => { state.reload(); setSelected(null); }} /> : null}</div>;
}
