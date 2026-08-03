import { useMemo, useState, type ReactNode } from "react";
import { api } from "./runtime/api";
import type { View } from "./model";
import type { GeneratedReportRecord, IncidentDetailResponse, ReportTemplateRecord } from "./runtime/types";
import { Badge, Button, DetailDrawer, EmptyState, ErrorState, IconButton, KeyValue, LoadingState, Modal, PageHeader, SearchField, StatusCell, Tabs } from "./ui";
import { formatTime, number, severityTone, text, useQuery } from "./runtime/query";
import { OverviewDashboard } from "./dashboard";
import { EventDetailContent, IncidentDetailContent } from "./incident-details";
import { EventsQueryWorkspace, IncidentQueueWorkspace, ResourcesWorkspace, RulesWorkspace } from "./kuma-workspaces";
import { RecordDetails, RuntimeOverviewCards } from "./record-details";
import { TaskDispatcherView } from "./task-dispatcher";
import { TopologyWorkbench } from "./topology-workbench";
import { DiscoveryWorkspace } from "./discovery-workspace";
import { SecurityOperationsWorkspace } from "./security-workspaces";
import { ServiceLifecyclePanel } from "./service-lifecycle";
import { AccessUsersWorkspace } from "./access-users-workspace";

type Notify = (message: string, tone?: string) => void;
type Navigate = (view: View) => void;
type Row = Record<string, unknown>;

function asRows(value: unknown): Row[] {
  return Array.isArray(value) ? value.filter((item): item is Row => Boolean(item) && typeof item === "object") : [];
}

function serviceConsoleHref(row: Row | null) {
  if (!row) return "";
  const workspace = asRows(row.workspaces).find((item) => item.external && /^https?:\/\//i.test(text(item.href, "")));
  return workspace ? text(workspace.href, "") : "";
}

function Field({ label, children, wide = false }: { label: string; children: ReactNode; wide?: boolean }) {
  return <label className={wide ? "wide" : ""}><span>{label}</span>{children}</label>;
}

function Metric({ label, value, detail, tone = "" }: { label: string; value: ReactNode; detail?: string; tone?: string }) {
  return <div className={`metric ${tone ? `metric-${tone}` : ""}`}><span>{label}</span><strong>{value}</strong>{detail ? <small>{detail}</small> : null}</div>;
}

function DataTable({ columns, rows, onOpen, empty = "Данные за выбранный период отсутствуют" }: { columns: Array<{ key: string; title: string; render?: (row: Row) => ReactNode }>; rows: Row[]; onOpen?: (row: Row) => void; empty?: string }) {
  if (!rows.length) return <EmptyState detail={empty} />;
  return <div className="native-grid"><table><thead><tr>{columns.map((column) => <th key={column.key}>{column.title}</th>)}</tr></thead><tbody>{rows.map((row, index) => <tr className={onOpen ? "sentinel-clickable-row" : ""} key={text(row.id ?? row.alert_id ?? row.agg_id ?? row.name ?? row.title, String(index))} onClick={onOpen ? () => onOpen(row) : undefined} onKeyDown={onOpen ? (event) => { if (event.key === "Enter" || event.key === " ") onOpen(row); } : undefined} tabIndex={onOpen ? 0 : undefined}>{columns.map((column) => <td key={column.key}>{column.render ? column.render(row) : text(row[column.key])}</td>)}</tr>)}</tbody></table></div>;
}

function QueryBoundary<T>({ state, children }: { state: { data?: T; error?: Error; loading: boolean; reload: () => void }; children: (data: T) => ReactNode }) {
  if (state.loading && !state.data) return <LoadingState />;
  if (state.error) return <ErrorState error={state.error} retry={state.reload} />;
  if (!state.data) return <EmptyState />;
  return <>{children(state.data)}</>;
}

export function OverviewView({ navigate }: { navigate: Navigate }) {
  return <OverviewDashboard navigate={navigate} />;
}

const incidentColumns = [
  { key: "severity", title: "Важность", render: (row: Row) => <Badge tone={severityTone(row.severity_agg ?? row.severity)}>{text(row.severity_agg ?? row.severity)}</Badge> },
  { key: "rule_name", title: "Правило", render: (row: Row) => <strong>{text(row.rule_name, "Без названия")}</strong> },
  { key: "status", title: "Статус", render: (row: Row) => <StatusCell value={text(row.status)} /> },
  { key: "entity_key", title: "Сущность" },
  { key: "source_summary", title: "Источник", render: (row: Row) => text(row.source_summary ?? row.source) },
  { key: "hits", title: "События", render: (row: Row) => number(row.raw_hits_total ?? row.hits).toLocaleString("ru-RU") },
  { key: "assignee", title: "Исполнитель" },
  { key: "ts_last", title: "Обновлен", render: (row: Row) => formatTime(row.ts_last ?? row.ts) },
];

function incidentId(row: Row) {
  return text(row.agg_id ?? row.alert_id ?? row.id, "");
}

export function IncidentsView({ mode, notify }: { mode: "agg" | "raw"; notify: Notify }) {
  const [query, setQuery] = useState("");
  const [statusFilter, setStatusFilter] = useState(mode === "agg" ? "active" : "all");
  const [selected, setSelected] = useState<Row | null>(null);
  const [detail, setDetail] = useState<IncidentDetailResponse | null>(null);
  const [detailError, setDetailError] = useState("");
  const includeTerminal = mode === "agg" && statusFilter !== "active";
  const state = useQuery(`incidents:${mode}:${statusFilter}:${query}`, () => api.incidents({ view: mode, q: query, window: "30d", limit: 500, include_terminal: includeTerminal }), 30_000);
  async function open(row: Row) {
    setSelected(row); setDetail(null); setDetailError("");
    try { setDetail(await api.incidentDetail(mode, incidentId(row), { window: "30d", event_limit: 100, alert_limit: 100, include_evidence: true })); }
    catch (error) { setDetailError(error instanceof Error ? error.message : String(error)); }
  }
  async function update(body: Row) {
    if (!selected) return;
    try { await api.updateIncident(mode, incidentId(selected), body); notify("Инцидент обновлен", "healthy"); setSelected(null); state.reload(); }
    catch (error) { notify(error instanceof Error ? error.message : String(error), "critical"); }
  }
  const allRows = (state.data?.items ?? []) as Row[];
  const activeStatuses = new Set(["new", "open", "assigned", "triaged", "reopened", "in_progress", "escalated"]);
  const visibleRows = allRows.filter((row) => {
    const status = text(row.status, "open").toLowerCase();
    if (statusFilter === "active") return activeStatuses.has(status);
    if (statusFilter === "resolved") return status === "closed" || status === "resolved";
    if (statusFilter === "false_positive") return status === "false_positive" || status === "suppressed";
    return true;
  });
  const critical = visibleRows.filter((row) => /critical|крит/i.test(text(row.severity_agg ?? row.severity))).length;
  const selectedStatus = selected ? text(selected.status, "open").toLowerCase() : "";
  const selectedIsActive = activeStatuses.has(selectedStatus);
  const selectedIsTerminal = new Set(["closed", "resolved", "false_positive", "suppressed"]).has(selectedStatus);
  return <div className="native-page"><PageHeader title={mode === "agg" ? "Инциденты" : "Алерты"} actions={<IconButton icon="refresh" label="Обновить" onClick={state.reload} />} />
    <section className="metric-grid sentinel-queue-metrics"><Metric label={mode === "agg" ? "В очереди" : "Срабатывания"} value={visibleRows.length} /><Metric label="Критические" tone={critical ? "warning" : ""} value={critical} /><Metric label="Открытые" value={visibleRows.filter((row) => activeStatuses.has(text(row.status, "open").toLowerCase())).length} /><Metric label="События" value={visibleRows.reduce((sum, row) => sum + number(row.raw_hits_total ?? row.hits), 0).toLocaleString("ru-RU")} /></section>
    <Tabs items={[{ id: "active", label: "Открытые" }, { id: "all", label: "Все" }, { id: "resolved", label: "Закрытые" }, { id: "false_positive", label: "False positive" }]} label="Фильтр очереди" onChange={setStatusFilter} value={statusFilter} />
    <div className="kuma-list-search"><SearchField onChange={setQuery} placeholder="Правило, сущность, источник или исполнитель..." value={query} /></div>
    <QueryBoundary state={state}>{(data) => <><div className="native-actionbar"><div><span>{mode === "agg" ? "Агрегированная очередь" : "Исходные срабатывания"}</span></div><div><span>Показано: {visibleRows.length} · доступно: {data.available_count ?? data.items.length}</span></div></div><DataTable columns={incidentColumns} onOpen={open} rows={visibleRows} /></>}</QueryBoundary>
    <DetailDrawer actions={selectedIsActive ? <><Button icon="user" onClick={() => update({ assignee: "current_user" })}>Назначить мне</Button><Button icon="check" onClick={() => update({ status: "closed", note: "Closed from Sentinel UI" })} tone="primary">Закрыть</Button><Button onClick={() => update({ status: "false_positive", note: "Marked as false positive from Sentinel UI" })} tone="danger">False positive</Button></> : selectedIsTerminal ? <Button icon="refresh" onClick={() => update({ status: "reopened", note: "Reopened from Sentinel UI" })} tone="primary">Вернуть в работу</Button> : null} eyebrow={selected ? text(selected.severity_agg ?? selected.severity) : undefined} onClose={() => setSelected(null)} open={Boolean(selected)} title={selected ? text(selected.rule_name, incidentId(selected)) : "Детали инцидента"}>
      {selected ? detailError ? <ErrorState error={new Error(detailError)} retry={() => open(selected)} /> : detail ? <IncidentDetailContent detail={detail} /> : <LoadingState label="Загрузка evidence..." /> : null}
    </DetailDrawer>
  </div>;
}

export function EventsView({ notify }: { notify: Notify }) {
  const [query, setQuery] = useState("");
  const [windowSize, setWindowSize] = useState("24h");
  const [selected, setSelected] = useState<Row | null>(null);
  const [submitted, setSubmitted] = useState(0);
  const state = useQuery(`events:${submitted}:${windowSize}`, () => api.eventsQuery({ query, window: windowSize, storage: "auto", limit: 200, offset: 0 }));
  const columns = [
    { key: "ts", title: "Время", render: (row: Row) => formatTime(row.ts) },
    { key: "severity", title: "Важность", render: (row: Row) => <Badge tone={severityTone(row.severity)}>{text(row.severity)}</Badge> },
    { key: "log_source", title: "Источник" }, { key: "category", title: "Категория" },
    { key: "src_ip", title: "Источник IP" }, { key: "dst_ip", title: "Назначение IP" },
    { key: "user_name", title: "Пользователь", render: (row: Row) => text(row.user_name ?? row.target_user) },
    { key: "message", title: "Сообщение", render: (row: Row) => <span className="sentinel-truncate">{text(row.message)}</span> },
  ];
  return <div className="native-page"><PageHeader title="Поиск событий" actions={<IconButton icon="refresh" label="Повторить запрос" onClick={state.reload} />} />
    <div className="kuma-query-console"><div className="kuma-query-toolbar"><SearchField onChange={setQuery} placeholder="Полнотекстовый запрос или выражение..." value={query} /><select aria-label="Временной диапазон" onChange={(event) => setWindowSize(event.target.value)} value={windowSize}><option value="1h">1 час</option><option value="24h">24 часа</option><option value="7d">7 дней</option><option value="30d">30 дней</option></select><Button icon="play" onClick={() => setSubmitted((value) => value + 1)} tone="primary">Выполнить</Button></div></div>
    <QueryBoundary state={state}>{(data) => <><div className="native-actionbar"><div><span>Production storage</span></div><div><span>{number(data.total_count ?? data.row_count).toLocaleString("ru-RU")} событий · {number(data.elapsed_ms)} мс</span></div></div><DataTable columns={columns} onOpen={setSelected} rows={data.rows as Row[]} /></>}</QueryBoundary>
    <DetailDrawer actions={selected ? <Button onClick={() => { navigator.clipboard.writeText(JSON.stringify(selected, null, 2)); notify("Данные события скопированы", "healthy"); }}>Копировать данные</Button> : null} onClose={() => setSelected(null)} open={Boolean(selected)} title={selected ? `${text(selected.log_source)} · ${formatTime(selected.ts)}` : "Событие"}>{selected ? <EventDetailContent event={selected} /> : null}</DetailDrawer>
  </div>;
}

const sourceColumns = [
  { key: "status", title: "Статус", render: (row: Row) => <StatusCell value={text(row.status)} /> },
  { key: "source_name", title: "Источник", render: (row: Row) => <strong>{text(row.source_name)}</strong> },
  { key: "source_type", title: "Тип" }, { key: "source_ips", title: "IP", render: (row: Row) => text(row.source_ips ?? row.observed_ips ?? row.cmdb_ip) },
  { key: "collector_name", title: "Коллектор" }, { key: "events", title: "События", render: (row: Row) => number(row.events).toLocaleString("ru-RU") },
  { key: "products", title: "Продукты", render: (row: Row) => text(row.products) }, { key: "last_seen", title: "Последнее событие", render: (row: Row) => formatTime(row.last_seen) },
];

export function SourcesView({ notify }: { notify: Notify }) {
  const [tab, setTab] = useState("sources");
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState<Row | null>(null);
  const [editingPolicy, setEditingPolicy] = useState<Row | null>(null);
  const state = useQuery("sources", async () => {
    const [sources, collectors, policies] = await Promise.all([api.sourcesInventory({ hours: 24, limit: 500 }), api.collectorsInventory({ hours: 24 }), api.sourcePolicies()]);
    return { sources, collectors, policies };
  }, 30_000);
  async function savePolicy(form: HTMLFormElement) {
    const values = new FormData(form);
    const body = {
      id: text(values.get("id"), `source-policy-${Date.now()}`), type: "source_monitoring_policy",
      name: text(values.get("name"), "Новая политика"), description: text(values.get("description"), ""),
      enabled: values.get("enabled") === "on", source_pattern: text(values.get("source_pattern"), "*"),
      window_hours: number(values.get("window_hours") || 24), min_events: number(values.get("min_events")),
      max_events: number(values.get("max_events") || 1000000), stale_after_minutes: number(values.get("stale_after_minutes") || 30),
      severity: text(values.get("severity"), "medium"), notifications: ["telegram"], owner: text(values.get("owner"), "SOC"),
    };
    try { await api.saveSourcePolicy(body); notify("Политика мониторинга сохранена", "healthy"); setEditingPolicy(null); state.reload(); }
    catch (error) { notify(error instanceof Error ? error.message : String(error), "critical"); }
  }
  return <div className="native-page"><PageHeader title="Источники и коллекторы" actions={<IconButton icon="refresh" label="Обновить" onClick={state.reload} />} />
    <QueryBoundary state={state}>{({ sources, collectors, policies }) => {
      const sourceRows = (sources.items as Row[]).filter((row) => JSON.stringify(row).toLowerCase().includes(query.toLowerCase()));
      const collectorRows = collectors.items as Row[];
      const policyRows = policies.items as Row[];
      return <>
        <Tabs items={[{ id: "sources", label: "Источники", count: sourceRows.length }, { id: "collectors", label: "Коллекторы", count: collectorRows.length }, { id: "policies", label: "Политики мониторинга", count: policyRows.length }]} label="Разделы источников" onChange={setTab} value={tab} />
        <div className="kuma-list-search"><SearchField onChange={setQuery} placeholder="Источник, IP, продукт или коллектор..." value={query} />{tab === "policies" ? <Button icon="plus" onClick={() => setEditingPolicy({})} tone="primary">Добавить политику</Button> : null}</div>
        {tab === "sources" ? <DataTable columns={sourceColumns} onOpen={setSelected} rows={sourceRows} /> : null}
        {tab === "collectors" ? <DataTable columns={[
          { key: "status", title: "Статус", render: (row) => <StatusCell value={text(row.status)} /> }, { key: "name", title: "Коллектор", render: (row) => <strong>{text(row.name)}</strong> },
          { key: "node", title: "Узел" }, { key: "protocols", title: "Протоколы", render: (row) => text(row.protocols) }, { key: "sources_count", title: "Источники" },
          { key: "events", title: "События", render: (row) => number(row.events).toLocaleString("ru-RU") }, { key: "last_seen", title: "Последняя активность", render: (row) => formatTime(row.last_seen) },
        ]} onOpen={setSelected} rows={collectorRows} /> : null}
        {tab === "policies" ? <DataTable columns={[
          { key: "enabled", title: "Состояние", render: (row) => <StatusCell value={row.enabled ? "Активна" : "Выключена"} /> }, { key: "name", title: "Политика", render: (row) => <strong>{text(row.name)}</strong> },
          { key: "source_pattern", title: "Выбор источников" }, { key: "window_hours", title: "Окно, ч" }, { key: "min_events", title: "Мин. событий" }, { key: "max_events", title: "Макс. событий" },
          { key: "violation_count", title: "Нарушения" }, { key: "evaluated_ts", title: "Проверена", render: (row) => formatTime(row.evaluated_ts) },
        ]} onOpen={setEditingPolicy} rows={policyRows} /> : null}
      </>;
    }}</QueryBoundary>
    <DetailDrawer onClose={() => setSelected(null)} open={Boolean(selected)} title={selected ? text(selected.source_name ?? selected.name) : "Источник"}>{selected ? <RecordDetails kind={selected.collector_id ? "collector" : "integration"} value={selected} /> : null}</DetailDrawer>
    <Modal footer={<><Button onClick={() => setEditingPolicy(null)}>Отмена</Button><Button form="source-policy-form" tone="primary" type="submit">Сохранить</Button></>} onClose={() => setEditingPolicy(null)} open={Boolean(editingPolicy)} title={editingPolicy?.id ? "Редактирование политики" : "Новая политика мониторинга"}>
      {editingPolicy ? <form className="kuma-form-grid" id="source-policy-form" onSubmit={(event) => { event.preventDefault(); void savePolicy(event.currentTarget); }}>
        <input name="id" type="hidden" value={text(editingPolicy.id, "")} /><Field label="Название" wide><input defaultValue={text(editingPolicy.name, "")} name="name" required /></Field><Field label="Описание" wide><textarea defaultValue={text(editingPolicy.description, "")} name="description" rows={3} /></Field>
        <Field label="Шаблон источников"><input defaultValue={text(editingPolicy.source_pattern, "*")} name="source_pattern" required /></Field><Field label="Владелец"><input defaultValue={text(editingPolicy.owner, "SOC")} name="owner" /></Field>
        <Field label="Окно, часов"><input defaultValue={number(editingPolicy.window_hours || 24)} min="1" name="window_hours" type="number" /></Field><Field label="Stale, минут"><input defaultValue={number(editingPolicy.stale_after_minutes || 30)} min="1" name="stale_after_minutes" type="number" /></Field>
        <Field label="Минимум событий"><input defaultValue={number(editingPolicy.min_events)} min="0" name="min_events" type="number" /></Field><Field label="Максимум событий"><input defaultValue={number(editingPolicy.max_events || 1000000)} min="1" name="max_events" type="number" /></Field>
        <Field label="Важность"><select defaultValue={text(editingPolicy.severity, "medium")} name="severity"><option value="low">Low</option><option value="medium">Medium</option><option value="high">High</option><option value="critical">Critical</option></select></Field><Field label="Состояние"><label className="sentinel-checkbox"><input defaultChecked={editingPolicy.enabled !== false} name="enabled" type="checkbox" /> Активна</label></Field>
      </form> : null}
    </Modal>
  </div>;
}

export function ResourcesView({ notify }: { notify: Notify }) {
  const [query, setQuery] = useState("");
  const [kind, setKind] = useState("");
  const [selected, setSelected] = useState<Row | null>(null);
  const [editing, setEditing] = useState<Row | null>(null);
  const state = useQuery(`resources:${kind}`, () => api.resourceCatalog({ kind: kind || undefined, include_runtime: true }));
  const rows = useMemo(() => asRows(state.data?.items).filter((row) => JSON.stringify(row).toLowerCase().includes(query.toLowerCase())), [query, state.data]);
  async function save(form: HTMLFormElement) {
    const values = new FormData(form);
    let config: Row = {}; let bindings: Row = {};
    try { config = JSON.parse(text(values.get("config"), "{}")); bindings = JSON.parse(text(values.get("bindings"), "{}")); }
    catch { notify("Config и bindings должны быть валидным JSON", "critical"); return; }
    try {
      await api.saveResource({ id: text(values.get("id"), ""), name: text(values.get("name")), kind: text(values.get("kind")), description: text(values.get("description"), ""), tenant_id: text(values.get("tenant_id"), "main"), config, bindings });
      notify("Ресурс сохранен", "healthy"); setEditing(null); state.reload();
    } catch (error) { notify(error instanceof Error ? error.message : String(error), "critical"); }
  }
  async function action(operation: "validate" | "publish", row: Row) {
    try {
      const result = operation === "validate" ? await api.validateResource(text(row.id)) : await api.publishResource(text(row.id));
      notify(operation === "validate" ? `Проверка завершена: ${text((result as Row).valid)}` : "Ресурс опубликован", "healthy"); state.reload();
    } catch (error) { notify(error instanceof Error ? error.message : String(error), "critical"); }
  }
  return <div className="native-page"><PageHeader title="Ресурсы платформы" actions={<><Button icon="plus" onClick={() => setEditing({ kind: "collector", tenant_id: "main", config: {}, bindings: {} })} tone="primary">Создать ресурс</Button><IconButton icon="refresh" label="Обновить" onClick={state.reload} /></>} />
    <div className="kuma-list-search"><SearchField onChange={setQuery} placeholder="Название, тип или tenant..." value={query} /><select aria-label="Тип ресурса" onChange={(event) => setKind(event.target.value)} value={kind}><option value="">Все типы</option><option value="collector">Коллекторы</option><option value="normalizer">Нормализаторы</option><option value="correlator">Корреляторы</option><option value="destination">Назначения</option><option value="connector">Коннекторы</option></select></div>
    <QueryBoundary state={state}>{() => <DataTable columns={[
      { key: "status", title: "Статус", render: (row) => <StatusCell value={text(row.status)} /> }, { key: "name", title: "Название", render: (row) => <strong>{text(row.name)}</strong> },
      { key: "kind", title: "Тип" }, { key: "version", title: "Версия" }, { key: "tenant_id", title: "Tenant" }, { key: "origin", title: "Происхождение" },
      { key: "updated_ts", title: "Изменен", render: (row) => formatTime(row.updated_ts) },
    ]} onOpen={setSelected} rows={rows} />}</QueryBoundary>
    <DetailDrawer actions={selected ? <><Button icon="settings" onClick={() => setEditing(selected)}>Редактировать</Button><Button onClick={() => action("validate", selected)}>Проверить</Button><Button icon="play" onClick={() => action("publish", selected)} tone="primary">Опубликовать</Button></> : null} onClose={() => setSelected(null)} open={Boolean(selected)} title={selected ? text(selected.name) : "Ресурс"}>{selected ? <RecordDetails kind="resource" value={selected} /> : null}</DetailDrawer>
    <Modal footer={<><Button onClick={() => setEditing(null)}>Отмена</Button><Button form="resource-form" tone="primary" type="submit">Сохранить</Button></>} onClose={() => setEditing(null)} open={Boolean(editing)} title={editing?.id ? "Редактирование ресурса" : "Новый ресурс"}>{editing ? <form className="kuma-form-grid" id="resource-form" onSubmit={(event) => { event.preventDefault(); void save(event.currentTarget); }}><input name="id" type="hidden" value={text(editing.id, "")} /><Field label="Название" wide><input defaultValue={text(editing.name, "")} name="name" required /></Field><Field label="Тип"><input defaultValue={text(editing.kind, "collector")} name="kind" required /></Field><Field label="Tenant"><input defaultValue={text(editing.tenant_id, "main")} name="tenant_id" required /></Field><Field label="Описание" wide><textarea defaultValue={text(editing.description, "")} name="description" rows={3} /></Field><Field label="Config JSON" wide><textarea className="sentinel-code-input" defaultValue={JSON.stringify(editing.config ?? {}, null, 2)} name="config" rows={12} /></Field><Field label="Bindings JSON" wide><textarea className="sentinel-code-input" defaultValue={JSON.stringify(editing.bindings ?? {}, null, 2)} name="bindings" rows={8} /></Field></form> : null}</Modal>
  </div>;
}

export function RulesView({ notify }: { notify: Notify }) {
  const [tab, setTab] = useState("drafts");
  const [selected, setSelected] = useState<Row | null>(null);
  const [editing, setEditing] = useState<Row | null>(null);
  const state = useQuery("rules", async () => {
    const [drafts, packs] = await Promise.all([api.builderDrafts(), api.correlationPacks()]);
    return { drafts, packs };
  });
  async function saveDraft(form: HTMLFormElement) {
    const values = new FormData(form); let blocks: unknown[];
    try { blocks = JSON.parse(text(values.get("blocks"), "[]")); } catch { notify("Blocks должны быть валидным JSON-массивом", "critical"); return; }
    try { await api.saveBuilderDraft({ id: text(values.get("id"), ""), title: text(values.get("title")), description: text(values.get("description"), ""), kind: text(values.get("kind"), "correlation"), blocks }); notify("Черновик сохранен", "healthy"); setEditing(null); state.reload(); }
    catch (error) { notify(error instanceof Error ? error.message : String(error), "critical"); }
  }
  async function draftAction(operation: "validate" | "test" | "publish", row: Row) {
    try {
      const result = operation === "validate" ? await api.validateBuilder(row) : operation === "test" ? await api.testBuilder(row) : await api.publishBuilder(text(row.id));
      notify(`${operation}: ${text((result as Row).status ?? (result as Row).valid, "готово")}`, "healthy"); state.reload();
    } catch (error) { notify(error instanceof Error ? error.message : String(error), "critical"); }
  }
  async function packAction(operation: "validate" | "test" | "publish", row: Row) {
    const id = text(row.pack_id);
    try {
      const result = operation === "validate" ? await api.validateCorrelationPack(id, row) : operation === "test" ? await api.testCorrelationPack(id, { include_runtime: true }) : await api.publishCorrelationPack(id);
      notify(`${operation}: ${text((result as Row).status ?? (result as Row).valid, "готово")}`, "healthy"); state.reload();
    } catch (error) { notify(error instanceof Error ? error.message : String(error), "critical"); }
  }
  return <div className="native-page"><PageHeader title="Контент детектирования" actions={<><Button icon="plus" onClick={() => setEditing({ kind: "correlation", blocks: [] })} tone="primary">Создать черновик</Button><IconButton icon="refresh" label="Обновить" onClick={state.reload} /></>} />
    <QueryBoundary state={state}>{({ drafts, packs }) => <><Tabs items={[{ id: "drafts", label: "Конструктор", count: drafts.items.length }, { id: "packs", label: "Пакеты корреляции", count: packs.items.length }]} label="Контент детектирования" onChange={setTab} value={tab} />
      {tab === "drafts" ? <DataTable columns={[
        { key: "status", title: "Статус", render: (row) => <StatusCell value={text(row.status)} /> }, { key: "title", title: "Название", render: (row) => <strong>{text(row.title)}</strong> }, { key: "kind", title: "Тип" }, { key: "version", title: "Версия" }, { key: "updated_ts", title: "Изменен", render: (row) => formatTime(row.updated_ts) }, { key: "published_ts", title: "Опубликован", render: (row) => formatTime(row.published_ts) },
      ]} onOpen={setSelected} rows={drafts.items as Row[]} /> : <DataTable columns={[
        { key: "status", title: "Статус", render: (row) => <StatusCell value={text(row.status)} /> }, { key: "title", title: "Пакет", render: (row) => <strong>{text(row.title)}</strong> }, { key: "version", title: "Версия" }, { key: "rule_count", title: "Правил" }, { key: "active_stream_rules", title: "Активных stream" }, { key: "owner", title: "Владелец" }, { key: "updated_ts", title: "Изменен", render: (row) => formatTime(row.updated_ts) },
      ]} onOpen={setSelected} rows={packs.items as Row[]} />}</>}</QueryBoundary>
    <DetailDrawer actions={selected ? tab === "drafts" ? <><Button icon="settings" onClick={() => setEditing(selected)}>Редактировать</Button><Button onClick={() => draftAction("validate", selected)}>Validate</Button><Button icon="play" onClick={() => draftAction("test", selected)}>Test</Button><Button onClick={() => draftAction("publish", selected)} tone="primary">Publish</Button></> : <><Button onClick={() => packAction("validate", selected)}>Validate</Button><Button icon="play" onClick={() => packAction("test", selected)}>Shadow test</Button><Button onClick={() => packAction("publish", selected)} tone="primary">Publish</Button></> : null} onClose={() => setSelected(null)} open={Boolean(selected)} title={selected ? text(selected.title) : "Правило"}>{selected ? <RecordDetails kind="rule" value={selected} /> : null}</DetailDrawer>
    <Modal footer={<><Button onClick={() => setEditing(null)}>Отмена</Button><Button form="builder-form" tone="primary" type="submit">Сохранить</Button></>} onClose={() => setEditing(null)} open={Boolean(editing)} title={editing?.id ? "Редактирование черновика" : "Новый черновик"}>{editing ? <form className="kuma-form-grid" id="builder-form" onSubmit={(event) => { event.preventDefault(); void saveDraft(event.currentTarget); }}><input name="id" type="hidden" value={text(editing.id, "")} /><Field label="Название" wide><input defaultValue={text(editing.title, "")} name="title" required /></Field><Field label="Тип"><select defaultValue={text(editing.kind, "correlation")} name="kind"><option value="collector">Коллектор</option><option value="normalizer">Нормализатор</option><option value="correlation">Коррелятор</option><option value="destination">Назначение</option></select></Field><Field label="Описание" wide><textarea defaultValue={text(editing.description, "")} name="description" rows={3} /></Field><Field label="Pipeline blocks JSON" wide><textarea className="sentinel-code-input" defaultValue={JSON.stringify(editing.blocks ?? [], null, 2)} name="blocks" rows={20} /></Field></form> : null}</Modal>
  </div>;
}

export function AssetsView() {
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState<Row | null>(null);
  const state = useQuery("assets", () => api.assetInventory({ hours: 720, limit: 500 }), 60_000);
  const rows = useMemo(() => asRows(state.data?.items).filter((row) => JSON.stringify(row).toLowerCase().includes(query.toLowerCase())), [query, state.data]);
  return <div className="native-page"><PageHeader title="Активы" actions={<IconButton icon="refresh" label="Обновить" onClick={state.reload} />} /><div className="kuma-list-search"><SearchField onChange={setQuery} placeholder="Имя, IP, сервис или владелец..." value={query} /></div><QueryBoundary state={state}>{() => <DataTable columns={[
    { key: "asset", title: "Актив", render: (row) => <strong>{text(row.asset)}</strong> }, { key: "cmdb_asset_id", title: "Asset ID" }, { key: "aliases", title: "IP и алиасы", render: (row) => text(row.aliases) },
    { key: "cmdb_service", title: "Сервис" }, { key: "cmdb_environment", title: "Сегмент" }, { key: "cmdb_owner", title: "Владелец" }, { key: "cmdb_criticality", title: "Критичность" },
    { key: "events", title: "События", render: (row) => number(row.events).toLocaleString("ru-RU") }, { key: "last_seen", title: "Последнее событие", render: (row) => formatTime(row.last_seen) },
  ]} onOpen={setSelected} rows={rows} />}</QueryBoundary><DetailDrawer onClose={() => setSelected(null)} open={Boolean(selected)} title={selected ? text(selected.asset) : "Актив"}>{selected ? <RecordDetails kind="asset" value={selected} /> : null}</DetailDrawer></div>;
}

export function CasesView({ notify }: { notify: Notify }) {
  const [query, setQuery] = useState(""); const [selected, setSelected] = useState<Row | null>(null); const [creating, setCreating] = useState(false);
  const state = useQuery(`cases:${query}`, () => api.cases({ q: query, limit: 300 }));
  async function create(form: HTMLFormElement) { const values = new FormData(form); try { await api.saveCase({ title: text(values.get("title")), summary: text(values.get("summary"), ""), severity: text(values.get("severity"), "medium"), status: "open", assignee: text(values.get("assignee"), "") }); notify("Кейс создан", "healthy"); setCreating(false); state.reload(); } catch (error) { notify(error instanceof Error ? error.message : String(error), "critical"); } }
  return <div className="native-page"><PageHeader title="Кейсы" actions={<><Button icon="plus" onClick={() => setCreating(true)} tone="primary">Создать кейс</Button><IconButton icon="refresh" label="Обновить" onClick={state.reload} /></>} /><div className="kuma-list-search"><SearchField onChange={setQuery} placeholder="Название, исполнитель или статус..." value={query} /></div><QueryBoundary state={state}>{(data) => <DataTable columns={[
    { key: "severity", title: "Важность", render: (row) => <Badge tone={severityTone(row.severity)}>{text(row.severity)}</Badge> }, { key: "title", title: "Кейс", render: (row) => <strong>{text(row.title)}</strong> }, { key: "status", title: "Статус", render: (row) => <StatusCell value={text(row.status)} /> },
    { key: "assignee", title: "Исполнитель" }, { key: "tasks", title: "Задачи", render: (row) => Array.isArray(row.tasks) ? row.tasks.length : 0 }, { key: "evidence", title: "Evidence", render: (row) => Array.isArray(row.evidence) ? row.evidence.length : 0 }, { key: "updated_ts", title: "Обновлен", render: (row) => formatTime(row.updated_ts) },
  ]} onOpen={setSelected} rows={data.items as Row[]} />}</QueryBoundary><DetailDrawer onClose={() => setSelected(null)} open={Boolean(selected)} title={selected ? text(selected.title) : "Кейс"}>{selected ? <RecordDetails kind="case" value={selected} /> : null}</DetailDrawer><Modal footer={<><Button onClick={() => setCreating(false)}>Отмена</Button><Button form="case-form" tone="primary" type="submit">Создать</Button></>} onClose={() => setCreating(false)} open={creating} title="Новый кейс"><form className="kuma-form-grid" id="case-form" onSubmit={(event) => { event.preventDefault(); void create(event.currentTarget); }}><Field label="Название" wide><input name="title" required /></Field><Field label="Описание" wide><textarea name="summary" rows={5} /></Field><Field label="Важность"><select name="severity"><option value="low">Low</option><option value="medium">Medium</option><option value="high">High</option><option value="critical">Critical</option></select></Field><Field label="Исполнитель"><input name="assignee" /></Field></form></Modal></div>;
}

export function ReportsView({ notify }: { notify: Notify }) {
  const [tab, setTab] = useState("runs");
  const [selectedRun, setSelectedRun] = useState<GeneratedReportRecord | null>(null);
  const [selectedTemplate, setSelectedTemplate] = useState<ReportTemplateRecord | null>(null);
  const [editing, setEditing] = useState<ReportTemplateRecord | null | undefined>(undefined);
  const state = useQuery("reports", async () => {
    const [templates, runs, capabilities] = await Promise.all([api.reportTemplates(), api.generatedReports({ limit: 200 }), api.reportingCapabilities()]);
    return { templates, runs, capabilities };
  }, 5_000);
  async function run(template: ReportTemplateRecord) {
    try {
      const result = await api.runReportTemplate(template.id, { tenant_scope: template.tenant_scope, idempotency_key: `manual:${template.id}:${Date.now()}` });
      notify(result.created ? "Отчет поставлен в очередь" : "Этот запуск уже существует", result.created ? "healthy" : "warning");
      setSelectedTemplate(null);
      setTab("runs");
      setSelectedRun(result.item);
      state.reload();
    } catch (error) { notify(error instanceof Error ? error.message : String(error), "critical"); }
  }
  async function saveTemplate(form: HTMLFormElement) {
    const values = new FormData(form);
    const current = editing ?? undefined;
    try {
      await api.saveReportTemplate({
        ...(current?.id ? { id: current.id } : {}),
        name: text(values.get("name")), description: text(values.get("description"), ""), owner: text(values.get("owner"), "soc-ops"),
        tenant_scope: ["main"], period: text(values.get("period"), "24h"), retention_days: number(values.get("retention_days")) || 90,
        sections: values.getAll("sections").map(String), formats: values.getAll("formats").map(String),
        schedule: { enabled: values.get("schedule_enabled") === "on", frequency: text(values.get("frequency"), "daily"), time: text(values.get("time"), "08:00"), timezone: text(values.get("timezone"), "Europe/Moscow"), recipients: text(values.get("recipients"), "").split(",").map((item) => item.trim()).filter(Boolean) },
      });
      notify(current ? "Шаблон обновлен" : "Шаблон создан", "healthy");
      setEditing(undefined); state.reload();
    } catch (error) { notify(error instanceof Error ? error.message : String(error), "critical"); }
  }
  async function toggleSchedule(template: ReportTemplateRecord) {
    try { await api.updateReportSchedule(template.id, { enabled: !template.schedule.enabled }); notify(template.schedule.enabled ? "Расписание выключено" : "Расписание включено", "healthy"); setSelectedTemplate(null); state.reload(); }
    catch (error) { notify(error instanceof Error ? error.message : String(error), "critical"); }
  }
  async function removeTemplate(template: ReportTemplateRecord) {
    if (!window.confirm(`Удалить шаблон «${template.name}»? История сформированных отчетов сохранится.`)) return;
    try { await api.deleteReportTemplate(template.id); notify("Шаблон удален", "healthy"); setSelectedTemplate(null); state.reload(); }
    catch (error) { notify(error instanceof Error ? error.message : String(error), "critical"); }
  }
  return <div className="native-page"><PageHeader title="Отчеты" actions={<><Button icon="plus" onClick={() => setEditing(null)} tone="primary">Создать шаблон</Button><IconButton icon="refresh" label="Обновить" onClick={state.reload} /></>} /><QueryBoundary state={state}>{({ templates, runs, capabilities }) => <><section className="metric-grid"><Metric label="Шаблоны" value={templates.items.length} /><Metric label="Активные расписания" value={templates.items.filter((item) => item.schedule.enabled).length} /><Metric label="Выполняются" value={runs.items.filter((item) => ["queued", "running"].includes(item.status)).length} /><Metric label="PDF" detail={capabilities.pdf_available ? "ReportLab runtime" : capabilities.pdf_unavailable_reason} value={capabilities.pdf_available ? "Доступен" : "Недоступен"} tone={capabilities.pdf_available ? "" : "warning"} /></section><Tabs items={[{ id: "runs", label: "История", count: runs.items.length }, { id: "templates", label: "Шаблоны", count: templates.items.length }]} label="Отчеты" onChange={(value) => { setTab(value); setSelectedRun(null); setSelectedTemplate(null); }} value={tab} />{tab === "runs" ? <DataTable columns={[
    { key: "status", title: "Статус", render: (row) => <StatusCell value={text(row.status)} /> }, { key: "name", title: "Отчет", render: (row) => <strong>{text(row.name)}</strong> }, { key: "progress", title: "Прогресс", render: (row) => { const progress = row.progress as Row; return <span>{number(progress?.percent)}%</span>; } }, { key: "owner", title: "Исполнитель" }, { key: "record_count", title: "Записей" }, { key: "duration_ms", title: "Время, мс" }, { key: "created_ts", title: "Запущен", render: (row) => formatTime(row.created_ts) },
  ]} onOpen={(row) => setSelectedRun(row as unknown as GeneratedReportRecord)} rows={runs.items as unknown as Row[]} /> : <DataTable columns={[
    { key: "name", title: "Шаблон", render: (row) => <strong>{text(row.name)}</strong> }, { key: "owner", title: "Владелец" }, { key: "period", title: "Период" }, { key: "formats", title: "Форматы", render: (row) => text(row.formats) }, { key: "sections", title: "Разделы", render: (row) => text(row.sections) }, { key: "schedule", title: "Расписание", render: (row) => { const schedule = row.schedule as Row; return <StatusCell value={schedule?.enabled ? `${text(schedule.frequency)} ${text(schedule.time)}` : "Выключено"} />; } }, { key: "next_run", title: "Следующий запуск", render: (row) => formatTime((row.schedule as Row)?.next_run_ts) },
  ]} onOpen={(row) => setSelectedTemplate(row as unknown as ReportTemplateRecord)} rows={templates.items as unknown as Row[]} />}</>}</QueryBoundary>
  <DetailDrawer actions={selectedTemplate ? <><Button icon="play" onClick={() => void run(selectedTemplate)} tone="primary">Сформировать</Button><Button icon="settings" onClick={() => { setEditing(selectedTemplate); setSelectedTemplate(null); }}>Изменить</Button><Button onClick={() => void toggleSchedule(selectedTemplate)}>{selectedTemplate.schedule.enabled ? "Выключить расписание" : "Включить расписание"}</Button><Button icon="delete" onClick={() => void removeTemplate(selectedTemplate)} tone="danger">Удалить</Button></> : null} onClose={() => setSelectedTemplate(null)} open={Boolean(selectedTemplate)} title={selectedTemplate?.name ?? "Шаблон"}>{selectedTemplate ? <><KeyValue rows={[["Владелец", selectedTemplate.owner], ["Tenant", selectedTemplate.tenant_scope.join(", ")], ["Период", selectedTemplate.period], ["Хранение", `${selectedTemplate.retention_days} дней`], ["Разделы", selectedTemplate.sections.join(", ")], ["Форматы", selectedTemplate.formats.join(", ")], ["Последний запуск", selectedTemplate.schedule.last_run_ts ? `${formatTime(selectedTemplate.schedule.last_run_ts)} · ${selectedTemplate.schedule.last_run_status}` : "Еще не запускался"], ["Следующий запуск", selectedTemplate.schedule.next_run_ts ? formatTime(selectedTemplate.schedule.next_run_ts) : "Расписание выключено"]]} />{selectedTemplate.description ? <p>{selectedTemplate.description}</p> : null}</> : null}</DetailDrawer>
  <DetailDrawer actions={selectedRun && ["completed", "completed_with_warnings", "failed"].includes(selectedRun.status) ? <>{["json", "csv", ...(state.data?.capabilities.pdf_available ? ["pdf"] : [])].map((format) => <a className="button button-default" href={`/api/reporting/runs/${encodeURIComponent(selectedRun.id)}/artifact?format=${format}`} key={format}><span>Скачать {format.toUpperCase()}</span></a>)}</> : null} onClose={() => setSelectedRun(null)} open={Boolean(selectedRun)} title={selectedRun?.name ?? "Запуск отчета"}>{selectedRun ? <><KeyValue rows={[["Статус", <StatusCell value={selectedRun.status} />], ["Прогресс", `${selectedRun.progress?.percent ?? 0}% (${selectedRun.progress?.sections_completed ?? 0}/${selectedRun.progress?.sections_total ?? selectedRun.sections.length})`], ["Tenant", selectedRun.tenant_scope.join(", ")], ["Период", `${formatTime(selectedRun.period.from_ts)} — ${formatTime(selectedRun.period.to_ts)}`], ["Записей", selectedRun.record_count.toLocaleString("ru-RU")], ["Исполнитель", selectedRun.owner], ["Длительность", `${selectedRun.duration_ms} мс`]]} />{(selectedRun.errors ?? []).length ? <section className="panel panel-flush"><header className="panel-header"><div className="panel-title"><h2>Ошибки выполнения</h2><span>Частичные результаты сохранены</span></div></header><DataTable columns={[{ key: "section", title: "Раздел" }, { key: "error", title: "Ошибка" }]} rows={(selectedRun.errors ?? []) as unknown as Row[]} /></section> : null}</> : null}</DetailDrawer>
  <Modal footer={<><Button onClick={() => setEditing(undefined)}>Отмена</Button><Button form="report-template-form" tone="primary" type="submit">Сохранить</Button></>} onClose={() => setEditing(undefined)} open={editing !== undefined} title={editing ? "Изменить шаблон" : "Новый шаблон отчета"}><form className="kuma-form-grid" id="report-template-form" onSubmit={(event) => { event.preventDefault(); void saveTemplate(event.currentTarget); }}><Field label="Название" wide><input defaultValue={editing?.name ?? ""} name="name" required /></Field><Field label="Описание" wide><textarea defaultValue={editing?.description ?? ""} name="description" rows={3} /></Field><Field label="Владелец"><input defaultValue={editing?.owner ?? "soc-ops"} name="owner" required /></Field><Field label="Tenant"><input disabled value="main" /></Field><Field label="Период"><select defaultValue={editing?.period ?? "24h"} name="period"><option value="12h">12 часов</option><option value="24h">24 часа</option><option value="7d">7 дней</option><option value="30d">30 дней</option></select></Field><Field label="Хранение, дней"><input defaultValue={editing?.retention_days ?? 90} max={3650} min={1} name="retention_days" type="number" /></Field><Field label="Разделы" wide><div className="kuma-checkbox-grid">{[["executive_summary", "Сводка"], ["incidents", "Инциденты"], ["sources", "Источники"], ["assets", "Активы"], ["vulnerabilities", "Уязвимости"], ["platform", "Платформа"]].map(([id, label]) => <label key={id}><input defaultChecked={editing ? editing.sections.includes(id) : ["executive_summary", "incidents", "sources"].includes(id)} name="sections" type="checkbox" value={id} /> {label}</label>)}</div></Field><Field label="Форматы" wide><div className="kuma-checkbox-grid">{["json", "csv", ...(state.data?.capabilities.pdf_available ? ["pdf"] : [])].map((format) => <label key={format}><input defaultChecked={editing ? editing.formats.includes(format as "json" | "csv" | "pdf") : format !== "pdf"} name="formats" type="checkbox" value={format} /> {format.toUpperCase()}</label>)}</div></Field><Field label="Расписание"><label><input defaultChecked={editing?.schedule.enabled ?? false} name="schedule_enabled" type="checkbox" /> Включено</label></Field><Field label="Частота"><select defaultValue={editing?.schedule.frequency ?? "daily"} name="frequency"><option value="shift">Каждую смену</option><option value="daily">Ежедневно</option><option value="weekly">Еженедельно</option><option value="monthly">Ежемесячно</option></select></Field><Field label="Время"><input defaultValue={editing?.schedule.time ?? "08:00"} name="time" required type="time" /></Field><Field label="Часовой пояс"><input defaultValue={editing?.schedule.timezone ?? "Europe/Moscow"} name="timezone" required /></Field><Field label="Получатели" wide><input defaultValue={editing?.schedule.recipients.join(", ") ?? ""} name="recipients" placeholder="soc@example.org, owner@example.org" /></Field></form></Modal></div>;
}

export function RuntimeView({ notify }: { notify: Notify }) {
  const [selected, setSelected] = useState<Row | null>(null);
  const state = useQuery("runtime", async () => {
    const [platform, health, certification, hosts, ingest, dlq] = await Promise.all([api.platformStatus(), api.healthOverview(), api.certificationHealth(), api.hostRuntimeOverview({ hours: 24, limit: 200 }), api.ingestOverview(), api.ingestDlq({ limit: 100 })]);
    return { platform, health, certification, hosts, ingest, dlq };
  }, 30_000);
  return <div className="native-page"><PageHeader title="Состояние платформы" actions={<IconButton icon="refresh" label="Обновить" onClick={state.reload} />} /><QueryBoundary state={state}>{({ platform, health, certification, hosts, ingest, dlq }) => <>
    <section className="metric-grid"><Metric label="ClickHouse" value={<StatusCell value={platform.clickhouse_ok ? "Healthy" : "Degraded"} />} /><Metric label="Стабильный EPS" value={number(certification.latest_certified_ceiling_eps).toLocaleString("ru-RU")} /><Metric label="Runtime targets" value={hosts.targets?.length ?? 0} /><Metric label="Stale targets" tone={number(hosts.metrics?.stale_targets) ? "warning" : ""} value={number(hosts.metrics?.stale_targets)} /><Metric label="Ingest DLQ" tone={number(dlq.metrics?.outstanding) ? "warning" : ""} value={number(dlq.metrics?.outstanding)} /></section>
    <ServiceLifecyclePanel notify={notify} />
    <section className="panel panel-flush"><header className="panel-header"><div className="panel-title"><h2>Узлы и сервисы</h2><span>Реальные runtime snapshots</span></div></header><DataTable columns={[
      { key: "stale", title: "Статус", render: (row) => <StatusCell value={row.stale ? "Stale" : "Healthy"} /> }, { key: "host_name", title: "Узел", render: (row) => <strong>{text(row.host_name)}</strong> }, { key: "host_role", title: "Роль" }, { key: "host_ip", title: "IP" }, { key: "last_seen_ts", title: "Последняя метрика", render: (row) => formatTime(row.last_seen_ts) }, { key: "snapshot", title: "Memory", render: (row) => `${number((row.snapshot as Row)?.memory_used_pct)}%` }, { key: "cpu", title: "CPU", render: (row) => `${number((row.snapshot as Row)?.cpu_pct)}%` },
    ]} onOpen={setSelected} rows={hosts.targets as unknown as Row[]} /></section>
    <section className="panel panel-flush"><header className="panel-header"><div className="panel-title"><h2>Ingest, transport и storage</h2><span>Операционные показатели production runtime</span></div></header><RuntimeOverviewCards certification={certification as Row} health={health as Row} ingest={ingest as Row} /></section>
  </>}</QueryBoundary><DetailDrawer onClose={() => setSelected(null)} open={Boolean(selected)} title={selected ? text(selected.host_name) : "Runtime target"}>{selected ? <RecordDetails kind="node" value={selected} /> : null}</DetailDrawer></div>;
}

export function AccessView({ notify }: { notify: Notify }) {
  const [tab, setTab] = useState("users"); const [selected, setSelected] = useState<Row | null>(null);
  const state = useQuery("access-secondary", async () => { const [accounts, grants, systems, providers] = await Promise.all([api.serviceAccounts(), api.accessGrants({ include_disabled: true }), api.accessSystems(), api.authProviders()]); return { accounts, grants, systems, providers }; });
  const tabs = [{ id: "users", label: "Пользователи" }, { id: "accounts", label: "Service accounts", count: state.data?.accounts.items.length }, { id: "grants", label: "Назначения", count: state.data?.grants.items.length }, { id: "systems", label: "Системы", count: state.data?.systems.items.length }, { id: "providers", label: "Провайдеры", count: state.data?.providers.items.length }];
  return <div className="native-page"><PageHeader title="Доступ и учетные записи" actions={tab === "users" ? null : <IconButton icon="refresh" label="Обновить" onClick={state.reload} />} /><Tabs items={tabs} label="Управление доступом" onChange={(value) => { setTab(value); setSelected(null); }} value={tab} />{tab === "users" ? <AccessUsersWorkspace notify={notify} /> : <QueryBoundary state={state}>{({ accounts, grants, systems, providers }) => { const rows = tab === "accounts" ? accounts.items : tab === "grants" ? grants.items : tab === "systems" ? systems.items : providers.items; return <DataTable columns={[
      { key: "enabled", title: "Статус", render: (row) => <StatusCell value={row.enabled === false ? "Выключен" : text(row.status, "Активен")} /> }, { key: "username", title: "Объект", render: (row) => <strong>{text(row.username ?? row.name ?? row.id ?? row.system_id)}</strong> }, { key: "role", title: "Роль", render: (row) => text(row.role ?? row.kind ?? row.principal_kind) }, { key: "permissions", title: "Разрешения", render: (row) => text(row.permissions ?? row.sections ?? row.scopes) }, { key: "updated_ts", title: "Изменен", render: (row) => formatTime(row.updated_ts ?? row.created_ts) },
    ]} onOpen={setSelected} rows={rows as Row[]} />; }}</QueryBoundary>}<DetailDrawer onClose={() => setSelected(null)} open={Boolean(selected)} title={selected ? text(selected.username ?? selected.name ?? selected.id) : "Доступ"}>{selected ? <RecordDetails kind="access" value={selected} /> : null}</DetailDrawer></div>;
}

export function CoverageView() {
  const [selected, setSelected] = useState<Row | null>(null);
  const state = useQuery("coverage", () => api.securityServices(), 30_000);
  return <div className="native-page"><PageHeader title="Покрытие средствами защиты" actions={<IconButton icon="refresh" label="Обновить" onClick={state.reload} />} /><QueryBoundary state={state}>{(data) => <><section className="metric-grid"><Metric label="Всего интеграций" value={data.total} /><Metric label="Healthy" value={data.healthy} /><Metric label="Quiet" tone={number(data.quiet) ? "warning" : ""} value={number(data.quiet)} /><Metric label="Degraded" tone={number(data.degraded) ? "warning" : ""} value={number(data.degraded)} /><Metric label="Stale" tone={number(data.stale) ? "warning" : ""} value={number(data.stale)} /></section><DataTable columns={[
    { key: "telemetry_state", title: "Телеметрия", render: (row) => <StatusCell value={text(row.telemetry_state)} /> }, { key: "title", title: "Система", render: (row) => <strong>{text(row.title)}</strong> }, { key: "product", title: "Продукт" }, { key: "host_name", title: "Узел" }, { key: "address", title: "Адрес" }, { key: "asset_group", title: "Группа активов" }, { key: "events_24h", title: "События 24ч", render: (row) => number(row.events_24h).toLocaleString("ru-RU") }, { key: "latest_event", title: "Последнее событие", render: (row) => formatTime(row.latest_event) },
  ]} onOpen={setSelected} rows={data.items as Row[]} /></>}</QueryBoundary><DetailDrawer actions={serviceConsoleHref(selected) ? <a className="button button-primary" href={serviceConsoleHref(selected)} rel="noreferrer" target="_blank">Открыть консоль</a> : null} onClose={() => setSelected(null)} open={Boolean(selected)} title={selected ? text(selected.title) : "Интеграция"}>{selected ? <RecordDetails kind="integration" value={selected} /> : null}</DetailDrawer></div>;
}

export function TopologyView() {
  const [selected, setSelected] = useState<Row | null>(null);
  const state = useQuery("topology", async () => { const [network, layout] = await Promise.all([api.networkTopology({ hours: 24, limit: 600 }), api.topologyLayout("network")]); return { network, layout }; }, 60_000);
  return <div className="native-page topology-page"><PageHeader eyebrow="Сегменты, активы и наблюдаемые потоки" title="Топология сети" actions={<IconButton icon="refresh" label="Обновить" onClick={state.reload} />} /><QueryBoundary state={state}>{({ network, layout }) => <><section className="metric-grid"><Metric label="Узлы" value={network.nodes.length} /><Metric label="Связи" value={network.edges.length} /><Metric label="Потоки" value={network.packet_flows?.length ?? 0} /><Metric label="Проблемы" tone={network.issues?.length ? "warning" : ""} value={network.issues?.length ?? 0} /></section><TopologyWorkbench data={network} onSave={async (positions) => { await api.saveTopologyLayout({ workspace: "network", expected_version: layout.version, positions }); state.reload(); }} onSelect={(node) => setSelected(node as unknown as Row)} saved={layout} /></>}</QueryBoundary><DetailDrawer onClose={() => setSelected(null)} open={Boolean(selected)} title={selected ? text(selected.label) : "Узел"}>{selected ? <RecordDetails kind="node" value={selected} /> : null}</DetailDrawer></div>;
}

export function DiscoveryView({ notify }: { notify: Notify }) {
  return <DiscoveryWorkspace notify={notify} />;
}

export function ResponseView({ notify }: { notify: Notify }) {
  const [tab, setTab] = useState("actions"); const [selected, setSelected] = useState<Row | null>(null);
  const state = useQuery("response", async () => { const [actions, executions, dlq, analytics] = await Promise.all([api.responseActions(), api.responseExecutions({ limit: 200 }), api.responseDlq({ limit: 100 }), api.responseAnalytics({ limit: 100 })]); return { actions, executions, dlq, analytics }; }, 30_000);
  async function execute(row: Row) { try { const dryRun = Boolean(row.dangerous || row.approval_required || row.requires_approval); await api.executeResponseAction(text(row.id), { dry_run: dryRun, linkage: { origin: "sentinel-ui" } }); notify(dryRun ? "Запущена безопасная проверка playbook" : "Playbook запущен", "healthy"); state.reload(); } catch (error) { notify(error instanceof Error ? error.message : String(error), "critical"); } }
  return <div className="native-page"><PageHeader title="SOAR и автоматизация" actions={<IconButton icon="refresh" label="Обновить" onClick={state.reload} />} /><QueryBoundary state={state}>{({ actions, executions, dlq, analytics }) => { const rows = tab === "actions" ? actions.items : tab === "executions" ? executions.items : dlq.items; return <><section className="metric-grid"><Metric label="Playbooks" value={number(analytics.metrics?.actions_total ?? actions.items.length)} /><Metric label="Выполнения" value={number(analytics.metrics?.executions_total)} /><Metric label="Успешность" value={`${number(analytics.metrics?.success_rate)}%`} /><Metric label="Ожидают подтверждения" tone={number(analytics.metrics?.pending_approvals) ? "warning" : ""} value={number(analytics.metrics?.pending_approvals)} /><Metric label="DLQ" tone={number(analytics.metrics?.dlq_total) ? "warning" : ""} value={number(analytics.metrics?.dlq_total)} /></section><Tabs items={[{ id: "actions", label: "Playbooks", count: actions.items.length }, { id: "executions", label: "Выполнения", count: executions.items.length }, { id: "dlq", label: "DLQ", count: dlq.items.length }]} label="SOAR" onChange={setTab} value={tab} /><DataTable columns={[
    { key: "status", title: "Статус", render: (row) => <StatusCell value={text(row.status, row.enabled === false ? "Выключен" : "Активен")} /> }, { key: "title", title: "Объект", render: (row) => <strong>{text(row.title ?? row.action_id ?? row.id)}</strong> }, { key: "kind", title: "Тип", render: (row) => text(row.kind ?? row.action_type) }, { key: "actor", title: "Инициатор" }, { key: "created_ts", title: "Создан", render: (row) => formatTime(row.created_ts) }, { key: "error", title: "Ошибка" },
  ]} onOpen={setSelected} rows={rows as Row[]} /></>; }}</QueryBoundary><DetailDrawer actions={selected && tab === "actions" ? <Button icon="play" onClick={() => execute(selected)} tone="primary">Выполнить</Button> : null} onClose={() => setSelected(null)} open={Boolean(selected)} title={selected ? text(selected.title ?? selected.id) : "SOAR"}>{selected ? <RecordDetails kind="soar" value={selected} /> : null}</DetailDrawer></div>;
}

export function VulnerabilityView({ notify }: { notify: Notify }) {
  const [selected, setSelected] = useState<Row | null>(null); const state = useQuery("vuln", () => api.vulnWorkbench({ days: 30, limit: 500 }), 60_000);
  async function sync() { try { await api.vulnSync({ source: "all", requested_by: "sentinel-ui" }); notify("Синхронизация уязвимостей запущена", "healthy"); state.reload(); } catch (error) { notify(error instanceof Error ? error.message : String(error), "critical"); } }
  return <div className="native-page"><PageHeader title="Управление уязвимостями" actions={<><Button icon="refresh" onClick={sync} tone="primary">Синхронизировать</Button><IconButton icon="refresh" label="Обновить" onClick={state.reload} /></>} /><QueryBoundary state={state}>{(data) => <><section className="metric-grid"><Metric label="Находки" value={number(data.summary?.findings)} /><Metric label="Требуют действия" value={number(data.summary?.actionable)} /><Metric label="Срочные" tone={number(data.summary?.urgent) ? "warning" : ""} value={number(data.summary?.urgent)} /><Metric label="CISA KEV" tone={number(data.summary?.kev) ? "warning" : ""} value={number(data.summary?.kev)} /><Metric label="SLA нарушен" tone={number(data.summary?.sla_breached) ? "warning" : ""} value={number(data.summary?.sla_breached)} /></section><DataTable columns={[
    { key: "severity", title: "Важность", render: (row) => <Badge tone={severityTone(row.severity)}>{text(row.severity)}</Badge> }, { key: "title", title: "Уязвимость", render: (row) => <strong>{text(row.title)}</strong> }, { key: "asset_hostname", title: "Актив", render: (row) => text(row.asset_hostname ?? row.target) }, { key: "target_ip", title: "IP" }, { key: "cves", title: "CVE", render: (row) => text(row.cves) }, { key: "cvss_score", title: "CVSS" }, { key: "epss", title: "EPSS" }, { key: "priority_score", title: "Приоритет" }, { key: "due_ts", title: "SLA", render: (row) => formatTime(row.due_ts) },
  ]} onOpen={setSelected} rows={asRows(data.items)} /></>}</QueryBoundary><DetailDrawer actions={selected ? <Button onClick={async () => { try { await api.vulnApplyExposure({ finding_keys: [text(selected.finding_key)], action: "create_case" }); notify("Remediation workflow создан", "healthy"); state.reload(); } catch (error) { notify(error instanceof Error ? error.message : String(error), "critical"); } }} tone="primary">Создать remediation</Button> : null} onClose={() => setSelected(null)} open={Boolean(selected)} title={selected ? text(selected.title) : "Уязвимость"}>{selected ? <RecordDetails kind="vulnerability" value={selected} /> : null}</DetailDrawer></div>;
}

export function ThreatIntelView() {
  const [tab, setTab] = useState("matches"); const [selected, setSelected] = useState<Row | null>(null); const state = useQuery("intel", () => api.threatIntelOverview({ hours: 72, limit: 100 }), 60_000);
  return <div className="native-page"><PageHeader eyebrow="Оперативное окно: 72 часа" title="Threat Intelligence" actions={<IconButton icon="refresh" label="Обновить" onClick={state.reload} />} /><QueryBoundary state={state}>{(data) => { const rows = tab === "matches" ? data.recent_matches : tab === "catalog" ? data.entries : data.malicious_sources; return <><section className="metric-grid"><Metric label="Индикаторы" value={number(data.summary?.indicators)} /><Metric label="Провайдеры" value={number(data.summary?.providers)} /><Metric label="Срабатывания 72ч" value={number(data.summary?.matches_24h)} /><Metric label="Вредоносные IP" value={number(data.summary?.malicious_ips)} /></section><Tabs items={[{ id: "matches", label: "Срабатывания", count: data.recent_matches?.length ?? 0 }, { id: "catalog", label: "Каталог IoC", count: data.entries?.length ?? 0 }, { id: "sources", label: "Источники атак", count: data.malicious_sources?.length ?? 0 }]} label="Threat intelligence" onChange={setTab} value={tab} /><DataTable columns={[
    { key: "severity", title: "Важность", render: (row) => <Badge tone={severityTone(row.severity ?? row.reputation)}>{text(row.severity ?? row.reputation)}</Badge> }, { key: "indicator", title: "Индикатор", render: (row) => <strong>{text(row.indicator ?? row.ip)}</strong> }, { key: "indicator_type", title: "Тип" }, { key: "provider", title: "Провайдер" }, { key: "country", title: "Страна" }, { key: "confidence", title: "Confidence" }, { key: "events", title: "События" }, { key: "last_seen", title: "Последнее наблюдение", render: (row) => formatTime(row.last_seen ?? row.updated_ts) },
  ]} onOpen={setSelected} rows={asRows(rows)} /></>; }}</QueryBoundary><DetailDrawer onClose={() => setSelected(null)} open={Boolean(selected)} title={selected ? text(selected.indicator ?? selected.ip) : "Индикатор"}>{selected ? <RecordDetails kind="threat" value={selected} /> : null}</DetailDrawer></div>;
}

export function IdentityView() {
  const [tab, setTab] = useState("users"); const [selected, setSelected] = useState<Row | null>(null);
  const state = useQuery("identity", async () => { const [status, users, groups, roles, clients] = await Promise.all([api.keycloakStatus(), api.keycloakUsers({ limit: 500 }), api.keycloakGroups(), api.keycloakRoles(), api.keycloakClients()]); return { status, users, groups, roles, clients }; }, 60_000);
  return <div className="native-page"><PageHeader title="Identity Security" actions={<IconButton icon="refresh" label="Обновить" onClick={state.reload} />} /><QueryBoundary state={state}>{({ status, users, groups, roles, clients }) => { const rows = tab === "users" ? users.items : tab === "groups" ? groups.items : tab === "roles" ? roles.items : clients.items; return <><section className="metric-grid"><Metric label="Keycloak" value={<StatusCell value={text(status.status ?? status.healthy, "Unknown")} />} /><Metric label="Пользователи" value={users.items.length} /><Metric label="Группы" value={groups.items.length} /><Metric label="Роли" value={roles.items.length} /><Metric label="OIDC clients" value={clients.items.length} /></section><Tabs items={[{ id: "users", label: "Пользователи", count: users.items.length }, { id: "groups", label: "Группы", count: groups.items.length }, { id: "roles", label: "Роли", count: roles.items.length }, { id: "clients", label: "Клиенты", count: clients.items.length }]} label="Identity" onChange={setTab} value={tab} /><DataTable columns={[
    { key: "enabled", title: "Статус", render: (row) => <StatusCell value={row.enabled === false ? "Выключен" : "Активен"} /> }, { key: "username", title: "Объект", render: (row) => <strong>{text(row.username ?? row.name ?? row.client_id ?? row.id)}</strong> }, { key: "email", title: "Email" }, { key: "description", title: "Описание" }, { key: "groups", title: "Группы", render: (row) => text(row.groups) }, { key: "roles", title: "Роли", render: (row) => text(row.roles) },
  ]} onOpen={setSelected} rows={rows as Row[]} /></>; }}</QueryBoundary><DetailDrawer onClose={() => setSelected(null)} open={Boolean(selected)} title={selected ? text(selected.username ?? selected.name ?? selected.client_id) : "Identity"}>{selected ? <RecordDetails kind="identity" value={selected} /> : null}</DetailDrawer></div>;
}

const serviceHints: Partial<Record<View, RegExp>> = {
  ngfw: /opnsense|firewall|ngfw/i, ids: /suricata|ips|ids/i, ndr: /zeek|arkime|ndr/i,
  container: /falco|container/i, vpn: /vpn|wireguard|openvpn|3x-ui|vless/i, dfir: /velociraptor|dfir/i,
  analysis: /clamav|yara|malware/i, evidence: /minio|evidence/i, pki: /step-ca|pki|certificate/i,
};

export function SecurityServiceView({ view, notify }: { view: View; notify: Notify }) {
  const [selected, setSelected] = useState<Row | null>(null); const [editing, setEditing] = useState<Row | null>(null);
  const state = useQuery(`service:${view}`, async () => {
    const services = await api.securityServices(); const hint = serviceHints[view] ?? new RegExp(view, "i");
    const matches = services.items.filter((item) => hint.test(`${item.service_id} ${item.title} ${item.product} ${item.role}`));
    const control = view === "ngfw" || view === "ids" ? await api.securityServiceControl(view === "ids" ? "ips" : "ngfw") : null;
    return { services: matches, control: control as Row | null };
  }, 30_000);
  async function firewallMutation(operation: string, body: Row) { try { await api.mutateFirewall(operation, body); notify(`Firewall: ${operation} выполнено`, "healthy"); setEditing(null); state.reload(); } catch (error) { notify(error instanceof Error ? error.message : String(error), "critical"); } }
  async function saveFirewall(form: HTMLFormElement) { const values = new FormData(form); await firewallMutation(text(values.get("uuid")) ? "update" : "create", { uuid: text(values.get("uuid"), ""), description: text(values.get("description")), interface: text(values.get("interface"), "opt5"), action: text(values.get("action"), "block"), protocol: text(values.get("protocol"), "any"), source: text(values.get("source"), "any"), destination: text(values.get("destination"), "any"), destination_port: text(values.get("destination_port"), ""), sequence: number(values.get("sequence") || 100), enabled: values.get("enabled") === "on", log: values.get("log") === "on" }); }
  const control = state.data?.control;
  const firewallRows = asRows((control?.firewall as Row)?.rules);
  const rulesetRows = asRows((control?.ids as Row)?.rulesets);
  return <div className="native-page"><PageHeader title={view === "ngfw" ? "OPNsense Network Firewall" : view === "ids" ? "Suricata Network IPS" : view === "ndr" ? "Network Detection and Response" : view === "container" ? "Container Runtime Security" : view === "vpn" ? "VPN и защищенный доступ" : view === "dfir" ? "Endpoint DFIR" : view === "analysis" ? "Malware Analysis" : view === "evidence" ? "Evidence Storage" : "Internal PKI"} actions={<><IconButton icon="refresh" label="Обновить" onClick={state.reload} />{view === "ngfw" ? <Button icon="plus" onClick={() => setEditing({ interface: "opt5", action: "block", protocol: "any", source: "any", destination: "any", sequence: 100, enabled: false, log: true })} tone="primary">Создать правило</Button> : null}{view === "ids" ? <><Button onClick={async () => { try { await api.mutateIds("reload"); notify("Suricata policy перезагружена", "healthy"); state.reload(); } catch (error) { notify(error instanceof Error ? error.message : String(error), "critical"); } }}>Reload</Button><Button onClick={async () => { try { await api.mutateIds("update"); notify("Сигнатуры обновлены", "healthy"); state.reload(); } catch (error) { notify(error instanceof Error ? error.message : String(error), "critical"); } }} tone="primary">Обновить сигнатуры</Button></> : null}</>} />
    <QueryBoundary state={state}>{({ services, control: loadedControl }) => <>{!services.length ? <EmptyState detail="В production inventory не найден соответствующий сервис. Фиктивные карточки не создаются." title="Сервис не обнаружен" /> : <><section className="metric-grid"><Metric label="Сервисы" value={services.length} /><Metric label="События 24ч" value={services.reduce((sum, item) => sum + number(item.events_24h), 0).toLocaleString("ru-RU")} /><Metric label="Управление" value={<StatusCell value={loadedControl ? "Доступно" : "Только мониторинг"} />} /></section><DataTable columns={[
      { key: "telemetry_state", title: "Телеметрия", render: (row) => <StatusCell value={text(row.telemetry_state)} /> }, { key: "title", title: "Система", render: (row) => <strong>{text(row.title)}</strong> }, { key: "product", title: "Продукт" }, { key: "host_name", title: "Узел" }, { key: "address", title: "Адрес" }, { key: "events_24h", title: "События 24ч" }, { key: "latest_event", title: "Последнее событие", render: (row) => formatTime(row.latest_event) },
    ]} onOpen={setSelected} rows={services as unknown as Row[]} /></>}
    {view === "ngfw" && control ? <section className="panel panel-flush"><header className="panel-header"><div className="panel-title"><h2>Политика межсетевого экрана</h2><span>{firewallRows.length} правил из OPNsense API</span></div></header><DataTable columns={[
      { key: "enabled", title: "Статус", render: (row) => <StatusCell value={row.enabled ? "Включено" : "Выключено"} /> }, { key: "description", title: "Правило", render: (row) => <strong>{text(row.description)}</strong> }, { key: "action", title: "Действие" }, { key: "interface", title: "Интерфейс" }, { key: "protocol", title: "Протокол" }, { key: "source", title: "Источник" }, { key: "destination", title: "Назначение" }, { key: "destination_port", title: "Порт" },
    ]} onOpen={setEditing} rows={firewallRows} /></section> : null}
    {view === "ids" && control ? <section className="panel panel-flush"><header className="panel-header"><div className="panel-title"><h2>Наборы правил Suricata</h2><span>{rulesetRows.length} rulesets</span></div></header><DataTable columns={[
      { key: "enabled", title: "Статус", render: (row) => <button className="sentinel-status-button" onClick={(event) => { event.stopPropagation(); void api.mutateIds("toggle_ruleset", { filename: text(row.filename), enabled: !row.enabled }).then(() => { notify("Ruleset обновлен", "healthy"); state.reload(); }).catch((error) => notify(error instanceof Error ? error.message : String(error), "critical")); }} type="button"><StatusCell value={row.enabled ? "Включен" : "Выключен"} /></button> }, { key: "filename", title: "Ruleset", render: (row) => <strong>{text(row.filename)}</strong> }, { key: "description", title: "Описание" }, { key: "modified_local", title: "Локальные изменения", render: (row) => row.modified_local ? "Да" : "Нет" },
    ]} rows={rulesetRows} /></section> : null}</>}</QueryBoundary>
    <DetailDrawer actions={serviceConsoleHref(selected) ? <a className="button button-primary" href={serviceConsoleHref(selected)} rel="noreferrer" target="_blank">Открыть консоль</a> : null} onClose={() => setSelected(null)} open={Boolean(selected)} title={selected ? text(selected.title) : "Сервис"}>{selected ? <RecordDetails kind="service" value={selected} /> : null}</DetailDrawer>
    <Modal footer={<><Button onClick={() => setEditing(null)}>Отмена</Button>{editing?.uuid ? <Button onClick={() => firewallMutation("delete", { uuid: text(editing.uuid), confirm: text(editing.description) })} tone="danger">Удалить</Button> : null}<Button form="firewall-form" tone="primary" type="submit">Сохранить и применить</Button></>} onClose={() => setEditing(null)} open={Boolean(editing)} title={editing?.uuid ? "Редактирование правила OPNsense" : "Новое правило OPNsense"}>{editing ? <form className="kuma-form-grid" id="firewall-form" onSubmit={(event) => { event.preventDefault(); void saveFirewall(event.currentTarget); }}><input name="uuid" type="hidden" value={text(editing.uuid, "")} /><Field label="Описание" wide><input defaultValue={text(editing.description, "")} name="description" required /></Field><Field label="Интерфейс"><input defaultValue={text(editing.interface, "opt5")} name="interface" required /></Field><Field label="Действие"><select defaultValue={text(editing.action, "block")} name="action"><option value="block">Block</option><option value="pass">Pass</option><option value="reject">Reject</option></select></Field><Field label="Протокол"><select defaultValue={text(editing.protocol, "any")} name="protocol"><option value="any">Any</option><option value="TCP">TCP</option><option value="UDP">UDP</option><option value="TCP/UDP">TCP/UDP</option><option value="ICMP">ICMP</option></select></Field><Field label="Источник"><input defaultValue={text(editing.source, "any")} name="source" /></Field><Field label="Назначение"><input defaultValue={text(editing.destination, "any")} name="destination" /></Field><Field label="Порт назначения"><input defaultValue={text(editing.destination_port, "")} name="destination_port" /></Field><Field label="Порядок"><input defaultValue={number(editing.sort_order ?? editing.sequence ?? 100)} name="sequence" type="number" /></Field><Field label="Флаги" wide><label className="sentinel-checkbox"><input defaultChecked={Boolean(editing.enabled)} name="enabled" type="checkbox" /> Включено</label><label className="sentinel-checkbox"><input defaultChecked={editing.log !== false} name="log" type="checkbox" /> Логировать</label></Field></form> : null}</Modal>
  </div>;
}

export function PrimaryView({ view, navigate, notify }: { view: View; navigate: Navigate; notify: Notify }) {
  switch (view) {
    case "overview": return <OverviewView navigate={navigate} />;
    case "alerts": return <IncidentQueueWorkspace mode="raw" notify={notify} />;
    case "incidents": return <IncidentQueueWorkspace mode="agg" notify={notify} />;
    case "events": return <EventsQueryWorkspace notify={notify} />;
    case "cases": return <CasesView notify={notify} />;
    case "assets": return <AssetsView />;
    case "reports": return <ReportsView notify={notify} />;
    case "resources": return <ResourcesWorkspace notify={notify} />;
    case "sources": return <SourcesView notify={notify} />;
    case "tasks": return <TaskDispatcherView navigate={navigate} />;
    case "rules": return <RulesWorkspace notify={notify} />;
    case "runtime": return <RuntimeView notify={notify} />;
    case "access": return <AccessView notify={notify} />;
    case "coverage": return <CoverageView />;
    case "topology": return <TopologyView />;
    case "discovery": return <DiscoveryView notify={notify} />;
    case "response": return <ResponseView notify={notify} />;
    case "exposure": return <VulnerabilityView notify={notify} />;
    case "intel": return <ThreatIntelView />;
    case "identity": return <IdentityView />;
    case "ndr":
    case "container":
    case "vpn":
    case "dfir":
    case "analysis":
    case "evidence":
    case "pki": return <SecurityOperationsWorkspace notify={notify} view={view} />;
    default: return <SecurityServiceView notify={notify} view={view} />;
  }
}
