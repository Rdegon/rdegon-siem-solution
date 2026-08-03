import { useEffect, useState, type ReactNode } from "react";
import { EventDetailContent } from "./incident-details";
import { api } from "./runtime/api";
import { formatTime, number, severityTone, text, useQuery } from "./runtime/query";
import type {
  HuntingEventDetailResponse,
  HuntingFilter,
  HuntingSavedSearchRecord,
  HuntingSpecification,
} from "./runtime/types";
import {
  Badge,
  Button,
  DetailDrawer,
  EmptyState,
  ErrorState,
  IconButton,
  LoadingState,
  PageHeader,
} from "./ui";

type Notify = (message: string, tone?: string) => void;
type Row = Record<string, unknown>;
type Column = { key: string; title: string; render?: (row: Row) => ReactNode };

export const EVENT_FILTER_FIELDS = [
  ["source_type", "Тип источника"],
  ["source", "Источник"],
  ["collector_profile", "Профиль коллектора"],
  ["category", "Категория"],
  ["severity", "Важность"],
  ["host", "Хост"],
  ["event_code", "Код события"],
  ["src_ip", "IP источника"],
  ["dst_ip", "IP назначения"],
  ["user_name", "Пользователь"],
  ["event_outcome", "Результат"],
  ["process_name", "Процесс"],
  ["message", "Сообщение"],
] as const;

const FILTER_OPERATORS = [
  ["eq", "равно"],
  ["neq", "не равно"],
  ["contains", "содержит"],
  ["not_contains", "не содержит"],
  ["in", "в списке"],
  ["exists", "заполнено"],
] as const;

const FACET_LABELS: Record<string, string> = {
  source_type: "Тип источника",
  source: "Источник",
  collector_profile: "Коллектор",
  category: "Категория",
  severity: "Важность",
  host: "Хост",
};

const COLUMNS: Column[] = [
  { key: "ts", title: "Время", render: (row) => formatTime(row.ts) },
  { key: "severity", title: "Важность", render: (row) => <Badge tone={severityTone(row.severity)}>{text(row.severity)}</Badge> },
  { key: "source", title: "Источник" },
  { key: "source_type", title: "Тип" },
  { key: "host", title: "Хост" },
  { key: "category", title: "Категория" },
  { key: "event_code", title: "Код" },
  { key: "src_ip", title: "Источник IP" },
  { key: "dst_ip", title: "Назначение IP" },
  { key: "user_name", title: "Пользователь", render: (row) => text(row.user_name ?? row.target_user) },
  { key: "message", title: "Сообщение", render: (row) => <span className="sentinel-truncate">{text(row.message)}</span> },
];

export function buildHuntingSpecification(input: {
  source: string;
  window: string;
  rangeMode: "window" | "custom";
  fromTs: string;
  toTs: string;
  filters: HuntingFilter[];
  expertQuery: string;
  pageSize: number;
}): HuntingSpecification {
  return {
    source: input.source,
    window: input.rangeMode === "window" ? input.window : "24h",
    from_ts: input.rangeMode === "custom" && input.fromTs ? new Date(input.fromTs).toISOString() : "",
    to_ts: input.rangeMode === "custom" && input.toTs ? new Date(input.toTs).toISOString() : "",
    filters: input.filters.map((item) => ({
      ...item,
      values: ["in", "not_in"].includes(item.operator)
        ? String(item.value ?? "").split(",").map((value) => value.trim()).filter(Boolean)
        : undefined,
    })),
    expert_query: input.expertQuery.trim(),
    limit: input.pageSize,
  };
}

function downloadTsv(data: Row[], columns: Column[]) {
  const escape = (value: unknown) => text(value).replace(/\t/g, " ").replace(/\r?\n/g, " ");
  const body = [
    columns.map((column) => column.title).join("\t"),
    ...data.map((row) => columns.map((column) => escape(row[column.key])).join("\t")),
  ].join("\n");
  const url = URL.createObjectURL(new Blob([body], { type: "text/tab-separated-values;charset=utf-8" }));
  const link = document.createElement("a");
  link.href = url;
  link.download = `sentinel-events-${new Date().toISOString().slice(0, 19).replace(/:/g, "-")}.tsv`;
  link.click();
  URL.revokeObjectURL(url);
}

function EventGrid({ columns, data, onOpen }: { columns: Column[]; data: Row[]; onOpen: (row: Row) => void }) {
  if (!data.length) return <EmptyState detail="По заданным условиям события не найдены" />;
  return <div className="native-grid kuma-dense-grid"><table><thead><tr>{columns.map((column) => <th key={column.key}>{column.title}</th>)}</tr></thead><tbody>{data.map((row, index) => <tr className="sentinel-clickable-row" key={text(row.stable_id ?? row.event_id, String(index))} onClick={() => onOpen(row)} onKeyDown={(event) => { if (event.key === "Enter" || event.key === " ") onOpen(row); }} tabIndex={0}>{columns.map((column) => <td key={column.key}>{column.render ? column.render(row) : text(row[column.key])}</td>)}</tr>)}</tbody></table></div>;
}

export function EventsHuntingWorkspace({ notify }: { notify: Notify }) {
  const [mode, setMode] = useState<"builder" | "expert">("builder");
  const [expertQuery, setExpertQuery] = useState("");
  const [filters, setFilters] = useState<HuntingFilter[]>([]);
  const [source, setSource] = useState("hot");
  const [windowSize, setWindowSize] = useState("24h");
  const [rangeMode, setRangeMode] = useState<"window" | "custom">("window");
  const [fromTs, setFromTs] = useState("");
  const [toTs, setToTs] = useState("");
  const [includeCount, setIncludeCount] = useState(false);
  const [pageSize, setPageSize] = useState(100);
  const [autoRefresh, setAutoRefresh] = useState(false);
  const [selected, setSelected] = useState<Row | null>(null);
  const [detail, setDetail] = useState<HuntingEventDetailResponse | null>(null);
  const [detailError, setDetailError] = useState<Error | null>(null);
  const [columnPicker, setColumnPicker] = useState(false);
  const [savedName, setSavedName] = useState("");
  const [selectedSavedId, setSelectedSavedId] = useState("");
  const [visibleKeys, setVisibleKeys] = useState(COLUMNS.map((column) => column.key));
  const [executed, setExecuted] = useState<HuntingSpecification>({ source: "hot", window: "24h", filters: [], expert_query: "", limit: 100 });
  const [cursorStack, setCursorStack] = useState([""]);
  const [pageIndex, setPageIndex] = useState(0);
  const capabilities = useQuery("hunting-capabilities", api.huntingCapabilities);
  const savedSearches = useQuery("hunting-saved-searches", api.huntingSavedSearches);
  const cursor = cursorStack[pageIndex] ?? "";
  const request = { ...executed, ...(cursor ? { cursor, pagination: "cursor" } : {}), include_count: includeCount && !cursor };
  const state = useQuery(`hunting-events:${JSON.stringify(request)}`, () => api.huntingQuery(request), autoRefresh ? 30_000 : undefined);
  const facetState = useQuery(`hunting-facets:${JSON.stringify(executed)}`, () => api.huntingFacets(executed));
  const visibleColumns = COLUMNS.filter((column) => visibleKeys.includes(column.key));
  const data = (state.data?.rows ?? []) as Row[];
  const lines = Array.from({ length: Math.max(5, expertQuery.split("\n").length) }, (_, index) => index + 1).join("\n");

  useEffect(() => {
    const available = capabilities.data?.items ?? [];
    if (!available.length || available.some((item) => item.id === source)) return;
    setSource(capabilities.data?.default || available[0].id);
  }, [capabilities.data, source]);

  useEffect(() => {
    setDetail(null);
    setDetailError(null);
    if (!selected) return;
    let active = true;
    api.huntingEventDetail(text(selected.stable_id ?? selected.event_id, ""), text(selected.ts, ""), executed.source).then(
      (value) => active && setDetail(value),
      (reason) => active && setDetailError(reason instanceof Error ? reason : new Error(String(reason))),
    );
    return () => { active = false; };
  }, [executed.source, selected]);

  const specification = () => buildHuntingSpecification({ source, window: windowSize, rangeMode, fromTs, toTs, filters, expertQuery, pageSize });
  const execute = () => {
    if (rangeMode === "custom" && (!fromTs || !toTs)) {
      notify("Для ручного диапазона укажите начало и конец", "warning");
      return;
    }
    setExecuted(specification());
    setCursorStack([""]);
    setPageIndex(0);
  };
  const addFilter = (field = "source", value = "") => setFilters((current) => [...current, { field, operator: "eq", value }]);
  const applySavedSearch = (item: HuntingSavedSearchRecord) => {
    const spec = item.specification;
    setSource(spec.source);
    setWindowSize(spec.window || "24h");
    setRangeMode(spec.from_ts || spec.to_ts ? "custom" : "window");
    setFromTs(spec.from_ts ? spec.from_ts.slice(0, 16) : "");
    setToTs(spec.to_ts ? spec.to_ts.slice(0, 16) : "");
    setFilters(spec.filters ?? []);
    setExpertQuery(spec.expert_query ?? "");
    setPageSize(spec.limit || 100);
    setSavedName(item.name);
    setSelectedSavedId(item.id);
    setExecuted(spec);
    setCursorStack([""]);
    setPageIndex(0);
  };
  const saveSearch = async () => {
    if (!savedName.trim()) { notify("Укажите имя сохраненного запроса", "warning"); return; }
    try {
      const existing = savedSearches.data?.items.find((item) => item.id === selectedSavedId);
      await api.huntingSaveSearch({
        ...(existing ? { id: existing.id, revision: existing.revision } : {}),
        name: savedName.trim(),
        specification: specification(),
      });
      setSavedName("");
      setSelectedSavedId("");
      savedSearches.reload();
      notify("Запрос сохранен в личном рабочем пространстве", "healthy");
    } catch (error) { notify(error instanceof Error ? error.message : String(error), "critical"); }
  };

  return <div className="native-page kuma-events-page">
    <PageHeader title="События" actions={<><label className="kuma-auto-refresh"><input checked={autoRefresh} onChange={(event) => setAutoRefresh(event.target.checked)} type="checkbox" /><span>Автообновление</span></label><select aria-label="Источник событий" onChange={(event) => setSource(event.target.value)} value={source}>{(capabilities.data?.items ?? []).map((item) => <option key={item.id} value={item.id}>{item.label}</option>)}{!capabilities.data?.items.length ? <option value="hot">Оперативное хранилище</option> : null}</select></>} />
    <section className="kuma-query-workspace">
      <div className="kuma-query-topline"><div><strong>Поиск событий</strong><span>Параметризованный запрос · tenant main · до 31 дня</span></div><div className="kuma-query-modes"><button className={mode === "builder" ? "active" : ""} onClick={() => setMode("builder")} type="button">Конструктор</button><button className={mode === "expert" ? "active" : ""} onClick={() => setMode("expert")} type="button">Экспертный</button></div></div>
      {mode === "builder" ? <div className="kuma-query-builder"><span>Где</span>{filters.length ? filters.map((filter, index) => <div className="kuma-editor-field" key={`${filter.field}-${index}`}><select aria-label={`Поле фильтра ${index + 1}`} onChange={(event) => setFilters((current) => current.map((item, itemIndex) => itemIndex === index ? { ...item, field: event.target.value } : item))} value={filter.field}>{EVENT_FILTER_FIELDS.map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select><select aria-label={`Оператор фильтра ${index + 1}`} onChange={(event) => setFilters((current) => current.map((item, itemIndex) => itemIndex === index ? { ...item, operator: event.target.value as HuntingFilter["operator"] } : item))} value={filter.operator}>{FILTER_OPERATORS.map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select>{filter.operator !== "exists" ? <input aria-label={`Значение фильтра ${index + 1}`} onChange={(event) => setFilters((current) => current.map((item, itemIndex) => itemIndex === index ? { ...item, value: event.target.value } : item))} placeholder={filter.operator === "in" ? "значения через запятую" : "значение"} value={filter.value ?? ""} /> : null}<IconButton icon="delete" label="Удалить фильтр" onClick={() => setFilters((current) => current.filter((_, itemIndex) => itemIndex !== index))} /></div>) : <span>Фильтры не заданы</span>}<Button icon="plus" onClick={() => addFilter()}>Условие</Button></div> : <div className="kuma-query-editor"><pre className="kuma-query-lines">{lines}</pre><textarea aria-label="Экспертный запрос событий" onChange={(event) => setExpertQuery(event.target.value)} placeholder={'severity:high AND (category:authentication OR source:linux*)\nSQL-команды не принимаются'} spellCheck={false} value={expertQuery} /></div>}
      <div className="kuma-filter-strip"><label className="kuma-editor-field"><span>Диапазон</span><select onChange={(event) => setRangeMode(event.target.value as "window" | "custom")} value={rangeMode}><option value="window">Готовый</option><option value="custom">Ручной</option></select></label>{rangeMode === "window" ? <label className="kuma-editor-field"><span>Период</span><select onChange={(event) => setWindowSize(event.target.value)} value={windowSize}><option value="1h">1 час</option><option value="6h">6 часов</option><option value="24h">24 часа</option><option value="7d">7 дней</option><option value="30d">30 дней</option></select></label> : <><label className="kuma-editor-field"><span>С</span><input onChange={(event) => setFromTs(event.target.value)} type="datetime-local" value={fromTs} /></label><label className="kuma-editor-field"><span>По</span><input onChange={(event) => setToTs(event.target.value)} type="datetime-local" value={toTs} /></label></>}<label className="kuma-editor-field"><span>Строк</span><select onChange={(event) => setPageSize(Number(event.target.value))} value={pageSize}><option value={50}>50</option><option value={100}>100</option><option value={250}>250</option></select></label></div>
      <div className="kuma-query-actions"><div><span className="kuma-query-chip">{source}</span><span className="kuma-query-chip">{rangeMode === "window" ? windowSize : "ручной диапазон"}</span><span className="kuma-query-chip">{filters.length} условий</span></div><div><IconButton icon="refresh" label="Повторить запрос" onClick={state.reload} /><Button icon="play" onClick={execute} tone="primary">Выполнить запрос</Button></div></div>
    </section>
    <div className="kuma-column-picker"><select aria-label="Сохраненные запросы" onChange={(event) => { setSelectedSavedId(event.target.value); const item = savedSearches.data?.items.find((candidate) => candidate.id === event.target.value); if (item) applySavedSearch(item); else setSavedName(""); }} value={selectedSavedId}><option value="">Сохраненные запросы</option>{(savedSearches.data?.items ?? []).map((item) => <option key={item.id} value={item.id}>{item.name}</option>)}</select><input aria-label="Имя запроса" onChange={(event) => setSavedName(event.target.value)} placeholder="Имя запроса" value={savedName} /><Button onClick={() => void saveSearch()}>{selectedSavedId ? "Обновить" : "Сохранить"}</Button>{selectedSavedId ? <Button onClick={async () => { try { await api.huntingDeleteSearch(selectedSavedId); setSelectedSavedId(""); setSavedName(""); savedSearches.reload(); notify("Сохраненный запрос удален", "healthy"); } catch (error) { notify(error instanceof Error ? error.message : String(error), "critical"); } }} tone="danger">Удалить</Button> : null}</div>
    {facetState.data ? <div className="kuma-column-picker">{Object.entries(facetState.data.facets).map(([facet, values]) => <div key={facet}><strong>{FACET_LABELS[facet] ?? facet}</strong>{values.slice(0, 5).map((item) => <Button key={item.value} onClick={() => addFilter(facet, item.value)} tone="ghost">{item.value} · {item.count.toLocaleString("ru-RU")}</Button>)}</div>)}</div> : null}
    <div className="kuma-results-toolbar"><div><h2>Результаты</h2><span>{typeof state.data?.total_count === "number" ? `${state.data.total_count.toLocaleString("ru-RU")} событий` : `${number(state.data?.row_count).toLocaleString("ru-RU")} на странице`} · страница {pageIndex + 1}</span></div><div><label className="kuma-auto-refresh"><input checked={includeCount} onChange={(event) => setIncludeCount(event.target.checked)} type="checkbox" /><span>Точное количество</span></label><Button onClick={() => { downloadTsv(data, visibleColumns); notify("Результат экспортирован в TSV", "healthy"); }}>Экспорт TSV</Button><IconButton active={columnPicker} icon="settings" label="Настроить столбцы" onClick={() => setColumnPicker((value) => !value)} /><IconButton disabled={pageIndex === 0} icon="previous" label="Предыдущая страница" onClick={() => setPageIndex((value) => Math.max(0, value - 1))} /><IconButton disabled={!state.data?.has_more || !state.data?.next_cursor} icon="next" label="Следующая страница" onClick={() => { const next = state.data?.next_cursor; if (!next) return; setCursorStack((current) => [...current.slice(0, pageIndex + 1), next]); setPageIndex((value) => value + 1); }} /></div></div>
    {columnPicker ? <div className="kuma-column-picker">{COLUMNS.map((column) => <label key={column.key}><input checked={visibleKeys.includes(column.key)} onChange={(event) => setVisibleKeys((current) => event.target.checked ? [...current, column.key] : current.length > 1 ? current.filter((key) => key !== column.key) : current)} type="checkbox" />{column.title}</label>)}</div> : null}
    {state.loading && !state.data ? <LoadingState label="Поиск событий..." /> : state.error ? <ErrorState error={state.error} retry={state.reload} /> : <EventGrid columns={visibleColumns} data={data} onOpen={setSelected} />}
    <DetailDrawer onClose={() => setSelected(null)} open={Boolean(selected)} title={selected ? `${text(selected.source ?? selected.log_source)} · ${formatTime(selected.ts)}` : "Событие"}>{detail ? <EventDetailContent event={detail.event as Row} /> : detailError ? <ErrorState error={detailError} retry={() => setSelected(selected ? { ...selected } : null)} /> : <LoadingState label="Загрузка карточки события..." />}</DetailDrawer>
  </div>;
}
