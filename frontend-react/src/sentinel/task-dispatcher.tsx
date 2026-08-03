import { useMemo, useState } from "react";
import type { View } from "./model";
import { api } from "./runtime/api";
import type { DiscoveryJob, GeneratedReportRecord, ResponseExecutionRecord, RetroscanRunRecord } from "./runtime/types";
import { formatTime, text, useQuery } from "./runtime/query";
import { Badge, Button, DetailDrawer, EmptyState, ErrorState, IconButton, LoadingState, PageHeader, SearchField, StatusCell, Tabs } from "./ui";
import { RecordDetails } from "./record-details";

type TaskKind = "report" | "response" | "discovery" | "retroscan";

export type TaskRow = {
  id: string;
  sourceId: string;
  kind: TaskKind;
  title: string;
  status: string;
  actor: string;
  createdTs: string;
  completedTs: string;
  durationMs?: number;
  progress?: number;
  raw: Record<string, unknown>;
};

type TaskFeed = {
  items: TaskRow[];
  issues: string[];
};

const kindLabels: Record<TaskKind, string> = {
  report: "Отчет",
  response: "SOAR",
  discovery: "Discovery",
  retroscan: "Retroscan",
};

function issueMessage(reason: unknown) {
  return reason instanceof Error ? reason.message : String(reason);
}

function reportTask(item: GeneratedReportRecord): TaskRow {
  return {
    id: `report:${item.id}`,
    sourceId: item.id,
    kind: "report",
    title: item.name || `Отчет ${item.id}`,
    status: item.status || "unknown",
    actor: item.owner || "system",
    createdTs: item.created_ts,
    completedTs: item.completed_ts,
    durationMs: item.duration_ms,
    raw: item as unknown as Record<string, unknown>,
  };
}

function responseTask(item: ResponseExecutionRecord): TaskRow {
  return {
    id: `response:${item.id}`,
    sourceId: item.id,
    kind: "response",
    title: text(item.message ?? item.action_id ?? item.kind, `Выполнение ${item.id}`),
    status: text(item.status, "unknown"),
    actor: text(item.actor, "system"),
    createdTs: text(item.created_ts),
    completedTs: text(item.executed_ts ?? item.approved_ts ?? item.rejected_ts),
    raw: item as Record<string, unknown>,
  };
}

function discoveryTask(item: DiscoveryJob): TaskRow {
  return {
    id: `discovery:${item.id}`,
    sourceId: item.id,
    kind: "discovery",
    title: text(item.summary ?? item.ip ?? item.candidate_id, `Discovery ${item.id}`),
    status: text(item.status, "unknown"),
    actor: text(item.method, "discovery"),
    createdTs: text(item.created_ts),
    completedTs: text(item.updated_ts),
    raw: item as Record<string, unknown>,
  };
}

export function retroscanTask(item: RetroscanRunRecord): TaskRow {
  const ruleCount = item.request?.rule_ids?.length ?? 0;
  return {
    id: `retroscan:${item.id}`,
    sourceId: item.id,
    kind: "retroscan",
    title: ruleCount ? `Retroscan · ${ruleCount} правил` : "Retroscan · все активные правила",
    status: text(item.status, "unknown"),
    actor: text(item.owner, "system"),
    createdTs: text(item.created_ts),
    completedTs: text(item.completed_ts),
    durationMs: item.duration_ms,
    progress: item.progress?.percent,
    raw: item as Record<string, unknown>,
  };
}

export function taskStatusGroup(status: string) {
  const value = status.toLowerCase();
  if (/fail|error|reject|cancel|dead|timeout/.test(value)) return "failed";
  if (/complete|success|done|finished|published|approved|dry_run|superseded|validated/.test(value)) return "completed";
  return "active";
}

export async function loadTaskFeed(): Promise<TaskFeed> {
  const [reports, response, discovery, retroscan] = await Promise.allSettled([
    api.generatedReports({ limit: 100 }),
    api.responseExecutions({ limit: 200 }),
    api.sourceDiscovery({ limit: 200 }),
    api.retroscanRuns({ limit: 200 }),
  ]);
  const issues: string[] = [];
  const items: TaskRow[] = [];

  if (reports.status === "fulfilled") items.push(...reports.value.items.map(reportTask));
  else issues.push(`Отчеты: ${issueMessage(reports.reason)}`);
  if (response.status === "fulfilled") items.push(...response.value.items.map(responseTask));
  else issues.push(`SOAR: ${issueMessage(response.reason)}`);
  if (discovery.status === "fulfilled") items.push(...discovery.value.jobs.map(discoveryTask));
  else issues.push(`Discovery: ${issueMessage(discovery.reason)}`);
  if (retroscan.status === "fulfilled") items.push(...retroscan.value.items.map(retroscanTask));
  else issues.push(`Retroscan: ${issueMessage(retroscan.reason)}`);

  items.sort((left, right) => Date.parse(right.createdTs || right.completedTs || "1970-01-01") - Date.parse(left.createdTs || left.completedTs || "1970-01-01"));
  return { items, issues };
}

function kindTone(kind: TaskKind) {
  return kind === "response" ? "critical" : kind === "discovery" ? "warning" : "info";
}

export function TaskDispatcherView({ navigate }: { navigate: (view: View) => void }) {
  const [status, setStatus] = useState("all");
  const [kind, setKind] = useState("all");
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState<TaskRow | null>(null);
  const state = useQuery("task-dispatcher", loadTaskFeed, 30_000);
  const rows = useMemo(() => (state.data?.items ?? []).filter((item) => {
    if (status !== "all" && taskStatusGroup(item.status) !== status) return false;
    if (kind !== "all" && item.kind !== kind) return false;
    return `${item.title} ${item.status} ${item.actor} ${item.sourceId}`.toLowerCase().includes(query.toLowerCase());
  }), [kind, query, state.data?.items, status]);
  const all = state.data?.items ?? [];
  const active = all.filter((item) => taskStatusGroup(item.status) === "active").length;
  const failed = all.filter((item) => taskStatusGroup(item.status) === "failed").length;
  const targetView: Record<TaskKind, View> = { report: "reports", response: "response", discovery: "discovery", retroscan: "rules" };

  return <div className="native-page task-dispatcher-page">
    <PageHeader eyebrow="Платформа · production operations" title="Диспетчер задач" actions={<IconButton icon="refresh" label="Обновить" onClick={state.reload} />} />
    {state.loading && !state.data ? <LoadingState label="Загрузка фоновых операций..." /> : null}
    {state.error ? <ErrorState error={state.error} retry={state.reload} /> : null}
    {state.data ? <>
      <section className="metric-grid">
        <div className="metric"><span>Всего операций</span><strong>{all.length}</strong><small>из production API</small></div>
        <div className="metric"><span>В работе</span><strong>{active}</strong><small>ожидают завершения</small></div>
        <div className={`metric ${failed ? "metric-critical" : ""}`}><span>С ошибкой</span><strong>{failed}</strong><small>требуют внимания</small></div>
        <div className="metric"><span>Контуры</span><strong>{new Set(all.map((item) => item.kind)).size}/4</strong><small>Reporting · SOAR · Discovery · Retroscan</small></div>
      </section>
      {state.data.issues.length ? <section className="task-feed-issues" role="status"><strong>Часть контуров недоступна</strong>{state.data.issues.map((issue) => <span key={issue}>{issue}</span>)}</section> : null}
      <div className="task-dispatcher-toolbar">
        <Tabs label="Статус задач" onChange={setStatus} value={status} items={[
          { id: "all", label: "Все", count: all.length },
          { id: "active", label: "В работе", count: active },
          { id: "completed", label: "Завершены", count: all.filter((item) => taskStatusGroup(item.status) === "completed").length },
          { id: "failed", label: "Ошибки", count: failed },
        ]} />
        <div><SearchField onChange={setQuery} placeholder="Операция, ID или исполнитель..." value={query} /><select aria-label="Тип операции" onChange={(event) => setKind(event.target.value)} value={kind}><option value="all">Все контуры</option><option value="report">Отчеты</option><option value="response">SOAR</option><option value="discovery">Discovery</option><option value="retroscan">Retroscan</option></select></div>
      </div>
      {!rows.length ? <EmptyState detail="Для выбранных фильтров фоновые операции не найдены." /> : <div className="native-grid task-dispatcher-table"><table><thead><tr><th>Контур</th><th>Операция</th><th>Статус</th><th>Исполнитель</th><th>Запущена</th><th>Завершена</th><th>Длительность</th></tr></thead><tbody>{rows.map((row) => <tr className="sentinel-clickable-row" key={row.id} onClick={() => setSelected(row)} onKeyDown={(event) => { if (event.key === "Enter" || event.key === " ") setSelected(row); }} tabIndex={0}><td><Badge tone={kindTone(row.kind)}>{kindLabels[row.kind]}</Badge></td><td><strong>{row.title}</strong><small>{row.sourceId}</small></td><td><StatusCell value={row.status} />{row.kind === "retroscan" && typeof row.progress === "number" ? <small>{row.progress}%</small> : null}</td><td>{row.actor}</td><td>{formatTime(row.createdTs)}</td><td>{formatTime(row.completedTs)}</td><td>{row.durationMs ? `${Math.round(row.durationMs / 100) / 10} с` : "—"}</td></tr>)}</tbody></table></div>}
    </> : null}
    <DetailDrawer actions={selected ? <Button onClick={() => { navigate(targetView[selected.kind]); setSelected(null); }} tone="primary">Открыть рабочий контур</Button> : null} eyebrow={selected ? kindLabels[selected.kind] : undefined} onClose={() => setSelected(null)} open={Boolean(selected)} title={selected?.title ?? "Операция"}>{selected ? <RecordDetails kind={selected.kind === "response" ? "soar" : selected.kind === "retroscan" ? "rule" : selected.kind} value={selected.raw} /> : null}</DetailDrawer>
  </div>;
}
