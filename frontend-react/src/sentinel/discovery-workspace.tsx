import { useMemo, useState, type ReactNode } from "react";
import { api } from "./runtime/api";
import type { DiscoveryCandidate, DiscoveryJob, SourceMonitoringPolicyRecord } from "./runtime/types";
import { formatTime, number, text, useQuery } from "./runtime/query";
import { Badge, Button, DetailDrawer, EmptyState, ErrorState, IconButton, LoadingState, Modal, PageHeader, SearchField, StatusCell, Tabs } from "./ui";

type Notify = (message: string, tone?: string) => void;
type DiscoveryTab = "new" | "known" | "connected" | "stale" | "low_priority" | "all";

const DEFAULT_NETWORKS = "192.168.3.0/24, 10.20.10.0/24, 10.20.20.0/24, 10.20.30.0/24, 10.20.40.0/24";

function Field({ label, children, wide = false }: { label: string; children: ReactNode; wide?: boolean }) {
  return <label className={wide ? "wide" : ""}><span>{label}</span>{children}</label>;
}

function lifecycle(candidate: DiscoveryCandidate): DiscoveryTab {
  const value = text(candidate.lifecycle_state, candidate.connected ? "connected" : "known").toLowerCase();
  return value === "low" ? "low_priority" : value as DiscoveryTab;
}

function lifecycleLabel(value: string) {
  return ({ new: "Новый", known: "Известный", connected: "Подключен", stale: "Устарел", low_priority: "Низкий приоритет" } as Record<string, string>)[value] ?? value;
}

function onboardingLabel(value: unknown) {
  const state = text(value, "not_started").toLowerCase();
  return ({
    not_started: "Не начато",
    candidate: "Не начато",
    prepared: "Подготовлено",
    installing: "Установка / ожидание события",
    connected: "Событие принято",
    verified: "Событие нормализовано",
    failed: "Ошибка",
  } as Record<string, string>)[state] ?? state;
}

function healthLabel(value: unknown) {
  const state = text(value, "unknown").toLowerCase();
  return ({ healthy: "Норма", active: "Норма", observed: "Наблюдается", pending: "Ожидается", delayed: "Задержка", degraded: "Ошибка", stale: "Устарел", not_connected: "Нет данных", unknown: "Нет данных" } as Record<string, string>)[state] ?? state;
}

function lagLabel(seconds: unknown) {
  const value = number(seconds);
  if (value < 0) return "нет данных";
  if (value < 60) return `${value} с`;
  if (value < 3600) return `${Math.round(value / 60)} мин`;
  return `${Math.round(value / 3600)} ч`;
}

function OnboardingPanel({ candidate, job, notify, onJob, reload }: { candidate: DiscoveryCandidate; job: DiscoveryJob | null; notify: Notify; onJob: (job: DiscoveryJob) => void; reload: () => void }) {
  const [busy, setBusy] = useState("");
  const [execution, setExecution] = useState<Record<string, unknown> | null>(null);
  const [credentials, setCredentials] = useState<Record<string, string>>({});

  async function prepare() {
    setBusy("prepare");
    try {
      const result = await api.prepareSourceOnboarding(candidate.id, { requested_telemetry: ["os", "auth", "process", "application"] });
      if (result.job) onJob(result.job);
      notify("Пакет подключения подготовлен", "healthy");
      reload();
    } catch (error) { notify(error instanceof Error ? error.message : String(error), "critical"); }
    finally { setBusy(""); }
  }

  async function execute(dryRun: boolean) {
    if (!job?.id) return;
    setBusy(dryRun ? "dry-run" : "execute");
    try {
      const result = await api.executeSourceOnboarding(job.id, { dry_run: dryRun, credentials });
      if (result.job) onJob(result.job);
      setExecution(result.execution ?? null);
      notify(dryRun ? "Проверка пакета выполнена" : "Операция запущена; статус подтвердится только событием", "healthy");
      reload();
    } catch (error) {
      notify(error instanceof Error ? error.message : String(error), "critical");
      reload();
    } finally { setBusy(""); }
  }

  async function verify() {
    if (!job?.id) return;
    setBusy("verify");
    try {
      const result = await api.verifySourceOnboarding(job.id);
      if (result.job) onJob(result.job);
      notify(result.verified ? "Источник подтвержден нормализованным событием" : result.connected ? "Событие принято, нормализация еще не подтверждена" : "Production-событие от источника пока не найдено", result.verified ? "healthy" : "warning");
      reload();
    } catch (error) { notify(error instanceof Error ? error.message : String(error), "critical"); }
    finally { setBusy(""); }
  }

  const commands = job?.command_preview ?? job?.network_commands ?? [];
  const lastExecution = { ...(job?.last_execution ?? {}), ...(execution ?? {}) };
  const packageReady = lastExecution.delivery_stage === "package_ready" || Boolean((lastExecution.artifacts as Record<string, unknown> | undefined)?.zip_path);

  return <div className="discovery-onboarding">
    <div className="discovery-onboarding-head"><div><strong>Управляемое подключение</strong><span>{text(candidate.recommendation?.collector_profile, "Профиль будет выбран по типу источника")}</span></div>{!candidate.connected ? <Button disabled={Boolean(busy)} icon="play" onClick={() => void prepare()} tone="primary">{busy === "prepare" ? "Подготовка..." : job ? "Пересобрать" : "Подготовить"}</Button> : null}</div>
    {job ? <>
      <div className="discovery-job-summary"><StatusCell value={onboardingLabel(job.status ?? candidate.monitoring_status)} /><span>{text(job.summary)}</span><small>{text(job.method)} · {formatTime(job.updated_ts ?? job.created_ts)}</small></div>
      <div className="discovery-telemetry">{(job.telemetry_selection ?? job.requested_telemetry ?? []).map((item) => <Badge key={item} tone="info">{item}</Badge>)}</div>
      {commands.length ? <div className="command-preview"><header><strong>Команды и этапы установки</strong><Button icon="copy" onClick={() => { void navigator.clipboard.writeText(commands.join("\n\n")); notify("Команды скопированы", "healthy"); }}>Копировать</Button></header>{commands.map((command, index) => <pre key={index}>{command}</pre>)}</div> : null}
      {(job.credential_requirements ?? []).length ? <div className="kuma-form-grid">{job.credential_requirements?.map((field) => <Field key={field.id} label={text(field.label, field.id)}><input autoComplete="off" onChange={(event) => setCredentials((current) => ({ ...current, [text(field.id)]: event.target.value }))} type={field.id?.includes("password") ? "password" : field.id === "port" ? "number" : "text"} /></Field>)}</div> : null}
      <div className="discovery-execution-actions">
        <Button disabled={Boolean(busy)} onClick={() => void execute(true)}>Проверить пакет</Button>
        {job.execution_supported ? <Button disabled={Boolean(busy)} icon="play" onClick={() => void execute(false)} tone="primary">{busy === "execute" ? "Выполнение..." : job.method === "windows_onboarding_package" ? "Сформировать пакет" : "Применить"}</Button> : <Badge tone="warning">Ручная установка по командам</Badge>}
        <Button disabled={Boolean(busy)} onClick={() => void verify()}>{busy === "verify" ? "Проверка..." : "Проверить событие"}</Button>
        {packageReady ? <a className="sentinel-button" href={api.sourceOnboardingPackageUrl(job.id)}>Скачать пакет</a> : null}
      </div>
      {execution ? <div className="operation-result"><div><strong>{text(execution.summary, "Операция завершена")}</strong><span>Статус: {onboardingLabel(execution.status)}</span></div></div> : null}
    </> : <p>Подготовка использует штатный профиль Linux, Windows, контейнера или приложения. Успех установки не считается подключением, пока SIEM не увидит и не нормализует реальное событие.</p>}
  </div>;
}

function PolicyWorkspace({ notify }: { notify: Notify }) {
  const state = useQuery("discovery:source-policies", () => api.sourcePolicies(), 30_000);
  const [editing, setEditing] = useState<SourceMonitoringPolicyRecord | null>(null);

  async function save(form: HTMLFormElement) {
    const values = new FormData(form);
    try {
      await api.saveSourcePolicy({
        id: text(values.get("id"), `source-policy-${Date.now()}`),
        type: "source_monitoring_policy",
        name: text(values.get("name")),
        description: text(values.get("description")),
        enabled: values.get("enabled") === "on",
        source_pattern: text(values.get("source_pattern"), "*"),
        window_hours: number(values.get("window_hours") || 24),
        min_events: number(values.get("min_events")),
        max_events: number(values.get("max_events")),
        stale_after_minutes: number(values.get("stale_after_minutes") || 30),
        severity: text(values.get("severity"), "medium"),
        owner: text(values.get("owner"), "SOC"),
        notifications: [],
      });
      notify("Политика мониторинга сохранена", "healthy");
      setEditing(null);
      state.reload();
    } catch (error) { notify(error instanceof Error ? error.message : String(error), "critical"); }
  }

  async function remove(policy: SourceMonitoringPolicyRecord) {
    if (!window.confirm(`Удалить политику «${policy.name}»?`)) return;
    try { await api.deleteSourcePolicy(policy.id); notify("Политика удалена", "healthy"); state.reload(); }
    catch (error) { notify(error instanceof Error ? error.message : String(error), "critical"); }
  }

  return <section className="native-grid">
    <div className="native-actionbar"><div><strong>Политики доступности источников</strong><span>Порог событий и допустимое время без телеметрии</span></div><Button icon="plus" onClick={() => setEditing({ id: "", type: "source_monitoring_policy", name: "", description: "", enabled: true, source_pattern: "*", window_hours: 24, min_events: 1, max_events: 0, stale_after_minutes: 30, severity: "medium", notifications: [], owner: "SOC" })} tone="primary">Добавить</Button></div>
    {state.loading && !state.data ? <LoadingState /> : state.error ? <ErrorState error={state.error} retry={state.reload} /> : (state.data?.items ?? []).length ? <table><thead><tr><th>Состояние</th><th>Политика</th><th>Источники</th><th>Окно / stale</th><th>Порог</th><th>Нарушения</th><th>Действия</th></tr></thead><tbody>{state.data?.items.map((policy) => <tr key={policy.id}><td><StatusCell value={policy.enabled ? text(policy.evaluation_status, "active") : "disabled"} /></td><td><strong>{policy.name}</strong><small>{policy.description}</small></td><td>{policy.source_pattern}<small>{number(policy.matched_sources)} совпадений</small></td><td>{policy.window_hours} ч<small>{policy.stale_after_minutes} мин без событий</small></td><td>{policy.min_events}–{policy.max_events || "∞"}</td><td>{number(policy.violation_count)}</td><td><div className="discovery-execution-actions"><Button onClick={() => setEditing(policy)}>Изменить</Button><Button onClick={() => void remove(policy)}>Удалить</Button></div></td></tr>)}</tbody></table> : <EmptyState detail="Политики мониторинга еще не созданы" />}
    <Modal footer={<><Button onClick={() => setEditing(null)}>Отмена</Button><Button form="discovery-policy-form" tone="primary" type="submit">Сохранить</Button></>} onClose={() => setEditing(null)} open={Boolean(editing)} title={editing?.id ? "Редактирование политики" : "Новая политика"}>{editing ? <form className="kuma-form-grid" id="discovery-policy-form" onSubmit={(event) => { event.preventDefault(); void save(event.currentTarget); }}>
      <input name="id" type="hidden" value={editing.id} /><Field label="Название" wide><input defaultValue={editing.name} name="name" required /></Field><Field label="Описание" wide><textarea defaultValue={editing.description} name="description" rows={2} /></Field><Field label="Шаблон источника"><input defaultValue={editing.source_pattern} name="source_pattern" required /></Field><Field label="Владелец"><input defaultValue={editing.owner} name="owner" /></Field><Field label="Окно, часов"><input defaultValue={editing.window_hours} min="1" name="window_hours" type="number" /></Field><Field label="Stale, минут"><input defaultValue={editing.stale_after_minutes} min="1" name="stale_after_minutes" type="number" /></Field><Field label="Минимум событий"><input defaultValue={editing.min_events} min="0" name="min_events" type="number" /></Field><Field label="Максимум событий"><input defaultValue={editing.max_events} min="0" name="max_events" type="number" /></Field><Field label="Важность"><select defaultValue={editing.severity} name="severity"><option value="low">Low</option><option value="medium">Medium</option><option value="high">High</option><option value="critical">Critical</option></select></Field><Field label="Состояние"><label className="sentinel-checkbox"><input defaultChecked={editing.enabled !== false} name="enabled" type="checkbox" /> Активна</label></Field>
    </form> : null}</Modal>
  </section>;
}

export function DiscoveryWorkspace({ notify }: { notify: Notify }) {
  const [tab, setTab] = useState<DiscoveryTab>("new");
  const [mode, setMode] = useState("inventory");
  const [query, setQuery] = useState("");
  const [networks, setNetworks] = useState(DEFAULT_NETWORKS);
  const [selected, setSelected] = useState<DiscoveryCandidate | null>(null);
  const [preparedJobs, setPreparedJobs] = useState<Record<string, DiscoveryJob>>({});
  const [scanning, setScanning] = useState(false);
  const state = useQuery("discovery:inventory", () => api.sourceDiscovery({ limit: 1000 }), 30_000);
  const items = useMemo(() => state.data?.items ?? [], [state.data?.items]);
  const counts = useMemo(() => ({
    new: items.filter((item) => lifecycle(item) === "new").length,
    known: items.filter((item) => lifecycle(item) === "known").length,
    connected: items.filter((item) => lifecycle(item) === "connected").length,
    stale: items.filter((item) => lifecycle(item) === "stale").length,
    low_priority: items.filter((item) => lifecycle(item) === "low_priority").length,
    all: items.length,
  }), [items]);
  const visible = items.filter((item) => {
    const telemetry = item.source_telemetry ?? {};
    const matchesSearch = !query.trim() || `${item.ip} ${item.hostname} ${item.probable_role} ${item.connected_source} ${item.asset_id} ${item.segment_label} ${telemetry.collector} ${telemetry.collector_profile}`.toLowerCase().includes(query.toLowerCase());
    return matchesSearch && (tab === "all" || lifecycle(item) === tab);
  }).sort((left, right) => number(right.relevance_score) - number(left.relevance_score));
  const selectedJob = selected ? preparedJobs[selected.id] ?? state.data?.jobs?.find((job) => job.candidate_id === selected.id || job.id === selected.last_job_id) ?? null : null;

  async function scan() {
    const targets = networks.split(",").map((item) => item.trim()).filter(Boolean);
    if (!targets.length) { notify("Укажите хотя бы одну сеть", "critical"); return; }
    setScanning(true);
    try { await api.scanSourceDiscovery({ networks: targets, mode: "safe" }); notify("Discovery по сегментам завершен", "healthy"); state.reload(); }
    catch (error) { notify(error instanceof Error ? error.message : String(error), "critical"); }
    finally { setScanning(false); }
  }

  return <div className="native-page discovery-page"><PageHeader eyebrow="Хосты, VM/LXC, контейнеры и приложения" title="Обнаружение и мониторинг источников" actions={<><Button disabled={scanning} icon="search" onClick={() => void scan()} tone="primary">{scanning ? "Сканирование..." : "Запустить discovery"}</Button><IconButton icon="refresh" label="Обновить" onClick={state.reload} /></>} />
    <Tabs items={[{ id: "inventory", label: "Источники" }, { id: "policies", label: "Политики мониторинга" }]} label="Рабочая область discovery" onChange={setMode} value={mode} />
    {mode === "policies" ? <PolicyWorkspace notify={notify} /> : <>
      <section className="discovery-scanbar"><label><span>Сегменты поиска</span><input onChange={(event) => setNetworks(event.target.value)} value={networks} /></label><small>80/443 учитываются только как низкоприоритетный контекст. Основная очередь содержит системы, способные передавать журналы ОС, контейнеров и приложений.</small></section>
      <section className="metric-grid"><div className="metric"><span>Новые</span><strong>{counts.new}</strong><small>впервые обнаружены</small></div><div className="metric"><span>Подключены</span><strong>{counts.connected}</strong><small>есть свежее production-событие</small></div><div className="metric"><span>Известные</span><strong>{counts.known}</strong><small>наблюдались повторно</small></div><div className="metric metric-warning"><span>Устарели</span><strong>{counts.stale}</strong><small>нет свежей телеметрии</small></div><div className="metric"><span>Низкий приоритет</span><strong>{counts.low_priority}</strong><small>только обычные web-порты</small></div></section>
      <div className="discovery-filterbar"><Tabs items={[{ id: "new", label: "Новые", count: counts.new }, { id: "known", label: "Известные", count: counts.known }, { id: "connected", label: "Подключенные", count: counts.connected }, { id: "stale", label: "Устаревшие", count: counts.stale }, { id: "low_priority", label: "Низкий приоритет", count: counts.low_priority }, { id: "all", label: "Все", count: counts.all }]} label="Состояние источников" onChange={(value) => setTab(value as DiscoveryTab)} value={tab} /><SearchField onChange={setQuery} placeholder="Узел, IP, актив, сегмент, коллектор..." value={query} /></div>
      {state.loading && !state.data ? <LoadingState /> : state.error ? <ErrorState error={state.error} retry={state.reload} /> : visible.length ? <div className="native-grid discovery-grid"><table><thead><tr><th>Состояние</th><th>Источник</th><th>Актив / сегмент</th><th>Коллектор / профиль</th><th>Последнее событие / EPS</th><th>Обработка</th><th>Подключение</th></tr></thead><tbody>{visible.map((item) => { const telemetry = item.source_telemetry ?? {}; return <tr className="sentinel-clickable-row" key={item.id} onClick={() => setSelected(item)}><td><StatusCell value={lifecycleLabel(lifecycle(item))} /></td><td><strong>{text(item.hostname, item.ip)}</strong><small>{text(item.ip, item.probable_role)}</small></td><td>{text(item.asset_id, item.binding_target)}<small>{text(item.segment_label, "UNASSIGNED")}</small></td><td>{text(telemetry.collector, item.connected_source)}<small>{text(telemetry.collector_profile, item.recommendation?.collector_profile)}</small></td><td>{formatTime(telemetry.last_event_ts)}<small>{number(telemetry.eps).toFixed(3)} EPS · lag {lagLabel(telemetry.event_lag_seconds)}</small></td><td><span>Приём: {healthLabel(telemetry.ingest_health)}</span><small>Парсинг: {healthLabel(telemetry.parsing_health)} · нормализация: {healthLabel(telemetry.normalization_health)}</small></td><td><StatusCell value={onboardingLabel(item.monitoring_status)} /><small>{number(telemetry.accepted_total)} принято · {number(telemetry.rejected_total)} отклонено</small></td></tr>; })}</tbody></table></div> : <EmptyState detail="Для выбранного состояния источников нет" />}
      <DetailDrawer actions={selected ? <Button icon="copy" onClick={() => { void navigator.clipboard.writeText(selected.ip); notify("IP скопирован", "healthy"); }}>Копировать IP</Button> : null} onClose={() => setSelected(null)} open={Boolean(selected)} title={selected ? text(selected.hostname, selected.ip) : "Источник"}>{selected ? <div className="discovery-detail"><div className="discovery-detail-summary"><div><span>IP / актив</span><strong>{text(selected.ip)} · {text(selected.asset_id, selected.binding_target)}</strong></div><div><span>Сегмент</span><strong>{text(selected.segment_label, "UNASSIGNED")}</strong></div><div><span>Последнее событие</span><strong>{formatTime(selected.source_telemetry?.last_event_ts)}</strong></div><div><span>EPS / lag</span><strong>{number(selected.source_telemetry?.eps).toFixed(3)} · {lagLabel(selected.source_telemetry?.event_lag_seconds)}</strong></div><div><span>Приём / парсинг</span><strong>{healthLabel(selected.source_telemetry?.ingest_health)} · {healthLabel(selected.source_telemetry?.parsing_health)}</strong></div><div><span>Нормализация</span><strong>{healthLabel(selected.source_telemetry?.normalization_health)}</strong></div></div><OnboardingPanel candidate={selected} job={selectedJob} notify={notify} onJob={(job) => setPreparedJobs((current) => ({ ...current, [selected.id]: job }))} reload={state.reload} /></div> : null}</DetailDrawer>
    </>}
  </div>;
}
