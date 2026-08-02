import { useMemo, useState } from "react";
import { api } from "./runtime/api";
import type { DiscoveryCandidate, DiscoveryJob } from "./runtime/types";
import { formatTime, number, text, useQuery } from "./runtime/query";
import { Badge, Button, DetailDrawer, EmptyState, ErrorState, Icon, IconButton, LoadingState, PageHeader, SearchField, StatusCell, Tabs } from "./ui";

type Notify = (message: string, tone?: string) => void;
type DiscoveryTab = "new" | "known" | "connected" | "stale" | "low" | "all";

const DEFAULT_NETWORKS = "192.168.3.0/24, 10.20.10.0/24, 10.20.20.0/24, 10.20.30.0/24, 10.20.40.0/24";

function lifecycle(candidate: DiscoveryCandidate) {
  return text(candidate.lifecycle_state, candidate.connected ? "connected" : "known").toLowerCase();
}

function OnboardingPanel({ candidate, job, notify, onPrepared }: { candidate: DiscoveryCandidate; job: DiscoveryJob | null; notify: Notify; onPrepared: (job: DiscoveryJob) => void }) {
  const [busy, setBusy] = useState("");
  const [execution, setExecution] = useState<Record<string, unknown> | null>(null);
  async function prepare() {
    setBusy("prepare");
    try {
      const result = await api.prepareSourceOnboarding(candidate.id, { telemetry: ["os", "auth", "process", "application"] });
      if (result.job) onPrepared(result.job);
      notify("Пакет подключения подготовлен", "healthy");
    } catch (error) { notify(error instanceof Error ? error.message : String(error), "critical"); }
    finally { setBusy(""); }
  }
  async function dryRun() {
    if (!job?.id) return;
    setBusy("execute");
    try {
      const result = await api.executeSourceOnboarding(job.id, { dry_run: true });
      setExecution(result.execution ?? null); notify("Dry-run подключения выполнен", "healthy");
    } catch (error) { notify(error instanceof Error ? error.message : String(error), "critical"); }
    finally { setBusy(""); }
  }
  const commands = job?.command_preview ?? job?.network_commands ?? [];
  return <div className="discovery-onboarding"><div className="discovery-onboarding-head"><div><strong>Подключение источника</strong><span>{text(candidate.recommendation?.collector_profile, "Профиль будет выбран автоматически")}</span></div><Button disabled={Boolean(busy)} icon="play" onClick={() => void prepare()} tone="primary">{busy === "prepare" ? "Подготовка..." : job ? "Пересобрать" : "Подготовить"}</Button></div>
    {job ? <><div className="discovery-job-summary"><StatusCell value={text(job.status, "prepared")} /><span>{text(job.summary)}</span><small>{text(job.method)} · {formatTime(job.updated_ts ?? job.created_ts)}</small></div><div className="discovery-telemetry">{(job.telemetry_selection ?? job.requested_telemetry ?? []).map((item) => <Badge key={item} tone="info">{item}</Badge>)}</div>{commands.length ? <div className="command-preview"><header><strong>Команды для сервера</strong><Button icon="copy" onClick={() => { void navigator.clipboard.writeText(commands.join("\n\n")); notify("Команды скопированы", "healthy"); }}>Копировать</Button></header>{commands.map((command, index) => <pre key={index}>{command}</pre>)}</div> : null}<div className="discovery-execution-actions"><Button disabled={Boolean(busy)} onClick={() => void dryRun()}>Проверить без изменений</Button>{job.execution_supported ? <Badge tone="healthy">Автоустановка поддерживается</Badge> : <Badge tone="warning">Требуется запуск команд на узле</Badge>}</div>{execution ? <div className="operation-result"><Icon name="check" /><div><strong>{text(execution.summary, "Проверка завершена")}</strong><span>Статус: {text(execution.status, "completed")}</span></div></div> : null}</> : <p>Будет создан пакет с настройкой ОС, журналов аутентификации, процессов и прикладных логов. Сетевые web-порты сами по себе источником не считаются.</p>}
  </div>;
}

export function DiscoveryWorkspace({ notify }: { notify: Notify }) {
  const [tab, setTab] = useState<DiscoveryTab>("new");
  const [query, setQuery] = useState("");
  const [networks, setNetworks] = useState(DEFAULT_NETWORKS);
  const [selected, setSelected] = useState<DiscoveryCandidate | null>(null);
  const [preparedJobs, setPreparedJobs] = useState<Record<string, DiscoveryJob>>({});
  const [scanning, setScanning] = useState(false);
  const state = useQuery("discovery:inventory", () => api.sourceDiscovery({ limit: 1000 }), 30_000);
  const items = useMemo(() => state.data?.items ?? [], [state.data?.items]);
  const counts = useMemo(() => ({
    new: items.filter((item) => lifecycle(item) === "new" && item.log_capable !== false).length,
    known: items.filter((item) => lifecycle(item) === "known" && item.log_capable !== false).length,
    connected: items.filter((item) => lifecycle(item) === "connected" || item.connected).length,
    stale: items.filter((item) => lifecycle(item) === "stale").length,
    low: items.filter((item) => item.log_capable === false).length,
    all: items.length,
  }), [items]);
  const visible = items.filter((item) => {
    const matchesSearch = !query.trim() || `${item.ip} ${item.hostname} ${item.probable_role} ${item.connected_source}`.toLowerCase().includes(query.toLowerCase());
    if (!matchesSearch) return false;
    if (tab === "all") return true;
    if (tab === "low") return item.log_capable === false;
    if (tab === "connected") return lifecycle(item) === "connected" || Boolean(item.connected);
    return lifecycle(item) === tab && item.log_capable !== false;
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

  return <div className="native-page discovery-page"><PageHeader eyebrow="Машины, VM/LXC и контейнерные хосты" title="Обнаружение источников" actions={<><Button disabled={scanning} icon="search" onClick={() => void scan()} tone="primary">{scanning ? "Сканирование..." : "Запустить discovery"}</Button><IconButton icon="refresh" label="Обновить" onClick={state.reload} /></>} />
    <section className="discovery-scanbar"><label><span>Сегменты поиска</span><input onChange={(event) => setNetworks(event.target.value)} value={networks} /></label><small>80/443 показываются как низкоприоритетный контекст. Основной результат: узлы, способные передавать логи ОС и приложений.</small></section>
    <section className="metric-grid"><div className="metric"><span>Новые источники</span><strong>{counts.new}</strong><small>еще не подключены</small></div><div className="metric"><span>Подключены</span><strong>{counts.connected}</strong><small>пишут в SIEM</small></div><div className="metric"><span>Известные</span><strong>{counts.known}</strong><small>повторно обнаружены</small></div><div className="metric metric-warning"><span>Устаревшие</span><strong>{counts.stale}</strong><small>давно не наблюдались</small></div><div className="metric"><span>Только web-сервисы</span><strong>{counts.low}</strong><small>вынесены из основной очереди</small></div></section>
    <div className="discovery-filterbar"><Tabs items={[{ id: "new", label: "Новые", count: counts.new }, { id: "known", label: "Известные", count: counts.known }, { id: "connected", label: "Подключенные", count: counts.connected }, { id: "stale", label: "Устаревшие", count: counts.stale }, { id: "low", label: "Низкий приоритет", count: counts.low }, { id: "all", label: "Все", count: counts.all }]} label="Состояние находок" onChange={(value) => setTab(value as DiscoveryTab)} value={tab} /><SearchField onChange={setQuery} placeholder="Hostname, IP, роль или источник..." value={query} /></div>
    {state.loading && !state.data ? <LoadingState /> : state.error ? <ErrorState error={state.error} retry={state.reload} /> : visible.length ? <div className="native-grid discovery-grid"><table><thead><tr><th>Состояние</th><th>Узел</th><th>Тип</th><th>Готовность к логированию</th><th>Источники SIEM</th><th>Последнее наблюдение</th><th>Релевантность</th></tr></thead><tbody>{visible.map((item) => <tr className="sentinel-clickable-row" key={item.id} onClick={() => setSelected(item)}><td><StatusCell value={lifecycle(item)} /></td><td><strong>{text(item.hostname, item.ip)}</strong><small>{item.ip}</small></td><td>{text(item.os_family, "unknown")}<small>{text(item.probable_role)}</small></td><td><Badge tone={item.log_capable === false ? "warning" : "healthy"}>{item.log_capable === false ? "Только сетевой сервис" : text(item.recommendation?.collector_profile, "Можно подключить")}</Badge><small>{text(item.port_summary)}</small></td><td>{text(item.connected_source, "Не подключен")}</td><td>{formatTime(item.last_seen_ts)}</td><td><strong>{number(item.relevance_score)}</strong><small>{text(item.relevance_reason)}</small></td></tr>)}</tbody></table></div> : <EmptyState detail="Для выбранного состояния находок нет" />}
    <DetailDrawer actions={selected ? <Button icon="copy" onClick={() => { void navigator.clipboard.writeText(selected.ip); notify("IP скопирован", "healthy"); }}>Копировать IP</Button> : null} onClose={() => setSelected(null)} open={Boolean(selected)} title={selected ? text(selected.hostname, selected.ip) : "Источник"}>{selected ? <div className="discovery-detail"><div className="discovery-detail-summary"><div><span>IP</span><strong>{selected.ip}</strong></div><div><span>Состояние</span><StatusCell value={lifecycle(selected)} /></div><div><span>ОС / роль</span><strong>{text(selected.os_family)} · {text(selected.probable_role)}</strong></div><div><span>Порты</span><strong>{text(selected.port_summary, "Не определены")}</strong></div></div><OnboardingPanel candidate={selected} job={selectedJob} notify={notify} onPrepared={(job) => setPreparedJobs((current) => ({ ...current, [selected.id]: job }))} /></div> : null}</DetailDrawer>
  </div>;
}
