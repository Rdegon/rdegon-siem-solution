import { useCallback, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";
import { api } from "../api";
import { AsyncGate } from "../async";
import { usePolledData } from "../hooks";
import {
  BreakdownBars,
  DrawerFieldGrid,
  DrawerOverlay,
  InfoList,
  KeyValue,
  MetricStrip,
  PanelHeader,
  SectionIntro,
  SeverityBadge,
  StatusBadge,
  TimeScopeBar,
  WorkspaceSection,
} from "../ui";
import { t, useShellContext } from "../context";
import { refreshIntervalMs, refreshOptions, rowOptions, timeRangeOptions, timeScopeSummary } from "../timeControls";
import type { HostRuntimeOverviewResponse, HostRuntimeSnapshotRecord, HostRuntimeTargetRecord } from "../types";

function metricValue(value: unknown, digits = 0) {
  const numeric = Number(value || 0);
  return Number.isFinite(numeric) ? numeric.toLocaleString(undefined, { maximumFractionDigits: digits }) : "0";
}

function hostStatus(target: HostRuntimeTargetRecord) {
  if (target.stale) return "stale";
  const snapshot = target.snapshot || {};
  const memoryPressure = String(snapshot.memory_pressure_status || "").toLowerCase();
  const severePressure =
    Number(snapshot.cpu_pct || 0) >= 95 ||
    memoryPressure === "high" ||
    memoryPressure === "critical" ||
    Number(snapshot.disk_used_pct || 0) >= 95;
  if (severePressure) return "pressure";
  return "healthy";
}

function hostMetric(snapshot: HostRuntimeSnapshotRecord | undefined, key: keyof HostRuntimeSnapshotRecord) {
  const value = snapshot?.[key];
  if (typeof value === "number") {
    if (key === "load_ratio") {
      return metricValue(value, 2);
    }
    return `${metricValue(value, 1)}%`;
  }
  return "n/a";
}

function hostMemorySummary(snapshot: HostRuntimeSnapshotRecord | undefined) {
  if (!snapshot) return "n/a";
  const available = Number(snapshot.memory_available_pct || 0);
  const cache = Number(snapshot.memory_cache_pct || 0);
  const swap = Number(snapshot.swap_used_pct || 0);
  const pressure = String(snapshot.memory_pressure_status || "").trim();
  if (available > 0) {
    return `${metricValue(available, 1)}% avail | ${metricValue(cache, 1)}% cache | ${metricValue(swap, 1)}% swap${pressure ? ` | ${pressure}` : ""}`;
  }
  return `${metricValue(snapshot.memory_used_pct || 0, 1)}% used`;
}

function presetToHours(preset: string) {
  const mapping: Record<string, number> = {
    "15m": 1,
    "1h": 1,
    "6h": 6,
    "24h": 24,
    "72h": 72,
    "7d": 168,
    "30d": 720,
    all: 720,
  };
  return mapping[preset] || 24;
}

export function HostRuntimePage() {
  const { lang, formatTimestamp } = useShellContext();
  const [searchParams] = useSearchParams();
  const [windowPreset, setWindowPreset] = useState("24h");
  const [limit, setLimit] = useState("50");
  const [refreshSeconds, setRefreshSeconds] = useState("30");
  const [selectedHost, setSelectedHost] = useState("");
  const [drawerOpen, setDrawerOpen] = useState(false);
  const loadOverview = useCallback(
    () =>
      api.hostRuntimeOverview({
        hours: presetToHours(windowPreset),
        limit: Number(limit || 50),
      }),
    [limit, windowPreset],
  );
  const state = usePolledData<HostRuntimeOverviewResponse>(loadOverview, refreshIntervalMs(refreshSeconds));

  const targets = useMemo(() => state.data?.targets || [], [state.data?.targets]);
  const recentAlerts = useMemo(() => state.data?.recent_alerts || [], [state.data?.recent_alerts]);
  const runtimePolicies = useMemo(
    () => Object.entries(state.data?.policy?.event_overrides || {}).map(([eventType, policy]) => ({
      eventType,
      title: eventType.replace(/^host_/, "").replaceAll("_", " "),
      suppressionSeconds: Number(policy.suppression_seconds || 0),
      escalateAfter: Number(policy.escalate_after || 1),
      severity: String(policy.severity || "inherited"),
    })),
    [state.data?.policy?.event_overrides],
  );
  const metrics = state.data?.metrics || {};
  const eventTypeBreakdown = state.data?.breakdowns?.event_types || [];
  const requestedHost = String(searchParams.get("host") || "").trim();

  useEffect(() => {
    if (requestedHost && targets.some((item) => String(item.host_name || "") === requestedHost)) {
      setSelectedHost(requestedHost);
      setDrawerOpen(true);
      return;
    }
    if (!selectedHost && targets.length) {
      setSelectedHost(String(targets[0].host_name || ""));
    }
  }, [requestedHost, selectedHost, targets]);

  const selectedTarget = useMemo(
    () => targets.find((item) => String(item.host_name || "") === selectedHost) || null,
    [selectedHost, targets],
  );
  const hostAlerts = useMemo(
    () => recentAlerts.filter((item) => String(item.host_name || "") === selectedHost),
    [recentAlerts, selectedHost],
  );
  const hostRuntimeRangeOptions = useMemo(
    () => timeRangeOptions(lang).filter((item) => item.value !== "custom"),
    [lang],
  );

  const runtimeMetrics = [
    {
      label: t(lang, { en: "Protected hosts", ru: "Контролируемые хосты" }),
      value: targets.length,
      hint: t(lang, { en: "Hosts expected to publish runtime telemetry.", ru: "Хосты, которые должны публиковать телеметрию runtime." }),
      tone: "info" as const,
    },
    {
      label: t(lang, { en: "Stale targets", ru: "Устаревшие цели" }),
      value: metrics.stale_targets || 0,
      hint: t(lang, { en: "Targets beyond the stale telemetry window.", ru: "Хосты вне допустимого окна телеметрии." }),
      tone: Number(metrics.stale_targets || 0) > 0 ? ("critical" as const) : ("success" as const),
    },
    {
      label: t(lang, { en: "Snapshot events", ru: "Снимки состояния" }),
      value: metrics.snapshot_events || 0,
      hint: t(lang, { en: "Recent host runtime snapshot events.", ru: "Недавние события снимков состояния хостов." }),
      tone: "default" as const,
    },
    {
      label: t(lang, { en: "Pressure alerts", ru: "Сигналы давления" }),
      value: metrics.alert_events || 0,
      hint: t(lang, { en: "Pressure, stale and flapping alerts in the window.", ru: "Сигналы давления, устаревания и флаппинга в выбранном окне." }),
      tone: Number(metrics.alert_events || 0) > 0 ? ("warning" as const) : ("success" as const),
    },
    {
      label: t(lang, { en: "Real RAM pressure", ru: "Реальное давление RAM" }),
      value: metrics.pressure_targets || 0,
      hint: t(lang, { en: "Targets with low MemAvailable or real swap pressure.", ru: "Хосты с низким MemAvailable или реальным давлением по swap." }),
      tone: Number(metrics.pressure_targets || 0) > 0 ? ("warning" as const) : ("success" as const),
    },
    {
      label: t(lang, { en: "Stale after", ru: "Порог устаревания" }),
      value: `${metricValue(metrics.stale_after_seconds || 0)}s`,
      hint: t(lang, { en: "Configured stale telemetry threshold.", ru: "Настроенный порог устаревшей телеметрии." }),
      tone: "default" as const,
    },
  ];
  const hostRuntimeScopeSummary = timeScopeSummary(lang, {
    rangeLabel: t(lang, { en: "Runtime window", ru: "Окно runtime" }),
    refreshSeconds,
    rows: limit,
    fromTs: "",
    toTs: "",
  });

  return (
    <AsyncGate states={[state]} loadingMessage={t(lang, { en: "Loading host runtime workspace...", ru: "Загрузка рабочей области Host Runtime..." })}>
      <div className="react-page react-page-host-runtime">
        <SectionIntro
          kicker={t(lang, { en: "Host Runtime", ru: "Runtime хостов" })}
          title={t(lang, { en: "Platform host telemetry", ru: "Телеметрия состояния хостов" })}
          subtitle={t(lang, {
            en: "Operational workspace for CPU, memory, disk, load, swap, inode, stale telemetry and service flapping signals.",
            ru: "Рабочая область по CPU, RAM, диску, нагрузке, swap, inode, устареванию телеметрии и флаппингу сервисов.",
          })}
          icon="dashboard"
        />

        <TimeScopeBar
          rangeLabel={t(lang, { en: "Time range", ru: "Временной диапазон" })}
          rangeValue={windowPreset}
          rangeOptions={hostRuntimeRangeOptions}
          onRangeChange={setWindowPreset}
          refreshLabel={t(lang, { en: "Refresh", ru: "Обновление" })}
          refreshValue={refreshSeconds}
          refreshOptions={refreshOptions(lang)}
          onRefreshChange={setRefreshSeconds}
          rowsLabel={t(lang, { en: "Rows", ru: "Строк" })}
          rowsValue={limit}
          rowsOptions={rowOptions()}
          onRowsChange={setLimit}
          summary={hostRuntimeScopeSummary}
        />

        <MetricStrip items={runtimeMetrics} />

        <section className="react-card">
          <PanelHeader
            title={t(lang, { en: "Node state map", ru: "Карта состояния узлов" })}
            subtitle={t(lang, {
              en: "Operational cards for each monitored machine with a direct jump to its event stream.",
              ru: "Карточки контролируемых машин с прямым переходом к логам конкретного узла.",
            })}
            icon="collectors"
          />
          <div className="react-chip-grid">
            {targets.map((item) => {
              const hostName = String(item.host_name || "");
              return (
                <section key={`card-${hostName}`} className="react-chip-card">
                  <div className="react-card-button-header">
                    <div>
                      <div className="react-top-kicker">{item.host_role || "node"}</div>
                      <strong>{hostName || "unknown"}</strong>
                    </div>
                    <StatusBadge value={hostStatus(item)} />
                  </div>
                  <div className="react-card-button-grid">
                    <span>IP</span><strong>{item.host_ip || "n/a"}</strong>
                    <span>CPU</span><strong>{hostMetric(item.snapshot, "cpu_pct")}</strong>
                    <span>RAM</span><strong>{hostMemorySummary(item.snapshot)}</strong>
                    <span>Disk</span><strong>{hostMetric(item.snapshot, "disk_used_pct")}</strong>
                  </div>
                  <div className="react-actions react-wrap">
                    <button
                      type="button"
                      className="react-link-button"
                      onClick={() => {
                        setSelectedHost(hostName);
                        setDrawerOpen(true);
                      }}
                    >
                      {t(lang, { en: "Details", ru: "Детали" })}
                    </button>
                    <a className="react-link-button" href={`/events?host=${encodeURIComponent(hostName)}`}>
                      {t(lang, { en: "Host logs", ru: "Логи хоста" })}
                    </a>
                  </div>
                </section>
              );
            })}
          </div>
        </section>

        <div className="react-grid react-grid-3">
          <WorkspaceSection
            title={t(lang, { en: "Host targets", ru: "Целевые хосты" })}
            subtitle={t(lang, { en: "Current runtime status and last snapshot for each monitored node.", ru: "Текущее состояние и последний снимок по каждому узлу." })}
            icon="collectors"
            tone="emphasis"
          >
            <div className="react-table-wrap">
              <table className="react-table">
                <thead>
                  <tr>
                    <th>{t(lang, { en: "Host", ru: "Хост" })}</th>
                    <th>{t(lang, { en: "Role", ru: "Роль" })}</th>
                    <th>IP</th>
                    <th>{t(lang, { en: "Status", ru: "Статус" })}</th>
                    <th>CPU</th>
                    <th>Memory</th>
                    <th>Disk</th>
                    <th>{t(lang, { en: "Last seen", ru: "Последняя активность" })}</th>
                  </tr>
                </thead>
                <tbody>
                  {targets.map((item) => (
                    <tr
                      key={item.host_name}
                      onClick={() => {
                        setSelectedHost(String(item.host_name || ""));
                        setDrawerOpen(true);
                      }}
                    >
                      <td>
                        <strong>{item.host_name}</strong>
                      </td>
                      <td>{item.host_role || "generic"}</td>
                      <td>{item.host_ip || "n/a"}</td>
                      <td>
                        <StatusBadge value={hostStatus(item)} />
                      </td>
                      <td>{hostMetric(item.snapshot, "cpu_pct")}</td>
                      <td>{hostMemorySummary(item.snapshot)}</td>
                      <td>{hostMetric(item.snapshot, "disk_used_pct")}</td>
                      <td>{item.last_seen_ts ? formatTimestamp(item.last_seen_ts, "compact") : "n/a"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </WorkspaceSection>

          <WorkspaceSection
            title={t(lang, { en: "Recent alerts", ru: "Последние сигналы" })}
            subtitle={t(lang, { en: "Pressure, stale and flapping events that should correlate into incidents.", ru: "События давления, устаревания и флаппинга, которые должны подниматься в инциденты." })}
            icon="incidents"
          >
            <div className="react-table-wrap">
              <table className="react-table">
                <thead>
                  <tr>
                    <th>{t(lang, { en: "Time", ru: "Время" })}</th>
                    <th>{t(lang, { en: "Host", ru: "Хост" })}</th>
                    <th>{t(lang, { en: "Event", ru: "Событие" })}</th>
                    <th>{t(lang, { en: "Severity", ru: "Серьезность" })}</th>
                    <th>{t(lang, { en: "Message", ru: "Сообщение" })}</th>
                  </tr>
                </thead>
                <tbody>
                  {recentAlerts.map((item, index) => (
                    <tr
                      key={`${item.ts}-${item.host_name}-${index}`}
                      onClick={() => {
                        setSelectedHost(String(item.host_name || ""));
                        setDrawerOpen(true);
                      }}
                    >
                      <td>{item.ts ? formatTimestamp(item.ts, "compact") : "n/a"}</td>
                      <td>{item.host_name || "n/a"}</td>
                      <td>{item.event_type || "unknown"}</td>
                      <td>
                        <SeverityBadge value={String(item.severity || "info")} />
                      </td>
                      <td>{item.message || "n/a"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </WorkspaceSection>

          <WorkspaceSection
            title={t(lang, { en: "Signal quality policy", ru: "Политика качества сигналов" })}
            subtitle={`${t(lang, { en: "Effective suppression and escalation loaded by production host telemetry.", ru: "Фактические подавление и эскалация, загруженные production-телеметрией." })} ${state.data?.policy?.version || ""}`.trim()}
            icon="control"
          >
            <div className="react-table-wrap">
              <table className="react-table">
                <thead>
                  <tr>
                    <th>{t(lang, { en: "Signal", ru: "Сигнал" })}</th>
                    <th>{t(lang, { en: "Suppression", ru: "Подавление" })}</th>
                    <th>{t(lang, { en: "Escalate after", ru: "Эскалация после" })}</th>
                    <th>{t(lang, { en: "Severity", ru: "Серьезность" })}</th>
                  </tr>
                </thead>
                <tbody>
                  {runtimePolicies.map((item) => (
                    <tr key={item.eventType}>
                      <td>
                        <strong>{item.title}</strong>
                        <div className="react-card-button-copy">{item.eventType}</div>
                      </td>
                      <td>{item.suppressionSeconds}s</td>
                      <td>{item.escalateAfter}</td>
                      <td>
                        <SeverityBadge value={item.severity} />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </WorkspaceSection>
        </div>

        <div className="react-grid react-grid-2">
          <WorkspaceSection
            title={t(lang, { en: "Event breakdown", ru: "Разбивка событий" })}
            subtitle={t(lang, { en: "Current host-runtime event mix in the selected window.", ru: "Текущая смесь событий Host Runtime в выбранном окне." })}
            icon="events"
          >
            <BreakdownBars items={eventTypeBreakdown} />
          </WorkspaceSection>

          <WorkspaceSection
            title={t(lang, { en: "Escalation notes", ru: "Правила эскалации" })}
            subtitle={t(lang, { en: "Operator guidance for when runtime signals should become incidents instead of only health noise.", ru: "Операторская логика, когда сигналы runtime должны становиться инцидентами, а не просто шумом health-контура." })}
            icon="docs"
          >
            <InfoList
              items={[
                {
                  label: t(lang, { en: "Suppression", ru: "Подавление" }),
                  value: t(lang, {
                    en: "Dedup and suppression are enforced through the host runtime policy pack before repeated alerts escalate.",
                    ru: "Дедупликация и подавление применяются policy pack до эскалации повторяющихся сигналов.",
                  }),
                },
                {
                  label: t(lang, { en: "Escalation", ru: "Эскалация" }),
                  value: t(lang, {
                    en: "Repeated pressure and stale telemetry signals should promote into incidents, not remain only in health views.",
                    ru: "Повторяющиеся сигналы давления и устаревшей телеметрии должны переходить в инциденты, а не оставаться только в health-представлениях.",
                  }),
                },
                {
                  label: t(lang, { en: "Coverage", ru: "Покрытие" }),
                  value: t(lang, {
                    en: "Production contour expects ingest, processing, storage, control-plane and transport nodes in the monitored set.",
                    ru: "Рабочий контур ожидает в наборе мониторинга узлы приема, обработки, хранения, управления и транспорта.",
                  }),
                },
              ]}
            />
          </WorkspaceSection>
        </div>

        <DrawerOverlay
          open={Boolean(drawerOpen && selectedTarget)}
          title={selectedTarget?.host_name || ""}
          subtitle={selectedTarget?.host_role || ""}
          onClose={() => setDrawerOpen(false)}
        >
          {selectedTarget ? (
            <>
              <section className="react-card react-card-nested">
                <PanelHeader
                  title={t(lang, { en: "Current snapshot", ru: "Текущий снимок" })}
                  subtitle={t(lang, { en: "Latest telemetry sample for the selected host.", ru: "Последний телеметрический снимок для выбранного хоста." })}
                  icon="dashboard"
                />
                <DrawerFieldGrid>
                  <KeyValue label={t(lang, { en: "Role", ru: "Роль" })} value={selectedTarget.host_role || "generic"} />
                  <KeyValue label="IP" value={selectedTarget.host_ip || "n/a"} />
                  <KeyValue label={t(lang, { en: "Last seen", ru: "Последняя активность" })} value={selectedTarget.last_seen_ts ? formatTimestamp(selectedTarget.last_seen_ts, "full") : "n/a"} />
                  <KeyValue label="CPU" value={hostMetric(selectedTarget.snapshot, "cpu_pct")} />
                  <KeyValue label={t(lang, { en: "RAM used", ru: "Использование RAM" })} value={hostMetric(selectedTarget.snapshot, "memory_used_pct")} />
                  <KeyValue label="MemAvailable" value={hostMetric(selectedTarget.snapshot, "memory_available_pct")} />
                  <KeyValue label={t(lang, { en: "Cache", ru: "Кэш" })} value={hostMetric(selectedTarget.snapshot, "memory_cache_pct")} />
                  <KeyValue label={t(lang, { en: "Disk", ru: "Диск" })} value={hostMetric(selectedTarget.snapshot, "disk_used_pct")} />
                  <KeyValue label={t(lang, { en: "Load", ru: "Нагрузка" })} value={hostMetric(selectedTarget.snapshot, "load_ratio")} />
                  <KeyValue label="Swap" value={hostMetric(selectedTarget.snapshot, "swap_used_pct")} />
                  <KeyValue label={t(lang, { en: "Pressure", ru: "Давление" })} value={String(selectedTarget.snapshot?.memory_pressure_status || "healthy")} />
                  <KeyValue label="Inodes" value={hostMetric(selectedTarget.snapshot, "inode_used_pct")} />
                </DrawerFieldGrid>
              </section>

              <section className="react-card react-card-nested">
                <PanelHeader
                  title={t(lang, { en: "Related alerts", ru: "Связанные сигналы" })}
                  subtitle={t(lang, { en: "Recent pressure and stale telemetry events for this host.", ru: "Недавние события давления на ресурсы и устаревания телеметрии по этому хосту." })}
                  icon="incidents"
                />
                <div className="react-list react-list-compact">
                  {hostAlerts.length ? (
                    hostAlerts.map((item, index) => (
                      <div key={`${item.ts}-${index}`} className="react-list-item">
                        <strong>{item.event_type || "unknown"}</strong>
                        <span>{item.ts ? formatTimestamp(item.ts, "compact") : "n/a"}</span>
                        <span>{item.message || "n/a"}</span>
                      </div>
                    ))
                  ) : (
                    <div className="react-list-item">
                      <strong>{t(lang, { en: "No recent host-specific alerts", ru: "Нет недавних сигналов по этому хосту" })}</strong>
                    </div>
                  )}
                </div>
              </section>
            </>
          ) : null}
        </DrawerOverlay>
      </div>
    </AsyncGate>
  );
}
