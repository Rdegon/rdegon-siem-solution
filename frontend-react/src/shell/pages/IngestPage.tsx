import { useCallback, useEffect, useMemo, useState } from "react";
import { api } from "../api";
import { AsyncGate } from "../async";
import { t, useShellContext } from "../context";
import { usePolledData } from "../hooks";
import {
  DrawerFieldGrid,
  DrawerOverlay,
  InfoList,
  JsonPreview,
  KeyValue,
  PanelHeader,
  SectionIntro,
  StatCard,
  StatusBadge,
} from "../ui";
import type { IngestDlqRecord, IngestDlqResponse, IngestHeartbeatRecord, IngestHeartbeatResponse, IngestOverviewResponse } from "../types";

export function IngestPage() {
  const { lang, formatTimestamp } = useShellContext();
  const [refreshTick, setRefreshTick] = useState(0);
  const loadOverview = useCallback(() => {
    void refreshTick;
    return api.ingestOverview();
  }, [refreshTick]);
  const loadSources = useCallback(() => {
    void refreshTick;
    return api.ingestSources({ limit: 200 });
  }, [refreshTick]);
  const loadCollectors = useCallback(() => {
    void refreshTick;
    return api.ingestCollectors({ limit: 200 });
  }, [refreshTick]);
  const loadDlq = useCallback(() => {
    void refreshTick;
    return api.ingestDlq({ limit: 100 });
  }, [refreshTick]);
  const overview = usePolledData<IngestOverviewResponse>(loadOverview, 15000);
  const sources = usePolledData<IngestHeartbeatResponse>(loadSources, 20000);
  const collectors = usePolledData<IngestHeartbeatResponse>(loadCollectors, 20000);
  const dlq = usePolledData<IngestDlqResponse>(loadDlq, 12000);
  const [selectedDlqId, setSelectedDlqId] = useState("");
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [actionState, setActionState] = useState("");

  const dlqItems = useMemo(() => dlq.data?.items || [], [dlq.data?.items]);
  const selectedDlq = useMemo(
    () => dlqItems.find((item) => String(item.id) === selectedDlqId) || null,
    [dlqItems, selectedDlqId],
  );

  useEffect(() => {
    if (!selectedDlqId && dlqItems.length) {
      setSelectedDlqId(String(dlqItems[0].id || ""));
    }
  }, [dlqItems, selectedDlqId]);

  async function replaySelected(dlqId: string) {
    setActionState(t(lang, { en: "Replaying DLQ event...", ru: "Повторно отправляю DLQ-событие..." }));
    try {
      const payload = await api.replayIngestDlq({ ids: [dlqId] });
      setActionState(`${t(lang, { en: "Replay completed", ru: "Повторная отправка завершена" })}: ${payload.replayed || 0}`);
      setRefreshTick((value) => value + 1);
    } catch (error) {
      setActionState(error instanceof Error ? error.message : "Replay failed");
    }
  }

  async function replayOutstanding() {
    setActionState(t(lang, { en: "Replaying outstanding DLQ...", ru: "Повторно отправляю зависшие DLQ..." }));
    try {
      const payload = await api.replayIngestDlq({ limit: 20 });
      setActionState(`${t(lang, { en: "Replay batch completed", ru: "Пакетная повторная отправка завершена" })}: ${payload.replayed || 0}`);
      setRefreshTick((value) => value + 1);
    } catch (error) {
      setActionState(error instanceof Error ? error.message : "Replay failed");
    }
  }

  async function suppressOutstanding() {
    setActionState(t(lang, { en: "Suppressing non-operational DLQ...", ru: "Suppressing non-operational DLQ..." }));
    try {
      const payload = await api.suppressIngestDlq({ limit: 50 });
      setActionState(`suppressed ${payload.suppressed || 0}`);
      setRefreshTick((value) => value + 1);
    } catch (error) {
      setActionState(error instanceof Error ? error.message : "Suppress failed");
    }
  }

  async function remediateOutstanding() {
    setActionState(t(lang, { en: "Running DLQ remediation...", ru: "Running DLQ remediation..." }));
    try {
      const payload = await api.remediateIngestDlq({ replay_limit: 50, suppress_limit: 50 });
      setActionState(`replayed ${payload.replayed || 0}, suppressed ${payload.suppressed || 0}`);
      setRefreshTick((value) => value + 1);
    } catch (error) {
      setActionState(error instanceof Error ? error.message : "Remediation failed");
    }
  }

  const metrics = overview.data?.metrics || {};
  const sourceMetrics = sources.data?.metrics || {};
  const collectorMetrics = collectors.data?.metrics || {};
  const dlqMetrics = dlq.data?.metrics || {};
  const kpis = [
    {
      label: t(lang, { en: "Received", ru: "Получено" }),
      value: metrics.received_total || 0,
      hint: t(lang, { en: "All payloads observed by the ingest edge, including invalid ones.", ru: "Все payload, полученные на входном контуре, включая невалидные." }),
    },
    {
      label: t(lang, { en: "Accepted", ru: "Принято" }),
      value: metrics.accepted_total || 0,
      hint: t(lang, { en: "Events written to the raw stream for downstream processing.", ru: "События, записанные в сырой поток для дальнейшей обработки." }),
    },
    {
      label: t(lang, { en: "DLQ outstanding", ru: "DLQ в очереди" }),
      value: overview.data?.dlq?.outstanding || 0,
      hint: t(lang, { en: "Payloads waiting for replay or investigation.", ru: "Payload, ожидающие повторной отправки или расследования." }),
    },
    {
      label: t(lang, { en: "Active sources", ru: "Активные источники" }),
      value: metrics.active_sources || 0,
      hint: t(lang, { en: "Healthy and delayed sources seen in the recent window.", ru: "Источники в норме и с задержкой за недавнее окно." }),
    },
    {
      label: t(lang, { en: "Active collectors", ru: "Активные коллекторы" }),
      value: metrics.active_collectors || 0,
      hint: t(lang, { en: "Collectors currently producing or recently seen on the edge.", ru: "Коллекторы, которые сейчас пишут или недавно были активны." }),
    },
  ];

  return (
    <AsyncGate states={[overview, sources, collectors, dlq]} loadingMessage={t(lang, { en: "Loading ingest fabric...", ru: "Загрузка контура приема..." })}>
      <div className="react-page">
        <SectionIntro
          kicker={t(lang, { en: "Ingest", ru: "Прием данных" })}
          title={t(lang, { en: "Ingest fabric and replay", ru: "Контур приема и повторной отправки" })}
          subtitle={t(lang, {
            en: "Live ingest runtime with source heartbeat, collector health, dead-letter queue visibility and replay controls.",
            ru: "Живой контур приема с пульсом источников, состоянием коллекторов, видимостью очереди проблемных событий и управлением повторной отправкой.",
          })}
          icon="ingest"
          actions={
            <div className="react-actions react-wrap">
              <button type="button" className="react-primary-button" onClick={remediateOutstanding}>
                {t(lang, { en: "Remediate DLQ", ru: "Исправить DLQ" })}
              </button>
              <button type="button" className="react-link-button" onClick={replayOutstanding}>
                {t(lang, { en: "Replay outstanding", ru: "Повторить очередь" })}
              </button>
            </div>
          }
        />

        <div className="react-grid react-grid-5">
          {kpis.map((card) => (
            <StatCard key={card.label} label={card.label} value={card.value} hint={card.hint} />
          ))}
        </div>

        <div className="react-grid react-grid-4">
          <section className="react-card">
            <PanelHeader
              title={t(lang, { en: "Runtime issues", ru: "Проблемы runtime" })}
              subtitle={t(lang, { en: "Current ingest warnings aggregated from the edge service.", ru: "Текущие предупреждения контура приема, агрегированные входным сервисом." })}
              icon="incidents"
              actions={
                <div className="react-actions react-wrap">
                  <button type="button" className="react-link-button" onClick={replayOutstanding}>
                    {t(lang, { en: "Replay", ru: "Replay" })}
                  </button>
                  <button type="button" className="react-link-button" onClick={suppressOutstanding}>
                    {t(lang, { en: "Suppress", ru: "Suppress" })}
                  </button>
                  <button type="button" className="react-link-button" onClick={remediateOutstanding}>
                    {t(lang, { en: "Remediate", ru: "Remediate" })}
                  </button>
                  {actionState ? <span className="react-inline-note">{actionState}</span> : null}
                </div>
              }
            />
            <div className="react-list react-list-compact">
              {(overview.data?.issues || []).length ? (
                (overview.data?.issues || []).map((item: string, index: number) => (
                  <div className="react-list-item" key={`${item}-${index}`}>
                    <strong>{item}</strong>
                  </div>
                ))
              ) : (
                <div className="react-list-item">
                  <strong>{t(lang, { en: "No active ingest issues", ru: "Активных проблем контура приема нет" })}</strong>
                </div>
              )}
            </div>
          </section>

          <section className="react-card">
            <PanelHeader
              title={t(lang, { en: "Source heartbeat", ru: "Heartbeat источников" })}
              subtitle={t(lang, { en: "Live source health from the ingest edge, independent from ClickHouse.", ru: "Живое состояние источников на входном контуре, независимо от ClickHouse." })}
              icon="sources"
            />
            <InfoList
              items={(sources.data?.items || []).slice(0, 8).map((item: IngestHeartbeatRecord) => ({
                label: `${item.source || item.id || "unknown"}`,
                value: `${item.status || "unknown"} / ${item.events_total || 0}`,
              }))}
            />
          </section>

          <section className="react-card">
            <PanelHeader
              title={t(lang, { en: "Collector heartbeat", ru: "Heartbeat коллекторов" })}
              subtitle={t(lang, { en: "Per-profile collector health and recent stream activity.", ru: "Состояние профилей коллекторов и недавняя активность в потоке." })}
              icon="collectors"
            />
            <InfoList
              items={(collectors.data?.items || []).slice(0, 8).map((item: IngestHeartbeatRecord) => ({
                label: `${item.collector_profile || item.id || "unknown"}`,
                value: `${item.status || "unknown"} / ${item.events_total || 0}`,
              }))}
            />
          </section>

          <section className="react-card">
            <PanelHeader
              title={t(lang, { en: "Runtime summary", ru: "Сводка контура" })}
              subtitle={t(lang, { en: "High-level ingest counters and last activity markers.", ru: "Ключевые счетчики приема и маркеры последней активности." })}
              icon="dashboard"
            />
            <InfoList
              items={[
                { label: t(lang, { en: "Last event", ru: "Последнее событие" }), value: formatTimestamp(metrics.last_event_ts, "compact") },
                { label: t(lang, { en: "Last source", ru: "Последний источник" }), value: String(metrics.last_source || "n/a") },
                { label: t(lang, { en: "Last collector", ru: "Последний коллектор" }), value: String(metrics.last_collector || "n/a") },
                { label: t(lang, { en: "Parser errors", ru: "Ошибки парсинга" }), value: metrics.parser_errors_total || 0 },
                { label: t(lang, { en: "Replay count", ru: "Количество повторов" }), value: metrics.replayed_total || 0 },
                { label: t(lang, { en: "Suppressed", ru: "Подавлено" }), value: Number(dlqMetrics.hidden_resolved || dlqMetrics.suppressed || 0) },
              ]}
            />
          </section>
        </div>

        <div className="react-grid react-grid-4">
          <section className="react-card">
            <PanelHeader
              title={t(lang, { en: "DLQ queue", ru: "Очередь DLQ" })}
              subtitle={t(lang, { en: "Inspect dead-letter payloads and replay them after validation.", ru: "Просматривайте dead-letter payload и повторно отправляйте их после проверки." })}
              icon="events"
            />
            <div className="react-list">
              {dlqItems.length ? (
                dlqItems.map((item: IngestDlqRecord) => (
                  <button
                    type="button"
                    className={`react-card react-card-button ${selectedDlqId === item.id ? "active" : ""}`}
                    key={item.id}
                    onClick={() => {
                      setSelectedDlqId(String(item.id || ""));
                      setDrawerOpen(true);
                    }}
                  >
                    <div className="react-card-button-header">
                      <div>
                        <strong>{item.reason || item.id}</strong>
                        <div className="react-card-button-copy">{item.collector_profile || item.collector || "unknown-collector"}</div>
                      </div>
                      <StatusBadge value={String(item.replay?.status || "pending")} />
                    </div>
                    <div className="react-card-button-grid">
                      <span>{t(lang, { en: "Source", ru: "Источник" })}</span>
                      <strong>{item.source_ip || "n/a"}</strong>
                      <span>{t(lang, { en: "Time", ru: "Время" })}</span>
                      <strong>{formatTimestamp(item.ingest_ts, "compact")}</strong>
                      <span>{t(lang, { en: "Path", ru: "Путь" })}</span>
                      <strong>{item.ingest_path || "n/a"}</strong>
                    </div>
                  </button>
                ))
              ) : (
                <div className="react-list-item">
                  <strong>{t(lang, { en: "DLQ is empty", ru: "DLQ пуст" })}</strong>
                </div>
              )}
            </div>
          </section>

          <section className="react-card">
            <PanelHeader
              title={t(lang, { en: "Source metrics", ru: "Метрики источников" })}
              subtitle={t(lang, { en: "Operational breakdown for source heartbeat states.", ru: "Операционный срез по состояниям heartbeat источников." })}
              icon="sources"
            />
            <InfoList
              items={[
                { label: t(lang, { en: "Total", ru: "Всего" }), value: sourceMetrics.total || 0 },
                { label: t(lang, { en: "Healthy", ru: "Норма" }), value: sourceMetrics.healthy || 0 },
                { label: t(lang, { en: "Delayed", ru: "Задержка" }), value: sourceMetrics.delayed || 0 },
                { label: t(lang, { en: "Stale", ru: "Нет новых данных" }), value: sourceMetrics.stale || 0 },
                { label: t(lang, { en: "Events", ru: "События" }), value: sourceMetrics.events_total || 0 },
              ]}
            />
          </section>

          <section className="react-card">
            <PanelHeader
              title={t(lang, { en: "Collector metrics", ru: "Метрики коллекторов" })}
              subtitle={t(lang, { en: "Operational breakdown for collector runtime states.", ru: "Операционный срез по состояниям runtime коллекторов." })}
              icon="collectors"
            />
            <InfoList
              items={[
                { label: t(lang, { en: "Total", ru: "Всего" }), value: collectorMetrics.total || 0 },
                { label: t(lang, { en: "Healthy", ru: "Healthy" }), value: collectorMetrics.healthy || 0 },
                { label: t(lang, { en: "Delayed", ru: "Delayed" }), value: collectorMetrics.delayed || 0 },
                { label: t(lang, { en: "Stale", ru: "Stale" }), value: collectorMetrics.stale || 0 },
                { label: t(lang, { en: "Events", ru: "События" }), value: collectorMetrics.events_total || 0 },
              ]}
            />
          </section>

          <section className="react-card">
            <PanelHeader
              title={t(lang, { en: "DLQ metrics", ru: "Метрики DLQ" })}
              subtitle={t(lang, { en: "Outstanding, replayed and visible DLQ items.", ru: "Ожидающие, повторно отправленные и видимые элементы DLQ." })}
              icon="control"
            />
            <InfoList
              items={[
                { label: t(lang, { en: "Visible", ru: "Видимых" }), value: dlqMetrics.visible || 0 },
                { label: t(lang, { en: "Outstanding", ru: "Ожидают обработки" }), value: dlqMetrics.outstanding || 0 },
                { label: t(lang, { en: "Replayed", ru: "Повторно отправлено" }), value: dlqMetrics.replayed || 0 },
                { label: t(lang, { en: "Suppressed", ru: "Подавлено" }), value: Number(dlqMetrics.hidden_resolved || dlqMetrics.suppressed || 0) },
                { label: t(lang, { en: "Total", ru: "Всего" }), value: dlqMetrics.total || 0 },
              ]}
            />
          </section>
        </div>

        <DrawerOverlay
          open={drawerOpen && Boolean(selectedDlq)}
          title={selectedDlq?.reason || selectedDlq?.id || ""}
          subtitle={selectedDlq ? `${selectedDlq.collector_profile || selectedDlq.collector || "collector"} / ${selectedDlq.replay?.status || "pending"}` : ""}
          onClose={() => setDrawerOpen(false)}
        >
          {selectedDlq ? (
            <>
              <section className="react-card react-card-nested">
                <PanelHeader
                  title={t(lang, { en: "DLQ event profile", ru: "Профиль DLQ-события" })}
                  subtitle={t(lang, { en: "Envelope, collector metadata and replay state.", ru: "Envelope, метаданные коллектора и состояние replay." })}
                  icon="events"
                  actions={
                    <button type="button" className="react-primary-button" onClick={() => replaySelected(String(selectedDlq.id || ""))}>
                      {t(lang, { en: "Replay event", ru: "Повторить событие" })}
                    </button>
                  }
                />
                <DrawerFieldGrid>
                  <KeyValue label="ID" value={selectedDlq.id} />
                  <KeyValue label={t(lang, { en: "Reason", ru: "Причина" })} value={selectedDlq.reason || "n/a"} />
                  <KeyValue label={t(lang, { en: "Replay status", ru: "Статус replay" })} value={<StatusBadge value={String(selectedDlq.replay?.status || "pending")} />} />
                  <KeyValue label={t(lang, { en: "Collector", ru: "Коллектор" })} value={selectedDlq.collector_profile || selectedDlq.collector || "n/a"} />
                  <KeyValue label={t(lang, { en: "Source", ru: "Источник" })} value={selectedDlq.source_ip || "n/a"} />
                  <KeyValue label={t(lang, { en: "Ingest time", ru: "Время ingest" })} value={formatTimestamp(selectedDlq.ingest_ts, "compact")} />
                </DrawerFieldGrid>
              </section>

              <section className="react-card react-card-nested">
                <PanelHeader
                  title={t(lang, { en: "Payload", ru: "Payload" })}
                  subtitle={t(lang, { en: "Original dead-letter payload as captured on the edge.", ru: "Исходный dead-letter payload, захваченный на edge." })}
                  icon="docs"
                />
                <JsonPreview value={selectedDlq.payload} />
              </section>

              <section className="react-card react-card-nested">
                <PanelHeader
                  title={t(lang, { en: "Metadata", ru: "Метаданные" })}
                  subtitle={t(lang, { en: "Collector and source hints used during replay.", ru: "Подсказки о коллекторе и источнике, используемые при replay." })}
                  icon="control"
                />
                <JsonPreview value={{ metadata: selectedDlq.metadata || {}, replay: selectedDlq.replay || {} }} />
              </section>
            </>
          ) : null}
        </DrawerOverlay>
      </div>
    </AsyncGate>
  );
}
