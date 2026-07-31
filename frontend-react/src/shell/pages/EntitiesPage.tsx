import { useCallback, useEffect, useMemo, useState } from "react";
import { api } from "../api";
import { AsyncGate } from "../async";
import { t, useShellContext } from "../context";
import { usePolledData } from "../hooks";
import { humanizeSourceName, humanizeTechnicalValue } from "../humanize";
import {
  DrawerFieldGrid,
  DrawerOverlay,
  InfoList,
  InvestigationActionRail,
  InvestigationSummaryStrip,
  InvestigationTimeline,
  KeyValue,
  PanelHeader,
  SectionIntro,
  SeverityBadge,
  StatCard,
  StatusBadge,
} from "../ui";
import type {
  BreakdownRecord,
  EntitiesResponse,
  EntityDetailResponse,
  EntityRecord,
  RiskSignalRecord,
} from "../types";

function humanizeEntityType(value: string, lang: "en" | "ru") {
  const normalized = String(value || "").trim().toLowerCase();
  const copy: Record<string, { en: string; ru: string }> = {
    host: { en: "Host", ru: "Хост" },
    user: { en: "User", ru: "Пользователь" },
    account: { en: "Account", ru: "Учетная запись" },
    process: { en: "Process", ru: "Процесс" },
    ip: { en: "IP address", ru: "IP-адрес" },
  };
  return copy[normalized]?.[lang] || normalized || (lang === "ru" ? "Сущность" : "Entity");
}

function humanizeEntityName(item: Partial<EntityRecord>, lang: "en" | "ru") {
  const raw = String(item.display_name || item.name || item.id || "").trim();
  const type = String(item.entity_type || "").trim().toLowerCase();
  if (!raw) return "";
  if (type === "host" || type === "ip") {
    return humanizeSourceName(raw, lang, { technicalSuffix: false }) || raw;
  }
  if (type === "user" || type === "account") {
    return humanizeTechnicalValue(raw, lang) || raw;
  }
  return raw;
}

function listToText(value: unknown) {
  return Array.isArray(value)
    ? value
        .map((item) => String(item || "").trim())
        .filter(Boolean)
        .join(", ")
    : "";
}

export function EntitiesPage() {
  const { lang, formatTimestamp } = useShellContext();
  const [refreshTick, setRefreshTick] = useState(0);
  const [selectedEntityId, setSelectedEntityId] = useState("");
  const [detailsOpen, setDetailsOpen] = useState(false);
  const [saveState, setSaveState] = useState("");
  const [signalForm, setSignalForm] = useState({
    entity_type: "host",
    entity_name: "",
    summary: "",
    kind: "rule_match",
    score: 25,
    severity: "medium",
    source: "react-shell",
    actor_ip: "",
    user_name: "",
    destination: "",
    outbound_destination: "",
    service: "",
    asset_id: "",
    indicator: "",
    vulnerability: "",
    process_name: "",
    parent_process: "",
  });
  const loadEntities = useCallback(() => {
    void refreshTick;
    return api.entities();
  }, [refreshTick]);
  const loadEntityDetail = useCallback(() => {
    void refreshTick;
    if (!selectedEntityId) {
      return Promise.resolve<EntityDetailResponse>({ item: null });
    }
    return api.entityDetail(selectedEntityId);
  }, [refreshTick, selectedEntityId]);
  const state = usePolledData<EntitiesResponse>(loadEntities, 30000);
  const detailState = usePolledData<EntityDetailResponse>(loadEntityDetail, 30000);
  const items = useMemo(() => state.data?.items || [], [state.data?.items]);
  const globalSignals = useMemo(() => state.data?.signals || [], [state.data?.signals]);
  const selected = useMemo(
    () => detailState.data?.item || items.find((item) => String(item.id) === selectedEntityId) || null,
    [detailState.data?.item, items, selectedEntityId],
  );

  useEffect(() => {
    if (!selectedEntityId && items.length) {
      setSelectedEntityId(String(items[0].id || ""));
    }
  }, [items, selectedEntityId]);

  const selectedSummary = useMemo(
    () =>
      selected
        ? [
            { label: "ID", value: selected.id, tone: "info" as const },
            { label: t(lang, { en: "Risk", ru: "Риск" }), value: <StatusBadge value={String(selected.risk_level || "none")} />, tone: String(selected.risk_level || "").toLowerCase() === "critical" ? ("critical" as const) : ("warning" as const) },
            { label: t(lang, { en: "Score", ru: "Скор" }), value: selected.risk_score || 0 },
            { label: t(lang, { en: "Signals", ru: "Сигналы" }), value: selected.signals_recent || 0 },
            { label: t(lang, { en: "Criticality", ru: "Критичность" }), value: <SeverityBadge value={String(selected.criticality || "medium")} /> },
            { label: t(lang, { en: "Last seen", ru: "Последняя активность" }), value: formatTimestamp(selected.last_seen_ts, "compact") },
          ]
        : [],
    [formatTimestamp, lang, selected],
  );

  const selectedActions = useMemo(() => {
    if (!selected) return [];
    const identity = encodeURIComponent(String(selected.display_name || selected.name || ""));
    return [
      { label: t(lang, { en: "Open events", ru: "Открыть события" }), href: `/app/events?q=${identity}` },
      { label: t(lang, { en: "Open incidents", ru: "Открыть инциденты" }), href: `/app/incidents?q=${identity}` },
      { label: t(lang, { en: "Open assets", ru: "Открыть активы" }), href: `/app/assets?q=${identity}` },
    ];
  }, [lang, selected]);

  const selectedTimeline = useMemo(() => {
    if (!selected) return [];
    const rawTimeline = Array.isArray(selected.timeline) ? selected.timeline : [];
    const normalized = rawTimeline.slice(0, 10).map((entry, index) => {
      const item = entry && typeof entry === "object" ? (entry as Record<string, unknown>) : {};
      return {
        id: `${selected.id}-${index}`,
        title: String(item.title || item.summary || item.kind || item.status || `Signal ${index + 1}`),
        subtitle: [item.entity_type, item.reason, item.note].filter(Boolean).join(" · "),
        meta: String(item.ts || item.observed_ts || item.last_seen_ts || item.created_ts || ""),
        tone: String(item.severity || item.risk_level || "").toLowerCase() === "critical" ? ("critical" as const) : ("warning" as const),
        body: [item.summary, item.message, item.description, item.score ? `score ${item.score}` : ""].filter(Boolean).join(" · "),
      };
    });
    return normalized;
  }, [selected]);

  async function addSignal() {
    setSaveState(t(lang, { en: "Recording signal...", ru: "Фиксирую сигнал..." }));
    try {
      const context = {
        ...(signalForm.actor_ip.trim() ? { actor_ip: signalForm.actor_ip.trim() } : {}),
        ...(signalForm.user_name.trim() ? { user_name: signalForm.user_name.trim() } : {}),
        ...(signalForm.destination.trim() ? { destination: signalForm.destination.trim() } : {}),
        ...(signalForm.outbound_destination.trim() ? { destination_ip: signalForm.outbound_destination.trim() } : {}),
        ...(signalForm.service.trim() ? { service: signalForm.service.trim() } : {}),
        ...(signalForm.asset_id.trim() ? { asset_id: signalForm.asset_id.trim() } : {}),
        ...(signalForm.indicator.trim() ? { indicator: signalForm.indicator.trim() } : {}),
        ...(signalForm.vulnerability.trim() ? { vulnerability: signalForm.vulnerability.trim() } : {}),
        ...(signalForm.process_name.trim() ? { process_name: signalForm.process_name.trim() } : {}),
        ...(signalForm.parent_process.trim() ? { parent_process: signalForm.parent_process.trim() } : {}),
      };
      const payload = await api.recordRiskSignal({
        entity_type: signalForm.entity_type,
        entity_name: signalForm.entity_name,
        summary: signalForm.summary,
        kind: signalForm.kind,
        score: signalForm.score,
        severity: signalForm.severity,
        source: signalForm.source || "react-shell",
        context,
      });
      setSaveState(`${t(lang, { en: "Signal recorded", ru: "Сигнал зафиксирован" })}: ${payload.entity?.display_name || payload.entity?.name}`);
      setSignalForm({
        entity_type: "host",
        entity_name: "",
        summary: "",
        kind: "rule_match",
        score: 25,
        severity: "medium",
        source: "react-shell",
        actor_ip: "",
        user_name: "",
        destination: "",
        outbound_destination: "",
        service: "",
        asset_id: "",
        indicator: "",
        vulnerability: "",
        process_name: "",
        parent_process: "",
      });
      setSelectedEntityId(String(payload.entity?.id || ""));
      setRefreshTick((value) => value + 1);
    } catch (error) {
      setSaveState(error instanceof Error ? error.message : t(lang, { en: "Signal failed", ru: "Не удалось зафиксировать сигнал" }));
    }
  }

  async function promoteToCase() {
    if (!selectedEntityId) return;
    setSaveState(t(lang, { en: "Promoting entity...", ru: "Поднимаю сущность в кейс..." }));
    try {
      const payload = await api.promoteEntityToCase(selectedEntityId, {});
      setSaveState(`${t(lang, { en: "Case created", ru: "Кейс создан" })}: ${payload.title}`);
      setRefreshTick((value) => value + 1);
    } catch (error) {
      setSaveState(error instanceof Error ? error.message : t(lang, { en: "Promotion failed", ru: "Не удалось создать кейс" }));
    }
  }

  const kpis = [
    {
      label: t(lang, { en: "Entities", ru: "Сущности" }),
      value: state.data?.metrics?.total || 0,
      hint: t(lang, { en: "Hosts, users, IPs and accounts linked to detections and cases.", ru: "Хосты, пользователи, IP-адреса и учетные записи, связанные с детектами и кейсами." }),
    },
    {
      label: t(lang, { en: "High risk", ru: "Высокий риск" }),
      value: state.data?.metrics?.high_risk || 0,
      hint: t(lang, { en: "Critical and high-risk entities by rolling score.", ru: "Критичные и высокорисковые сущности по накопленному риску." }),
    },
    {
      label: t(lang, { en: "Open signals", ru: "Открытые сигналы" }),
      value: state.data?.metrics?.open_signals || 0,
      hint: t(lang, { en: "Signals that still contribute to the current risk posture.", ru: "Сигналы, которые все еще влияют на текущую риск-позицию." }),
    },
    {
      label: t(lang, { en: "Promotion candidates", ru: "Кандидаты на кейс" }),
      value: state.data?.metrics?.promotion_candidates || 0,
      hint: t(lang, { en: "Signals eligible for insight-to-case promotion.", ru: "Сигналы, готовые к переводу в полноценный кейс." }),
    },
    {
      label: t(lang, { en: "Anomalous", ru: "Аномальные" }),
      value: state.data?.metrics?.anomalous_entities || 0,
      hint: t(lang, { en: "Entities with elevated anomaly score in UEBA v1.", ru: "Сущности с повышенным anomaly score в UEBA v1." }),
    },
    {
      label: t(lang, { en: "Privileged", ru: "Привилегированные" }),
      value: state.data?.metrics?.privileged_entities || 0,
      hint: t(lang, { en: "Entities heuristically treated as privileged or service identities.", ru: "Сущности, которые похожи на привилегированные или сервисные идентичности." }),
    },
    {
      label: t(lang, { en: "Graph edges", ru: "Связи графа" }),
      value: state.data?.metrics?.graph_edges || 0,
      hint: t(lang, { en: "Evidence graph relationships already materialized for investigation pivots.", ru: "Связи evidence graph, уже подготовленные для расследований." }),
    },
    {
      label: t(lang, { en: "Actor context", ru: "Контекст акторов" }),
      value: state.data?.metrics?.actor_context_ready || 0,
      hint: t(lang, { en: "Entities already carrying actor or source IP context.", ru: "Сущности, где уже есть actor/source IP контекст." }),
    },
    {
      label: t(lang, { en: "Destination context", ru: "Контекст направлений" }),
      value: state.data?.metrics?.destination_context_ready || 0,
      hint: t(lang, { en: "Entities with destination, service or outbound context.", ru: "Сущности, где уже есть destination/service/outbound контекст." }),
    },
    {
      label: t(lang, { en: "Indicator context", ru: "Контекст индикаторов" }),
      value: state.data?.metrics?.indicator_context_ready || 0,
      hint: t(lang, { en: "Entities already linked to threat indicators, hashes or IOC values.", ru: "Сущности, уже связанные с TI-индикаторами, хешами или IOC-значениями." }),
    },
    {
      label: t(lang, { en: "Vulnerability context", ru: "Контекст уязвимостей" }),
      value: state.data?.metrics?.vuln_context_ready || 0,
      hint: t(lang, { en: "Entities enriched with vulnerability or finding-key relationships.", ru: "Сущности, обогащенные связями с уязвимостями и finding-key." }),
    },
    {
      label: t(lang, { en: "Process lineage", ru: "Lineage процессов" }),
      value: state.data?.metrics?.process_lineage_ready || 0,
      hint: t(lang, { en: "Entities carrying process and parent-process lineage for investigations.", ru: "Сущности, где уже есть процесс и родительский процесс для расследования." }),
    },
    {
      label: t(lang, { en: "Outbound destinations", ru: "Исходящие направления" }),
      value: state.data?.metrics?.outbound_destination_ready || 0,
      hint: t(lang, { en: "Entities with materialized outbound hosts, domains or IP targets.", ru: "Сущности, где уже материализованы исходящие хосты, домены или IP-цели." }),
    },
    {
      label: t(lang, { en: "Behavioral models", ru: "Поведенческие модели" }),
      value: state.data?.metrics?.behavioral_models_ready || 0,
      hint: t(lang, { en: "Entities already covered by failed-auth, drift, rarity or lateral-movement signals.", ru: "Сущности, уже покрытые failed-auth, drift, rarity или lateral-movement сигналами." }),
    },
    {
      label: t(lang, { en: "Investigation ready", ru: "Готово к расследованию" }),
      value: state.data?.metrics?.investigation_ready || 0,
      hint: t(lang, { en: "Entities with enough context for a first-pass investigation pivot.", ru: "Сущности, по которым уже хватает контекста для первого расследовательского пивота." }),
    },
  ];

  return (
    <AsyncGate states={[state, detailState]} loadingMessage="Loading entities...">
      <div className="react-page">
        <SectionIntro
          kicker={t(lang, { en: "Entities", ru: "Сущности" })}
          title={t(lang, { en: "Entities and UEBA", ru: "Сущности и UEBA" })}
          subtitle={t(lang, {
            en: "Entity-centric layer with rolling risk score, signal accumulation, baseline and evidence graph.",
            ru: "Слой сущностей с накоплением риска, baseline-профилем и evidence graph для расследований.",
          })}
          icon="entities"
        />

        <div className="react-grid react-grid-4">
          {kpis.map((card) => (
            <StatCard key={card.label} label={card.label} value={card.value} hint={card.hint} />
          ))}
        </div>

        <div className="react-grid react-grid-4">
          <section className="react-card">
            <PanelHeader
              title={t(lang, { en: "Entity register", ru: "Реестр сущностей" })}
              subtitle={t(lang, { en: "Linked objects for users, hosts, IPs and service accounts.", ru: "Связанные объекты для пользователей, хостов, IP-адресов и сервисных учетных записей." })}
              icon="entities"
            />
            <div className="react-list">
              {items.map((item: EntityRecord) => (
                <button
                  type="button"
                  className={`react-card react-card-button ${selectedEntityId === item.id ? "active" : ""}`}
                  key={item.id}
                  onClick={() => {
                    setSelectedEntityId(String(item.id || ""));
                    setDetailsOpen(true);
                  }}
                >
                  <div className="react-card-button-header">
                    <div>
                      <strong>{humanizeEntityName(item, lang) || item.id}</strong>
                      <div className="react-card-button-copy">{humanizeEntityType(String(item.entity_type || ""), lang)}</div>
                    </div>
                    <StatusBadge value={String(item.risk_level || "none")} />
                  </div>
                  <div className="react-card-button-grid">
                    <span>{t(lang, { en: "Risk score", ru: "Риск-скор" })}</span>
                    <strong>{item.risk_score || 0}</strong>
                    <span>{t(lang, { en: "Signals", ru: "Сигналы" })}</span>
                    <strong>{item.signals_recent || 0}</strong>
                    <span>{t(lang, { en: "Last seen", ru: "Последняя активность" })}</span>
                    <strong>{formatTimestamp(item.last_seen_ts, "compact")}</strong>
                  </div>
                </button>
              ))}
            </div>
          </section>

          <section className="react-card">
            <PanelHeader
              title={t(lang, { en: "Record risk signal", ru: "Зафиксировать сигнал риска" })}
              subtitle={t(lang, { en: "Feed entity risk from weak or strong signals.", ru: "Пополняйте риск сущности слабыми и сильными сигналами." })}
              icon="control"
              actions={saveState ? <span className="react-inline-note">{saveState}</span> : undefined}
            />
            <div className="react-form-grid">
              <select className="react-select react-select-inline" value={signalForm.entity_type} onChange={(event) => setSignalForm((current) => ({ ...current, entity_type: event.target.value }))}>
                <option value="host">{t(lang, { en: "Host", ru: "Хост" })}</option>
                <option value="user">{t(lang, { en: "User", ru: "Пользователь" })}</option>
                <option value="ip">IP</option>
                <option value="account">{t(lang, { en: "Account", ru: "Учетная запись" })}</option>
                <option value="process">{t(lang, { en: "Process", ru: "Процесс" })}</option>
              </select>
              <input className="react-input" value={signalForm.entity_name} onChange={(event) => setSignalForm((current) => ({ ...current, entity_name: event.target.value }))} placeholder={t(lang, { en: "Entity name", ru: "Имя сущности" })} />
              <input className="react-input" value={signalForm.summary} onChange={(event) => setSignalForm((current) => ({ ...current, summary: event.target.value }))} placeholder={t(lang, { en: "Signal summary", ru: "Краткое описание сигнала" })} />
              <input className="react-input" value={signalForm.kind} onChange={(event) => setSignalForm((current) => ({ ...current, kind: event.target.value }))} placeholder={t(lang, { en: "Kind: failed_auth,rare_activity,lateral_movement", ru: "Тип: failed_auth,rare_activity,lateral_movement" })} />
              <input className="react-input" value={signalForm.source} onChange={(event) => setSignalForm((current) => ({ ...current, source: event.target.value }))} placeholder={t(lang, { en: "Source", ru: "Источник" })} />
              <input className="react-input" type="number" min={1} max={100} value={signalForm.score} onChange={(event) => setSignalForm((current) => ({ ...current, score: Number(event.target.value || 0) }))} />
              <select className="react-select react-select-inline" value={signalForm.severity} onChange={(event) => setSignalForm((current) => ({ ...current, severity: event.target.value }))}>
                <option value="critical">{t(lang, { en: "Critical", ru: "Критично" })}</option>
                <option value="high">{t(lang, { en: "High", ru: "Высоко" })}</option>
                <option value="medium">{t(lang, { en: "Medium", ru: "Средне" })}</option>
                <option value="low">{t(lang, { en: "Low", ru: "Низко" })}</option>
                <option value="info">{t(lang, { en: "Info", ru: "Инфо" })}</option>
              </select>
              <input className="react-input" value={signalForm.actor_ip} onChange={(event) => setSignalForm((current) => ({ ...current, actor_ip: event.target.value }))} placeholder={t(lang, { en: "Actor/source IP", ru: "Actor/source IP" })} />
              <input className="react-input" value={signalForm.user_name} onChange={(event) => setSignalForm((current) => ({ ...current, user_name: event.target.value }))} placeholder={t(lang, { en: "User / target user", ru: "Пользователь / target user" })} />
              <input className="react-input" value={signalForm.destination} onChange={(event) => setSignalForm((current) => ({ ...current, destination: event.target.value }))} placeholder={t(lang, { en: "Destination / host / domain", ru: "Назначение / хост / домен" })} />
              <input className="react-input" value={signalForm.outbound_destination} onChange={(event) => setSignalForm((current) => ({ ...current, outbound_destination: event.target.value }))} placeholder={t(lang, { en: "Outbound IP / destination IP", ru: "Исходящий IP / destination IP" })} />
              <input className="react-input" value={signalForm.service} onChange={(event) => setSignalForm((current) => ({ ...current, service: event.target.value }))} placeholder={t(lang, { en: "Service", ru: "Сервис" })} />
              <input className="react-input" value={signalForm.asset_id} onChange={(event) => setSignalForm((current) => ({ ...current, asset_id: event.target.value }))} placeholder="Asset ID / host_name" />
              <input className="react-input" value={signalForm.indicator} onChange={(event) => setSignalForm((current) => ({ ...current, indicator: event.target.value }))} placeholder={t(lang, { en: "Indicator / IOC / hash / URL", ru: "Индикатор / IOC / хеш / URL" })} />
              <input className="react-input" value={signalForm.vulnerability} onChange={(event) => setSignalForm((current) => ({ ...current, vulnerability: event.target.value }))} placeholder={t(lang, { en: "Vulnerability / CVE / finding", ru: "Уязвимость / CVE / finding" })} />
              <input className="react-input" value={signalForm.process_name} onChange={(event) => setSignalForm((current) => ({ ...current, process_name: event.target.value }))} placeholder={t(lang, { en: "Process", ru: "Процесс" })} />
              <input className="react-input" value={signalForm.parent_process} onChange={(event) => setSignalForm((current) => ({ ...current, parent_process: event.target.value }))} placeholder={t(lang, { en: "Parent process", ru: "Родительский процесс" })} />
              <button type="button" className="react-primary-button" onClick={addSignal}>{t(lang, { en: "Record signal", ru: "Записать сигнал" })}</button>
              <button type="button" className="react-link-button" onClick={promoteToCase}>{t(lang, { en: "Promote selected to case", ru: "Создать кейс по выбранной сущности" })}</button>
            </div>
          </section>

          <section className="react-card">
            <PanelHeader
              title={t(lang, { en: "Risk levels", ru: "Уровни риска" })}
              subtitle={t(lang, { en: "Current entity distribution by risk level.", ru: "Текущее распределение сущностей по уровню риска." })}
              icon="dashboard"
            />
            <InfoList items={(state.data?.breakdowns?.risk_level || []).map((item: BreakdownRecord) => ({ label: String(item.label || "unknown"), value: item.count || 0 }))} />
            <InfoList items={(state.data?.breakdowns?.entity_type || []).map((item: BreakdownRecord) => ({ label: `${t(lang, { en: "Type", ru: "Тип" })}: ${String(item.label || "unknown")}`, value: item.count || 0 }))} />
          </section>

          <section className="react-card">
            <PanelHeader
              title={t(lang, { en: "Recent signals", ru: "Недавние сигналы" })}
              subtitle={t(lang, { en: "Signals that contribute to the current risk state.", ru: "Сигналы, которые формируют текущую риск-позицию." })}
              icon="events"
            />
            <div className="react-list react-list-compact">
              {globalSignals.slice(0, 8).map((item: RiskSignalRecord) => (
                <div className="react-list-item" key={item.id}>
                  <strong>{item.entity_name}</strong>
                  <span>{item.summary || item.kind} / {item.score}</span>
                </div>
              ))}
            </div>
          </section>
        </div>

        <DrawerOverlay
          open={detailsOpen && Boolean(selected)}
          title={selected?.display_name || selected?.name || ""}
          subtitle={selected ? `${selected.entity_type} / ${selected.risk_level}` : ""}
          onClose={() => setDetailsOpen(false)}
        >
          {selected ? (
            <>
              <InvestigationSummaryStrip items={selectedSummary} />
              <InvestigationActionRail items={selectedActions} />

              <section className="react-card react-card-nested">
                <PanelHeader title={t(lang, { en: "Entity profile", ru: "Профиль сущности" })} subtitle={t(lang, { en: "Risk, criticality, linked cases and enrichment attributes.", ru: "Риск, критичность, связанные кейсы и атрибуты обогащения." })} icon="entities" />
                <DrawerFieldGrid>
                  <KeyValue label="ID" value={selected.id} />
                  <KeyValue label={t(lang, { en: "Risk level", ru: "Уровень риска" })} value={<StatusBadge value={String(selected.risk_level || "none")} />} />
                  <KeyValue label={t(lang, { en: "Risk score", ru: "Риск-скор" })} value={selected.risk_score || 0} />
                  <KeyValue label={t(lang, { en: "Criticality", ru: "Критичность" })} value={<SeverityBadge value={String(selected.criticality || "medium")} />} />
                  <KeyValue label={t(lang, { en: "Signals", ru: "Сигналы" })} value={selected.signals_recent || 0} />
                  <KeyValue label={t(lang, { en: "Last seen", ru: "Последняя активность" })} value={formatTimestamp(selected.last_seen_ts, "compact")} />
                </DrawerFieldGrid>
              </section>

              <section className="react-card react-card-nested">
                <PanelHeader title={t(lang, { en: "Behavior baseline", ru: "Поведенческий baseline" })} subtitle={t(lang, { en: "UEBA v1 summary for current entity posture.", ru: "Сводка UEBA v1 по текущей позиции сущности." })} icon="dashboard" />
                <DrawerFieldGrid>
                  <KeyValue label={t(lang, { en: "Peer group", ru: "Группа сравнения" })} value={String(selected.baseline?.peer_group || "n/a")} />
                  <KeyValue label={t(lang, { en: "Anomaly", ru: "Аномалия" })} value={Number(selected.baseline?.anomaly_score || 0)} />
                  <KeyValue label={t(lang, { en: "Novelty", ru: "Новизна" })} value={Number(selected.baseline?.novelty_score || 0)} />
                  <KeyValue label={t(lang, { en: "Behavior drift", ru: "Поведенческий drift" })} value={Number(selected.baseline?.behavior_drift_score || 0)} />
                  <KeyValue label={t(lang, { en: "Rare activity", ru: "Редкая активность" })} value={Number(selected.baseline?.rare_activity_score || 0)} />
                  <KeyValue label={t(lang, { en: "Failed auth", ru: "Неудачные входы" })} value={Number(selected.baseline?.failed_auth_count || 0)} />
                  <KeyValue label={t(lang, { en: "Expected/day", ru: "Ожидаемо/день" })} value={Number(selected.baseline?.expected_signals_per_day || 0)} />
                  <KeyValue label={t(lang, { en: "Privileged", ru: "Привилегированная" })} value={selected.baseline?.privileged ? "yes" : "no"} />
                  <KeyValue label={t(lang, { en: "Host telemetry", ru: "Host telemetry" })} value={selected.baseline?.host_telemetry_ready ? "yes" : "no"} />
                  <KeyValue label={t(lang, { en: "Lateral precursor", ru: "Признак lateral movement" })} value={selected.baseline?.lateral_movement_precursor ? "yes" : "no"} />
                  <KeyValue label={t(lang, { en: "Privilege precursor", ru: "Признак escalation" })} value={selected.baseline?.privilege_escalation_precursor ? "yes" : "no"} />
                </DrawerFieldGrid>
                <InfoList
                  items={[
                    { label: t(lang, { en: "Sources", ru: "Источники" }), value: listToText(selected.relationships?.sources) || "n/a" },
                    { label: t(lang, { en: "Actor IPs", ru: "IP акторов" }), value: listToText(selected.relationships?.actor_ips) || "n/a" },
                    { label: t(lang, { en: "Users", ru: "Пользователи" }), value: listToText(selected.relationships?.users) || "n/a" },
                    { label: t(lang, { en: "Destinations", ru: "Назначения" }), value: listToText(selected.relationships?.destinations) || "n/a" },
                    { label: t(lang, { en: "Outbound", ru: "Исходящие направления" }), value: listToText(selected.relationships?.outbound_destinations) || "n/a" },
                    { label: t(lang, { en: "Services", ru: "Сервисы" }), value: listToText(selected.relationships?.services) || "n/a" },
                    { label: t(lang, { en: "Assets", ru: "Активы" }), value: listToText(selected.relationships?.assets) || "n/a" },
                    { label: t(lang, { en: "Indicators", ru: "Индикаторы" }), value: listToText(selected.relationships?.indicators) || "n/a" },
                    { label: t(lang, { en: "Vulnerabilities", ru: "Уязвимости" }), value: listToText(selected.relationships?.vulnerabilities) || "n/a" },
                    { label: t(lang, { en: "Processes", ru: "Процессы" }), value: listToText(selected.relationships?.processes) || "n/a" },
                    { label: t(lang, { en: "Parent processes", ru: "Родительские процессы" }), value: listToText(selected.relationships?.parent_processes) || "n/a" },
                    { label: t(lang, { en: "Behavior findings", ru: "Поведенческие находки" }), value: listToText(selected.relationships?.behavioral_findings) || "n/a" },
                    { label: t(lang, { en: "Linked cases", ru: "Связанные кейсы" }), value: listToText(selected.relationships?.linked_cases) || "n/a" },
                  ]}
                />
              </section>

              <section className="react-card react-card-nested">
                <PanelHeader title={t(lang, { en: "Evidence graph", ru: "Evidence graph" })} subtitle={t(lang, { en: "Investigation nodes and relationships prepared for pivoting.", ru: "Узлы и связи расследования, подготовленные для дальнейших переходов." })} icon="builders" />
                <InfoList items={(selected.evidence_graph?.nodes || []).map((item: Record<string, unknown>) => ({ label: String(item.label || item.id || "node"), value: String(item.type || "node") }))} />
                <InfoList items={(selected.evidence_graph?.edges || []).map((item: Record<string, unknown>) => ({ label: `${String(item.source || "")} -> ${String(item.target || "")}`, value: String(item.label || "edge") }))} />
              </section>

              <section className="react-card react-card-nested">
                <PanelHeader title={t(lang, { en: "Hypotheses", ru: "Гипотезы" })} subtitle={t(lang, { en: "What an analyst should validate next.", ru: "Что аналитик должен проверить следующим шагом." })} icon="incidents" />
                <InfoList items={(selected.hypotheses || []).map((item: Record<string, unknown>, index: number) => ({ label: String(item.title || `hypothesis-${index + 1}`), value: `${Math.round(Number(item.confidence || 0) * 100)}% / ${String(item.rationale || "")}` }))} />
              </section>

              <section className="react-card react-card-nested">
                <PanelHeader title={t(lang, { en: "Investigation bundle", ru: "Набор расследования" })} subtitle={t(lang, { en: "Prepared pivots and summary fields for the analyst workflow.", ru: "Подготовленные pivots и summary-поля для analyst workflow." })} icon="docs" />
                <InfoList
                  items={[
                    { label: t(lang, { en: "Actors", ru: "Акторы" }), value: listToText(selected.investigation_bundle?.actors) || "n/a" },
                    { label: t(lang, { en: "Users", ru: "Пользователи" }), value: listToText(selected.investigation_bundle?.users) || "n/a" },
                    { label: t(lang, { en: "Destinations", ru: "Назначения" }), value: listToText(selected.investigation_bundle?.destinations) || "n/a" },
                    { label: t(lang, { en: "Services", ru: "Сервисы" }), value: listToText(selected.investigation_bundle?.services) || "n/a" },
                    { label: t(lang, { en: "Assets", ru: "Активы" }), value: listToText(selected.investigation_bundle?.assets) || "n/a" },
                    { label: t(lang, { en: "Indicators", ru: "Индикаторы" }), value: listToText(selected.investigation_bundle?.indicators) || "n/a" },
                    { label: t(lang, { en: "Vulnerabilities", ru: "Уязвимости" }), value: listToText(selected.investigation_bundle?.vulnerabilities) || "n/a" },
                    { label: t(lang, { en: "Processes", ru: "Процессы" }), value: listToText(selected.investigation_bundle?.processes) || "n/a" },
                    { label: t(lang, { en: "Parents", ru: "Родители" }), value: listToText(selected.investigation_bundle?.parent_processes) || "n/a" },
                    { label: t(lang, { en: "Behavior findings", ru: "Поведенческие находки" }), value: listToText(selected.investigation_bundle?.behavioral_findings) || "n/a" },
                    { label: t(lang, { en: "Pivot keys", ru: "Pivot keys" }), value: listToText(selected.investigation_bundle?.pivot_keys) || "n/a" },
                  ]}
                />
              </section>

              <section className="react-card react-card-nested">
                <PanelHeader title={t(lang, { en: "Linked cases", ru: "Связанные кейсы" })} subtitle={t(lang, { en: "Cases generated or linked from this entity.", ru: "Кейсы, созданные или привязанные к этой сущности." })} icon="cases" />
                <InfoList items={(selected.linked_cases || []).map((item) => ({ label: String(item), value: t(lang, { en: "linked", ru: "связано" }) }))} />
              </section>

              <InvestigationTimeline
                title={t(lang, { en: "Risk evidence timeline", ru: "Таймлайн риск-сигналов" })}
                subtitle={t(lang, { en: "Signal accumulation normalized into a readable investigation chain.", ru: "Накопление сигналов, приведенное к читаемой цепочке расследования." })}
                icon="events"
                items={selectedTimeline}
                emptyMessage={t(lang, { en: "Entity evidence timeline is not available.", ru: "Таймлайн сущности пока недоступен." })}
              />
            </>
          ) : null}
        </DrawerOverlay>
      </div>
    </AsyncGate>
  );
}
