import { useCallback, useEffect, useMemo, useState } from "react";
import { api } from "../api";
import { AsyncGate } from "../async";
import { t, useShellContext } from "../context";
import { useFeedback } from "../feedback";
import { usePolledData } from "../hooks";
import {
  BreakdownBars,
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
import type {
  ConnectorRecord,
  ConnectorRunRecord,
  ContentBundleRecord,
  HealthOverviewResponse,
  ResponseActionSummary,
  SavedSearchRecord,
} from "../types";

type BundleForm = {
  title: string;
  bundle_type: string;
  version: string;
  description: string;
  owner: string;
  release_ring: string;
  linked_pack_id: string;
  change_ticket: string;
  coverage_domains: string;
  personas: string;
};

const emptyBundleForm = (): BundleForm => ({
  title: "",
  bundle_type: "connector-pack",
  version: "1.0.0",
  description: "",
  owner: "soc-content",
  release_ring: "soc-core",
  linked_pack_id: "",
  change_ticket: "",
  coverage_domains: "",
  personas: "",
});

function asList(value: string) {
  return value
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);
}

function stringifyList(value: unknown) {
  return Array.isArray(value)
    ? value
        .map((item) => String(item || "").trim())
        .filter(Boolean)
        .join(", ")
    : "";
}

function percent(value: unknown) {
  return `${Number(value || 0).toFixed(1)}%`;
}

export function ConnectorsPage() {
  const { lang, formatTimestamp } = useShellContext();
  const { announce, pushToast } = useFeedback();
  const [refreshTick, setRefreshTick] = useState(0);
  const loadOverview = useCallback(() => {
    void refreshTick;
    return api.connectorsOverview();
  }, [refreshTick]);
  const loadHealth = useCallback<() => Promise<HealthOverviewResponse>>(() => {
    void refreshTick;
    return api.healthOverview();
  }, [refreshTick]);
  const loadSavedSearches = useCallback(() => {
    void refreshTick;
    return api.savedSearches();
  }, [refreshTick]);
  const loadBundles = useCallback(() => {
    void refreshTick;
    return api.contentBundles();
  }, [refreshTick]);
  const overview = usePolledData(loadOverview, 30000);
  const health = usePolledData<HealthOverviewResponse>(loadHealth, 45000);
  const savedSearches = usePolledData(loadSavedSearches, 60000);
  const bundlesState = usePolledData(loadBundles, 60000);
  const [selectedConnectorId, setSelectedConnectorId] = useState("");
  const [detailsOpen, setDetailsOpen] = useState(false);
  const [saveState, setSaveState] = useState("");
  const [actionState, setActionState] = useState("");
  const [bundleState, setBundleState] = useState("");
  const [createForm, setCreateForm] = useState({
    title: "",
    description: "",
    family: "source",
    source_family: "custom_api",
    group: "custom",
    mode: "push",
    request_url: "",
    request_method: "GET",
    token_env: "",
    owner: "integration-engineering",
    bundle_id: "integrations-enterprise-v2",
    release_stage: "validated",
    runbook_id: "",
    onboarding_template: "",
    support_tier: "enterprise",
    playbooks: "",
    compliance_controls: "",
    collection_depth: "expanded",
    coverage_score: 82,
    parsing_coverage_pct: 82,
    telemetry_quality_pct: 82,
    realtime: false,
    actor_ip_ready: true,
    entity_mapping_ready: true,
    host_telemetry_ready: false,
    event_families: "",
    evidence_fields: "",
    enrichment: "",
    investigation_pivots: "",
  });
  const [bundleForm, setBundleForm] = useState<BundleForm>(emptyBundleForm());
  const [announcedConnectors, setAnnouncedConnectors] = useState(-1);
  const connectors = useMemo(() => overview.data?.items || [], [overview.data?.items]);
  const responseActions = overview.data?.actions || [];
  const contentBundles = useMemo(
    () => bundlesState.data?.items || overview.data?.bundles || [],
    [bundlesState.data?.items, overview.data?.bundles],
  );
  const selectedConnector = useMemo(
    () => connectors.find((item) => String(item.id) === selectedConnectorId) || null,
    [connectors, selectedConnectorId],
  );
  const connectorRuns = useMemo(
    () => (overview.data?.recent_runs || []).filter((item) => !selectedConnectorId || String(item.connector_id) === selectedConnectorId),
    [overview.data, selectedConnectorId],
  );
  const postureGaps = useMemo(
    () =>
      Array.isArray(overview.data?.posture?.gaps)
        ? (overview.data?.posture?.gaps || []).map((item) => String(item || "").trim()).filter(Boolean)
        : [],
    [overview.data?.posture],
  );
  const issueQueue = useMemo(
    () => [...(health.data?.issues || []), ...postureGaps].slice(0, 12),
    [health.data?.issues, postureGaps],
  );

  useEffect(() => {
    if (!selectedConnectorId && connectors.length) {
      setSelectedConnectorId(String(connectors[0].id || ""));
    }
  }, [connectors, selectedConnectorId]);

  useEffect(() => {
    if (!overview.data || connectors.length === announcedConnectors) return;
    setAnnouncedConnectors(connectors.length);
    announce(
      t(lang, {
        en: `Connector runtime updated. ${connectors.length} connector definitions are visible.`,
        ru: `Контур коннекторов обновлён. Сейчас видно ${connectors.length} определений.`,
      }),
    );
  }, [announce, announcedConnectors, connectors.length, lang, overview.data]);

  async function createConnector() {
    setSaveState(t(lang, { en: "Saving connector...", ru: "Сохраняю коннектор..." }));
    try {
      const blockType = createForm.mode === "pull" ? "rest_pull" : createForm.mode === "poll" ? "sql_source" : "webhook_source";
      const requestUrl = createForm.request_url.trim();
      const payload = await api.saveConnector({
        title: createForm.title,
        description: createForm.description,
        family: createForm.family,
        source_family: createForm.source_family,
        group: createForm.group,
        mode: createForm.mode,
        block_type: blockType,
        runtime: requestUrl
          ? {
              request: {
                url: requestUrl,
                method: createForm.request_method,
                timeout_ms: 10000,
                ...(createForm.token_env.trim()
                  ? { auth: { type: "bearer", token_env: createForm.token_env.trim() } }
                  : {}),
              },
            }
          : {},
        secret_requirements: createForm.token_env.trim()
          ? [{ env: createForm.token_env.trim(), label: createForm.token_env.trim(), required: true }]
          : [],
        telemetry: {
          collection_depth: createForm.collection_depth,
          coverage_score: Number(createForm.coverage_score || 0),
          parsing_coverage_pct: Number(createForm.parsing_coverage_pct || 0),
          telemetry_quality_pct: Number(createForm.telemetry_quality_pct || 0),
          realtime: Boolean(createForm.realtime),
          actor_ip_ready: Boolean(createForm.actor_ip_ready),
          entity_mapping_ready: Boolean(createForm.entity_mapping_ready),
          host_telemetry_ready: Boolean(createForm.host_telemetry_ready),
          event_families: asList(createForm.event_families),
          evidence_fields: asList(createForm.evidence_fields),
          enrichment: asList(createForm.enrichment),
          investigation_pivots: asList(createForm.investigation_pivots),
        },
        operations: {
          owner: createForm.owner,
          bundle_id: createForm.bundle_id,
          release_stage: createForm.release_stage,
          runbook_id: createForm.runbook_id,
          onboarding_template: createForm.onboarding_template,
          support_tier: createForm.support_tier,
          playbooks: asList(createForm.playbooks),
          compliance_controls: asList(createForm.compliance_controls),
        },
      });
      pushToast({
        title: t(lang, { en: "Connector saved", ru: "Коннектор сохранён" }),
        message: payload.title,
        tone: "success",
      });
      setSaveState(`${t(lang, { en: "Saved", ru: "Сохранён" })}: ${payload.title}`);
      setSelectedConnectorId(String(payload.id || ""));
      setRefreshTick((value) => value + 1);
      setCreateForm({
        title: "",
        description: "",
        family: "source",
        source_family: "custom_api",
        group: "custom",
        mode: "push",
        request_url: "",
        request_method: "GET",
        token_env: "",
        owner: "integration-engineering",
        bundle_id: "integrations-enterprise-v2",
        release_stage: "validated",
        runbook_id: "",
        onboarding_template: "",
        support_tier: "enterprise",
        playbooks: "",
        compliance_controls: "",
        collection_depth: "expanded",
        coverage_score: 82,
        parsing_coverage_pct: 82,
        telemetry_quality_pct: 82,
        realtime: false,
        actor_ip_ready: true,
        entity_mapping_ready: true,
        host_telemetry_ready: false,
        event_families: "",
        evidence_fields: "",
        enrichment: "",
        investigation_pivots: "",
      });
    } catch (error) {
      const message = error instanceof Error ? error.message : "Save failed";
      setSaveState(message);
      pushToast({
        title: t(lang, { en: "Connector save failed", ru: "Не удалось сохранить коннектор" }),
        message,
        tone: "error",
      });
    }
  }

  async function saveBundle() {
    setBundleState(t(lang, { en: "Saving bundle...", ru: "Сохраняю пакет..." }));
    try {
      const payload = await api.saveContentBundle({
        title: bundleForm.title,
        bundle_type: bundleForm.bundle_type,
        version: bundleForm.version,
        description: bundleForm.description,
        owner: bundleForm.owner,
        release_ring: bundleForm.release_ring,
        linked_pack_id: bundleForm.linked_pack_id,
        change_ticket: bundleForm.change_ticket,
        coverage_domains: asList(bundleForm.coverage_domains),
        personas: asList(bundleForm.personas),
        quality_gates: {
          schema: true,
          replay: true,
          detections: true,
          approvals: true,
        },
      });
      setBundleState(`${t(lang, { en: "Saved", ru: "Сохранён" })}: ${payload.title}`);
      pushToast({
        title: t(lang, { en: "Bundle saved", ru: "Пакет сохранён" }),
        message: String(payload.title || payload.id || ""),
        tone: "success",
      });
      setBundleForm(emptyBundleForm());
      setRefreshTick((current) => current + 1);
    } catch (error) {
      const message = error instanceof Error ? error.message : "Bundle save failed";
      setBundleState(message);
      pushToast({
        title: t(lang, { en: "Bundle save failed", ru: "Не удалось сохранить пакет" }),
        message,
        tone: "error",
      });
    }
  }

  async function promoteBundle(bundleId: string, stage: string) {
    setBundleState(t(lang, { en: "Promoting bundle...", ru: "Продвигаю пакет..." }));
    try {
      const payload = await api.promoteContentBundle(bundleId, {
        stage,
        release_notes: `${stage} via react-shell`,
      });
      setBundleState(`${t(lang, { en: "Promoted", ru: "Продвинут" })}: ${payload.title} -> ${payload.stage}`);
      pushToast({
        title: t(lang, { en: "Bundle promoted", ru: "Пакет продвинут" }),
        message: `${payload.title} -> ${payload.stage}`,
        tone: "success",
      });
      setRefreshTick((current) => current + 1);
    } catch (error) {
      const message = error instanceof Error ? error.message : "Bundle promotion failed";
      setBundleState(message);
      pushToast({
        title: t(lang, { en: "Promotion failed", ru: "Продвижение не удалось" }),
        message,
        tone: "error",
      });
    }
  }

  async function runConnector(connectorId: string) {
    setActionState(t(lang, { en: "Running dry test...", ru: "Запускаю пробный прогон..." }));
    try {
      const payload = await api.runConnector(connectorId, { dry_run: true, trigger: "ui" });
      pushToast({
        title: t(lang, { en: "Dry run completed", ru: "Пробный прогон завершён" }),
        message: payload.run?.connector_id || connectorId,
        tone: "success",
      });
      setActionState(`${t(lang, { en: "Dry run completed", ru: "Пробный прогон завершён" })}: ${payload.run?.connector_id || connectorId}`);
      setRefreshTick((value) => value + 1);
    } catch (error) {
      const message = error instanceof Error ? error.message : "Dry run failed";
      setActionState(message);
      pushToast({
        title: t(lang, { en: "Dry run failed", ru: "Пробный прогон завершился ошибкой" }),
        message,
        tone: "error",
      });
    }
  }

  async function runAction(actionId: string) {
    setActionState(t(lang, { en: "Executing action...", ru: "Выполняю действие..." }));
    try {
      const payload = await api.executeResponseAction(actionId, { dry_run: true, payload: { source: "react-shell" } });
      pushToast({
        title: t(lang, { en: "Action accepted", ru: "Действие принято" }),
        message: payload.execution?.status || actionId,
        tone: "success",
      });
      setActionState(`${t(lang, { en: "Action accepted", ru: "Действие принято" })}: ${payload.execution?.status || actionId}`);
      setRefreshTick((value) => value + 1);
    } catch (error) {
      const message = error instanceof Error ? error.message : "Action failed";
      setActionState(message);
      pushToast({
        title: t(lang, { en: "Action failed", ru: "Не удалось выполнить действие" }),
        message,
        tone: "error",
      });
    }
  }

  const metrics = overview.data?.metrics || {};
  const kpis = [
    {
      label: t(lang, { en: "Connectors", ru: "Коннекторы" }),
      value: metrics.total || 0,
      hint: t(lang, { en: "Registered inbound and outbound connector definitions.", ru: "Зарегистрированные входящие и исходящие определения коннекторов." }),
    },
    {
      label: t(lang, { en: "Telemetry coverage", ru: "Покрытие телеметрии" }),
      value: percent(metrics.telemetry_coverage_avg),
      hint: t(lang, { en: "Average depth and field quality across the connector estate.", ru: "Средняя глубина и качество полей по всему контуру коннекторов." }),
    },
    {
      label: t(lang, { en: "Enterprise ready", ru: "Enterprise ready" }),
      value: metrics.enterprise_ready || 0,
      hint: t(lang, { en: "Connectors with realtime, actor IP and evidence contracts in place.", ru: "Коннекторы с realtime, IP акторов и evidence-контрактом." }),
    },
    {
      label: t(lang, { en: "Evidence ready", ru: "Готовы к расследованию" }),
      value: metrics.evidence_ready || 0,
      hint: t(lang, { en: "Connectors already exposing evidence fields for investigations.", ru: "Коннекторы, которые уже отдают evidence-поля для расследований." }),
    },
    {
      label: t(lang, { en: "Managed by bundle", ru: "Под bundle lifecycle" }),
      value: metrics.managed_by_bundle || 0,
      hint: t(lang, { en: "Definitions already tied to content lifecycle and release rings.", ru: "Определения, уже привязанные к lifecycle контента и release ring." }),
    },
    {
      label: t(lang, { en: "Ecosystem present", ru: "Домены экосистемы" }),
      value: metrics.ecosystem_present || 0,
      hint: t(lang, { en: "Required enterprise connector domains already represented in the estate.", ru: "Обязательные enterprise-домены коннекторов, уже представленные в контуре." }),
    },
    {
      label: t(lang, { en: "Live domains", ru: "Live-домены" }),
      value: metrics.ecosystem_live_ready || 0,
      hint: t(lang, { en: "Required connector domains that are already release-gate ready.", ru: "Обязательные домены коннекторов, уже готовые к live по release gate." }),
    },
  ];

  return (
    <AsyncGate
      states={[overview, health, savedSearches, bundlesState]}
      loadingMessage={t(lang, { en: "Loading connector runtime...", ru: "Загрузка контура коннекторов..." })}
    >
      <div className="react-page">
        <SectionIntro
          kicker={t(lang, { en: "Connectors", ru: "Коннекторы" })}
          title={t(lang, { en: "Connector runtime and content operations", ru: "Контур коннекторов и content operations" })}
          subtitle={t(lang, {
            en: "Operational layer for connectors, telemetry contracts, release bundles and outbound hooks.",
            ru: "Операционный слой для коннекторов, контрактов телеметрии, release-пакетов и исходящих хуков.",
          })}
          icon="connectors"
        />

        <div className="react-grid react-grid-5">
          {kpis.map((card) => (
            <StatCard key={card.label} label={card.label} value={card.value} hint={card.hint} />
          ))}
        </div>

        <div className="react-grid react-grid-4">
          <section className="react-card">
            <PanelHeader
              title={t(lang, { en: "Connector registry", ru: "Реестр коннекторов" })}
              subtitle={t(lang, { en: "Definitions, telemetry depth and dry-run control surface.", ru: "Определения, глубина телеметрии и плоскость пробного прогона." })}
              icon="connectors"
            />
            <div className="react-list">
              {connectors.map((item: ConnectorRecord) => (
                <button
                  type="button"
                  className={`react-card react-card-button ${selectedConnectorId === item.id ? "active" : ""}`}
                  key={item.id}
                  onClick={() => {
                    setSelectedConnectorId(String(item.id || ""));
                    setDetailsOpen(true);
                  }}
                >
                  <div className="react-card-button-header">
                    <div>
                      <strong>{item.title}</strong>
                      <div className="react-card-button-copy">{item.description}</div>
                    </div>
                    <StatusBadge value={String(item.status || "planned")} />
                  </div>
                  <div className="react-card-button-grid">
                    <span>{t(lang, { en: "Depth", ru: "Глубина" })}</span>
                    <strong>{String(item.telemetry?.collection_depth || "basic")}</strong>
                    <span>{t(lang, { en: "Coverage", ru: "Покрытие" })}</span>
                    <strong>{Number(item.telemetry?.coverage_score || 0)}</strong>
                    <span>{t(lang, { en: "Bundle", ru: "Bundle" })}</span>
                    <strong>{String(item.operations?.bundle_id || "n/a")}</strong>
                  </div>
                </button>
              ))}
            </div>
          </section>

          <section className="react-card">
            <PanelHeader
              title={t(lang, { en: "Runtime actions", ru: "Действия runtime" })}
              subtitle={t(lang, { en: "Dry-run connectors and outbound playbooks from the shell.", ru: "Запускайте пробные прогоны коннекторов и исходящих плейбуков прямо из shell." })}
              icon="control"
              actions={actionState ? <span className="react-inline-note">{actionState}</span> : undefined}
            />
            <div className="react-list react-list-compact">
              {connectors.slice(0, 6).map((item: ConnectorRecord) => (
                <button type="button" className="react-list-item" key={`run-${item.id}`} onClick={() => runConnector(String(item.id || ""))}>
                  <strong>{item.title}</strong>
                  <span>{t(lang, { en: "Dry-run connector", ru: "Пробный прогон коннектора" })}</span>
                </button>
              ))}
              {responseActions.map((item: ResponseActionSummary) => (
                <button type="button" className="react-list-item" key={`action-${item.id}`} onClick={() => runAction(String(item.id || ""))}>
                  <strong>{item.title}</strong>
                  <span>{t(lang, { en: "Dry-run outbound action", ru: "Пробный прогон исходящего действия" })}</span>
                </button>
              ))}
            </div>
          </section>

          <section className="react-card">
            <PanelHeader
              title={t(lang, { en: "Secret readiness", ru: "Готовность секретов" })}
              subtitle={t(lang, { en: "Readiness inventory only. Secret values never leave the backend.", ru: "Только инвентарь готовности. Значения секретов backend не отдаёт." })}
              icon="docs"
            />
            <InfoList
              items={(health.data?.secrets?.items || []).slice(0, 8).map((item) => ({
                label: item.label,
                value: `${item.status}${item.required ? ` / ${t(lang, { en: "required", ru: "обязательно" })}` : ""}`,
              }))}
            />
          </section>

          <section className="react-card">
            <PanelHeader
              title={t(lang, { en: "Issue queue", ru: "Очередь проблем" })}
              subtitle={t(lang, { en: "Cross-plane health and connector posture gaps.", ru: "Сводные рабочие проблемы и posture-gap по контуру коннекторов." })}
              icon="incidents"
            />
            <div className="react-list react-list-compact">
              {issueQueue.length ? (
                issueQueue.map((item, index) => (
                  <div className="react-list-item" key={`${item}-${index}`}>
                    <strong>{item}</strong>
                  </div>
                ))
              ) : (
                <div className="react-list-item">
                  <strong>{t(lang, { en: "No active issues", ru: "Активных проблем нет" })}</strong>
                </div>
              )}
            </div>
          </section>
        </div>

        <div className="react-grid react-grid-4">
          <section className="react-card">
            <PanelHeader
              title={t(lang, { en: "Create connector", ru: "Создать коннектор" })}
              subtitle={t(lang, { en: "Seed a custom connector directly in the control plane.", ru: "Создайте собственное определение коннектора прямо в control plane." })}
              icon="control"
              actions={saveState ? <span className="react-inline-note">{saveState}</span> : undefined}
            />
            <div className="react-form-grid">
              <input className="react-input" value={createForm.title} onChange={(event) => setCreateForm((current) => ({ ...current, title: event.target.value }))} placeholder={t(lang, { en: "Connector title", ru: "Название коннектора" })} />
              <input className="react-input" value={createForm.description} onChange={(event) => setCreateForm((current) => ({ ...current, description: event.target.value }))} placeholder={t(lang, { en: "Description", ru: "Описание" })} />
              <select className="react-select react-select-inline" value={createForm.family} onChange={(event) => setCreateForm((current) => ({ ...current, family: event.target.value }))}>
                <option value="source">{t(lang, { en: "source", ru: "источник" })}</option>
                <option value="action">{t(lang, { en: "action", ru: "действие" })}</option>
              </select>
              <input className="react-input" value={createForm.source_family} onChange={(event) => setCreateForm((current) => ({ ...current, source_family: event.target.value }))} placeholder={t(lang, { en: "Source family", ru: "Семейство источника" })} />
              <input className="react-input" value={createForm.group} onChange={(event) => setCreateForm((current) => ({ ...current, group: event.target.value }))} placeholder={t(lang, { en: "Group", ru: "Группа" })} />
              <select className="react-select react-select-inline" value={createForm.mode} onChange={(event) => setCreateForm((current) => ({ ...current, mode: event.target.value }))}>
                <option value="push">push</option>
                <option value="pull">pull</option>
                <option value="poll">poll</option>
                <option value="output">output</option>
              </select>
              <input className="react-input" value={createForm.request_url} onChange={(event) => setCreateForm((current) => ({ ...current, request_url: event.target.value }))} placeholder={t(lang, { en: "Runtime URL", ru: "URL для runtime" })} />
              <select className="react-select react-select-inline" value={createForm.request_method} onChange={(event) => setCreateForm((current) => ({ ...current, request_method: event.target.value }))}>
                <option value="GET">GET</option>
                <option value="POST">POST</option>
              </select>
              <input className="react-input" value={createForm.token_env} onChange={(event) => setCreateForm((current) => ({ ...current, token_env: event.target.value }))} placeholder={t(lang, { en: "Token env (optional)", ru: "Переменная окружения для токена (опционально)" })} />
              <input className="react-input" value={createForm.owner} onChange={(event) => setCreateForm((current) => ({ ...current, owner: event.target.value }))} placeholder={t(lang, { en: "Owner", ru: "Владелец" })} />
              <input className="react-input" value={createForm.bundle_id} onChange={(event) => setCreateForm((current) => ({ ...current, bundle_id: event.target.value }))} placeholder="Bundle ID" />
              <select className="react-select react-select-inline" value={createForm.release_stage} onChange={(event) => setCreateForm((current) => ({ ...current, release_stage: event.target.value }))}>
                <option value="draft">draft</option>
                <option value="validated">validated</option>
                <option value="staged">staged</option>
                <option value="active">active</option>
              </select>
              <input className="react-input" value={createForm.runbook_id} onChange={(event) => setCreateForm((current) => ({ ...current, runbook_id: event.target.value }))} placeholder="Runbook ID" />
              <input className="react-input" value={createForm.onboarding_template} onChange={(event) => setCreateForm((current) => ({ ...current, onboarding_template: event.target.value }))} placeholder={t(lang, { en: "Onboarding template", ru: "Шаблон onboarding" })} />
              <select className="react-select react-select-inline" value={createForm.support_tier} onChange={(event) => setCreateForm((current) => ({ ...current, support_tier: event.target.value }))}>
                <option value="community">community</option>
                <option value="enterprise">enterprise</option>
              </select>
              <input className="react-input" value={createForm.playbooks} onChange={(event) => setCreateForm((current) => ({ ...current, playbooks: event.target.value }))} placeholder={t(lang, { en: "Playbooks", ru: "Плейбуки" })} />
              <input className="react-input" value={createForm.compliance_controls} onChange={(event) => setCreateForm((current) => ({ ...current, compliance_controls: event.target.value }))} placeholder={t(lang, { en: "Compliance controls", ru: "Комплаенс-контроли" })} />
              <select className="react-select react-select-inline" value={createForm.collection_depth} onChange={(event) => setCreateForm((current) => ({ ...current, collection_depth: event.target.value }))}>
                <option value="basic">basic</option>
                <option value="expanded">expanded</option>
                <option value="deep">deep</option>
              </select>
              <input className="react-input" type="number" min={0} max={100} value={createForm.coverage_score} onChange={(event) => setCreateForm((current) => ({ ...current, coverage_score: Number(event.target.value || 0) }))} placeholder={t(lang, { en: "Coverage score", ru: "Скор покрытия" })} />
              <input className="react-input" type="number" min={0} max={100} value={createForm.parsing_coverage_pct} onChange={(event) => setCreateForm((current) => ({ ...current, parsing_coverage_pct: Number(event.target.value || 0) }))} placeholder={t(lang, { en: "Parsing coverage %", ru: "Покрытие парсинга %" })} />
              <input className="react-input" type="number" min={0} max={100} value={createForm.telemetry_quality_pct} onChange={(event) => setCreateForm((current) => ({ ...current, telemetry_quality_pct: Number(event.target.value || 0) }))} placeholder={t(lang, { en: "Telemetry quality %", ru: "Качество телеметрии %" })} />
              <div className="react-actions react-wrap">
                <label className="react-toggle"><input type="checkbox" checked={createForm.realtime} onChange={(event) => setCreateForm((current) => ({ ...current, realtime: event.target.checked }))} /><span>Realtime</span></label>
                <label className="react-toggle"><input type="checkbox" checked={createForm.actor_ip_ready} onChange={(event) => setCreateForm((current) => ({ ...current, actor_ip_ready: event.target.checked }))} /><span>{t(lang, { en: "Actor IP", ru: "IP акторов" })}</span></label>
                <label className="react-toggle"><input type="checkbox" checked={createForm.entity_mapping_ready} onChange={(event) => setCreateForm((current) => ({ ...current, entity_mapping_ready: event.target.checked }))} /><span>{t(lang, { en: "Entity mapping", ru: "Маппинг сущностей" })}</span></label>
                <label className="react-toggle"><input type="checkbox" checked={createForm.host_telemetry_ready} onChange={(event) => setCreateForm((current) => ({ ...current, host_telemetry_ready: event.target.checked }))} /><span>Host telemetry</span></label>
              </div>
              <input className="react-input" value={createForm.event_families} onChange={(event) => setCreateForm((current) => ({ ...current, event_families: event.target.value }))} placeholder={t(lang, { en: "Event families", ru: "Семейства событий" })} />
              <input className="react-input" value={createForm.evidence_fields} onChange={(event) => setCreateForm((current) => ({ ...current, evidence_fields: event.target.value }))} placeholder={t(lang, { en: "Evidence fields", ru: "Evidence-поля" })} />
              <input className="react-input" value={createForm.enrichment} onChange={(event) => setCreateForm((current) => ({ ...current, enrichment: event.target.value }))} placeholder={t(lang, { en: "Enrichment", ru: "Обогащение" })} />
              <input className="react-input" value={createForm.investigation_pivots} onChange={(event) => setCreateForm((current) => ({ ...current, investigation_pivots: event.target.value }))} placeholder={t(lang, { en: "Investigation pivots", ru: "Pivots расследования" })} />
              <button type="button" className="react-primary-button" onClick={createConnector}>
                {t(lang, { en: "Save connector", ru: "Сохранить коннектор" })}
              </button>
            </div>
          </section>

          <section className="react-card">
            <PanelHeader
              title={t(lang, { en: "Bundle lifecycle", ru: "Lifecycle пакетов" })}
              subtitle={t(lang, { en: "Manage release packs for connectors, searches and playbooks.", ru: "Управляйте release-пакетами для коннекторов, поисков и плейбуков." })}
              icon="builders"
              actions={bundleState ? <span className="react-inline-note">{bundleState}</span> : undefined}
            />
            <div className="react-form-grid">
              <input className="react-input" value={bundleForm.title} onChange={(event) => setBundleForm((current) => ({ ...current, title: event.target.value }))} placeholder={t(lang, { en: "Bundle title", ru: "Название пакета" })} />
              <select className="react-select react-select-inline" value={bundleForm.bundle_type} onChange={(event) => setBundleForm((current) => ({ ...current, bundle_type: event.target.value }))}>
                <option value="connector-pack">connector-pack</option>
                <option value="content-pack">content-pack</option>
                <option value="playbook-pack">playbook-pack</option>
              </select>
              <input className="react-input" value={bundleForm.version} onChange={(event) => setBundleForm((current) => ({ ...current, version: event.target.value }))} placeholder={t(lang, { en: "Version", ru: "Версия" })} />
              <input className="react-input" value={bundleForm.owner} onChange={(event) => setBundleForm((current) => ({ ...current, owner: event.target.value }))} placeholder={t(lang, { en: "Owner", ru: "Владелец" })} />
              <input className="react-input" value={bundleForm.release_ring} onChange={(event) => setBundleForm((current) => ({ ...current, release_ring: event.target.value }))} placeholder={t(lang, { en: "Release ring", ru: "Release ring" })} />
              <input className="react-input" value={bundleForm.linked_pack_id} onChange={(event) => setBundleForm((current) => ({ ...current, linked_pack_id: event.target.value }))} placeholder={t(lang, { en: "Linked pack", ru: "Связанный pack" })} />
              <input className="react-input" value={bundleForm.change_ticket} onChange={(event) => setBundleForm((current) => ({ ...current, change_ticket: event.target.value }))} placeholder={t(lang, { en: "Change ticket", ru: "Change ticket" })} />
              <input className="react-input" value={bundleForm.coverage_domains} onChange={(event) => setBundleForm((current) => ({ ...current, coverage_domains: event.target.value }))} placeholder={t(lang, { en: "Coverage domains", ru: "Домены покрытия" })} />
              <input className="react-input" value={bundleForm.personas} onChange={(event) => setBundleForm((current) => ({ ...current, personas: event.target.value }))} placeholder={t(lang, { en: "Personas", ru: "Персоны" })} />
              <textarea className="react-query-editor" rows={3} value={bundleForm.description} onChange={(event) => setBundleForm((current) => ({ ...current, description: event.target.value }))} placeholder={t(lang, { en: "Bundle description", ru: "Описание пакета" })} />
              <button type="button" className="react-primary-button" onClick={saveBundle} disabled={!bundleForm.title.trim()}>
                {t(lang, { en: "Save bundle", ru: "Сохранить пакет" })}
              </button>
            </div>
          </section>

          <section className="react-card">
            <PanelHeader
              title={t(lang, { en: "Telemetry posture", ru: "Срез по телеметрии" })}
              subtitle={t(lang, { en: "Connector estate by telemetry depth and release stage.", ru: "Контур коннекторов по глубине телеметрии и стадии релиза." })}
              icon="dashboard"
            />
            <section className="react-card react-card-nested">
              <PanelHeader title={t(lang, { en: "Collection depth", ru: "Глубина сбора" })} subtitle={t(lang, { en: "Coverage by collection density.", ru: "Покрытие по плотности и глубине сбора." })} />
              <BreakdownBars items={overview.data?.breakdowns?.collection_depth || []} />
            </section>
            <section className="react-card react-card-nested">
              <PanelHeader title={t(lang, { en: "Release stage", ru: "Стадия релиза" })} subtitle={t(lang, { en: "Bundle and rollout maturity.", ru: "Зрелость bundle и rollout lifecycle." })} />
              <BreakdownBars items={overview.data?.breakdowns?.release_stage || []} />
              <InfoList
                items={[
                  { label: t(lang, { en: "Parsing quality", ru: "Качество парсинга" }), value: percent(overview.data?.metrics?.parsing_coverage_avg) },
                  { label: t(lang, { en: "Telemetry quality", ru: "Качество телеметрии" }), value: percent(overview.data?.metrics?.telemetry_quality_avg) },
                  { label: t(lang, { en: "Release-gate ready", ru: "Готово по release-gate" }), value: overview.data?.metrics?.release_gate_ready || 0 },
                  { label: t(lang, { en: "Runbook ready", ru: "Есть runbook" }), value: overview.data?.metrics?.runbook_ready || 0 },
                  { label: t(lang, { en: "Onboarding ready", ru: "Есть onboarding" }), value: overview.data?.metrics?.onboarding_ready || 0 },
                ]}
              />
            </section>
            <section className="react-card react-card-nested">
              <PanelHeader title={t(lang, { en: "Hard release gates", ru: "Жесткие release gates" })} subtitle={t(lang, { en: "Enterprise ecosystem, telemetry quality and investigation readiness.", ru: "Enterprise-экосистема, качество телеметрии и готовность к расследованию." })} />
              <InfoList
                items={[
                  { label: t(lang, { en: "Ecosystem coverage", ru: "Покрытие экосистемы" }), value: `${Number(overview.data?.posture?.ecosystem_coverage_pct || 0).toFixed(1)}%` },
                  { label: t(lang, { en: "Live-ready ecosystem", ru: "Live-ready экосистема" }), value: `${Number(overview.data?.posture?.ecosystem_live_ready_pct || 0).toFixed(1)}%` },
                  { label: t(lang, { en: "Actor/source IP coverage", ru: "Покрытие actor/source IP" }), value: `${Number(overview.data?.posture?.actor_ip_ready_pct || 0).toFixed(1)}%` },
                  { label: t(lang, { en: "Host telemetry coverage", ru: "Покрытие host telemetry" }), value: `${Number(overview.data?.posture?.host_telemetry_ready_pct || 0).toFixed(1)}%` },
                  { label: t(lang, { en: "Investigation ready", ru: "Готовность к расследованию" }), value: `${Number(overview.data?.posture?.investigation_ready_pct || 0).toFixed(1)}%` },
                  { label: t(lang, { en: "Hard-gate status", ru: "Статус hard-gate" }), value: String(overview.data?.posture?.hard_gate_status || "unknown") },
                ]}
              />
              <InfoList
                items={[
                  ...(Array.isArray(overview.data?.posture?.ecosystem_missing)
                    ? (overview.data?.posture?.ecosystem_missing || []).map((item: unknown, index: number) => ({
                        label: `${t(lang, { en: "Missing domain", ru: "Отсутствующий домен" })} ${index + 1}`,
                        value: String(item || "n/a"),
                      }))
                    : []),
                  ...(Array.isArray(overview.data?.posture?.ecosystem_live_blockers)
                    ? (overview.data?.posture?.ecosystem_live_blockers || []).map((item: unknown, index: number) => ({
                        label: `${t(lang, { en: "Live blocker", ru: "Блокер live" })} ${index + 1}`,
                        value: String(item || "n/a"),
                      }))
                    : []),
                  ...issueQueue.slice(0, 4).map((item, index) => ({
                    label: `${t(lang, { en: "Gap", ru: "Разрыв" })} ${index + 1}`,
                    value: item,
                  })),
                ]}
              />
            </section>
            <section className="react-card react-card-nested">
              <PanelHeader title={t(lang, { en: "Status", ru: "Статус" })} subtitle={t(lang, { en: "Runtime health by connector state.", ru: "Runtime-health по текущему состоянию коннекторов." })} />
              <BreakdownBars items={overview.data?.breakdowns?.status || []} />
            </section>
          </section>

          <section className="react-card">
            <PanelHeader
              title={t(lang, { en: "Saved searches", ru: "Сохранённые поиски" })}
              subtitle={t(lang, { en: "Hot and cold search entry points bound to personas and bundles.", ru: "Точки входа в hot/cold поиск, привязанные к персонам и пакетам." })}
              icon="events"
            />
            <div className="react-list react-list-compact">
              {(savedSearches.data?.items || []).map((item: SavedSearchRecord) => (
                <div className="react-list-item" key={item.id}>
                  <strong>{item.title}</strong>
                  <span>{[item.storage, item.window, item.persona, item.owner].filter(Boolean).join(" / ")}</span>
                </div>
              ))}
            </div>
          </section>
        </div>

        <section className="react-card">
          <PanelHeader
            title={t(lang, { en: "Published bundles", ru: "Пакеты в lifecycle" })}
            subtitle={t(lang, { en: "Lifecycle view for content and connector packs.", ru: "Lifecycle-представление для content и connector packs." })}
            icon="builders"
          />
          <div className="react-list">
            {contentBundles.map((item: ContentBundleRecord) => (
              <section className="react-card react-card-nested" key={item.id}>
                <div className="react-card-button-header">
                  <div>
                    <strong>{item.title || item.id}</strong>
                    <div className="react-card-button-copy">
                      {[item.bundle_type, item.version, item.release_ring, item.owner].filter(Boolean).join(" / ")}
                    </div>
                  </div>
                  <StatusBadge value={String(item.stage || item.status || "draft")} />
                </div>
                <div className="react-card-button-grid">
                  <span>{t(lang, { en: "Coverage", ru: "Покрытие" })}</span>
                  <strong>{stringifyList(item.coverage_domains) || "n/a"}</strong>
                  <span>{t(lang, { en: "Personas", ru: "Персоны" })}</span>
                  <strong>{stringifyList(item.personas) || "n/a"}</strong>
                  <span>{t(lang, { en: "Validated", ru: "Валидация" })}</span>
                  <strong>{item.last_validation_ts ? formatTimestamp(item.last_validation_ts, "compact") : "n/a"}</strong>
                  <span>{t(lang, { en: "Gate", ru: "Гейт" })}</span>
                  <strong>{String(item.release_gate?.status || "draft")}</strong>
                  <span>{t(lang, { en: "Signed", ru: "Подписан" })}</span>
                  <strong>{item.integrity?.signed ? "yes" : "no"}</strong>
                </div>
                <div className="react-actions react-wrap">
                  <button type="button" className="react-link-button" onClick={() => promoteBundle(String(item.id || ""), "validated")}>
                    {t(lang, { en: "Validate", ru: "Проверить" })}
                  </button>
                  <button type="button" className="react-link-button" onClick={() => promoteBundle(String(item.id || ""), "staged")}>
                    {t(lang, { en: "Stage", ru: "Стадировать" })}
                  </button>
                  <button type="button" className="react-link-button" onClick={() => promoteBundle(String(item.id || ""), "active")}>
                    {t(lang, { en: "Activate", ru: "Активировать" })}
                  </button>
                </div>
              </section>
            ))}
          </div>
        </section>

        <DrawerOverlay
          open={detailsOpen && Boolean(selectedConnector)}
          title={selectedConnector?.title || ""}
          subtitle={selectedConnector?.description || ""}
          onClose={() => setDetailsOpen(false)}
        >
          {selectedConnector ? (
            <>
              <section className="react-card react-card-nested">
                <PanelHeader title={t(lang, { en: "Connector profile", ru: "Профиль коннектора" })} subtitle={t(lang, { en: "Schema, runtime features and health details.", ru: "Схема, возможности runtime и детали по состоянию." })} icon="connectors" />
                <DrawerFieldGrid>
                  <KeyValue label="ID" value={selectedConnector.id} />
                  <KeyValue label={t(lang, { en: "Family", ru: "Семейство" })} value={selectedConnector.family} />
                  <KeyValue label={t(lang, { en: "Mode", ru: "Режим" })} value={selectedConnector.mode} />
                  <KeyValue label={t(lang, { en: "Source family", ru: "Семейство источника" })} value={selectedConnector.source_family} />
                  <KeyValue label={t(lang, { en: "Status", ru: "Статус" })} value={<StatusBadge value={String(selectedConnector.status || "planned")} />} />
                  <KeyValue label={t(lang, { en: "Updated", ru: "Обновлён" })} value={formatTimestamp(selectedConnector.updated_ts, "compact")} />
                </DrawerFieldGrid>
              </section>

              <section className="react-card react-card-nested">
                <PanelHeader title={t(lang, { en: "Telemetry contract", ru: "Контракт телеметрии" })} subtitle={t(lang, { en: "Collection depth, evidence fields and investigation readiness.", ru: "Глубина сбора, evidence-поля и готовность к расследованию." })} icon="events" />
                <DrawerFieldGrid>
                  <KeyValue label={t(lang, { en: "Collection depth", ru: "Глубина сбора" })} value={String(selectedConnector.telemetry?.collection_depth || "basic")} />
                  <KeyValue label={t(lang, { en: "Coverage score", ru: "Скор покрытия" })} value={Number(selectedConnector.telemetry?.coverage_score || 0)} />
                  <KeyValue label={t(lang, { en: "Parsing quality", ru: "Качество парсинга" })} value={percent(selectedConnector.telemetry?.parsing_coverage_pct)} />
                  <KeyValue label={t(lang, { en: "Telemetry quality", ru: "Качество телеметрии" })} value={percent(selectedConnector.telemetry?.telemetry_quality_pct)} />
                  <KeyValue label="Realtime" value={selectedConnector.telemetry?.realtime ? "yes" : "no"} />
                  <KeyValue label={t(lang, { en: "Actor IP ready", ru: "IP источника готовы" })} value={selectedConnector.telemetry?.actor_ip_ready ? "yes" : "no"} />
                  <KeyValue label={t(lang, { en: "Host telemetry", ru: "Host telemetry" })} value={selectedConnector.telemetry?.host_telemetry_ready ? "yes" : "no"} />
                  <KeyValue label={t(lang, { en: "Evidence fields", ru: "Evidence-поля" })} value={stringifyList(selectedConnector.telemetry?.evidence_fields) || "n/a"} />
                </DrawerFieldGrid>
                <InfoList
                  items={[
                    { label: t(lang, { en: "Event families", ru: "Семейства событий" }), value: stringifyList(selectedConnector.telemetry?.event_families) || "n/a" },
                    { label: t(lang, { en: "Enrichment", ru: "Обогащение" }), value: stringifyList(selectedConnector.telemetry?.enrichment) || "n/a" },
                    { label: t(lang, { en: "Investigation pivots", ru: "Pivots расследования" }), value: stringifyList(selectedConnector.telemetry?.investigation_pivots) || "n/a" },
                    { label: t(lang, { en: "Playbooks", ru: "Плейбуки" }), value: stringifyList(selectedConnector.operations?.playbooks) || "n/a" },
                    { label: t(lang, { en: "Compliance", ru: "Комплаенс" }), value: stringifyList(selectedConnector.operations?.compliance_controls) || "n/a" },
                  ]}
                />
              </section>

              <section className="react-card react-card-nested">
                <PanelHeader title={t(lang, { en: "Lifecycle operations", ru: "Lifecycle-операции" })} subtitle={t(lang, { en: "Bundle ownership, release stage and release governance.", ru: "Владелец bundle, стадия релиза и release-governance." })} icon="builders" />
                <DrawerFieldGrid>
                  <KeyValue label={t(lang, { en: "Release stage", ru: "Стадия релиза" })} value={String(selectedConnector.operations?.release_stage || "draft")} />
                  <KeyValue label="Bundle ID" value={String(selectedConnector.operations?.bundle_id || "n/a")} />
                  <KeyValue label={t(lang, { en: "Owner", ru: "Владелец" })} value={String(selectedConnector.operations?.owner || "n/a")} />
                  <KeyValue label={t(lang, { en: "Release gate", ru: "Release gate" })} value={String(selectedConnector.release_gate?.status || "draft")} />
                  <KeyValue label={t(lang, { en: "Runbook", ru: "Runbook" })} value={String(selectedConnector.operations?.runbook_id || "n/a")} />
                  <KeyValue label={t(lang, { en: "Onboarding", ru: "Onboarding" })} value={String(selectedConnector.operations?.onboarding_template || "n/a")} />
                  <KeyValue label={t(lang, { en: "Support tier", ru: "Уровень поддержки" })} value={String(selectedConnector.operations?.support_tier || "community")} />
                  <KeyValue label={t(lang, { en: "Enterprise ready", ru: "Enterprise ready" })} value={selectedConnector.telemetry?.realtime && selectedConnector.telemetry?.actor_ip_ready ? "yes" : "partial"} />
                </DrawerFieldGrid>
              </section>

              <section className="react-card react-card-nested">
                <PanelHeader title={t(lang, { en: "Secret requirements", ru: "Требуемые секреты" })} subtitle={t(lang, { en: "Readiness-only references used by the runtime.", ru: "Только ссылки готовности, используемые контуром runtime." })} icon="docs" />
                <InfoList items={(selectedConnector.secret_requirements || []).map((item) => ({ label: item.label, value: item.env }))} />
              </section>

              <section className="react-card react-card-nested">
                <PanelHeader title={t(lang, { en: "Recent runs", ru: "Недавние запуски" })} subtitle={t(lang, { en: "Most recent runtime events for this connector.", ru: "Последние события runtime по этому коннектору." })} icon="events" />
                <div className="react-list react-list-compact">
                  {connectorRuns.length ? connectorRuns.map((item: ConnectorRunRecord) => (
                    <div className="react-list-item" key={item.id}>
                      <strong>{item.status}</strong>
                      <span>{formatTimestamp(item.finished_ts, "compact")} / {item.message || item.trigger}</span>
                    </div>
                  )) : <div className="react-list-item"><strong>{t(lang, { en: "No runs yet", ru: "Запусков пока нет" })}</strong></div>}
                </div>
              </section>

              <section className="react-card react-card-nested">
                <PanelHeader title={t(lang, { en: "Mappings", ru: "Схемы и сопоставления" })} subtitle={t(lang, { en: "Schema and dataset hints used by the current control plane.", ru: "Подсказки по схеме и наборам данных для текущего control plane." })} icon="builders" />
                <JsonPreview value={selectedConnector.mappings || {}} />
              </section>

              <section className="react-card react-card-nested">
                <PanelHeader title={t(lang, { en: "Runtime config", ru: "Настройки runtime" })} subtitle={t(lang, { en: "Request, auth and executor settings stored with this connector.", ru: "Настройки запроса, авторизации и исполнителя, сохранённые в коннекторе." })} icon="control" />
                <JsonPreview value={selectedConnector.runtime || {}} />
              </section>
            </>
          ) : null}
        </DrawerOverlay>
      </div>
    </AsyncGate>
  );
}
