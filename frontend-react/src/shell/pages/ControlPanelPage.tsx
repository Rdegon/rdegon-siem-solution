import { useCallback, useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { api } from "../api";
import { DashboardCanvas } from "../DashboardCanvas";
import { usePolledData } from "../hooks";
import { AsyncGate } from "../async";
import { BreakdownBars, DrawerOverlay, Icon, InfoList, PanelHeader, SectionIntro, StatCard } from "../ui";
import { t, useShellContext } from "../context";
import type {
  ComplianceEvidencePackResponse,
  DashboardDefinition,
  DashboardLayoutItemRecord,
  DashboardWidgetCatalogRecord,
  EnterpriseReleaseGatesResponse,
} from "../types";

type LayoutItem = {
  widget: string;
  span: number;
};

function localizeDashboardTitle(title: string, lang: "en" | "ru") {
  const normalized = String(title || "").trim().toLowerCase();
  const known: Record<string, { en: string; ru: string }> = {
    "security overview / обзор безопасности": { en: "Security Overview", ru: "Обзор безопасности" },
    "collector health / коллекторы": { en: "Collector Health", ru: "Коллекторы" },
    "network exposure / сетевое покрытие": { en: "Network Exposure", ru: "Сетевое покрытие" },
    "vpn browser activity / vpn-активность": { en: "VPN Browser Activity", ru: "VPN-активность" },
    "incident operations / операции soc": { en: "Incident Operations", ru: "Операции SOC" },
  };
  return known[normalized] ? t(lang, known[normalized]) : title;
}

function localizeDashboardDescription(description: string, lang: "en" | "ru") {
  const normalized = String(description || "").trim().toLowerCase();
  const known: Record<string, { en: string; ru: string }> = {
    "drag-and-drop layout for a custom control panel.": {
      en: "Drag-and-drop layout for a custom control panel.",
      ru: "Перетаскиваемый макет для пользовательской панели управления.",
    },
    "built-in overview template for the operational shell.": {
      en: "Built-in overview template for the operational shell.",
      ru: "Встроенный обзорный шаблон для операционной оболочки.",
    },
    "transport and collector posture across the pipeline.": {
      en: "Transport and collector posture across the pipeline.",
      ru: "Состояние транспорта и коллекторов по всему контуру.",
    },
    "default soc posture view with incidents, event volume, source activity and targeted ports.": {
      en: "Default SOC posture view with incidents, event volume, source activity and targeted ports.",
      ru: "Базовый обзор SOC с инцидентами, объемом событий, активностью источников и целевыми портами.",
    },
    "incident queue, severity mix and operator pivots for the current response lane.": {
      en: "Incident queue, severity mix and operator pivots for the current response lane.",
      ru: "Очередь инцидентов, распределение важности и операторские переходы для текущего контура triage.",
    },
  };
  return known[normalized] ? t(lang, known[normalized]) : description;
}

function localizeWidgetCatalogTitle(widgetId: string, fallback: string, lang: "en" | "ru") {
  const known: Record<string, { en: string; ru: string }> = {
    kpis: { en: "Key metrics", ru: "Ключевые метрики" },
    severity_breakdown: { en: "Severity breakdown", ru: "Распределение важности" },
    timelines: { en: "Time dynamics", ru: "Динамика по времени" },
    attack_geo: { en: "Attack geography", ru: "География атак" },
    vpn_geo: { en: "VPN destination map", ru: "Карта VPN-направлений" },
    targeted_ports: { en: "Targeted ports", ru: "Целевые порты" },
    category_breakdown: { en: "Top categories", ru: "Топ категорий" },
    incidents_table: { en: "Incident queue", ru: "Очередь инцидентов" },
  };
  return known[widgetId] ? t(lang, known[widgetId]) : fallback;
}

function localizeWidgetCatalogDescription(widgetId: string, fallback: string, lang: "en" | "ru") {
  const known: Record<string, { en: string; ru: string }> = {
    kpis: { en: "Top-line operational counters and health pulse.", ru: "Верхнеуровневые операционные счетчики и пульс платформы." },
    severity_breakdown: { en: "Event and alert breakdown by severity and status.", ru: "Разбивка событий и алертов по важности и статусу." },
    timelines: { en: "Timeline of events and alerts for the selected window.", ru: "Лента событий и алертов в выбранном временном окне." },
    attack_geo: { en: "GeoIP map and country sources for incoming traffic.", ru: "GeoIP-карта и страны-источники входящего трафика." },
    vpn_geo: { en: "Destination countries for VPN egress activity.", ru: "Страны назначений для VPN-egress и пользовательского трафика." },
    targeted_ports: { en: "Most targeted ports and service categories.", ru: "Самые атакуемые порты и категории сервисов." },
    category_breakdown: { en: "Normalized event categories in the current stream.", ru: "Нормализованные категории в текущем потоке событий." },
    incidents_table: { en: "Fresh incident queue with pivots into investigation.", ru: "Свежая очередь инцидентов с быстрыми переходами в расследование." },
  };
  return known[widgetId] ? t(lang, known[widgetId]) : fallback;
}

export function ControlPanelPage() {
  const { lang } = useShellContext();
  const navigate = useNavigate();
  const loadRegistry = useCallback(() => api.dashboards(), []);
  const loadSummary = useCallback(() => api.dashboard(), []);
  const loadBundles = useCallback(() => api.contentBundles(), []);
  const loadConnectorsOverview = useCallback(() => api.connectorsOverview(), []);
  const loadResponseAnalytics = useCallback(() => api.responseAnalytics({ limit: 200 }), []);
  const loadReleaseGates = useCallback<() => Promise<EnterpriseReleaseGatesResponse>>(() => api.enterpriseReleaseGates(), []);
  const loadEvidencePack = useCallback<() => Promise<ComplianceEvidencePackResponse>>(() => api.complianceEvidencePack(), []);
  const loadHostRuntime = useCallback(() => api.hostRuntimeOverview({ hours: 24, limit: 50 }), []);
  const registry = usePolledData(loadRegistry, 45000);
  const summary = usePolledData(loadSummary, 30000);
  const bundlesState = usePolledData(loadBundles, 60000);
  const connectorsState = usePolledData(loadConnectorsOverview, 45000);
  const responseState = usePolledData(loadResponseAnalytics, 45000);
  const releaseGatesState = usePolledData(loadReleaseGates, 45000);
  const evidencePackState = usePolledData(loadEvidencePack, 60000);
  const hostRuntimeState = usePolledData(loadHostRuntime, 45000);
  const [dashboardsState, setDashboardsState] = useState<DashboardDefinition[]>([]);
  const [selectedId, setSelectedId] = useState("");
  const [creatingNew, setCreatingNew] = useState(false);
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const [layout, setLayout] = useState<LayoutItem[]>([]);
  const [dragIndex, setDragIndex] = useState<number | null>(null);
  const [saveState, setSaveState] = useState("");
  const [libraryOpen, setLibraryOpen] = useState(false);

  const dashboards = useMemo(
    () => (dashboardsState.length ? dashboardsState : registry.data?.dashboards || []),
    [dashboardsState, registry.data],
  );
  const widgetCatalog = registry.data?.widget_catalog || [];
  const selected = creatingNew ? null : dashboards.find((item) => item.id === selectedId) || dashboards[0];

  useEffect(() => {
    if (registry.data?.dashboards?.length) {
      setDashboardsState(registry.data.dashboards);
    }
  }, [registry.data]);

  useEffect(() => {
    if (!selectedId && dashboards.length && !creatingNew) {
      setSelectedId(String(dashboards[0].id || ""));
    }
  }, [creatingNew, dashboards, selectedId]);

  useEffect(() => {
    if (!selected) return;
    setTitle(localizeDashboardTitle(String(selected.title || ""), lang));
    setDescription(localizeDashboardDescription(String(selected.description || ""), lang));
    setLayout(
      (selected.layout || []).map((item: DashboardLayoutItemRecord) => ({
        widget: String(item.widget || ""),
        span: Number(item.span || 1) >= 2 ? 2 : 1,
      })),
    );
  }, [lang, selected]);

  const widgetIds = new Set(layout.map((item) => item.widget));

  function addWidget(widgetId: string) {
    if (!widgetId || widgetIds.has(widgetId)) return;
    const spec = widgetCatalog.find((item: DashboardWidgetCatalogRecord) => item.id === widgetId);
    setLayout((current) => [...current, { widget: widgetId, span: Number(spec?.default_span || 1) >= 2 ? 2 : 1 }]);
  }

  function removeWidget(widgetId: string) {
    setLayout((current) => current.filter((item) => item.widget !== widgetId));
  }

  function toggleSpan(widgetId: string) {
    setLayout((current) =>
      current.map((item) => (item.widget === widgetId ? { ...item, span: item.span >= 2 ? 1 : 2 } : item)),
    );
  }

  function dropAt(targetIndex: number) {
    if (dragIndex === null || dragIndex === targetIndex) return;
    setLayout((current) => {
      const next = [...current];
      const [moved] = next.splice(dragIndex, 1);
      next.splice(targetIndex, 0, moved);
      return next;
    });
    setDragIndex(null);
  }

  async function saveDashboard() {
    setSaveState(t(lang, { en: "Saving dashboard...", ru: "Сохраняю дашборд..." }));
    try {
      const payload = await api.saveDashboard({
        title,
        description,
        widgets: layout.map((item) => item.widget),
        layout,
      });
      setSaveState(`${t(lang, { en: "Saved", ru: "Сохранен" })}: ${localizeDashboardTitle(String(payload.title || ""), lang)}`);
      setSelectedId(String(payload.id || ""));
      setCreatingNew(false);
      setDashboardsState((current) => {
        const next = current.filter((item) => item.id !== payload.id);
        next.push(payload);
        return next;
      });
    } catch (error) {
      setSaveState(error instanceof Error ? error.message : t(lang, { en: "Save failed", ru: "Сохранение не выполнено" }));
    }
  }

  async function deleteDashboard() {
    if (!selected || selected.built_in) return;
    setSaveState(`${t(lang, { en: "Deleting", ru: "Удаляю" })}: ${localizeDashboardTitle(String(selected.title || ""), lang)}...`);
    try {
      await api.deleteDashboard(String(selected.id));
      setSaveState(`${t(lang, { en: "Deleted", ru: "Удален" })}: ${localizeDashboardTitle(String(selected.title || ""), lang)}`);
      setSelectedId("");
      setCreatingNew(false);
      setDashboardsState((current) => current.filter((item) => item.id !== selected.id));
    } catch (error) {
      setSaveState(error instanceof Error ? error.message : t(lang, { en: "Delete failed", ru: "Удаление не выполнено" }));
    }
  }

  function newTemplate() {
    setCreatingNew(true);
    setSelectedId("");
    setTitle(t(lang, { en: "Custom SOC template", ru: "Кастомный SOC-шаблон" }));
    setDescription(t(lang, {
      en: "Drag-and-drop layout for a custom control panel.",
      ru: "Перетаскиваемый макет для кастомной панели управления.",
    }));
    setLayout([
      { widget: "kpis", span: 2 },
      { widget: "severity_breakdown", span: 2 },
      { widget: "timelines", span: 2 },
    ]);
    setSaveState("");
  }

  const contentGateStats = useMemo(
    () =>
      (bundlesState.data?.items || []).reduce(
        (acc, item) => {
          const gate = (item.release_gate || {}) as Record<string, unknown>;
          if (gate.ready_for_live) acc.liveReady += 1;
          else if (gate.ready_for_stage) acc.stageReady += 1;
          else if (gate.ready_for_validation) acc.validationReady += 1;
          else acc.blocked += 1;
          return acc;
        },
        { liveReady: 0, stageReady: 0, validationReady: 0, blocked: 0 },
      ),
    [bundlesState.data?.items],
  );

  const maturityCards = [
    {
      label: t(lang, { en: "Bundles", ru: "Bundles" }),
      value: bundlesState.data?.items?.length || 0,
      hint: t(lang, { en: "Content objects already moved under lifecycle governance.", ru: "Контент-объекты, уже находящиеся под lifecycle-governance." }),
    },
    {
      label: t(lang, { en: "Connector coverage", ru: "Покрытие коннекторов" }),
      value: `${Number(connectorsState.data?.metrics?.telemetry_coverage_avg || 0).toFixed(1)}%`,
      hint: t(lang, { en: "Average telemetry depth across the connector estate.", ru: "Средняя глубина телеметрии по контуру коннекторов." }),
    },
    {
      label: t(lang, { en: "Parsing quality", ru: "Parsing quality" }),
      value: `${Number(connectorsState.data?.metrics?.parsing_coverage_avg || 0).toFixed(1)}%`,
      hint: t(lang, { en: "Average parser and schema coverage across live connectors.", ru: "Average parser and schema coverage across live connectors." }),
    },
    {
      label: t(lang, { en: "Enterprise ready", ru: "Enterprise ready" }),
      value: connectorsState.data?.metrics?.enterprise_ready || 0,
      hint: t(lang, { en: "Connectors ready for realtime, actor IP and evidence pivots.", ru: "Коннекторы, уже готовые к realtime, IP акторов и evidence-pivot расследований." }),
    },
    {
      label: t(lang, { en: "Release gates", ru: "Release gates" }),
      value: connectorsState.data?.metrics?.release_gate_ready || 0,
      hint: t(lang, { en: "Connector definitions currently ready for live release.", ru: "Connector definitions currently ready for live release." }),
    },
    {
      label: t(lang, { en: "Governed playbooks", ru: "Governed playbooks" }),
      value: responseState.data?.metrics?.governed_actions || 0,
      hint: t(lang, { en: "Response actions with governance, rollback and evidence contracts.", ru: "Ответные действия с governance-, rollback- и evidence-контрактами." }),
    },
    {
      label: t(lang, { en: "Compliance coverage", ru: "Compliance coverage" }),
      value: `${Number(responseState.data?.metrics?.compliance_coverage_pct || 0).toFixed(1)}%`,
      hint: t(lang, { en: "Coverage of mapped compliance controls in the response layer.", ru: "Покрытие compliance-контролей в контуре response." }),
    },
    {
      label: t(lang, { en: "Memory truth", ru: "Memory truth" }),
      value: `${Number(hostRuntimeState.data?.metrics?.avg_memory_available_pct || 0).toFixed(1)}%`,
      hint: t(lang, { en: "Average genuinely available memory across monitored hosts.", ru: "Average genuinely available memory across monitored hosts." }),
    },
  ];

  return (
    <AsyncGate states={[registry, summary, bundlesState, connectorsState, responseState, releaseGatesState, evidencePackState, hostRuntimeState]} loadingMessage={t(lang, { en: "Loading control panel...", ru: "Загрузка панели управления..." })}>
      <div className="react-page">
        <SectionIntro
          kicker={t(lang, { en: "Control Panel", ru: "Панель управления" })}
          title={t(lang, { en: "Dashboard composer", ru: "Композер дашбордов" })}
          subtitle={t(lang, {
            en: "Admin workspace for templates, page layout and widget placement.",
            ru: "Админская зона для шаблонов, макета страниц и расположения виджетов.",
          })}
          icon="control"
          actions={
            <div className="react-actions react-wrap">
              <button type="button" className="react-link-button" onClick={newTemplate}>
                {t(lang, { en: "New template", ru: "Новый шаблон" })}
              </button>
              <button
                type="button"
                className="react-link-button"
                style={{ display: "inline-flex", alignItems: "center", gap: 8 }}
                onClick={() => setLibraryOpen(true)}
                aria-label={t(lang, { en: "Open page settings", ru: "Открыть настройки страницы" })}
              >
                <Icon name="control" size={15} />
                <span>{t(lang, { en: "Page settings", ru: "Настройки страницы" })}</span>
              </button>
            </div>
          }
        />

        <div className="react-grid react-grid-5">
          {maturityCards.map((card) => (
            <StatCard key={card.label} label={card.label} value={card.value} hint={card.hint} />
          ))}
        </div>

        <div className="react-grid react-grid-4">
          <section className="react-card">
            <PanelHeader
              title={t(lang, { en: "Content operations", ru: "Content operations" })}
              subtitle={t(lang, { en: "Lifecycle posture for packs, bundles and search surfaces.", ru: "Lifecycle-срез по пакетам, bundle и поисковым поверхностям." })}
              icon="builders"
            />
            <BreakdownBars
              items={Object.entries(
                (bundlesState.data?.items || []).reduce<Record<string, number>>((acc, item) => {
                  const key = String(item.stage || "draft");
                  acc[key] = (acc[key] || 0) + 1;
                  return acc;
                }, {}),
              ).map(([label, value]) => ({ label, value }))}
            />
            <InfoList
              items={[
                { label: t(lang, { en: "Live ready", ru: "Готово к live" }), value: contentGateStats.liveReady },
                { label: t(lang, { en: "Stage ready", ru: "Готово к stage" }), value: contentGateStats.stageReady },
                { label: t(lang, { en: "Validation ready", ru: "Готово к validation" }), value: contentGateStats.validationReady },
                { label: t(lang, { en: "Blocked", ru: "Заблокировано" }), value: contentGateStats.blocked },
                ...(bundlesState.data?.items || []).slice(0, 3).map((item) => ({
                  label: String(item.title || item.id || "bundle"),
                  value: [item.stage, item.release_ring, item.owner].filter(Boolean).join(" / "),
                })),
              ]}
            />
          </section>

          <section className="react-card">
            <PanelHeader
              title={t(lang, { en: "Connector and telemetry posture", ru: "Срез по коннекторам и телеметрии" })}
              subtitle={t(lang, { en: "Operational maturity of the connector estate.", ru: "Операционная зрелость контура коннекторов." })}
              icon="connectors"
            />
            <BreakdownBars items={connectorsState.data?.breakdowns?.collection_depth || []} />
            <InfoList
              items={[
                { label: t(lang, { en: "Bundle coverage", ru: "Bundle coverage" }), value: `${Number(connectorsState.data?.posture?.bundle_coverage_pct || 0).toFixed(1)}%` },
                { label: t(lang, { en: "Evidence ready", ru: "Evidence ready" }), value: `${Number(connectorsState.data?.posture?.evidence_ready_pct || 0).toFixed(1)}%` },
                { label: t(lang, { en: "Realtime ready", ru: "Realtime ready" }), value: `${Number(connectorsState.data?.posture?.realtime_ready_pct || 0).toFixed(1)}%` },
                { label: t(lang, { en: "Parsing quality", ru: "Качество парсинга" }), value: `${Number(connectorsState.data?.metrics?.parsing_coverage_avg || 0).toFixed(1)}%` },
                { label: t(lang, { en: "Telemetry quality", ru: "Качество телеметрии" }), value: `${Number(connectorsState.data?.metrics?.telemetry_quality_avg || 0).toFixed(1)}%` },
                { label: t(lang, { en: "Release-gate ready", ru: "Готово по release-gate" }), value: connectorsState.data?.metrics?.release_gate_ready || 0 },
                { label: t(lang, { en: "Runbook ready", ru: "Есть runbook" }), value: connectorsState.data?.metrics?.runbook_ready || 0 },
              ]}
            />
          </section>

          <section className="react-card">
            <PanelHeader
              title={t(lang, { en: "Response governance", ru: "Response governance" })}
              subtitle={t(lang, { en: "SOAR, compliance and evidence control surface.", ru: "Контур SOAR, compliance и evidence-контроля." })}
              icon="control"
            />
            <BreakdownBars items={responseState.data?.breakdowns?.playbook_classes || []} />
            <InfoList
              items={[
                { label: t(lang, { en: "Owner coverage", ru: "Owner coverage" }), value: `${Number(responseState.data?.metrics?.owner_coverage_pct || 0).toFixed(1)}%` },
                { label: t(lang, { en: "Evidence contracts", ru: "Evidence contracts" }), value: `${Number(responseState.data?.metrics?.evidence_contract_pct || 0).toFixed(1)}%` },
                { label: t(lang, { en: "Rollback ready", ru: "Rollback ready" }), value: `${Number(responseState.data?.metrics?.rollback_ready_pct || 0).toFixed(1)}%` },
                { label: t(lang, { en: "Preconditions", ru: "Предусловия" }), value: `${Number(responseState.data?.metrics?.precondition_coverage_pct || 0).toFixed(1)}%` },
                { label: t(lang, { en: "Integration targets", ru: "Целевые интеграции" }), value: `${Number(responseState.data?.metrics?.integration_target_pct || 0).toFixed(1)}%` },
                { label: t(lang, { en: "Compliance", ru: "Комплаенс" }), value: `${Number(responseState.data?.metrics?.compliance_coverage_pct || 0).toFixed(1)}%` },
              ]}
            />
          </section>

          <section className="react-card">
            <PanelHeader
              title={t(lang, { en: "Release gates", ru: "Release gates" })}
              subtitle={t(lang, { en: "Hard gates blocking enterprise release readiness.", ru: "Жесткие гейты, определяющие enterprise-готовность релиза." })}
              icon="incidents"
            />
            <InfoList
              items={[
                { label: t(lang, { en: "Passed", ru: "Пройдено" }), value: releaseGatesState.data?.summary?.passed || 0 },
                { label: t(lang, { en: "Failed", ru: "Провалено" }), value: releaseGatesState.data?.summary?.failed || 0 },
                { label: t(lang, { en: "Blocked", ru: "Заблокировано" }), value: releaseGatesState.data?.release_blocked ? "yes" : "no" },
                { label: t(lang, { en: "Next actions", ru: "Следующие действия" }), value: (releaseGatesState.data?.next_actions || []).join(", ") || "n/a" },
              ]}
            />
            <InfoList
              items={(releaseGatesState.data?.gates || []).map((gate) => ({
                label: String(gate.title || gate.id || "gate"),
                value: `${String(gate.status || "unknown")} / ${String(gate.metric || "")}`,
              }))}
            />
          </section>

          <section className="react-card">
            <PanelHeader
              title={t(lang, { en: "Evidence pack", ru: "Evidence pack" })}
              subtitle={t(lang, { en: "Auditor-grade export surface for governance and release reviews.", ru: "Экспортируемый auditor-grade контур для governance и release-review." })}
              icon="docs"
            />
            <InfoList
              items={[
                { label: t(lang, { en: "Pack ID", ru: "Pack ID" }), value: String(evidencePackState.data?.evidence_pack_id || "n/a") },
                { label: t(lang, { en: "Bundles", ru: "Bundles" }), value: Array.isArray(evidencePackState.data?.content_bundles) ? evidencePackState.data?.content_bundles?.length || 0 : 0 },
                { label: t(lang, { en: "Connectors", ru: "Коннекторы" }), value: Array.isArray(evidencePackState.data?.connector_registry) ? evidencePackState.data?.connector_registry?.length || 0 : 0 },
                { label: t(lang, { en: "Control families", ru: "Семейства контролей" }), value: Array.isArray(evidencePackState.data?.governance?.control_families) ? String((evidencePackState.data?.governance?.control_families || []).join(", ")) : "n/a" },
                { label: t(lang, { en: "Controls", ru: "Контроли" }), value: Array.isArray(evidencePackState.data?.governance?.controls) ? String((evidencePackState.data?.governance?.controls || []).slice(0, 8).join(", ")) : "n/a" },
                { label: t(lang, { en: "Export supported", ru: "Экспорт поддерживается" }), value: evidencePackState.data?.governance?.export_supported ? "yes" : "no" },
              ]}
            />
          </section>

          <section className="react-card">
            <PanelHeader
              title={t(lang, { en: "Runtime truth", ru: "Runtime truth" })}
              subtitle={t(lang, { en: "Distinguish real memory pressure from normal cache growth on monitored hosts.", ru: "Distinguish real memory pressure from normal cache growth on monitored hosts." })}
              icon="access"
            />
            <InfoList
              items={[
                { label: t(lang, { en: "Stale targets", ru: "Stale targets" }), value: hostRuntimeState.data?.metrics?.stale_targets || 0 },
                { label: t(lang, { en: "Pressure targets", ru: "Pressure targets" }), value: hostRuntimeState.data?.metrics?.pressure_targets || 0 },
                { label: t(lang, { en: "Cache-heavy targets", ru: "Cache-heavy targets" }), value: hostRuntimeState.data?.metrics?.cache_heavy_targets || 0 },
                { label: t(lang, { en: "Available memory", ru: "Available memory" }), value: `${Number(hostRuntimeState.data?.metrics?.avg_memory_available_pct || 0).toFixed(1)}%` },
                { label: t(lang, { en: "Cache footprint", ru: "Размер page cache" }), value: `${Number(hostRuntimeState.data?.metrics?.avg_memory_cache_pct || 0).toFixed(1)}%` },
              ]}
            />
            <p className="react-section-copy">{String(hostRuntimeState.data?.memory_truth?.summary || "")}</p>
          </section>
        </div>

        <section className="react-card">
          <PanelHeader
            title={t(lang, { en: "Current template", ru: "Текущий шаблон" })}
            subtitle={t(lang, {
              en: "Layout, templates and widget placement for control workspaces.",
              ru: "Макет, шаблоны и расположение виджетов для управляемых пространств.",
            })}
            icon="dashboard"
          />
          <div className="react-form-grid">
            <input className="react-input" value={title} onChange={(event) => setTitle(event.target.value)} placeholder={t(lang, { en: "Dashboard title", ru: "Название дашборда" })} />
            <input className="react-input" value={description} onChange={(event) => setDescription(event.target.value)} placeholder={t(lang, { en: "Description", ru: "Описание" })} />
            <div className="react-actions react-wrap">
              <select
                className="react-select react-select-inline"
                value={selected?.id || ""}
                onChange={(event) => {
                  setCreatingNew(false);
                  setSelectedId(event.target.value);
                }}
              >
                <option value="">{t(lang, { en: "Select dashboard", ru: "Выбрать дашборд" })}</option>
                {dashboards.map((item) => (
                  <option value={item.id} key={item.id}>
                    {localizeDashboardTitle(String(item.title || ""), lang)}
                  </option>
                ))}
              </select>
              <button type="button" className="react-primary-button" onClick={saveDashboard}>
                {t(lang, { en: "Save", ru: "Сохранить" })}
              </button>
              {!selected?.built_in && selected?.id ? (
                <button type="button" className="react-link-button" onClick={deleteDashboard}>
                  {t(lang, { en: "Delete", ru: "Удалить" })}
                </button>
              ) : null}
              {saveState ? <span className="react-inline-note">{saveState}</span> : null}
            </div>
          </div>
          <DashboardCanvas
            layout={layout}
            data={summary.data || {}}
            editable
            onDragStartItem={(index) => setDragIndex(index)}
            onDropItem={dropAt}
            onRemove={removeWidget}
            onToggleSpan={toggleSpan}
            onFocusIncident={(incidentId) => {
              navigate(`/incidents?focus=${encodeURIComponent(incidentId)}`);
            }}
          />
        </section>

        <DrawerOverlay
          open={libraryOpen}
          title={t(lang, { en: "Page settings", ru: "Настройки страницы" })}
          subtitle={t(lang, {
            en: "Manage widgets and template actions for the current control workspace.",
            ru: "Управляйте виджетами и шаблонами в текущем рабочем пространстве.",
          })}
          onClose={() => setLibraryOpen(false)}
        >
          <section className="react-card react-card-nested">
            <PanelHeader
              title={t(lang, { en: "Widget catalog", ru: "Каталог виджетов" })}
              subtitle={t(lang, { en: "Add widgets to the current template.", ru: "Добавляйте виджеты в текущий шаблон." })}
              icon="dashboard"
            />
            <div className="react-list react-list-compact">
              {widgetCatalog.map((item: DashboardWidgetCatalogRecord) => (
                <button
                  type="button"
                  className="react-list-item"
                  key={item.id}
                  onClick={() => addWidget(String(item.id))}
                  disabled={widgetIds.has(String(item.id))}
                >
                  <strong>{localizeWidgetCatalogTitle(String(item.id || ""), String(item.title || ""), lang)}</strong>
                  <span>{localizeWidgetCatalogDescription(String(item.id || ""), String(item.description || ""), lang)}</span>
                </button>
              ))}
            </div>
          </section>
          <section className="react-card react-card-nested">
            <PanelHeader
              title={t(lang, { en: "Workspace model", ru: "Модель рабочей зоны" })}
              subtitle={t(lang, {
                en: "Control Panel is reserved for layout, template and widget management.",
                ru: "Панель управления нужна для макетов, шаблонов и виджетов.",
              })}
              icon="docs"
            />
            <div className="react-page-settings-note">
              {t(lang, {
                en: "Analysts work in Overview, Events, Incidents and Threat Intel. Administrators use this page to compose and publish dashboards.",
                ru: "Аналитики работают в Обзоре, Событиях, Инцидентах и Киберразведке. Здесь администратор композит и публикует дашборды.",
              })}
            </div>
          </section>
        </DrawerOverlay>
      </div>
    </AsyncGate>
  );
}
