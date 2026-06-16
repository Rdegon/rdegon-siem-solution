import { useCallback, useEffect, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api } from "../api";
import { AsyncGate } from "../async";
import { t, useShellContext } from "../context";
import { useAsyncData, useDebouncedValue } from "../hooks";
import {
  DrawerFieldGrid,
  DrawerOverlay,
  EmptyState,
  Icon,
  JsonPreview,
  KeyValue,
  PanelHeader,
  SectionIntro,
  StatCard,
  StatusBadge,
} from "../ui";
import type {
  DiscoveryCandidate,
  DiscoveryJob,
  IntegrationTemplateRecord,
  IntegrationsCatalogResponse,
  ProxmoxFleetRecord,
  ProxmoxFleetResponse,
  RuntimeBlob,
  SourceDiscoveryResponse,
  SourceInventoryRecord,
  SourcesInventoryResponse,
} from "../types";

type SourceView = "register" | "freshness" | "integrations" | "discovery" | "fleet";

function safeText(value: unknown, fallback = "n/a") {
  const text = String(value ?? "").trim();
  return text || fallback;
}

function listText(values: unknown, fallback = "n/a") {
  if (!Array.isArray(values)) return fallback;
  const items = values.map((value) => String(value || "").trim()).filter(Boolean);
  return items.length ? items.join(", ") : fallback;
}

function sourceIpSummary(item: SourceInventoryRecord, fallback = "n/a") {
  const sourceIps = Array.isArray(item.source_ips) ? item.source_ips : [];
  let values = [item.cmdb_ip, ...sourceIps]
    .map((value) => String(value || "").trim())
    .filter(Boolean);
  if (!values.length && Array.isArray(item.observed_ips)) {
    values = item.observed_ips.map((value) => String(value || "").trim()).filter(Boolean);
  }
  return values.length ? Array.from(new Set(values)).join(", ") : fallback;
}

function pickSourceTemplates(item: SourceInventoryRecord, templates: IntegrationTemplateRecord[]) {
  const haystack = [
    item?.source_name,
    item?.source_type,
    ...(item?.products || []),
    ...(item?.services || []),
    ...(item?.categories || []),
  ]
    .map((value) => String(value || "").toLowerCase())
    .join(" ");
  const ranked = templates
    .map((template) => {
      let score = 0;
      const id = String(template.id || "");
      if (haystack.includes("sql") || haystack.includes("postgres") || haystack.includes("mysql")) {
        if (id === "sql-source") score += 4;
      }
      if (haystack.includes("mongo") || haystack.includes("elastic") || haystack.includes("document")) {
        if (id === "nosql-source") score += 4;
      }
      if (haystack.includes("api") || haystack.includes("nextcloud") || haystack.includes("proxmox") || haystack.includes("scanner")) {
        if (id === "rest-pull") score += 3;
      }
      if (haystack.includes("webhook") || haystack.includes("json")) {
        if (id === "webhook-source") score += 3;
      }
      if (!score && id === "webhook-source") score = 1;
      return { template, score };
    })
    .sort((left, right) => right.score - left.score);
  return ranked.filter((item) => item.score > 0).slice(0, 3).map((item) => item.template);
}

export function SourcesPage() {
  const { lang } = useShellContext();
  const loadSources = useCallback(() => api.sourcesInventory(), []);
  const loadIntegrations = useCallback(() => api.integrationsCatalog(), []);
  const [fleetRefreshToken, setFleetRefreshToken] = useState(0);
  const loadFleet = useCallback(() => {
    void fleetRefreshToken;
    return api.proxmoxFleet({ limit: 500 });
  }, [fleetRefreshToken]);
  const [discoveryRefreshToken, setDiscoveryRefreshToken] = useState(0);
  const loadDiscovery = useCallback(() => {
    void discoveryRefreshToken;
    return api.sourceDiscovery();
  }, [discoveryRefreshToken]);
  const state = useAsyncData<SourcesInventoryResponse>(loadSources);
  const integrationsState = useAsyncData<IntegrationsCatalogResponse>(loadIntegrations);
  const fleetState = useAsyncData<ProxmoxFleetResponse>(loadFleet);
  const discoveryState = useAsyncData<SourceDiscoveryResponse>(loadDiscovery);
  const [searchParams] = useSearchParams();
  const [query, setQuery] = useState("");
  const [selectedSource, setSelectedSource] = useState<SourceInventoryRecord | null>(null);
  const [selectedFleetId, setSelectedFleetId] = useState("");
  const [selectedCandidateId, setSelectedCandidateId] = useState("");
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [view, setView] = useState<SourceView>("register");
  const [scanCidr, setScanCidr] = useState("192.168.1.0/24");
  const [scanBusy, setScanBusy] = useState(false);
  const [scanState, setScanState] = useState("");
  const [jobState, setJobState] = useState("");
  const [jobBusy, setJobBusy] = useState(false);
  const [bindingTarget, setBindingTarget] = useState("");
  const [bindingNote, setBindingNote] = useState("");
  const [jobCredentials, setJobCredentials] = useState<Record<string, Record<string, string>>>({});
  const debouncedQuery = useDebouncedValue(query, 250);

  const items = useMemo(() => {
    const rows = state.data?.items || [];
    const token = String(debouncedQuery || "").trim().toLowerCase();
    if (!token) return rows;
    return rows.filter((item: SourceInventoryRecord) => JSON.stringify(item).toLowerCase().includes(token));
  }, [state.data, debouncedQuery]);

  const sourceIntegrations = useMemo(() => {
    const rows = integrationsState.data?.items || [];
    return rows.filter((item: IntegrationTemplateRecord) => item.family === "source");
  }, [integrationsState.data]);

  const typeBreakdown = useMemo(() => {
    const counts = new Map<string, number>();
    for (const item of items) {
      const type = String(item.source_type || "unknown");
      counts.set(type, (counts.get(type) || 0) + 1);
    }
    return Array.from(counts.entries())
      .map(([label, count]) => ({ label, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 6);
  }, [items]);

  const collectors = useMemo(() => {
    const counts = new Map<string, number>();
    for (const item of items) {
      const collector = String(item.collector_name || item.collector_id || "unbound");
      counts.set(collector, (counts.get(collector) || 0) + 1);
    }
    return Array.from(counts.entries())
      .map(([label, count]) => ({ label, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 8);
  }, [items]);

  const integrationGroups = useMemo(() => {
    const counts = new Map<string, number>();
    for (const item of sourceIntegrations) {
      const group = String(item.group || "general");
      counts.set(group, (counts.get(group) || 0) + 1);
    }
    return Array.from(counts.entries())
      .map(([label, count]) => ({ label, count }))
      .sort((a, b) => b.count - a.count);
  }, [sourceIntegrations]);
  const vulnerabilityTemplates = useMemo(
    () => sourceIntegrations.filter((item: IntegrationTemplateRecord) => String(item.group || "").toLowerCase() === "vulnerability"),
    [sourceIntegrations],
  );
  const transportModes = useMemo(() => {
    const counts = new Map<string, number>();
    for (const item of sourceIntegrations) {
      const mode = String(item.mode || "runtime");
      counts.set(mode, (counts.get(mode) || 0) + 1);
    }
    return Array.from(counts.entries())
      .map(([label, count]) => ({ label, count }))
      .sort((a, b) => b.count - a.count);
  }, [sourceIntegrations]);
  const attentionQueue = useMemo(
    () =>
      items
        .filter((item: SourceInventoryRecord) => item.status !== "active")
        .sort((left: SourceInventoryRecord, right: SourceInventoryRecord) => Number(right.notable_events || 0) - Number(left.notable_events || 0))
        .slice(0, 8),
    [items],
  );
  const signalProfiles = useMemo(
    () =>
      items
        .map((item: SourceInventoryRecord) => ({
          source: item.source_name,
          auth: Number(item.auth_events || 0),
          audit: Number(item.audit_events || 0),
          notable: Number(item.notable_events || 0),
          status: item.status,
          collector: item.collector_name || item.collector_id || "unbound",
        }))
        .sort((left, right) => right.notable - left.notable || right.auth + right.audit - (left.auth + left.audit))
        .slice(0, 8),
    [items],
  );
  const selectedTemplates = useMemo(
    () => (selectedSource ? pickSourceTemplates(selectedSource, sourceIntegrations) : []),
    [selectedSource, sourceIntegrations],
  );
  const discoveryItems = useMemo(() => {
    const rows = discoveryState.data?.items || [];
    const token = String(debouncedQuery || "").trim().toLowerCase();
    if (!token) return rows;
    return rows.filter((item: DiscoveryCandidate) => JSON.stringify(item).toLowerCase().includes(token));
  }, [debouncedQuery, discoveryState.data]);
  const discoveryJobs = useMemo(() => discoveryState.data?.jobs || [], [discoveryState.data]);
  const fleetItems = useMemo(() => {
    const rows = fleetState.data?.items || [];
    const token = String(debouncedQuery || "").trim().toLowerCase();
    if (!token) return rows;
    return rows.filter((item: ProxmoxFleetRecord) => JSON.stringify(item).toLowerCase().includes(token));
  }, [debouncedQuery, fleetState.data]);
  const fleetMetrics = fleetState.data?.metrics || {};
  const selectedFleetItem = useMemo(
    () => fleetItems.find((item: ProxmoxFleetRecord) => String(item.id || "") === selectedFleetId) || fleetItems[0] || null,
    [fleetItems, selectedFleetId],
  );
  const selectedCandidate = useMemo(
    () => discoveryItems.find((item: DiscoveryCandidate) => String(item.id || "") === selectedCandidateId) || discoveryItems[0] || null,
    [discoveryItems, selectedCandidateId],
  );
  const selectedCandidateJob = useMemo(() => {
    const lastJobId = String(selectedCandidate?.last_job_id || "");
    return discoveryJobs.find((item: DiscoveryJob) => String(item.id || "") === lastJobId) || null;
  }, [discoveryJobs, selectedCandidate]);
  const selectedJobCredentialValues = useMemo(
    () => (selectedCandidateJob ? jobCredentials[String(selectedCandidateJob.id || "")] || {} : {}),
    [jobCredentials, selectedCandidateJob],
  );
  const discoveryMetrics = discoveryState.data?.metrics || {};
  const sourceIssues = [
    state.error,
    integrationsState.error ? `Integrations: ${integrationsState.error}` : "",
    fleetState.error ? `Proxmox fleet: ${fleetState.error}` : "",
    discoveryState.error ? `Discovery: ${discoveryState.error}` : "",
  ].filter(Boolean);
  const fallbackSourceCount = items.filter((item: SourceInventoryRecord) => item.inventory_source === "ingest-health-fallback").length;

  useEffect(() => {
    const nextQuery = String(searchParams.get("q") || "").trim();
    const nextView = String(searchParams.get("view") || "").trim().toLowerCase();
    const focus = String(searchParams.get("focus") || "").trim();
    if (searchParams.has("q")) {
      setQuery(nextQuery);
    }
    if (nextView === "register" || nextView === "freshness" || nextView === "integrations" || nextView === "discovery" || nextView === "fleet") {
      setView(nextView as SourceView);
    }
    if (focus) {
      setSelectedSource((current: SourceInventoryRecord | null) => {
        if (current?.source_name === focus) return current;
        const row = (state.data?.items || []).find((item: SourceInventoryRecord) => String(item.source_name || "") === focus);
        return row || current;
      });
    }
  }, [searchParams, state.data]);

  useEffect(() => {
    const selectedStillVisible = selectedSource
      ? items.some((item: SourceInventoryRecord) => String(item.source_name || "") === String(selectedSource.source_name || ""))
      : false;
    if (selectedSource && !selectedStillVisible) {
      setSelectedSource(debouncedQuery && items.length ? items[0] : null);
      return;
    }
    if (!selectedSource && items.length && debouncedQuery) {
      setSelectedSource(items[0]);
    }
  }, [debouncedQuery, items, selectedSource]);

  useEffect(() => {
    if (selectedFleetId && !fleetItems.some((item: ProxmoxFleetRecord) => String(item.id || "") === selectedFleetId)) {
      setSelectedFleetId("");
      return;
    }
    if (!selectedFleetId && fleetItems.length) {
      const preferred = fleetItems.find((item: ProxmoxFleetRecord) => String(item.state || "") === "onboardable") || fleetItems[0];
      setSelectedFleetId(String(preferred?.id || ""));
    }
  }, [fleetItems, selectedFleetId]);

  useEffect(() => {
    if (selectedCandidateId && !discoveryItems.some((item: DiscoveryCandidate) => String(item.id || "") === selectedCandidateId)) {
      setSelectedCandidateId("");
      return;
    }
    if (!selectedCandidateId && discoveryItems.length) {
      const unmanaged = discoveryItems.find((item: DiscoveryCandidate) => !item.connected);
      setSelectedCandidateId(String((unmanaged || discoveryItems[0]).id || ""));
    }
  }, [discoveryItems, selectedCandidateId]);

  useEffect(() => {
    setBindingTarget(
      String(
        selectedCandidate?.binding_override?.target ||
          selectedCandidate?.binding_target ||
          selectedCandidate?.connected_source ||
          selectedCandidate?.hostname ||
          selectedCandidate?.ip ||
          "",
      ),
    );
    setBindingNote(String(selectedCandidate?.binding_override?.note || ""));
  }, [selectedCandidate]);

  const kpiCards = [
    {
      label: t(lang, { en: "Sources", ru: "Источники" }),
      value: items.length,
      hint: t(lang, {
        en: "Distinct telemetry emitters in the active inventory.",
        ru: "Уникальные эмиттеры телеметрии в активном инвентаре.",
      }),
    },
    {
      label: t(lang, { en: "Active", ru: "Активные" }),
      value: items.filter((item: SourceInventoryRecord) => item.status === "active").length,
      hint: t(lang, {
        en: "Sources reporting within freshness thresholds.",
        ru: "Источники, укладывающиеся в пороги свежести.",
      }),
    },
    {
      label: t(lang, { en: "Needs attention", ru: "Требуют внимания" }),
      value: items.filter((item: SourceInventoryRecord) => item.status !== "active").length,
      hint: t(lang, {
        en: "Sources in delayed or stale state.",
        ru: "Источники в состоянии delayed или stale.",
      }),
    },
    {
      label: t(lang, { en: "Threat intel hits", ru: "TI совпадения" }),
      value: items.reduce((sum: number, item: SourceInventoryRecord) => sum + Number(item.ti_hits || 0), 0),
      hint: t(lang, {
        en: "Aggregated TI matches tied to the current source estate.",
        ru: "Суммарные TI-совпадения, связанные с текущим набором источников.",
      }),
    },
    {
      label: t(lang, { en: "Templates", ru: "Шаблоны" }),
      value: sourceIntegrations.length,
      hint: t(lang, {
        en: "Available webhook, database and API onboarding templates.",
        ru: "Доступные шаблоны onboarding для webhook, БД и API.",
      }),
    },
  ];

  async function runDiscoveryScan() {
    setScanBusy(true);
    setScanState("");
    try {
      const payload = await api.scanSourceDiscovery({ cidr: scanCidr, max_hosts: 256, timeout_seconds: 0.35 });
      const discovered = Number(payload?.scan?.discovered || 0);
      const unmanaged = Number(payload?.scan?.discovered_unmanaged || 0);
      setScanState(`Scanned ${payload?.scan?.hosts_scanned || 0} hosts, found ${discovered} active nodes, ${unmanaged} unmanaged.`);
      setDiscoveryRefreshToken((value) => value + 1);
      const firstUnmanaged = (payload?.items || []).find((item: DiscoveryCandidate) => !item.connected) || (payload?.items || [])[0];
      if (firstUnmanaged?.id) {
        setSelectedCandidateId(String(firstUnmanaged.id));
      }
    } catch (error) {
      setScanState(error instanceof Error ? error.message : "Scan failed");
    } finally {
      setScanBusy(false);
    }
  }

  async function prepareCandidateOnboarding() {
    if (!selectedCandidate?.id) return;
    setJobState("");
    try {
      const payload = await api.prepareSourceOnboarding(String(selectedCandidate.id));
      setJobState(`Prepared onboarding job ${payload?.job?.id || ""}`);
      setDiscoveryRefreshToken((value) => value + 1);
    } catch (error) {
      setJobState(error instanceof Error ? error.message : "Unable to prepare onboarding job");
    }
  }

  async function previewCandidateOnboarding() {
    const jobId = String(selectedCandidate?.last_job_id || selectedCandidateJob?.id || "");
    if (!jobId) return;
    setJobState("");
    try {
      const payload = await api.executeSourceOnboarding(jobId, { dry_run: true });
      setJobState(String(payload?.execution?.summary || `Preview completed for ${jobId}`));
      setDiscoveryRefreshToken((value) => value + 1);
    } catch (error) {
      setJobState(error instanceof Error ? error.message : "Unable to preview onboarding");
    }
  }

  function updateJobCredential(fieldId: string, value: string) {
    const jobId = String(selectedCandidateJob?.id || "");
    if (!jobId) return;
    setJobCredentials((current) => ({
      ...current,
      [jobId]: {
        ...(current[jobId] || {}),
        [fieldId]: value,
      },
    }));
  }

  async function executeCandidateOnboarding() {
    const jobId = String(selectedCandidate?.last_job_id || selectedCandidateJob?.id || "");
    if (!jobId) return;
    setJobBusy(true);
    setJobState("");
    try {
      const payload = await api.executeSourceOnboarding(jobId, {
        dry_run: false,
        credentials: selectedJobCredentialValues,
      });
      const execution = payload.execution || {};
      setJobState(String(execution.summary || `Executed onboarding job ${jobId}`));
      setDiscoveryRefreshToken((value) => value + 1);
    } catch (error) {
      setJobState(error instanceof Error ? error.message : "Unable to execute onboarding");
    } finally {
      setJobBusy(false);
    }
  }

  async function saveBindingOverride() {
    if (!selectedCandidate) return;
    const payload = {
      target: bindingTarget || selectedCandidate.connected_source || selectedCandidate.hostname || selectedCandidate.ip,
      aliases: [selectedCandidate.connected_source, selectedCandidate.hostname, selectedCandidate.ip].filter(Boolean),
      hostname: selectedCandidate.hostname,
      ip: selectedCandidate.ip,
      scope: "source_discovery",
      note: bindingNote,
      enabled: true,
    };
    try {
      if (selectedCandidate.binding_override_id) {
        await api.updateAssetBindingOverride(String(selectedCandidate.binding_override_id), payload);
      } else {
        await api.saveAssetBindingOverride(payload);
      }
      setJobState("Binding override saved.");
      setDiscoveryRefreshToken((value) => value + 1);
    } catch (error) {
      setJobState(error instanceof Error ? error.message : "Unable to save binding override");
    }
  }

  async function removeBindingOverride() {
    if (!selectedCandidate?.binding_override_id) return;
    try {
      await api.deleteAssetBindingOverride(String(selectedCandidate.binding_override_id));
      setJobState("Binding override removed.");
      setDiscoveryRefreshToken((value) => value + 1);
    } catch (error) {
      setJobState(error instanceof Error ? error.message : "Unable to remove binding override");
    }
  }

  return (
    <AsyncGate states={[state]} loadingMessage="Loading sources...">
    <div className="react-page react-page-sources">
      <SectionIntro
        kicker={t(lang, { en: "Sources", ru: "Источники" })}
        title={t(lang, { en: "Telemetry sources", ru: "Источники телеметрии" })}
        icon="sources"
        actions={
          <div className="react-actions react-wrap">
            <input
              className="react-input react-input-grow"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder={t(lang, {
                en: "Search source, type, collector...",
                ru: "Поиск по источнику, типу или коллектору...",
              })}
            />
            <button type="button" className="react-icon-button" onClick={() => setSettingsOpen(true)} aria-label="Source page settings">
              <Icon name="control" size={15} />
            </button>
          </div>
        }
      />
      {fallbackSourceCount ? (
        <div className="react-inline-note react-inline-note-spaced">
          Source inventory is using ingest runtime fallback for {fallbackSourceCount} sources while ClickHouse inventory is degraded or empty.
        </div>
      ) : null}
      {sourceIssues.length ? (
        <div className="react-inline-note react-inline-note-spaced">
          Partial source workspace: {sourceIssues.join(" / ")}
        </div>
      ) : null}

      <div className="react-grid react-grid-5">
        {kpiCards.map((card) => (
          <StatCard key={card.label} label={card.label} value={card.value} hint={card.hint} />
        ))}
      </div>

      <div className="react-segmented">
        <button type="button" className={view === "register" ? "active" : ""} onClick={() => setView("register")}>
          {t(lang, { en: "Register", ru: "Реестр" })}
        </button>
        <button type="button" className={view === "freshness" ? "active" : ""} onClick={() => setView("freshness")}>
          {t(lang, { en: "Freshness", ru: "Свежесть" })}
        </button>
        <button type="button" className={view === "integrations" ? "active" : ""} onClick={() => setView("integrations")}>
          {t(lang, { en: "Integrations", ru: "Интеграции" })}
        </button>
        <button type="button" className={view === "discovery" ? "active" : ""} onClick={() => setView("discovery")}>
          {t(lang, { en: "Discovery", ru: "Discovery" })}
        </button>
        <button type="button" className={view === "fleet" ? "active" : ""} onClick={() => setView("fleet")}>
          {t(lang, { en: "Fleet", ru: "Флот" })}
        </button>
      </div>

      {view === "register" ? (
        <div className="react-split react-split-xl">
          <section className="react-card">
            <PanelHeader title="Source register" subtitle="Emitter-centric view: freshness, signal mix and collector binding." />
            <div className="react-table-wrap">
              <table className="react-table">
                <thead>
                  <tr>
                    <th>Source</th>
                    <th>IP</th>
                    <th>Status</th>
                    <th>Type</th>
                    <th>Collector</th>
                    <th>Events</th>
                    <th>Signal mix</th>
                    <th>Last seen</th>
                  </tr>
                </thead>
                <tbody>
                  {items.map((item: SourceInventoryRecord) => (
                    <tr
                      key={item.source_name}
                      className={selectedSource?.source_name === item.source_name ? "react-table-row-active" : ""}
                      onClick={() => setSelectedSource(item)}
                    >
                      <td>
                        <strong>{item.source_name}</strong>
                      </td>
                      <td>{sourceIpSummary(item)}</td>
                      <td>
                        <StatusBadge value={item.status || "unknown"} />
                      </td>
                      <td>{item.source_type}</td>
                      <td>{item.collector_name || item.collector_id}</td>
                      <td>{item.events}</td>
                      <td>
                        {Number(item.auth_events || 0)} auth / {Number(item.audit_events || 0)} audit
                      </td>
                      <td>{item.last_seen || "n/a"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>

          <aside className="react-card react-drawer">
            {selectedSource ? (
              <>
                <PanelHeader
                  title={selectedSource.source_name}
                  subtitle={`${safeText(selectedSource.source_type)} / ${safeText(selectedSource.collector_name || selectedSource.collector_id)}`}
                  actions={
                    <div className="react-actions react-wrap">
                      <Link className="react-link-button" to={`/events?q=${encodeURIComponent(`log_source = '${selectedSource.source_name}'`)}`}>
                        Open in Events
                      </Link>
                      <Link className="react-link-button" to={`/incidents?q=${encodeURIComponent(selectedSource.source_name)}`}>
                        Related incidents
                      </Link>
                      <Link className="react-link-button" to={`/collectors?q=${encodeURIComponent(String(selectedSource.collector_name || selectedSource.collector_id || ""))}`}>
                        Collector path
                      </Link>
                      <Link className="react-link-button" to="/builders?kind=integration">
                        Open integration builder
                      </Link>
                    </div>
                  }
                />
                <section className="react-card react-card-nested">
                  <PanelHeader title="Emitter health" subtitle="Freshness, collector binding and signal balance for the selected source." />
                  <DrawerFieldGrid>
                    <KeyValue label="Status" value={<StatusBadge value={selectedSource.status || "unknown"} />} />
                    <KeyValue label="Source IP" value={sourceIpSummary(selectedSource)} />
                    <KeyValue label="CMDB IP" value={safeText(selectedSource.cmdb_ip)} />
                    <KeyValue label="Observed IPs" value={listText(selectedSource.observed_ips)} />
                    <KeyValue label="Source type" value={safeText(selectedSource.source_type)} />
                    <KeyValue label="Collector" value={safeText(selectedSource.collector_name || selectedSource.collector_id)} />
                    <KeyValue label="Events 24h" value={selectedSource.events} />
                    <KeyValue label="Auth events" value={selectedSource.auth_events} />
                    <KeyValue label="Audit events" value={selectedSource.audit_events} />
                    <KeyValue label="TI hits" value={selectedSource.ti_hits} />
                    <KeyValue label="Notable events" value={selectedSource.notable_events} />
                    <KeyValue label="Last seen" value={safeText(selectedSource.last_seen)} />
                  </DrawerFieldGrid>
                </section>
                <section className="react-card react-card-nested">
                  <PanelHeader title="Business and integration context" subtitle="Aliases, products and onboarding fit for the selected emitter." />
                  <DrawerFieldGrid>
                    <KeyValue label="Products" value={(selectedSource.products || []).join(", ") || "n/a"} />
                    <KeyValue label="Categories" value={(selectedSource.categories || []).join(", ") || "n/a"} />
                    <KeyValue label="Aliases" value={listText(selectedSource.aliases)} />
                    <KeyValue label="Services" value={(selectedSource.services || []).join(", ") || "n/a"} />
                    <KeyValue label="Environments" value={Array.isArray(selectedSource.environments) ? selectedSource.environments.join(", ") || "n/a" : "n/a"} />
                    <KeyValue label="CMDB owner" value={safeText(selectedSource.cmdb_owner)} />
                    <KeyValue label="Signal mix" value={`${Number(selectedSource.auth_events || 0)} auth / ${Number(selectedSource.audit_events || 0)} audit`} />
                    <KeyValue
                      label="Template fit"
                      value={selectedTemplates.map((item: IntegrationTemplateRecord) => item.title).join(", ") || "n/a"}
                    />
                  </DrawerFieldGrid>
                </section>
                <section className="react-card react-card-nested">
                  <PanelHeader title="Integration candidates" subtitle="Most likely onboarding templates for the selected source family and signal profile." />
                  <div className="react-chip-grid">
                    {(selectedTemplates.length ? selectedTemplates : sourceIntegrations.slice(0, 3)).map((item: IntegrationTemplateRecord) => (
                      <div key={item.id} className="react-chip-card">
                        <div className="react-top-kicker">{item.group || "general"}</div>
                        <strong>{item.title}</strong>
                        <span>{item.description}</span>
                        <Link className="react-link-button" to={`/builders?kind=integration&template=${encodeURIComponent(String(item.id || ""))}`}>
                          Use in Builder
                        </Link>
                      </div>
                    ))}
                  </div>
                </section>
                <section className="react-card react-card-nested">
                  <PanelHeader title="External manager readiness" subtitle="Recommended ingestion path if this source needs to be reconciled with a future Vulnerability Manager." />
                  <DrawerFieldGrid>
                    <KeyValue label="Suggested mode" value={selectedTemplates[0]?.mode || "pull"} />
                    <KeyValue label="Suggested template" value={selectedTemplates[0]?.title || "Webhook source"} />
                    <KeyValue
                      label="Vuln-manager path"
                      value={
                        vulnerabilityTemplates.map((item: IntegrationTemplateRecord) => item.title).slice(0, 3).join(", ") ||
                        "REST API pull source"
                      }
                    />
                    <KeyValue label="Protocols" value={(selectedTemplates[0]?.protocols || []).join(", ") || "https"} />
                  </DrawerFieldGrid>
                </section>
              </>
            ) : (
              <EmptyState message="Select a source to inspect freshness, products and collector binding." />
            )}
          </aside>
        </div>
      ) : null}

      {view === "freshness" ? (
        <div className="react-grid react-grid-2">
          <section className="react-card">
            <PanelHeader title="Source classes" subtitle="What kinds of emitters are active in the telemetry plane." />
            <div className="react-chip-grid">
              {typeBreakdown.map((row) => (
                <div key={row.label} className="react-chip-card">
                  <div className="react-top-kicker">Type</div>
                  <strong>{row.label}</strong>
                  <span>{row.count} sources</span>
                </div>
              ))}
            </div>
          </section>
          <section className="react-card">
            <PanelHeader title="Collector bindings" subtitle="How emitters are distributed across collector pipelines." />
            <div className="react-table-wrap">
              <table className="react-table">
                <thead>
                  <tr>
                    <th>Collector</th>
                    <th>Sources</th>
                  </tr>
                </thead>
                <tbody>
                  {collectors.map((row) => (
                    <tr key={row.label}>
                      <td>{row.label}</td>
                      <td>{row.count}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
          <section className="react-card">
            <PanelHeader title="Needs attention" subtitle="Sources not currently within healthy freshness thresholds." />
            <div className="react-list react-list-compact">
              {attentionQueue.map((item: SourceInventoryRecord) => (
                <button key={item.source_name} type="button" className="react-list-item" onClick={() => { setSelectedSource(item); setView("register"); }}>
                  <strong>{item.source_name}</strong>
                  <span>{safeText(item.source_type)} / {safeText(item.collector_name || item.collector_id)}</span>
                  <span>{item.status || "unknown"} / {safeText(item.last_seen)}</span>
                </button>
              ))}
            </div>
          </section>
          <section className="react-card">
            <PanelHeader title="Signal profiles" subtitle="Auth/audit/notable balance for the busiest or riskiest emitters." />
            <div className="react-table-wrap">
              <table className="react-table">
                <thead>
                  <tr>
                    <th>Source</th>
                    <th>Status</th>
                    <th>Auth</th>
                    <th>Audit</th>
                    <th>Notable</th>
                    <th>Collector</th>
                  </tr>
                </thead>
                <tbody>
                  {signalProfiles.map((row) => (
                    <tr key={row.source}>
                      <td>{row.source}</td>
                      <td><StatusBadge value={row.status || "unknown"} /></td>
                      <td>{row.auth}</td>
                      <td>{row.audit}</td>
                      <td>{row.notable}</td>
                      <td>{row.collector}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
        </div>
      ) : null}

      {view === "integrations" ? (
        <div className="react-grid react-grid-2">
          <section className="react-card">
            <PanelHeader title="Vulnerability Manager-ready templates" subtitle="Prepared source templates that can be reused when the external Vulnerability Manager arrives." />
            <div className="react-chip-grid">
              {vulnerabilityTemplates.map((item: IntegrationTemplateRecord) => (
                <div key={item.id} className="react-chip-card">
                  <div className="react-top-kicker">{item.group || "vulnerability"}</div>
                  <strong>{item.title}</strong>
                  <span>{item.description}</span>
                  <span>{item.mode} / {(item.protocols || []).join(", ")}</span>
                  <Link className="react-link-button" to={`/builders?kind=integration&template=${encodeURIComponent(String(item.id || ""))}`}>
                    Use in Builder
                  </Link>
                </div>
              ))}
            </div>
          </section>
          <section className="react-card">
            <PanelHeader title="Integration families" subtitle="Source onboarding patterns beyond syslog and Windows collectors." />
            <div className="react-chip-grid">
              {sourceIntegrations.map((item: IntegrationTemplateRecord) => (
                <div key={item.id} className="react-chip-card">
                  <div className="react-top-kicker">{item.group || "general"}</div>
                  <strong>{item.title}</strong>
                  <span>{item.description}</span>
                  <span>{item.mode} / {(item.protocols || []).join(", ")}</span>
                  <Link className="react-link-button" to={`/builders?kind=integration&template=${encodeURIComponent(String(item.id || ""))}`}>
                    Use in Builder
                  </Link>
                </div>
              ))}
            </div>
          </section>
          <section className="react-card">
            <PanelHeader title="Integration groups" subtitle="How onboarding templates are distributed by source family." />
            <div className="react-table-wrap">
              <table className="react-table">
                <thead>
                  <tr>
                    <th>Group</th>
                    <th>Templates</th>
                  </tr>
                </thead>
                <tbody>
                  {integrationGroups.map((row) => (
                    <tr key={row.label}>
                      <td>{row.label}</td>
                      <td>{row.count}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
          <section className="react-card">
            <PanelHeader title="Transport modes" subtitle="Push, pull and polling patterns available to source onboarding." />
            <div className="react-chip-grid">
              {transportModes.map((row) => (
                <div key={row.label} className="react-chip-card">
                  <div className="react-top-kicker">Mode</div>
                  <strong>{row.label}</strong>
                  <span>{row.count} templates</span>
                </div>
              ))}
            </div>
          </section>
          <section className="react-card">
            <PanelHeader title="Operational hand-off" subtitle="How a new external source moves from template selection into runtime telemetry." />
            <div className="react-info-list">
              <div className="react-info-row">
                <span>1. Template</span>
                <strong>Choose webhook, database or REST pull</strong>
              </div>
              <div className="react-info-row">
                <span>2. Collector fit</span>
                <strong>Bind to protocol and transport surface</strong>
              </div>
              <div className="react-info-row">
                <span>3. Builder path</span>
                <strong>Generate and publish runtime integration draft</strong>
              </div>
            </div>
            <div className="react-actions react-wrap">
              <Link className="react-link-button" to="/collectors?view=protocols">
                Collector protocols
              </Link>
              <Link className="react-link-button" to="/builders?kind=integration">
                Integration builder
              </Link>
              <Link className="react-link-button" to="/vuln">
                Vulnerability hand-off
              </Link>
            </div>
          </section>
        </div>
      ) : null}

      {view === "discovery" ? (
        <div className="react-split react-split-xl">
          <section className="react-card">
            <PanelHeader
              title="LAN discovery and onboarding"
              subtitle="Find unmanaged LAN nodes, infer their platform, and prepare monitoring rollout jobs."
              actions={
                <div className="react-actions react-wrap">
                  <input
                    className="react-input"
                    value={scanCidr}
                    onChange={(event) => setScanCidr(event.target.value)}
                    placeholder="192.168.1.0/24"
                  />
                  <button type="button" className="react-primary-button" onClick={runDiscoveryScan} disabled={scanBusy}>
                    {scanBusy ? "Scanning..." : "Run discovery"}
                  </button>
                </div>
              }
            />
            <div className="react-grid react-grid-4">
              <StatCard label="Candidates" value={discoveryMetrics.total || 0} hint="Hosts seen during discovery." />
              <StatCard label="Unmanaged" value={discoveryMetrics.unmanaged || 0} hint="Hosts not matched to live telemetry sources." />
              <StatCard label="Auto-ready" value={discoveryMetrics.auto_ready || 0} hint="Candidates that can be onboarded through Linux, Windows or network automation." />
              <StatCard label="Prepared jobs" value={discoveryMetrics.prepared || 0} hint="Monitoring jobs already prepared for follow-up." />
            </div>
            {scanState ? <div className="react-inline-note">{scanState}</div> : null}
            <div className="react-table-wrap">
              <table className="react-table">
                <thead>
                  <tr>
                    <th>IP</th>
                    <th>Status</th>
                    <th>OS</th>
                    <th>Role</th>
                    <th>Ports</th>
                    <th>Monitoring</th>
                    <th>Recommendation</th>
                  </tr>
                </thead>
                <tbody>
                  {discoveryItems.map((item: DiscoveryCandidate) => (
                    <tr
                      key={item.id}
                      className={selectedCandidate?.id === item.id ? "react-table-row-active" : ""}
                      onClick={() => setSelectedCandidateId(String(item.id || ""))}
                    >
                      <td>
                        <strong>{item.ip}</strong>
                        <div className="react-muted">{safeText(item.hostname, "no dns")}</div>
                      </td>
                      <td><StatusBadge value={item.status || "candidate"} /></td>
                      <td>{safeText(item.os_family)}</td>
                      <td>{safeText(item.probable_role)}</td>
                      <td>{safeText(item.port_summary)}</td>
                      <td><StatusBadge value={item.monitoring_status || "candidate"} /></td>
                      <td>{safeText(item.recommendation?.title)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="react-card react-card-nested">
              <PanelHeader title="Prepared jobs" subtitle="Latest onboarding jobs and dry-run previews for unmanaged hosts." />
              <div className="react-list react-list-compact">
                {discoveryJobs.length ? (
                  discoveryJobs.slice(0, 8).map((job: DiscoveryJob) => (
                    <button
                      key={job.id}
                      type="button"
                      className="react-list-item"
                      onClick={() => setSelectedCandidateId(String(job.candidate_id || ""))}
                    >
                      <strong>{job.summary || job.method}</strong>
                      <span>{job.ip || "n/a"} / {job.collector_profile || "n/a"}</span>
                      <span>{job.status || "prepared"} / {job.updated_ts || job.created_ts || "n/a"}</span>
                    </button>
                  ))
                ) : (
                  <EmptyState message="No onboarding jobs prepared yet." />
                )}
              </div>
            </div>
          </section>

          <aside className="react-card react-drawer">
            {selectedCandidate ? (
              <>
                <PanelHeader
                  title={`${selectedCandidate.ip} ${selectedCandidate.hostname ? `(${selectedCandidate.hostname})` : ""}`.trim()}
                  subtitle={`${safeText(selectedCandidate.os_family)} / ${safeText(selectedCandidate.probable_role)} / confidence ${Number(selectedCandidate.confidence || 0).toFixed(2)}`}
                  actions={
                    <div className="react-actions react-wrap">
                      <button type="button" className="react-primary-button" onClick={prepareCandidateOnboarding}>
                        Prepare monitoring
                      </button>
                      <button
                        type="button"
                        className="react-link-button"
                        onClick={previewCandidateOnboarding}
                        disabled={!selectedCandidate.last_job_id}
                      >
                        Preview auto-onboarding
                      </button>
                      <button
                        type="button"
                        className="react-link-button"
                        onClick={executeCandidateOnboarding}
                        disabled={!selectedCandidateJob?.execution_supported || jobBusy}
                      >
                        {jobBusy ? "Executing..." : "Execute live"}
                      </button>
                    </div>
                  }
                />
                <section className="react-card react-card-nested">
                  <PanelHeader title="Discovery profile" subtitle="What the scanner observed and how the platform classified the host." />
                  <DrawerFieldGrid>
                    <KeyValue label="Connected" value={selectedCandidate.connected ? "yes" : "no"} />
                    <KeyValue label="Status" value={<StatusBadge value={selectedCandidate.status || "candidate"} />} />
                    <KeyValue label="Monitoring" value={<StatusBadge value={selectedCandidate.monitoring_status || "candidate"} />} />
                    <KeyValue label="Source family" value={safeText(selectedCandidate.source_family)} />
                    <KeyValue label="Collector profile" value={safeText(selectedCandidate.recommendation?.collector_profile)} />
                    <KeyValue label="Template" value={safeText(selectedCandidate.recommendation?.integration_template)} />
                    <KeyValue label="Auto method" value={safeText(selectedCandidate.recommendation?.auto_monitoring_method)} />
                    <KeyValue label="Last seen" value={safeText(selectedCandidate.last_seen_ts)} />
                  </DrawerFieldGrid>
                </section>
                <section className="react-card react-card-nested">
                  <PanelHeader title="Open services" subtitle="Ports, banners and titles discovered on the candidate host." />
                  <div className="react-chip-grid">
                    {(selectedCandidate.open_ports || []).map((port) => (
                      <div key={`${selectedCandidate.id}-${port.port}`} className="react-chip-card">
                        <div className="react-top-kicker">{port.service || "tcp"}</div>
                        <strong>{port.port}</strong>
                        <span>{safeText(port.server || port.banner || port.title, "banner unavailable")}</span>
                      </div>
                    ))}
                  </div>
                </section>
                <section className="react-card react-card-nested">
                  <PanelHeader title="Monitoring rollout" subtitle="How the platform can place this host under monitoring." />
                  <DrawerFieldGrid>
                    <KeyValue label="Recommendation" value={safeText(selectedCandidate.recommendation?.title)} />
                    <KeyValue label="Auto-ready" value={selectedCandidate.recommendation?.auto_monitoring_supported ? "yes" : "no"} />
                    <KeyValue label="Connected source" value={safeText(selectedCandidate.connected_source)} />
                    <KeyValue label="Last job" value={safeText(selectedCandidate.last_job_id)} />
                    <KeyValue label="Asset hint" value={safeText(selectedCandidate.connected_source || selectedCandidate.hostname || selectedCandidate.ip)} />
                  </DrawerFieldGrid>
                  {jobState ? <div className="react-inline-note">{jobState}</div> : null}
                </section>
                <section className="react-card react-card-nested">
                  <PanelHeader title="Binding remediation" subtitle="Override asset binding directly from discovery so onboarding and vulnerability flows resolve the same target." />
                  <DrawerFieldGrid>
                    <KeyValue label="Override state" value={selectedCandidate.binding_override ? <StatusBadge value="active" /> : <StatusBadge value="pending" />} />
                    <KeyValue label="Binding target" value={safeText(selectedCandidate.binding_target || bindingTarget)} />
                    <KeyValue label="Overrides total" value={Number(discoveryMetrics.binding_overrides_total || 0)} />
                    <KeyValue label="Applied now" value={Number(discoveryMetrics.binding_overrides_applied || 0)} />
                  </DrawerFieldGrid>
                  <div className="react-form-grid" style={{ marginTop: 16 }}>
                    <input className="react-input" value={bindingTarget} onChange={(event) => setBindingTarget(event.target.value)} placeholder="Asset or source target" />
                    <input className="react-input react-input-full" value={bindingNote} onChange={(event) => setBindingNote(event.target.value)} placeholder="Operator note" />
                  </div>
                  <div className="react-actions" style={{ marginTop: 12 }}>
                    <button type="button" className="react-link-button" onClick={saveBindingOverride}>Save override</button>
                    <button type="button" className="react-link-button" onClick={removeBindingOverride} disabled={!selectedCandidate.binding_override_id}>Remove override</button>
                  </div>
                </section>
                {selectedCandidateJob ? (
                  <section className="react-card react-card-nested">
                    <PanelHeader title="Prepared job detail" subtitle="The current rollout plan and what the executor will do." />
                    <DrawerFieldGrid>
                      <KeyValue label="Job" value={safeText(selectedCandidateJob.id)} />
                      <KeyValue label="Status" value={<StatusBadge value={selectedCandidateJob.status || "prepared"} />} />
                      <KeyValue label="Executor" value={selectedCandidateJob.execution_supported ? "available" : "manual"} />
                      <KeyValue label="Method" value={safeText(selectedCandidateJob.method)} />
                      <KeyValue label="Vendor" value={safeText(selectedCandidateJob.network_vendor)} />
                    </DrawerFieldGrid>
                    {(selectedCandidateJob.credential_requirements || []).length ? (
                      <section className="react-card react-card-nested">
                        <PanelHeader title="Execution credentials" subtitle="Ephemeral operator input for SSH-based rollout. Values stay in browser state only." />
                        <div className="react-form-grid">
                          {(selectedCandidateJob.credential_requirements || []).map((field) => {
                            const fieldId = String(field.id || "");
                            const label = safeText(field.label || fieldId, fieldId);
                            const secure = /password|secret/i.test(fieldId);
                            return (
                              <label key={`${selectedCandidateJob.id}-${fieldId}`} className="react-field">
                                <span className="react-label">{label}{field.required ? " *" : ""}</span>
                                <input
                                  className="react-input"
                                  type={secure ? "password" : "text"}
                                  value={selectedJobCredentialValues[fieldId] || ""}
                                  onChange={(event) => updateJobCredential(fieldId, event.target.value)}
                                  placeholder={label}
                                />
                              </label>
                            );
                          })}
                        </div>
                      </section>
                    ) : null}
                    <div className="react-list react-list-compact">
                      {(selectedCandidateJob.command_preview || []).map((line: string, index: number) => (
                        <div key={`${selectedCandidateJob.id}-${index}`} className="react-list-item">
                          <strong>{index + 1}.</strong>
                          <span>{line}</span>
                        </div>
                      ))}
                    </div>
                    {selectedCandidateJob.config_preview ? (
                      <details className="react-details" open>
                        <summary>Config preview</summary>
                        <JsonPreview value={{ config_preview: selectedCandidateJob.config_preview }} />
                      </details>
                    ) : null}
                    {(selectedCandidateJob.network_commands || []).length ? (
                      <details className="react-details" open>
                        <summary>Network command set</summary>
                        <JsonPreview value={{ commands: selectedCandidateJob.network_commands }} />
                      </details>
                    ) : null}
                    {selectedCandidateJob.last_execution ? (
                      <details className="react-details" open>
                        <summary>Last execution</summary>
                        <JsonPreview value={selectedCandidateJob.last_execution as RuntimeBlob} />
                      </details>
                    ) : null}
                  </section>
                ) : null}
              </>
            ) : (
              <EmptyState message="Run discovery or pick a candidate host to inspect rollout options." />
            )}
          </aside>
        </div>
      ) : null}

      {view === "fleet" ? (
        <div className="react-split react-split-xl">
          <section className="react-card">
            <PanelHeader
              title="Proxmox fleet"
              subtitle="Live hypervisor-backed inventory with onboarding, monitoring, runtime and OpenVAS coverage state."
              actions={
                <button
                  type="button"
                  className="react-link-button"
                  onClick={async () => {
                    setJobState("");
                    try {
                      const payload = await api.syncProxmoxFleet();
                      const total = Number(payload?.metrics?.total || payload?.items?.length || 0);
                      setJobState(`Fleet sync completed: ${total} guests.`);
                      setFleetRefreshToken((value) => value + 1);
                    } catch (error) {
                      setJobState(error instanceof Error ? error.message : "Unable to sync Proxmox fleet");
                    }
                  }}
                >
                  Sync fleet
                </button>
              }
            />
            <div className="react-grid react-grid-4" style={{ marginBottom: 16 }}>
              <StatCard label="Guests" value={Number(fleetMetrics.total || fleetItems.length || 0)} hint="All guests returned by the live hypervisor inventory." />
              <StatCard label="Connected" value={Number(fleetMetrics.connected || 0)} hint="Guests already visible as telemetry or managed assets." />
              <StatCard label="Onboardable" value={Number(fleetMetrics.onboardable || 0)} hint="Reachable guests ready for monitoring rollout." />
              <StatCard label="Offline" value={Number(fleetMetrics.offline || 0)} hint="Powered-off or unreachable guests still retained in inventory." />
            </div>
            <div className="react-table-wrap">
              <table className="react-table">
                <thead>
                  <tr>
                    <th>Guest</th>
                    <th>State</th>
                    <th>Type</th>
                    <th>Role</th>
                    <th>IP</th>
                    <th>Coverage</th>
                  </tr>
                </thead>
                <tbody>
                  {fleetItems.map((item) => (
                    <tr key={item.id} onClick={() => setSelectedFleetId(String(item.id || ""))}>
                      <td>
                        <strong>{safeText(item.name)}</strong>
                        <div className="react-muted-line">{safeText(item.business_service)}</div>
                      </td>
                      <td><StatusBadge value={safeText(item.state, "inventory-only")} /></td>
                      <td>{safeText(item.guest_type)}</td>
                      <td>{safeText(item.role)}</td>
                      <td>{safeText(item.ip)}</td>
                      <td>
                        {[
                          item.connected ? "logs" : "",
                          item.host_runtime_enabled ? "runtime" : "",
                          item.vuln_scannable ? "openvas" : "",
                        ]
                          .filter(Boolean)
                          .join(" | ") || "inventory"}
                      </td>
                    </tr>
                  ))}
                  {!fleetItems.length ? (
                    <tr>
                      <td colSpan={6}>No Proxmox fleet records loaded yet.</td>
                    </tr>
                  ) : null}
                </tbody>
              </table>
            </div>
          </section>
          <aside className="react-detail-column">
            {selectedFleetItem ? (
              <>
                <section className="react-card">
                  <PanelHeader
                    title={`${safeText(selectedFleetItem.name)} ${selectedFleetItem.ip ? `(${selectedFleetItem.ip})` : ""}`.trim()}
                    subtitle={`${safeText(selectedFleetItem.role)} / ${safeText(selectedFleetItem.os_family)} / ${safeText(selectedFleetItem.guest_type)}`}
                  />
                  <DrawerFieldGrid>
                    <KeyValue label="State" value={<StatusBadge value={safeText(selectedFleetItem.state, "inventory-only")} />} />
                    <KeyValue label="Connected" value={selectedFleetItem.connected ? "yes" : "no"} />
                    <KeyValue label="Reachable" value={selectedFleetItem.reachable ? "yes" : "no"} />
                    <KeyValue label="Monitoring" value={selectedFleetItem.monitoring_supported ? "supported" : "inventory-only"} />
                    <KeyValue label="Host runtime" value={selectedFleetItem.host_runtime_enabled ? "enabled target" : "not targeted"} />
                    <KeyValue label="OpenVAS" value={selectedFleetItem.vuln_scannable ? "scannable" : "not available"} />
                    <KeyValue label="Asset ID" value={safeText(selectedFleetItem.asset_id)} />
                    <KeyValue label="Last seen" value={safeText(selectedFleetItem.last_seen_ts)} />
                  </DrawerFieldGrid>
                </section>
                <section className="react-card react-card-nested">
                  <PanelHeader title="Operational pivots" subtitle="How this guest maps into onboarding, runtime and vulnerability workflows." />
                  <div className="react-list react-list-compact">
                    <Link className="react-list-item" to={`/sources?view=discovery&q=${encodeURIComponent(String(selectedFleetItem.ip || selectedFleetItem.name || ""))}`}>
                      <strong>Discovery and onboarding</strong>
                      <span>Prepare Linux, Windows or network onboarding from the existing rollout lanes.</span>
                    </Link>
                    <Link className="react-list-item" to={`/vuln?q=${encodeURIComponent(String(selectedFleetItem.ip || selectedFleetItem.name || ""))}`}>
                      <strong>Vulnerability coverage</strong>
                      <span>Review OpenVAS scans, fleet coverage and critical exposure for this guest.</span>
                    </Link>
                    <Link className="react-list-item" to={`/assets?q=${encodeURIComponent(String(selectedFleetItem.asset_id || selectedFleetItem.name || ""))}`}>
                      <strong>Assets and investigations</strong>
                      <span>Pivot into the normalized asset identity used across sources, events and vulnerability workflows.</span>
                    </Link>
                  </div>
                </section>
                {jobState ? <div className="react-inline-note">{jobState}</div> : null}
              </>
            ) : (
              <EmptyState message="Pick a fleet guest to inspect monitoring and vulnerability coverage." />
            )}
          </aside>
        </div>
      ) : null}

      <DrawerOverlay
        open={settingsOpen}
        title="Source page settings"
        subtitle="Emitter-side workflows, integrations and pivots for telemetry source management."
        onClose={() => setSettingsOpen(false)}
      >
        <section className="react-card react-card-nested">
          <PanelHeader title="Operational pivots" subtitle="Jump into source-centric analyst workspaces." icon="sources" />
          <div className="react-actions react-wrap">
            <Link className="react-link-button" to="/events?q=log_source%20!%3D%20%27%27" onClick={() => setSettingsOpen(false)}>
              All sources in Events
            </Link>
            <Link className="react-link-button" to="/incidents" onClick={() => setSettingsOpen(false)}>
              Incident queue
            </Link>
            <Link className="react-link-button" to="/collectors" onClick={() => setSettingsOpen(false)}>
              Collector bindings
            </Link>
          </div>
        </section>
        <section className="react-card react-card-nested">
          <PanelHeader title="Integration templates" subtitle="Webhook, database and API onboarding available in the content plane." icon="builders" />
          <div className="react-chip-grid">
            {sourceIntegrations.map((item: IntegrationTemplateRecord) => (
              <div key={item.id} className="react-chip-card">
                <div className="react-top-kicker">{item.group || "general"}</div>
                <strong>{item.title}</strong>
                <span>{item.description}</span>
                <span>{item.mode} / {(item.protocols || []).join(", ")}</span>
              </div>
            ))}
          </div>
          <div className="react-actions react-wrap">
            <Link className="react-link-button" to="/builders" onClick={() => setSettingsOpen(false)}>
              Open integration builder
            </Link>
          </div>
        </section>
        <section className="react-card react-card-nested">
          <PanelHeader title="External manager hand-off" subtitle="Preferred source-side transport options for a future Vulnerability Manager." icon="sources" />
          <div className="react-chip-grid">
            {vulnerabilityTemplates.slice(0, 3).map((item: IntegrationTemplateRecord) => (
              <div key={item.id} className="react-chip-card">
                <div className="react-top-kicker">{item.mode || "pull"}</div>
                <strong>{item.title}</strong>
                <span>{(item.protocols || []).join(", ") || "https"}</span>
              </div>
            ))}
          </div>
        </section>
      </DrawerOverlay>
    </div>
    </AsyncGate>
  );
}
