import { useCallback, useEffect, useMemo, useState } from "react";
import { Search } from "lucide-react";
import { Link, useSearchParams } from "react-router-dom";
import { api } from "../api";
import { AsyncGate } from "../async";
import { t, useShellContext } from "../context";
import { useAsyncData, useDebouncedValue } from "../hooks";
import { humanizeSourceName } from "../humanize";
import { DrawerFieldGrid, DrawerOverlay, EmptyState, Icon, InvestigationActionRail, InvestigationSummaryStrip, InvestigationTimeline, JsonPreview, KeyValue, PanelHeader, SeverityBadge, StatCard, StatusBadge } from "../ui";
import { NativeActionBar, NativePageHeader, NativePager } from "../native";
import type { AssetInventoryResponse, AssetRecord, DiscoveryCandidate, DiscoveryJob, RuntimeBlob, SourceDiscoveryResponse } from "../types";

type AssetView = "inventory" | "exposure" | "ownership" | "unconnected";

function safeText(value: unknown, fallback = "n/a") {
  const text = String(value ?? "").trim();
  return text || fallback;
}

const ONBOARDING_TELEMETRY_OPTIONS = [
  { id: "syslog", label: "Syslog", hint: "Linux/network operational logs" },
  { id: "linux_auth", label: "Linux auth", hint: "/var/log/auth.log, secure, sudo, sshd" },
  { id: "auditd", label: "Linux auditd", hint: "execve, privilege and file audit" },
  { id: "process_runtime", label: "Process runtime", hint: "process, parent, command-line evidence" },
  { id: "windows_event", label: "Windows Event", hint: "Security, System, Application" },
  { id: "sysmon", label: "Sysmon", hint: "process, network, image-load telemetry" },
  { id: "powershell", label: "PowerShell", hint: "script block and operational logs" },
  { id: "network_syslog", label: "Network syslog", hint: "firewall/router/switch logs" },
  { id: "netflow", label: "NetFlow/IPFIX", hint: "flow metadata from network devices" },
  { id: "config_backup", label: "Config backup", hint: "device config snapshots for IR" },
  { id: "app_json", label: "Application JSON", hint: "HTTP/API/application audit events" },
  { id: "service_probe", label: "Service probes", hint: "reachable services, banners, onboarding fit" },
  { id: "vulnerability_scan", label: "Vulnerability handoff", hint: "scan target and exposure context" },
];

const DEFAULT_ONBOARDING_CREDENTIALS: Record<string, string> = {
  protocol: "ssh",
  management_ip: "",
  port: "22",
  username: "",
  password: "",
  sudo_password: "",
  enable_password: "",
  winrm_transport: "https",
  snmp_community: "",
  api_token: "",
  private_key_ref: "",
  certificate_ref: "",
  vault_ref: "",
};

function telemetryDefaultsForCandidate(candidate: DiscoveryCandidate | null) {
  const osFamily = String(candidate?.os_family || "").toLowerCase();
  const role = String(candidate?.probable_role || candidate?.source_family || "").toLowerCase();
  if (osFamily.includes("windows")) return ["windows_event", "sysmon", "powershell"];
  if (osFamily.includes("network") || role.includes("router") || role.includes("network")) return ["network_syslog", "netflow", "config_backup"];
  if (osFamily.includes("application")) return ["app_json", "syslog", "vulnerability_scan"];
  if (osFamily.includes("linux") || role.includes("proxmox")) return ["syslog", "linux_auth", "auditd", "process_runtime"];
  return ["syslog", "service_probe", "vulnerability_scan"];
}

function credentialsDefaultsForCandidate(candidate: DiscoveryCandidate | null): Record<string, string> {
  const ports = (candidate?.open_ports || []).map((item) => Number(item.port || 0));
  const hasPort = (port: number) => ports.includes(port);
  const osFamily = String(candidate?.os_family || "").toLowerCase();
  const role = String(candidate?.probable_role || candidate?.source_family || "").toLowerCase();
  if (osFamily.includes("windows")) {
    return {
      ...DEFAULT_ONBOARDING_CREDENTIALS,
      protocol: hasPort(3389) ? "rdp" : "winrm",
      port: hasPort(5986) ? "5986" : hasPort(5985) ? "5985" : hasPort(3389) ? "3389" : "5986",
      management_ip: String(candidate?.ip || ""),
    };
  }
  if (osFamily.includes("network") || role.includes("router") || role.includes("network")) {
    return {
      ...DEFAULT_ONBOARDING_CREDENTIALS,
      protocol: hasPort(22) ? "ssh" : hasPort(161) ? "snmp" : "ssh",
      port: hasPort(22) ? "22" : hasPort(161) ? "161" : "22",
      management_ip: String(candidate?.ip || ""),
    };
  }
  return {
    ...DEFAULT_ONBOARDING_CREDENTIALS,
    protocol: hasPort(8006) ? "https" : "ssh",
    port: hasPort(22) ? "22" : hasPort(8006) ? "8006" : "22",
    management_ip: String(candidate?.ip || ""),
  };
}

export function AssetsPage() {
  const { lang } = useShellContext();
  const assetLabel = useCallback((value: unknown) => humanizeSourceName(value, lang, { technicalSuffix: false }) || String(value || ""), [lang]);
  const [assetRefreshToken, setAssetRefreshToken] = useState(0);
  const loadAssets = useCallback(() => {
    void assetRefreshToken;
    return api.assetInventory();
  }, [assetRefreshToken]);
  const [discoveryRefreshToken, setDiscoveryRefreshToken] = useState(0);
  const loadDiscovery = useCallback(() => {
    void discoveryRefreshToken;
    return api.sourceDiscovery({ limit: 500 });
  }, [discoveryRefreshToken]);
  const state = useAsyncData<AssetInventoryResponse>(loadAssets);
  const discoveryState = useAsyncData<SourceDiscoveryResponse>(loadDiscovery);
  const [searchParams] = useSearchParams();
  const [query, setQuery] = useState("");
  const [selectedAsset, setSelectedAsset] = useState<AssetRecord | null>(null);
  const [selectedCandidateId, setSelectedCandidateId] = useState("");
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [view, setView] = useState<AssetView>("inventory");
  const [scanCidr, setScanCidr] = useState("192.168.1.0/24");
  const [scanPorts, setScanPorts] = useState("22,80,135,139,161,389,443,445,514,1514,3389,5985,5986,8006,8080,8443");
  const [scanBusy, setScanBusy] = useState(false);
  const [scanState, setScanState] = useState("");
  const [jobState, setJobState] = useState("");
  const [jobBusy, setJobBusy] = useState(false);
  const [jobCredentials, setJobCredentials] = useState<Record<string, Record<string, string>>>({});
  const [onboardingCredentials, setOnboardingCredentials] = useState<Record<string, string>>(DEFAULT_ONBOARDING_CREDENTIALS);
  const [telemetrySelection, setTelemetrySelection] = useState<string[]>(["syslog", "linux_auth", "auditd", "process_runtime"]);
  const debouncedQuery = useDebouncedValue(query, 250);

  const items = useMemo(() => {
    const rows = state.data?.items || [];
    const token = String(debouncedQuery || "").trim().toLowerCase();
    if (!token) return rows;
    return rows.filter((item: AssetRecord) => JSON.stringify(item).toLowerCase().includes(token));
  }, [state.data, debouncedQuery]);
  const discoveryCandidates = useMemo(() => {
    const rows = (discoveryState.data?.items || []).filter((item: DiscoveryCandidate) => {
      const monitoringStatus = String(item.monitoring_status || item.status || "").toLowerCase();
      return !item.connected && monitoringStatus !== "connected";
    });
    const token = String(debouncedQuery || "").trim().toLowerCase();
    if (!token) return rows;
    return rows.filter((item: DiscoveryCandidate) => JSON.stringify(item).toLowerCase().includes(token));
  }, [debouncedQuery, discoveryState.data]);
  const discoveryJobs = useMemo(() => discoveryState.data?.jobs || [], [discoveryState.data]);
  const discoveryMetrics = discoveryState.data?.metrics || {};
  const selectedCandidate = useMemo(
    () => discoveryCandidates.find((item: DiscoveryCandidate) => String(item.id || "") === selectedCandidateId) || discoveryCandidates[0] || null,
    [discoveryCandidates, selectedCandidateId],
  );
  const selectedCandidateJob = useMemo(() => {
    const lastJobId = String(selectedCandidate?.last_job_id || "");
    return (
      discoveryJobs.find((item: DiscoveryJob) => String(item.id || "") === lastJobId) ||
      discoveryJobs.find((item: DiscoveryJob) => String(item.candidate_id || "") === String(selectedCandidate?.id || "")) ||
      null
    );
  }, [discoveryJobs, selectedCandidate]);
  const selectedJobCredentialValues = useMemo(
    () => (selectedCandidateJob ? jobCredentials[String(selectedCandidateJob.id || "")] || {} : {}),
    [jobCredentials, selectedCandidateJob],
  );
  const activeCredentialValues = useMemo<Record<string, string>>(
    () => {
      const values: Record<string, string> = {
        ...onboardingCredentials,
        ...selectedJobCredentialValues,
        management_ip: onboardingCredentials.management_ip || String(selectedCandidate?.ip || ""),
      };
      return values;
    },
    [onboardingCredentials, selectedCandidate?.ip, selectedJobCredentialValues],
  );
  const owners = useMemo(() => {
    const counts = new Map<string, number>();
    for (const item of items) {
      const owner = String(item.cmdb_owner || "unassigned");
      counts.set(owner, (counts.get(owner) || 0) + 1);
    }
    return Array.from(counts.entries())
      .map(([label, count]) => ({ label, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 6);
  }, [items]);
  const services = useMemo(() => {
    const counts = new Map<string, number>();
    for (const item of items) {
      const service = String(item.cmdb_service || "unassigned");
      counts.set(service, (counts.get(service) || 0) + 1);
    }
    return Array.from(counts.entries())
      .map(([label, count]) => ({ label, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 6);
  }, [items]);
  const exposureQueue = useMemo(
    () =>
      [...items]
        .sort((a: AssetRecord, b: AssetRecord) => {
          const aScore = Number(a.notable_events || 0) * 5 + Number(a.events || 0);
          const bScore = Number(b.notable_events || 0) * 5 + Number(b.events || 0);
          return bScore - aScore;
        })
        .slice(0, 8),
    [items],
  );
  const ownerHotspots = useMemo(() => {
    const stats = new Map<string, { owner: string; assets: number; notable: number; critical: number }>();
    for (const item of items) {
      const owner = String(item.cmdb_owner || "unassigned");
      const current = stats.get(owner) || { owner, assets: 0, notable: 0, critical: 0 };
      current.assets += 1;
      current.notable += Number(item.notable_events || 0);
      if (["high", "critical"].includes(String(item.cmdb_criticality || "").toLowerCase())) current.critical += 1;
      stats.set(owner, current);
    }
    return Array.from(stats.values())
      .sort((left, right) => right.notable - left.notable || right.assets - left.assets)
      .slice(0, 8);
  }, [items]);
  const productFootprint = useMemo(() => {
    const counts = new Map<string, number>();
    for (const item of items) {
      for (const product of item.products || []) {
        const label = String(product || "").trim();
        if (!label) continue;
        counts.set(label, (counts.get(label) || 0) + 1);
      }
    }
    return Array.from(counts.entries())
      .map(([label, count]) => ({ label, count }))
      .sort((left, right) => right.count - left.count)
      .slice(0, 8);
  }, [items]);

  useEffect(() => {
    const nextQuery = String(searchParams.get("q") || "").trim();
    const nextView = String(searchParams.get("view") || "").trim().toLowerCase();
    const focus = String(searchParams.get("focus") || "").trim();
    if (searchParams.has("q")) {
      setQuery(nextQuery);
    }
    if (nextView === "inventory" || nextView === "exposure" || nextView === "ownership" || nextView === "unconnected") {
      setView(nextView as AssetView);
    }
    if (focus) {
      setSelectedAsset((current: AssetRecord | null) => {
        if (current?.asset === focus) return current;
        const row = (state.data?.items || []).find((item: AssetRecord) => String(item.asset || "") === focus);
        return row || current;
      });
    }
  }, [searchParams, state.data]);

  useEffect(() => {
    const selectedStillVisible = selectedAsset
      ? items.some((item: AssetRecord) => String(item.asset || "") === String(selectedAsset.asset || ""))
      : false;
    if (selectedAsset && !selectedStillVisible) {
      setSelectedAsset(debouncedQuery && items.length ? items[0] : null);
      return;
    }
    if (!selectedAsset && items.length && debouncedQuery) {
      setSelectedAsset(items[0]);
    }
  }, [debouncedQuery, items, selectedAsset]);

  useEffect(() => {
    if (selectedCandidateId && !discoveryCandidates.some((item: DiscoveryCandidate) => String(item.id || "") === selectedCandidateId)) {
      setSelectedCandidateId("");
      return;
    }
    if (!selectedCandidateId && discoveryCandidates.length) {
      setSelectedCandidateId(String(discoveryCandidates[0].id || ""));
    }
  }, [discoveryCandidates, selectedCandidateId]);

  useEffect(() => {
    setTelemetrySelection(telemetryDefaultsForCandidate(selectedCandidate));
    setOnboardingCredentials(credentialsDefaultsForCandidate(selectedCandidate));
    setJobState("");
  }, [selectedCandidate]);

  const criticalAssets = items.filter((item: AssetRecord) => ["high", "critical"].includes(String(item.cmdb_criticality || "").toLowerCase()));
  const observedAudit = items.filter((item: AssetRecord) => Number(item.audit_events || 0) > 0);
  const selectedAssetSummary = useMemo(
    () =>
      selectedAsset
        ? [
            { label: t(lang, { en: "Asset", ru: "Актив" }), value: assetLabel(selectedAsset.asset), tone: "info" as const },
            { label: t(lang, { en: "Criticality", ru: "Критичность" }), value: selectedAsset.cmdb_criticality ? <SeverityBadge value={String(selectedAsset.cmdb_criticality)} /> : "n/a", tone: ["high", "critical"].includes(String(selectedAsset.cmdb_criticality || "").toLowerCase()) ? ("critical" as const) : ("default" as const) },
            { label: t(lang, { en: "Owner", ru: "Владелец" }), value: selectedAsset.cmdb_owner || "n/a" },
            { label: t(lang, { en: "Service", ru: "Сервис" }), value: selectedAsset.cmdb_service || "n/a" },
            { label: t(lang, { en: "Exposure", ru: "Экспозиция" }), value: Number(selectedAsset.notable_events || 0) * 5 + Number(selectedAsset.events || 0), tone: Number(selectedAsset.notable_events || 0) ? ("warning" as const) : ("default" as const) },
            { label: t(lang, { en: "Last seen", ru: "Последняя активность" }), value: selectedAsset.last_seen || "n/a" },
          ]
        : [],
    [assetLabel, lang, selectedAsset],
  );
  const selectedAssetTimeline = useMemo(
    () =>
      selectedAsset
        ? [
            {
              id: `${selectedAsset.asset}-business`,
              title: t(lang, { en: "Business context", ru: "Бизнес-контекст" }),
              subtitle: [selectedAsset.cmdb_service || "unassigned service", selectedAsset.cmdb_owner || "no owner"].join(" · "),
              meta: selectedAsset.cmdb_environment || "environment",
              body: [selectedAsset.cmdb_asset_id, ...(selectedAsset.aliases || [])].filter(Boolean).join(" · ") || t(lang, { en: "No CMDB aliases attached.", ru: "CMDB-алиасы не привязаны." }),
            },
            {
              id: `${selectedAsset.asset}-telemetry`,
              title: t(lang, { en: "Telemetry pressure", ru: "Нагрузка телеметрии" }),
              subtitle: t(lang, { en: "Observed activity in the current operating window.", ru: "Наблюдаемая активность в текущем рабочем окне." }),
              meta: `${Number(selectedAsset.events || 0)} events`,
              tone: Number(selectedAsset.notable_events || 0) ? ("warning" as const) : ("info" as const),
              body: `${Number(selectedAsset.notable_events || 0)} notable · ${Number(selectedAsset.audit_events || 0)} audit · ${(selectedAsset.categories || []).join(", ") || "no category breakdown"}`,
            },
            {
              id: `${selectedAsset.asset}-products`,
              title: t(lang, { en: "Product footprint", ru: "Продуктовый след" }),
              subtitle: t(lang, { en: "Installed or observed products bound to the asset.", ru: "Установленные или наблюдаемые продукты, привязанные к активу." }),
              meta: `${(selectedAsset.products || []).length} products`,
              body: (selectedAsset.products || []).join(", ") || t(lang, { en: "No product footprint recorded.", ru: "Продуктовый след не зафиксирован." }),
            },
          ]
        : [],
    [lang, selectedAsset],
  );

  function discoveryScanPorts() {
    return scanPorts
      .split(",")
      .map((value) => Number(value.trim()))
      .filter((value) => Number.isFinite(value) && value > 0 && value <= 65535);
  }

  async function runDiscoveryScan() {
    setScanBusy(true);
    setScanState("");
    try {
      const payload = await api.scanSourceDiscovery({
        cidr: scanCidr,
        ports: discoveryScanPorts(),
        max_hosts: 512,
        timeout_seconds: 0.35,
      });
      const discovered = Number(payload?.scan?.discovered || 0);
      const unmanaged = Number(payload?.scan?.discovered_unmanaged || 0);
      setScanState(`Discovery scan completed: ${payload?.scan?.hosts_scanned || 0} hosts scanned, ${discovered} active, ${unmanaged} unconnected.`);
      setDiscoveryRefreshToken((value) => value + 1);
      const firstUnmanaged = (payload?.items || []).find((item: DiscoveryCandidate) => !item.connected) || (payload?.items || [])[0];
      if (firstUnmanaged?.id) setSelectedCandidateId(String(firstUnmanaged.id));
    } catch (error) {
      setScanState(error instanceof Error ? error.message : "Discovery scan failed");
    } finally {
      setScanBusy(false);
    }
  }

  async function prepareCandidateOnboarding() {
    if (!selectedCandidate?.id) return;
    setJobState("");
    try {
      const payload = await api.prepareSourceOnboarding(String(selectedCandidate.id), {
        requested_telemetry: telemetrySelection,
      });
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
      const payload = await api.executeSourceOnboarding(jobId, {
        dry_run: true,
        credentials: {
          telemetry_selection: telemetrySelection,
        },
      });
      setJobState(String(payload?.execution?.summary || `Preview completed for ${jobId}`));
      setDiscoveryRefreshToken((value) => value + 1);
    } catch (error) {
      setJobState(error instanceof Error ? error.message : "Unable to preview onboarding");
    }
  }

  async function executeCandidateOnboarding() {
    const jobId = String(selectedCandidate?.last_job_id || selectedCandidateJob?.id || "");
    if (!jobId) return;
    setJobBusy(true);
    setJobState("");
    try {
      const payload = await api.executeSourceOnboarding(jobId, {
        dry_run: false,
        credentials: {
          ...activeCredentialValues,
          telemetry_selection: telemetrySelection,
          requested_telemetry: telemetrySelection,
        },
      });
      setJobState(String(payload?.execution?.summary || `Executed onboarding job ${jobId}`));
      setDiscoveryRefreshToken((value) => value + 1);
    } catch (error) {
      setJobState(error instanceof Error ? error.message : "Unable to execute onboarding");
    } finally {
      setJobBusy(false);
    }
  }

  function updateJobCredential(fieldId: string, value: string) {
    const jobId = String(selectedCandidateJob?.id || "");
    if (!jobId) {
      setOnboardingCredentials((current) => ({ ...current, [fieldId]: value }));
      return;
    }
    setJobCredentials((current) => ({
      ...current,
      [jobId]: {
        ...(current[jobId] || {}),
        [fieldId]: value,
      },
    }));
  }

  function updateOnboardingCredential(fieldId: string, value: string) {
    setOnboardingCredentials((current) => ({ ...current, [fieldId]: value }));
    if (selectedCandidateJob?.id) {
      updateJobCredential(fieldId, value);
    }
  }

  function toggleTelemetryOption(optionId: string) {
    setTelemetrySelection((current) => {
      if (current.includes(optionId)) {
        const next = current.filter((item) => item !== optionId);
        return next.length ? next : current;
      }
      return [...current, optionId];
    });
  }

  return (
    <AsyncGate states={[state]} loadingMessage={t(lang, { en: "Loading assets...", ru: "Загрузка активов..." })}>
    <div className="react-page native-page">
      <NativePageHeader
        title={t(lang, { en: "Assets", ru: "Активы" })}
        icon="assets"
        actions={
          <>
            <button type="button" className="react-icon-button" onClick={() => setSettingsOpen(true)} aria-label="Asset page settings">
              <Icon name="control" size={15} />
            </button>
            <button type="button" className="react-primary-button" onClick={() => setAssetRefreshToken((value) => value + 1)}>{t(lang, { en: "Refresh", ru: "Обновить" })}</button>
          </>
        }
      />
      <div className="native-list-search">
        <label className="native-search-field">
          <Search size={16} aria-hidden="true" />
          <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder={t(lang, { en: "Search assets, IP addresses, owners and services", ru: "Поиск по активам, IP-адресам, владельцам и сервисам" })} />
        </label>
        <button type="button" className="react-link-button" onClick={() => setQuery("")}>{t(lang, { en: "Clear", ru: "Очистить" })}</button>
      </div>
      <div className="native-workspace-tabs native-asset-tabs" role="tablist" aria-label={t(lang, { en: "Asset views", ru: "Представления активов" })}>
        <div>
        <button type="button" className={view === "inventory" ? "active" : ""} onClick={() => setView("inventory")}>{t(lang, { en: "Inventory", ru: "Инвентарь" })}</button>
        <button type="button" className={view === "unconnected" ? "active" : ""} onClick={() => setView("unconnected")}>{t(lang, { en: "Unconnected assets", ru: "Неподключенные активы" })}</button>
        <button type="button" className={view === "exposure" ? "active" : ""} onClick={() => setView("exposure")}>{t(lang, { en: "Exposure", ru: "Экспозиция" })}</button>
        <button type="button" className={view === "ownership" ? "active" : ""} onClick={() => setView("ownership")}>{t(lang, { en: "Ownership", ru: "Владение" })}</button>
        </div>
        <span>{t(lang, { en: "Observed assets", ru: "Наблюдаемые активы" })}: <strong>{items.length}</strong></span>
      </div>
      <NativeActionBar
        primary={(
          <>
            <Link className="react-link-button" to="/events?q=asset_id%20!=%20%27%27">{t(lang, { en: "Find in events", ru: "Найти в событиях" })}</Link>
            <Link className="react-link-button" to="/vuln/hosts">{t(lang, { en: "Vulnerabilities", ru: "Уязвимости" })}</Link>
          </>
        )}
        meta={(
          <>
            <span>{t(lang, { en: "Critical", ru: "Критичные" })}: <strong>{criticalAssets.length}</strong></span>
            <span>{t(lang, { en: "With audit", ru: "С аудитом" })}: <strong>{observedAudit.length}</strong></span>
            <span>{t(lang, { en: "Owners", ru: "Владельцы" })}: <strong>{owners.length}</strong></span>
          </>
        )}
      />

      {view === "unconnected" ? (
      <div className="react-split react-split-xl">
        <section className="react-card">
          <PanelHeader
            title={t(lang, { en: "Unconnected assets", ru: "Неподключенные активы" })}
            subtitle={t(lang, {
              en: "Hosts discovered by network scanning but not yet connected as telemetry sources. Select a host to prepare monitoring rollout.",
              ru: "Хосты, найденные сетевым сканированием, но еще не подключенные как источники телеметрии. Выберите хост, чтобы подготовить подключение.",
            })}
            actions={
              <div className="react-actions react-wrap">
                <input className="react-input" value={scanCidr} onChange={(event) => setScanCidr(event.target.value)} placeholder="192.168.1.0/24" />
                <button type="button" className="react-primary-button" onClick={runDiscoveryScan} disabled={scanBusy}>
                  {scanBusy ? "Scanning..." : "Scan network"}
                </button>
              </div>
            }
          />
          <div className="react-grid react-grid-4">
            <StatCard label="Candidates" value={Number(discoveryMetrics.total || 0)} hint="All hosts retained in source discovery storage." />
            <StatCard label="Unconnected" value={discoveryCandidates.length} hint="Discovered hosts not matched to live telemetry sources." />
            <StatCard label="Auto-ready" value={Number(discoveryMetrics.auto_ready || 0)} hint="Hosts with an executable onboarding recommendation." />
            <StatCard label="Prepared jobs" value={Number(discoveryMetrics.prepared || 0)} hint="Monitoring rollout jobs already prepared." />
          </div>
          <div className="react-form-grid" style={{ marginTop: 14 }}>
            <label className="react-field react-input-full">
              <span className="react-label">Discovery ports</span>
              <input className="react-input" value={scanPorts} onChange={(event) => setScanPorts(event.target.value)} placeholder="22,80,443,514,3389,5985" />
            </label>
          </div>
          {scanState ? <div className="react-inline-note react-inline-note-spaced">{scanState}</div> : null}
          {discoveryState.error ? <div className="react-inline-note react-inline-note-spaced">{discoveryState.error}</div> : null}
          <div className="react-table-wrap">
            <table className="react-table">
              <thead>
                <tr>
                  <th>IP</th>
                  <th>Hostname</th>
                  <th>Services</th>
                  <th>Role</th>
                  <th>OS</th>
                  <th>Monitoring</th>
                  <th>Recommendation</th>
                </tr>
              </thead>
              <tbody>
                {discoveryCandidates.map((item: DiscoveryCandidate) => (
                  <tr
                    key={item.id}
                    className={selectedCandidate?.id === item.id ? "react-table-row-active" : ""}
                    onClick={() => setSelectedCandidateId(String(item.id || ""))}
                  >
                    <td><strong>{safeText(item.ip)}</strong></td>
                    <td>{safeText(item.hostname, `host-${String(item.ip || "").replace(/\./g, "-")}`)}</td>
                    <td>{safeText(item.port_summary || (item.open_ports || []).map((port) => `${port.port}/${port.service || "tcp"}`).join(", "))}</td>
                    <td>{safeText(item.probable_role || item.source_family)}</td>
                    <td>{safeText(item.os_family)}</td>
                    <td><StatusBadge value={item.monitoring_status || "candidate"} /></td>
                    <td>{safeText(item.recommendation?.title)}</td>
                  </tr>
                ))}
                {!discoveryCandidates.length ? (
                  <tr>
                    <td colSpan={7}>{discoveryState.loading ? "Loading discovery candidates..." : "No unconnected assets. Run discovery scan or clear the search filter."}</td>
                  </tr>
                ) : null}
              </tbody>
            </table>
          </div>
        </section>

        <aside className="react-detail-column">
          {selectedCandidate ? (
            <>
              <section className="react-card">
                <PanelHeader
                  title={`${safeText(selectedCandidate.hostname, "unknown-host")} / ${safeText(selectedCandidate.ip)}`}
                  subtitle={`${safeText(selectedCandidate.os_family)} / ${safeText(selectedCandidate.probable_role)} / confidence ${Number(selectedCandidate.confidence || 0).toFixed(2)}`}
                />
                <DrawerFieldGrid>
                  <KeyValue label="IP" value={safeText(selectedCandidate.ip)} />
                  <KeyValue label="Hostname" value={safeText(selectedCandidate.hostname)} />
                  <KeyValue label="Services" value={safeText(selectedCandidate.port_summary)} />
                  <KeyValue label="Source family" value={safeText(selectedCandidate.source_family)} />
                  <KeyValue label="Collector profile" value={safeText(selectedCandidate.recommendation?.collector_profile)} />
                  <KeyValue label="Auto method" value={safeText(selectedCandidate.recommendation?.auto_monitoring_method)} />
                  <KeyValue label="Last seen" value={safeText(selectedCandidate.last_seen_ts)} />
                  <KeyValue label="Last job" value={safeText(selectedCandidate.last_job_id || selectedCandidateJob?.id)} />
                </DrawerFieldGrid>
                {jobState ? <div className="react-inline-note react-inline-note-spaced">{jobState}</div> : null}
              </section>

              <section className="react-card react-card-nested react-connection-wizard">
                <PanelHeader
                  title="Connection wizard"
                  subtitle="Choose exactly what telemetry to collect and enter the management credentials used by the onboarding action."
                  icon="connectors"
                  actions={
                    <div className="react-actions react-wrap">
                      <button type="button" className="react-primary-button" onClick={prepareCandidateOnboarding}>
                        Prepare connection
                      </button>
                      <button type="button" className="react-link-button" onClick={previewCandidateOnboarding} disabled={!selectedCandidate.last_job_id && !selectedCandidateJob?.id}>
                        Preview
                      </button>
                      <button type="button" className="react-link-button" onClick={executeCandidateOnboarding} disabled={!selectedCandidateJob?.execution_supported || jobBusy}>
                        {jobBusy ? "Executing..." : "Connect live"}
                      </button>
                    </div>
                  }
                />
                <div className="react-wizard-steps">
                  <div className="react-wizard-step">
                    <span>1</span>
                    <strong>Telemetry profiles</strong>
                    <small>{telemetrySelection.length} selected</small>
                  </div>
                  <div className="react-wizard-step">
                    <span>2</span>
                    <strong>Credentials</strong>
                    <small>{safeText(activeCredentialValues.protocol, "ssh")} / {safeText(activeCredentialValues.management_ip || selectedCandidate.ip)}</small>
                  </div>
                  <div className="react-wizard-step">
                    <span>3</span>
                    <strong>Rollout</strong>
                    <small>{selectedCandidateJob ? safeText(selectedCandidateJob.status, "prepared") : "not prepared"}</small>
                  </div>
                </div>
                <div className="react-telemetry-picker">
                  {ONBOARDING_TELEMETRY_OPTIONS.map((option) => (
                    <label key={option.id} className={`react-telemetry-option${telemetrySelection.includes(option.id) ? " selected" : ""}`}>
                      <input type="checkbox" checked={telemetrySelection.includes(option.id)} onChange={() => toggleTelemetryOption(option.id)} />
                      <span>
                        <strong>{option.label}</strong>
                        <small>{option.hint}</small>
                      </span>
                    </label>
                  ))}
                </div>
                <div className="react-form-grid react-inline-note-spaced">
                  <label className="react-field">
                    <span className="react-label">Protocol</span>
                    <select className="react-select" value={activeCredentialValues.protocol || "ssh"} onChange={(event) => updateOnboardingCredential("protocol", event.target.value)}>
                      <option value="ssh">SSH</option>
                      <option value="rdp">RDP</option>
                      <option value="winrm">WinRM</option>
                      <option value="snmp">SNMP</option>
                      <option value="https">HTTPS/API</option>
                      <option value="http">HTTP/API</option>
                    </select>
                  </label>
                  <label className="react-field">
                    <span className="react-label">Management IP</span>
                    <input className="react-input" value={activeCredentialValues.management_ip || ""} onChange={(event) => updateOnboardingCredential("management_ip", event.target.value)} placeholder="192.168.1.x" />
                  </label>
                  <label className="react-field">
                    <span className="react-label">Port</span>
                    <input className="react-input" value={activeCredentialValues.port || ""} onChange={(event) => updateOnboardingCredential("port", event.target.value)} placeholder="22 / 3389 / 5986 / 161" />
                  </label>
                  <label className="react-field">
                    <span className="react-label">Username</span>
                    <input className="react-input" value={activeCredentialValues.username || ""} onChange={(event) => updateOnboardingCredential("username", event.target.value)} placeholder="operator / admin" />
                  </label>
                  <label className="react-field">
                    <span className="react-label">Password</span>
                    <input className="react-input" type="password" value={activeCredentialValues.password || ""} onChange={(event) => updateOnboardingCredential("password", event.target.value)} placeholder="write-only" />
                  </label>
                  <label className="react-field">
                    <span className="react-label">Sudo password</span>
                    <input className="react-input" type="password" value={activeCredentialValues.sudo_password || ""} onChange={(event) => updateOnboardingCredential("sudo_password", event.target.value)} placeholder="optional" />
                  </label>
                  <label className="react-field">
                    <span className="react-label">Enable password</span>
                    <input className="react-input" type="password" value={activeCredentialValues.enable_password || ""} onChange={(event) => updateOnboardingCredential("enable_password", event.target.value)} placeholder="network devices" />
                  </label>
                  <label className="react-field">
                    <span className="react-label">SNMP community</span>
                    <input className="react-input" value={activeCredentialValues.snmp_community || ""} onChange={(event) => updateOnboardingCredential("snmp_community", event.target.value)} placeholder="community or vault ref" />
                  </label>
                  <label className="react-field react-input-full">
                    <span className="react-label">API token / Vault ref</span>
                    <input className="react-input" value={activeCredentialValues.api_token || activeCredentialValues.vault_ref || ""} onChange={(event) => updateOnboardingCredential("api_token", event.target.value)} placeholder="paste token for one-time execution or vault:// reference" />
                  </label>
                  <label className="react-field react-input-full">
                    <span className="react-label">Private key ref</span>
                    <input className="react-input" value={activeCredentialValues.private_key_ref || ""} onChange={(event) => updateOnboardingCredential("private_key_ref", event.target.value)} placeholder="vault://secret/siem/host-access/.../private_key" />
                  </label>
                  <label className="react-field react-input-full">
                    <span className="react-label">Certificate ref</span>
                    <input className="react-input" value={activeCredentialValues.certificate_ref || ""} onChange={(event) => updateOnboardingCredential("certificate_ref", event.target.value)} placeholder="vault://secret/siem/host-access/.../certificate" />
                  </label>
                </div>
                <div className="react-inline-note react-inline-note-spaced">
                  Raw secret fields are only sent with the final execution request. Prepared jobs store telemetry choices and command previews, not passwords.
                </div>
              </section>

              <section className="react-card react-card-nested">
                <PanelHeader title="Open services" subtitle="Detected TCP services used to choose the onboarding method." />
                <div className="react-chip-grid">
                  {(selectedCandidate.open_ports || []).map((port) => (
                    <div key={`${selectedCandidate.id}-${port.port}`} className="react-chip-card">
                      <div className="react-top-kicker">{safeText(port.service || "tcp")}</div>
                      <strong>{port.port}</strong>
                      <span>{safeText(port.server || port.banner || port.title, "banner unavailable")}</span>
                    </div>
                  ))}
                  {!(selectedCandidate.open_ports || []).length ? <EmptyState message="No open-service details recorded for this host." /> : null}
                </div>
              </section>

              {selectedCandidateJob ? (
                <section className="react-card react-card-nested">
                  <PanelHeader title="Connection job" subtitle="Prepared onboarding plan. Credentials are kept only in browser state until execution." />
                  <DrawerFieldGrid>
                    <KeyValue label="Job" value={safeText(selectedCandidateJob.id)} />
                    <KeyValue label="Status" value={<StatusBadge value={selectedCandidateJob.status || "prepared"} />} />
                    <KeyValue label="Method" value={safeText(selectedCandidateJob.method)} />
                    <KeyValue label="Executor" value={selectedCandidateJob.execution_supported ? "available" : "manual"} />
                    <KeyValue label="Vendor" value={safeText(selectedCandidateJob.network_vendor)} />
                    <KeyValue label="Collector" value={safeText(selectedCandidateJob.collector_profile)} />
                  </DrawerFieldGrid>
                  {(selectedCandidateJob.credential_requirements || []).length ? (
                    <div className="react-form-grid" style={{ marginTop: 14 }}>
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
                              value={activeCredentialValues[fieldId] || ""}
                              onChange={(event) => updateOnboardingCredential(fieldId, event.target.value)}
                              placeholder={label}
                            />
                          </label>
                        );
                      })}
                    </div>
                  ) : null}
                  {(selectedCandidateJob.command_preview || []).length ? (
                    <div className="react-list react-list-compact react-inline-note-spaced">
                      {(selectedCandidateJob.command_preview || []).map((line: string, index: number) => (
                        <div key={`${selectedCandidateJob.id}-${index}`} className="react-list-item">
                          <strong>{index + 1}.</strong>
                          <span>{line}</span>
                        </div>
                      ))}
                    </div>
                  ) : null}
                  {selectedCandidateJob.config_preview ? (
                    <details className="react-details" open>
                      <summary>Config preview</summary>
                      <JsonPreview value={{ config_preview: selectedCandidateJob.config_preview }} />
                    </details>
                  ) : null}
                  {(selectedCandidateJob.network_commands || []).length ? (
                    <details className="react-details" open>
                      <summary>Network commands</summary>
                      <JsonPreview value={{ commands: selectedCandidateJob.network_commands } as RuntimeBlob} />
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
            <EmptyState message="Select an unconnected asset or run a network scan to create onboarding candidates." />
          )}
        </aside>
      </div>
      ) : null}

      {view === "inventory" ? (
      <>
        <section className="native-grid native-assets-grid">
          <div className="react-table-wrap">
            <table className="react-table">
              <thead>
                <tr>
                  <th>{t(lang, { en: "Asset", ru: "Актив" })}</th>
                  <th>IP / alias</th>
                  <th>{t(lang, { en: "Owner", ru: "Владелец" })}</th>
                  <th>{t(lang, { en: "Criticality", ru: "Критичность" })}</th>
                  <th>{t(lang, { en: "Service", ru: "Сервис" })}</th>
                  <th>{t(lang, { en: "Products", ru: "Продукты" })}</th>
                  <th>{t(lang, { en: "Exposure", ru: "Экспозиция" })}</th>
                  <th>{t(lang, { en: "Last seen", ru: "Последняя активность" })}</th>
                </tr>
              </thead>
              <tbody>
                {items.map((item: AssetRecord) => (
                  <tr key={item.asset} className={selectedAsset?.asset === item.asset ? "react-table-row-active" : ""} onClick={() => setSelectedAsset(item)}>
                    <td><button type="button" className="native-primary-cell" onClick={() => setSelectedAsset(item)}><strong>{assetLabel(item.asset)}</strong><small>{item.cmdb_asset_id || item.cmdb_environment || "observed"}</small></button></td>
                    <td>{(item.aliases || []).slice(0, 2).join(", ") || "n/a"}</td>
                    <td>{item.cmdb_owner || "n/a"}</td>
                    <td>{item.cmdb_criticality ? <SeverityBadge value={item.cmdb_criticality} /> : "n/a"}</td>
                    <td>{item.cmdb_service || "n/a"}</td>
                    <td>{(item.products || []).slice(0, 2).join(", ") || "n/a"}</td>
                    <td>{Number(item.notable_events || 0) > 0 ? <StatusBadge value="assigned" /> : <StatusBadge value="active" />}</td>
                    <td>{item.last_seen || "n/a"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
        <NativePager shown={items.length} total={state.data?.items?.length || items.length} lang={lang} />
        <DrawerOverlay
          open={Boolean(selectedAsset)}
          title={selectedAsset ? assetLabel(selectedAsset.asset) : t(lang, { en: "Asset details", ru: "Информация об активе" })}
          subtitle={selectedAsset ? `${selectedAsset.cmdb_service || "n/a"} / ${selectedAsset.cmdb_environment || "n/a"}` : ""}
          onClose={() => setSelectedAsset(null)}
          panelClassName="react-drawer-panel-wide"
        >
          {selectedAsset ? (
            <>
                <InvestigationSummaryStrip items={selectedAssetSummary} />
                <InvestigationActionRail
                  items={[
                    { label: t(lang, { en: "Open in Events", ru: "Открыть в событиях" }), href: `/app/events?q=${encodeURIComponent(`log_source = '${selectedAsset.asset}'`)}` },
                    { label: t(lang, { en: "Related incidents", ru: "Связанные инциденты" }), href: `/app/incidents?q=${encodeURIComponent(selectedAsset.asset)}` },
                    { label: t(lang, { en: "Host exposure", ru: "Экспозиция хоста" }), href: `/app/vuln/hosts?q=${encodeURIComponent(selectedAsset.asset)}`, tone: "warning" as const },
                  ]}
                />
                <InvestigationTimeline
                  title={t(lang, { en: "Asset investigation model", ru: "Модель расследования актива" })}
                  subtitle={t(lang, { en: "Business ownership, telemetry pressure and product footprint collapsed into one asset-facing drawer.", ru: "Бизнес-владение, давление телеметрии и продуктовый след сведены в одно окно актива." })}
                  icon="assets"
                  items={selectedAssetTimeline}
                  emptyMessage={t(lang, { en: "No investigation context available for this asset.", ru: "Для этого актива пока нет расследовательского контекста." })}
                />
                <section className="react-card react-card-nested">
                  <PanelHeader title={t(lang, { en: "Business context", ru: "Бизнес-контекст" })} subtitle={t(lang, { en: "Ownership, criticality and service context for the selected CMDB asset.", ru: "Владение, критичность и сервисный контекст выбранного CMDB-актива." })} />
                  <DrawerFieldGrid>
                    <KeyValue label={t(lang, { en: "Owner", ru: "Владелец" })} value={selectedAsset.cmdb_owner || "n/a"} />
                    <KeyValue label={t(lang, { en: "Criticality", ru: "Критичность" })} value={selectedAsset.cmdb_criticality || "n/a"} />
                    <KeyValue label={t(lang, { en: "Environment", ru: "Окружение" })} value={selectedAsset.cmdb_environment || "n/a"} />
                    <KeyValue label={t(lang, { en: "Business service", ru: "Бизнес-сервис" })} value={selectedAsset.cmdb_service || "n/a"} />
                    <KeyValue label={t(lang, { en: "CMDB asset id", ru: "ID актива в CMDB" })} value={selectedAsset.cmdb_asset_id || "n/a"} />
                    <KeyValue label={t(lang, { en: "Aliases", ru: "Алиасы" })} value={(selectedAsset.aliases || []).map((item) => assetLabel(item)).join(", ") || "n/a"} />
                    <KeyValue label={t(lang, { en: "Tags", ru: "Теги" })} value={(selectedAsset.cmdb_tags || []).join(", ") || "n/a"} />
                    <KeyValue label={t(lang, { en: "Last seen", ru: "Последняя активность" })} value={selectedAsset.last_seen || "n/a"} />
                  </DrawerFieldGrid>
                </section>
                <section className="react-card react-card-nested">
                  <PanelHeader title={t(lang, { en: "Exposure and telemetry", ru: "Экспозиция и телеметрия" })} subtitle={t(lang, { en: "Operational context, products and exposure indicators tied to this asset.", ru: "Операционный контекст, продукты и индикаторы экспозиции, связанные с этим активом." })} />
                  <DrawerFieldGrid>
                    <KeyValue label={t(lang, { en: "Events 24h", ru: "События за 24ч" })} value={selectedAsset.events} />
                    <KeyValue label={t(lang, { en: "Notable events", ru: "Значимые события" })} value={selectedAsset.notable_events} />
                    <KeyValue label={t(lang, { en: "Audit events", ru: "События аудита" })} value={selectedAsset.audit_events} />
                    <KeyValue
                      label={t(lang, { en: "Exposure score", ru: "Скор экспозиции" })}
                      value={Number(selectedAsset.notable_events || 0) * 5 + Number(selectedAsset.events || 0)}
                    />
                    <KeyValue label={t(lang, { en: "Categories", ru: "Категории" })} value={(selectedAsset.categories || []).join(", ") || "n/a"} />
                    <KeyValue label={t(lang, { en: "Products", ru: "Продукты" })} value={(selectedAsset.products || []).join(", ") || "n/a"} />
                    <KeyValue label={t(lang, { en: "Installed footprint", ru: "Установленный след" })} value={(selectedAsset.products || []).length || 0} />
                    <KeyValue label={t(lang, { en: "Expected ports", ru: "Ожидаемые порты" })} value={(selectedAsset.cmdb_expected_ports || []).join(", ") || "n/a"} />
                  </DrawerFieldGrid>
                </section>
              </>
            ) : (
              <EmptyState message={t(lang, { en: "Select an asset to inspect its business and telemetry context.", ru: "Выберите актив, чтобы открыть его бизнес-контекст и телеметрию." })} />
            )}
        </DrawerOverlay>
      </>
      ) : null}

      {view === "ownership" ? (
      <div className="react-grid react-grid-2">
        <section className="react-card">
          <PanelHeader title={t(lang, { en: "Ownership lens", ru: "Срез по владению" })} subtitle={t(lang, { en: "Who owns the estate and where critical context is concentrated.", ru: "Кто владеет инфраструктурой и где сосредоточен критичный контекст." })} />
          <div className="react-table-wrap">
            <table className="react-table">
              <thead>
                <tr>
                  <th>{t(lang, { en: "Owner", ru: "Владелец" })}</th>
                  <th>{t(lang, { en: "Assets", ru: "Активы" })}</th>
                </tr>
              </thead>
              <tbody>
                {owners.map((row) => (
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
          <PanelHeader title={t(lang, { en: "Service exposure queue", ru: "Очередь сервисной экспозиции" })} subtitle={t(lang, { en: "Assets most likely to require analyst attention first.", ru: "Активы, которые с наибольшей вероятностью требуют внимания аналитика в первую очередь." })} />
          <div className="react-list react-list-compact">
            {exposureQueue.map((item: AssetRecord) => (
              <button key={item.asset} type="button" className="react-list-item" onClick={() => setSelectedAsset(item)}>
                <strong>{item.asset}</strong>
                <span>{item.cmdb_service || t(lang, { en: "unassigned service", ru: "сервис не назначен" })} / {item.cmdb_owner || t(lang, { en: "no owner", ru: "владелец не назначен" })}</span>
                <span>{Number(item.notable_events || 0)} {t(lang, { en: "notable", ru: "значимых" })}, {Number(item.events || 0)} {t(lang, { en: "events", ru: "событий" })}</span>
              </button>
            ))}
          </div>
        </section>
      </div>
      ) : null}

      {view === "ownership" ? (
      <section className="react-card">
          <PanelHeader title={t(lang, { en: "Owner hotspots", ru: "Горячие точки владельцев" })} subtitle={t(lang, { en: "Owners carrying the highest notable activity and critical business context.", ru: "Владельцы с наибольшей значимой активностью и критичным бизнес-контекстом." })} />
        <div className="react-table-wrap">
          <table className="react-table">
            <thead>
              <tr>
                <th>{t(lang, { en: "Owner", ru: "Владелец" })}</th>
                <th>{t(lang, { en: "Assets", ru: "Активы" })}</th>
                <th>{t(lang, { en: "Critical", ru: "Критичные" })}</th>
                <th>{t(lang, { en: "Notable events", ru: "Значимые события" })}</th>
              </tr>
            </thead>
            <tbody>
              {ownerHotspots.map((row) => (
                <tr key={row.owner}>
                  <td>{row.owner}</td>
                  <td>{row.assets}</td>
                  <td>{row.critical}</td>
                  <td>{row.notable}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
      ) : null}

      {view === "ownership" ? (
      <section className="react-card">
        <PanelHeader title={t(lang, { en: "Service portfolio", ru: "Портфель сервисов" })} subtitle={t(lang, { en: "Business services represented in the current telemetry window.", ru: "Бизнес-сервисы, представленные в текущем окне телеметрии." })} />
        <div className="react-chip-grid">
          {services.map((row) => (
            <div key={row.label} className="react-chip-card">
              <div className="react-top-kicker">{t(lang, { en: "Service", ru: "Сервис" })}</div>
              <strong>{row.label}</strong>
              <span>{row.count} assets</span>
            </div>
          ))}
        </div>
      </section>
      ) : null}

      {view === "exposure" ? (
      <div className="react-grid react-grid-2">
        <section className="react-card">
          <PanelHeader title={t(lang, { en: "Critical asset exposure", ru: "Экспозиция критичных активов" })} subtitle={t(lang, { en: "Critical and high-value assets ranked by notable activity.", ru: "Критичные и высокоценные активы, ранжированные по значимой активности." })} />
          <div className="react-list react-list-compact">
            {criticalAssets.slice(0, 10).map((item: AssetRecord) => (
              <button key={item.asset} type="button" className="react-list-item" onClick={() => { setSelectedAsset(item); setView("inventory"); }}>
                <strong>{item.asset}</strong>
                <span>{item.cmdb_service || "unassigned service"} / {item.cmdb_owner || "no owner"}</span>
                <span>{Number(item.notable_events || 0)} notable, {Number(item.events || 0)} events</span>
              </button>
            ))}
          </div>
        </section>
        <section className="react-card">
          <PanelHeader title={t(lang, { en: "Service exposure queue", ru: "Очередь сервисной экспозиции" })} subtitle={t(lang, { en: "Assets most likely to require analyst attention first.", ru: "Активы, которые с наибольшей вероятностью требуют внимания аналитика в первую очередь." })} />
          <div className="react-list react-list-compact">
            {exposureQueue.map((item: AssetRecord) => (
              <button key={item.asset} type="button" className="react-list-item" onClick={() => { setSelectedAsset(item); setView("inventory"); }}>
                <strong>{item.asset}</strong>
                <span>{item.cmdb_service || "unassigned service"} / {item.cmdb_owner || "no owner"}</span>
                <span>{Number(item.notable_events || 0)} notable, {Number(item.events || 0)} events</span>
              </button>
            ))}
          </div>
        </section>
      </div>
      ) : null}

      {view === "exposure" ? (
      <section className="react-card">
        <PanelHeader title={t(lang, { en: "Product footprint", ru: "Продуктовый след" })} subtitle={t(lang, { en: "Installed products most represented in the currently exposed asset estate.", ru: "Продукты, наиболее широко представленные в текущем наборе подверженных активов." })} />
        <div className="react-chip-grid">
          {productFootprint.map((row) => (
            <div key={row.label} className="react-chip-card">
              <div className="react-top-kicker">{t(lang, { en: "Product", ru: "Продукт" })}</div>
              <strong>{row.label}</strong>
              <span>{row.count} assets</span>
            </div>
          ))}
        </div>
      </section>
      ) : null}

      <DrawerOverlay open={settingsOpen} title={t(lang, { en: "Asset page settings", ru: "Настройки страницы активов" })} subtitle={t(lang, { en: "Business-context pivots and CMDB-first controls for the asset inventory.", ru: "Переходы по бизнес-контексту и CMDB-first управление инвентарем активов." })} onClose={() => setSettingsOpen(false)}>
        <section className="react-card react-card-nested">
          <PanelHeader title={t(lang, { en: "Quick pivots", ru: "Быстрые переходы" })} subtitle={t(lang, { en: "Jump straight into related analyst workspaces.", ru: "Переходите сразу в связанные рабочие зоны аналитика." })} icon="assets" />
          <div className="react-actions react-wrap">
            <Link className="react-link-button" to="/events?q=asset_id%20!=%20%27%27" onClick={() => setSettingsOpen(false)}>{t(lang, { en: "Assets in Events", ru: "Активы в событиях" })}</Link>
            <Link className="react-link-button" to="/incidents" onClick={() => setSettingsOpen(false)}>{t(lang, { en: "Open incidents", ru: "Открыть инциденты" })}</Link>
            <Link className="react-link-button" to="/vuln/hosts" onClick={() => setSettingsOpen(false)}>{t(lang, { en: "Exposure by host", ru: "Экспозиция по хостам" })}</Link>
          </div>
        </section>
        <section className="react-card react-card-nested">
          <PanelHeader title={t(lang, { en: "What Assets means", ru: "Что означает раздел «Активы»" })} subtitle={t(lang, { en: "Canonical CMDB objects with ownership, criticality and business service context.", ru: "Канонические CMDB-объекты с контекстом владения, критичности и бизнес-сервиса." })} icon="docs" />
          <DrawerFieldGrid>
            <KeyValue label={t(lang, { en: "Primary lens", ru: "Основная оптика" })} value={t(lang, { en: "Business / CMDB", ru: "Бизнес / CMDB" })} />
            <KeyValue label={t(lang, { en: "Best use", ru: "Лучший сценарий" })} value={t(lang, { en: "Owners, criticality, services, exposure and linked incidents", ru: "Владельцы, критичность, сервисы, экспозиция и связанные инциденты" })} />
            <KeyValue label={t(lang, { en: "Main pivots", ru: "Главные переходы" })} value="Events, Incidents, Vulnerabilities" />
            <KeyValue label={t(lang, { en: "Identity keys", ru: "Ключи идентичности" })} value="asset_id, aliases, owner, service" />
          </DrawerFieldGrid>
        </section>
        <section className="react-card react-card-nested">
          <PanelHeader title={t(lang, { en: "Ownership focus", ru: "Фокус по владению" })} subtitle={t(lang, { en: "Who owns the estate and where the business context is concentrated.", ru: "Кто владеет инфраструктурой и где сосредоточен бизнес-контекст." })} icon="assets" />
          <div className="react-chip-grid">
            {owners.map((row) => (
              <div key={row.label} className="react-chip-card">
                <div className="react-top-kicker">{t(lang, { en: "Owner", ru: "Владелец" })}</div>
                <strong>{row.label}</strong>
                <span>{row.count} {t(lang, { en: "assets", ru: "активов" })}</span>
              </div>
            ))}
          </div>
        </section>
        <section className="react-card react-card-nested">
          <PanelHeader title={t(lang, { en: "Critical ownership", ru: "Критичное владение" })} subtitle={t(lang, { en: "Owners with the largest notable-event concentration and critical assets.", ru: "Владельцы с наибольшей концентрацией значимых событий и критичных активов." })} icon="assets" />
          <div className="react-table-wrap">
            <table className="react-table">
              <thead>
                <tr>
                  <th>{t(lang, { en: "Owner", ru: "Владелец" })}</th>
                  <th>{t(lang, { en: "Assets", ru: "Активы" })}</th>
                  <th>{t(lang, { en: "Critical", ru: "Критичные" })}</th>
                  <th>{t(lang, { en: "Notable", ru: "Значимые" })}</th>
                </tr>
              </thead>
              <tbody>
                {ownerHotspots.map((row) => (
                  <tr key={row.owner}>
                    <td>{row.owner}</td>
                    <td>{row.assets}</td>
                    <td>{row.critical}</td>
                    <td>{row.notable}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      </DrawerOverlay>
    </div>
    </AsyncGate>
  );
}
