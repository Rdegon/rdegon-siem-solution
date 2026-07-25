import { useCallback, useEffect, useMemo, useState } from "react";
import { Link, useLocation, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { api } from "../api";
import { useAsyncData, useDebouncedValue } from "../hooks";
import { AsyncGate } from "../async";
import { useFeedback } from "../feedback";
import {
  DrawerFieldGrid,
  DrawerOverlay,
  EmptyState,
  KeyValue,
  MetricStrip,
  PageTabs,
  PanelHeader,
  SectionIntro,
  SeverityBadge,
  StatCard,
} from "../ui";
import { t, useShellContext } from "../context";
import type {
  AssetInventoryResponse,
  AssetRecord,
  IntegrationTemplateRecord,
  IntegrationsCatalogResponse,
  VulnCveRow,
  VulnExposureWorkbenchResponse,
  VulnFindingRow,
  VulnIntegrationContractResponse,
  VulnIntegrationTemplate,
  VulnHostRow,
  VulnMaturityResponse,
  VulnOverviewResponse,
  VulnRuntimeResponse,
  VulnReportDetailResponse,
  VulnReportsResponse,
  VulnReportSummary,
  VulnSoftwareRow,
  VulnUnmappedTargetRecord,
} from "../types";

type VulnEntityKind = "host" | "service" | "cve";
type ReportSummaryCard = VulnReportSummary & { targets: string[]; reportPath: string };
type NormalizedReportDetail = VulnReportDetailResponse & {
  cves: string[];
  targets: string[];
  ports: string[];
  findings: Array<VulnFindingRow & { cves: string[] }>;
};

function safeText(value: unknown, fallback = "n/a") {
  const text = String(value ?? "").trim();
  return text || fallback;
}

function scannerPriority(item: { scanner_family?: unknown; scanner_source?: unknown }) {
  const family = String(item.scanner_family || item.scanner_source || "").trim().toLowerCase();
  const source = String(item.scanner_source || "").trim().toLowerCase();
  if (family === "greenbone" || family === "openvas" || source.includes("greenbone") || source.includes("openvas")) {
    return 0;
  }
  if (family === "nmap" || source.includes("nmap")) {
    return 2;
  }
  return 1;
}

function scannerLabel(item: { scanner_family?: unknown; scanner_source?: unknown }) {
  const family = String(item.scanner_family || "").trim().toLowerCase();
  const source = String(item.scanner_source || "").trim();
  if (family === "greenbone" || family === "openvas" || /greenbone|openvas/i.test(source)) {
    return "OpenVAS / Greenbone";
  }
  if (family === "nmap" || /nmap/i.test(source)) {
    return "Nmap secondary";
  }
  return source || "Unknown scanner";
}

function classifyVulnActionFailure(action: "sync" | "import" | "apply", error: unknown) {
  const rawMessage = error instanceof Error ? error.message : "Request failed";
  const safeMessage = String(rawMessage || "").trim() || "Request failed";
  if (/403|permission|forbidden/i.test(safeMessage)) {
    return {
      state: "Permission denied. The current account is missing vuln:operate for vulnerability control actions.",
      toastTitle:
        action === "sync"
          ? "Vulnerability sync denied"
          : action === "import"
            ? "Vulnerability import denied"
            : "Vulnerability policy action denied",
      toastMessage: "The current account is missing vuln:operate.",
    };
  }
  if (/probe/i.test(safeMessage)) {
    return {
      state: `Greenbone probe failed: ${safeMessage}`,
      toastTitle: "Greenbone probe failed",
      toastMessage: safeMessage,
    };
  }
  if (/no fresh reports/i.test(safeMessage)) {
    return {
      state: "No fresh Greenbone reports were available for import.",
      toastTitle: "No fresh reports",
      toastMessage: safeMessage,
    };
  }
  if (/import/i.test(safeMessage)) {
    return {
      state: `Report import failed: ${safeMessage}`,
      toastTitle: "Vulnerability import failed",
      toastMessage: safeMessage,
    };
  }
  return {
    state:
      action === "sync"
        ? `Target sync failed: ${safeMessage}`
        : action === "import"
          ? `Report import failed: ${safeMessage}`
          : `Policy application failed: ${safeMessage}`,
    toastTitle:
      action === "sync"
        ? "Vulnerability sync failed"
        : action === "import"
          ? "Vulnerability import failed"
          : "Policy apply failed",
    toastMessage: safeMessage,
  };
}

function sqlLiteral(value: string) {
  return String(value || "").replace(/'/g, "''");
}

function buildEventPivot(kind: VulnEntityKind, value: string) {
  const safe = sqlLiteral(value);
  if (kind === "host") {
    return `dst_ip = '${safe}' OR host_name = '${safe}' OR log_source = '${safe}'`;
  }
  if (kind === "service") {
    return `process_name ILIKE '%${safe}%' OR device_product ILIKE '%${safe}%' OR message ILIKE '%${safe}%'`;
  }
  return `message ILIKE '%${safe}%'`;
}

function normalizeKey(value: unknown) {
  return String(value ?? "").trim().toLowerCase();
}

function buildAssetIndex(items: AssetRecord[]) {
  const index = new Map<string, AssetRecord>();
  for (const item of items || []) {
    const keys = [item.asset, ...(item.aliases || [])];
    for (const key of keys) {
      const normalized = normalizeKey(key);
      if (normalized && !index.has(normalized)) {
        index.set(normalized, item);
      }
    }
  }
  return index;
}

function uniqueStrings(values: Array<string | undefined | null>) {
  return Array.from(new Set(values.map((value) => String(value || "").trim()).filter(Boolean)));
}

function arrayOfStrings(value: unknown) {
  if (Array.isArray(value)) return value.map((item) => String(item || "").trim()).filter(Boolean);
  const text = String(value ?? "").trim();
  return text ? [text] : [];
}

function normalizeUnmappedTarget(value: unknown): VulnUnmappedTargetRecord {
  if (value && typeof value === "object") {
    const item = value as Record<string, unknown>;
    return {
      finding_key: String(item.finding_key || ""),
      report_id: String(item.report_id || ""),
      target: String(item.target || item.hostname || item.ip || ""),
      hostname: String(item.hostname || ""),
      ip: String(item.ip || ""),
      severity: String(item.severity || ""),
      cvss_score: Number(item.cvss_score || 0),
      reason: String(item.reason || ""),
      suggested_asset_id: String(item.suggested_asset_id || ""),
      suggested_hostname: String(item.suggested_hostname || ""),
      suggested_ip: String(item.suggested_ip || ""),
      suggested_basis: String(item.suggested_basis || ""),
      suggested_confidence: Number(item.suggested_confidence || 0),
      matched_alias: String(item.matched_alias || ""),
    };
  }
  const target = String(value || "");
  return {
    target,
    hostname: target,
    suggested_asset_id: target,
  };
}

function arrayOfRows<T = unknown>(value: unknown) {
  return Array.isArray(value) ? (value as T[]) : [];
}

function vulnEntityTitle(lang: "en" | "ru", kind: VulnEntityKind) {
  if (kind === "host") return t(lang, { en: "Host exposure", ru: "Экспозиция хоста" });
  if (kind === "service") return t(lang, { en: "Software and service", ru: "ПО и сервис" });
  return t(lang, { en: "CVE context", ru: "Контекст CVE" });
}

function VulnTabs(lang: "en" | "ru") {
  return (
    <PageTabs
      items={[
        { to: "/vuln", label: t(lang, { en: "Overview", ru: "Обзор" }) },
        { to: "/vuln/hosts", label: t(lang, { en: "Hosts", ru: "Хосты" }) },
        { to: "/vuln/reports", label: t(lang, { en: "Reports", ru: "Отчеты" }) },
        { to: "/vuln/findings", label: t(lang, { en: "Findings", ru: "Находки" }) },
        { to: "/vuln/cves", label: "CVEs" },
        { to: "/vuln/software", label: t(lang, { en: "Software", ru: "ПО / сервисы" }) },
      ]}
    />
  );
}

export function VulnPage() {
  const { formatTimestamp, lang, permissions } = useShellContext();
  const { pushToast } = useFeedback();
  const navigate = useNavigate();
  const location = useLocation();
  const params = useParams<{ reportId?: string }>();
  const [searchParams, setSearchParams] = useSearchParams();
  const [search, setSearch] = useState("");
  const [refreshTick, setRefreshTick] = useState(0);
  const [actionState, setActionState] = useState("");
  const [overrideTarget, setOverrideTarget] = useState("");
  const [overrideNote, setOverrideNote] = useState("");
  const debouncedSearch = useDebouncedValue(search, 300);

  const reportId = decodeURIComponent(String(params.reportId || "").trim());
  const path = location.pathname;
  const mode =
    path.includes("/reports")
      ? "reports"
      : path.endsWith("/hosts")
        ? "hosts"
        : path.endsWith("/findings")
          ? "findings"
          : path.endsWith("/cves")
            ? "cves"
            : path.endsWith("/software")
              ? "software"
              : "overview";

  const entityKindParam = String(searchParams.get("entity_kind") || "").trim().toLowerCase();
  const entityValueParam = String(searchParams.get("entity_value") || "").trim();
  const selectedEntity = useMemo(
    () =>
      entityValueParam && ["host", "service", "cve"].includes(entityKindParam)
        ? ({ kind: entityKindParam as VulnEntityKind, value: entityValueParam } satisfies { kind: VulnEntityKind; value: string })
        : null,
    [entityKindParam, entityValueParam],
  );

  const loadReports = useCallback<() => Promise<VulnReportsResponse>>(() => {
    void refreshTick;
    return api.reports();
  }, [refreshTick]);
  const loadOverview = useCallback<() => Promise<VulnOverviewResponse>>(() => {
    void refreshTick;
    return api.vulnOverview({ days: 30, limit: 20 });
  }, [refreshTick]);
  const loadIntegrations = useCallback<() => Promise<IntegrationsCatalogResponse>>(() => api.integrationsCatalog(), []);
  const loadIntegrationContract = useCallback<() => Promise<VulnIntegrationContractResponse>>(() => api.vulnIntegrationContract(), []);
  const loadRuntime = useCallback<() => Promise<VulnRuntimeResponse>>(() => {
    void refreshTick;
    return api.vulnRuntime({ days: 14 });
  }, [refreshTick]);
  const loadMaturity = useCallback<() => Promise<VulnMaturityResponse>>(() => {
    void refreshTick;
    return api.vulnMaturity({ days: 30, limit: 100 });
  }, [refreshTick]);
  const loadWorkbench = useCallback<() => Promise<VulnExposureWorkbenchResponse>>(() => {
    void refreshTick;
    return api.vulnWorkbench({ days: 30, limit: 200 });
  }, [refreshTick]);
  const loadHosts = useCallback(() => api.vulnHosts({ q: debouncedSearch, days: 30, limit: 120 }), [debouncedSearch]);
  const loadSoftware = useCallback(() => api.vulnSoftware({ q: debouncedSearch, days: 30, limit: 120 }), [debouncedSearch]);
  const loadCves = useCallback(() => api.vulnCves({ q: debouncedSearch, days: 30, limit: 120 }), [debouncedSearch]);
  const loadFindings = useCallback(() => api.vulnFindings({ q: debouncedSearch, days: 30, limit: 200 }), [debouncedSearch]);
  const loadReportDetail = useCallback(
    () => (reportId ? api.reportDetail(reportId) : Promise.resolve(null)),
    [reportId],
  );
  const loadEntityFindings = useCallback(
    () => (selectedEntity ? api.vulnFindings({ q: selectedEntity.value, days: 30, limit: 200 }) : Promise.resolve(null)),
    [selectedEntity],
  );
  const loadAssets = useCallback<() => Promise<AssetInventoryResponse>>(() => api.assetInventory({ hours: 24 * 14, limit: 500 }), []);
  const reportsState = useAsyncData<VulnReportsResponse>(loadReports);
  const overviewState = useAsyncData<VulnOverviewResponse>(loadOverview);
  const integrationsState = useAsyncData<IntegrationsCatalogResponse>(loadIntegrations);
  const contractState = useAsyncData<VulnIntegrationContractResponse>(loadIntegrationContract);
  const runtimeState = useAsyncData<VulnRuntimeResponse>(loadRuntime);
  const maturityState = useAsyncData<VulnMaturityResponse>(loadMaturity);
  const workbenchState = useAsyncData<VulnExposureWorkbenchResponse>(loadWorkbench);
  const hostsState = useAsyncData(loadHosts);
  const softwareState = useAsyncData(loadSoftware);
  const cvesState = useAsyncData(loadCves);
  const findingsState = useAsyncData(loadFindings);
  const reportDetailState = useAsyncData<VulnReportDetailResponse | null>(loadReportDetail);
  const entityFindingsState = useAsyncData(loadEntityFindings);
  const assetsState = useAsyncData<AssetInventoryResponse>(loadAssets);

  useEffect(() => {
    const nextQuery = String(searchParams.get("q") || "").trim();
    if (nextQuery !== search) {
      setSearch(nextQuery);
    }
  }, [search, searchParams]);

  const overview = overviewState.data || { summary: {}, hosts: [], services: [], cves: [] };
  const reports = useMemo(() => reportsState.data?.items || [], [reportsState.data]);
  const reportDetail = reportDetailState.data;
  const findings = findingsState.data?.items || [];
  const hosts = hostsState.data?.items || overview.hosts || [];
  const softwareRows = softwareState.data?.items || [];
  const cveRows = cvesState.data?.items || [];
  const vulnIntegrations = useMemo(
    () =>
      (integrationsState.data?.items || []).filter(
        (item: IntegrationTemplateRecord) =>
          String(item.group || "").toLowerCase() === "vulnerability" ||
          /openvas|greenbone|vulnerability|compliance/i.test(String(item.title || "")),
      ),
    [integrationsState.data],
  );
  const integrationContract = contractState.data || {
    version: "vuln-import-v1",
    entities: [],
    templates: [],
    transport_modes: [],
    notes: [],
  };
  const vulnRuntime = useMemo(() => runtimeState.data || {}, [runtimeState.data]);
  const vulnMaturity = useMemo(() => maturityState.data || {}, [maturityState.data]);
  const vulnWorkbench = useMemo(() => workbenchState.data || {}, [workbenchState.data]);
  const canOperateVuln = useMemo(() => permissions.includes("vuln:operate"), [permissions]);
  const runtimeBlob = useMemo(() => ((vulnRuntime.runtime || {}) as Record<string, unknown>), [vulnRuntime.runtime]);
  const probeState = useMemo(
    () => ((vulnRuntime.probe || runtimeBlob.probe || {}) as Record<string, unknown>),
    [runtimeBlob.probe, vulnRuntime.probe],
  );
  const targetSyncState = useMemo(
    () => ((runtimeBlob.target_sync || {}) as Record<string, unknown>),
    [runtimeBlob.target_sync],
  );
  const reportImportState = useMemo(
    () => ((runtimeBlob.report_import || {}) as Record<string, unknown>),
    [runtimeBlob.report_import],
  );
  const fleetCoverage = useMemo(
    () => vulnMaturity.fleet_coverage || vulnRuntime.fleet_coverage || {},
    [vulnMaturity.fleet_coverage, vulnRuntime.fleet_coverage],
  );
  const unmappedQueue = useMemo(() => (vulnMaturity.unmapped_targets || []).map((item) => normalizeUnmappedTarget(item)), [vulnMaturity.unmapped_targets]);
  const assetIndex = useMemo(() => buildAssetIndex(assetsState.data?.items || []), [assetsState.data]);

  useEffect(() => {
    const firstItem = unmappedQueue[0];
    setOverrideTarget(String(firstItem?.suggested_asset_id || firstItem?.target || ""));
    setOverrideNote(firstItem?.target ? `Suggested from unmapped target ${firstItem.target}` : "");
  }, [unmappedQueue]);

  const entitySummary = useMemo(() => {
    const rows = entityFindingsState.data?.items || [];
    const reportIds = new Set<string>();
    const hostsFound = new Set<string>();
    const ports = new Set<string>();
    const services = new Set<string>();
    const cves = new Set<string>();
    for (const row of rows) {
      if (row.report_id) reportIds.add(String(row.report_id));
      const host = safeText(row.dst_ip || row.host_name || row.source, "");
      if (host) hostsFound.add(host);
      if (row.dst_port) ports.add(String(row.dst_port));
      const service = safeText(row.service || row.process_name, "");
      if (service) services.add(service);
      for (const cve of row.cves || []) cves.add(String(cve));
    }
    return {
      findings: rows.length,
      reportIds: Array.from(reportIds),
      hosts: Array.from(hostsFound),
      ports: Array.from(ports),
      services: Array.from(services),
      cves: Array.from(cves),
      sample: rows.slice(0, 20),
    };
  }, [entityFindingsState.data]);

  const relatedAssets = useMemo(() => {
    const candidates = selectedEntity?.kind === "host" ? [selectedEntity.value] : entitySummary.hosts;
    const matched = uniqueStrings(candidates).map((candidate) => assetIndex.get(normalizeKey(candidate))).filter(Boolean) as AssetRecord[];
    return Array.from(new Map(matched.map((item) => [String(item.asset || ""), item])).values());
  }, [assetIndex, entitySummary.hosts, selectedEntity]);

  const reportSummaries = useMemo<ReportSummaryCard[]>(
    () =>
      reports
        .map((item) => ({
          ...item,
          targets: arrayOfStrings(item.targets),
          reportPath: `/vuln/reports/${encodeURIComponent(String(item.report_id || ""))}`,
        }))
        .sort((left, right) => {
          const priority = scannerPriority(left) - scannerPriority(right);
          if (priority !== 0) return priority;
          return String(right.ts_last || "").localeCompare(String(left.ts_last || ""));
        }),
    [reports],
  );
  const reportCatalogStats = useMemo(() => {
    const scanners = new Set<string>();
    const targets = new Set<string>();
    let findingsTotal = 0;
    let newest = "";
    for (const item of reportSummaries) {
      scanners.add(scannerLabel(item));
      for (const target of item.targets || []) targets.add(target);
      findingsTotal += Number(item.finding_count || item.findings || 0);
      const seen = String(item.ts_last || item.ts || "");
      if (seen && seen > newest) newest = seen;
    }
    return {
      scanners: scanners.size,
      targets: targets.size,
      findingsTotal,
      newest,
    };
  }, [reportSummaries]);

  const normalizedReportDetail = useMemo<NormalizedReportDetail | null>(() => {
    if (!reportDetail) return null;
    return {
      ...reportDetail,
      cves: arrayOfStrings(reportDetail.cves),
      targets: arrayOfStrings(reportDetail.targets),
      ports: arrayOfStrings(reportDetail.ports),
      findings: arrayOfRows<VulnFindingRow>(reportDetail.findings).map((row) => ({
        ...row,
        cves: arrayOfStrings(row.cves),
      })),
    };
  }, [reportDetail]);

  function setEntity(kind: VulnEntityKind, value: string) {
    const next = new URLSearchParams(searchParams);
    next.set("entity_kind", kind);
    next.set("entity_value", value);
    setSearchParams(next);
  }

  function clearEntity() {
    const next = new URLSearchParams(searchParams);
    next.delete("entity_kind");
    next.delete("entity_value");
    setSearchParams(next);
  }

  async function syncTargets() {
    if (!canOperateVuln) {
      const failure = classifyVulnActionFailure("sync", new Error("Request failed: 403"));
      setActionState(failure.state);
      pushToast({ title: failure.toastTitle, message: failure.toastMessage, tone: "error" });
      return;
    }
    setActionState("Syncing vulnerability targets...");
    try {
      const result = await api.vulnSync({ limit: 500 });
      setActionState(`Sync completed: ${Number(result.synced || result.updated || result.created || 0).toLocaleString()}`);
      setRefreshTick((value) => value + 1);
      pushToast({ title: "Vulnerability sync completed", message: String(result.synced || result.updated || result.created || 0), tone: "success" });
    } catch (error) {
      const failure = classifyVulnActionFailure("sync", error);
      setActionState(failure.state);
      pushToast({ title: failure.toastTitle, message: failure.toastMessage, tone: "error" });
    }
  }

  async function importReports() {
    if (!canOperateVuln) {
      const failure = classifyVulnActionFailure("import", new Error("Request failed: 403"));
      setActionState(failure.state);
      pushToast({ title: failure.toastTitle, message: failure.toastMessage, tone: "error" });
      return;
    }
    setActionState("Importing scanner reports...");
    try {
      const result = await api.vulnImport({ limit: 20 });
      setActionState(`Import completed: ${Number(result.imported || result.created || result.updated || 0).toLocaleString()}`);
      setRefreshTick((value) => value + 1);
      pushToast({ title: "Vulnerability import completed", message: String(result.imported || result.created || result.updated || 0), tone: "success" });
    } catch (error) {
      const failure = classifyVulnActionFailure("import", error);
      setActionState(failure.state);
      pushToast({ title: failure.toastTitle, message: failure.toastMessage, tone: "error" });
    }
  }

  async function applyPolicies() {
    if (!canOperateVuln) {
      const failure = classifyVulnActionFailure("apply", new Error("Request failed: 403"));
      setActionState(failure.state);
      pushToast({ title: failure.toastTitle, message: failure.toastMessage, tone: "error" });
      return;
    }
    setActionState("Applying vulnerability incident policies...");
    try {
      const result = await api.vulnApplyPolicies({ days: 30, limit: 50 });
      setActionState(`Policies applied: ${Number(result.created || 0).toLocaleString()} case(s) created`);
      setRefreshTick((value) => value + 1);
      pushToast({
        title: "Vulnerability policies applied",
        message: `${Number(result.created || 0).toLocaleString()} created / ${Number(result.skipped || 0).toLocaleString()} skipped`,
        tone: "success",
      });
    } catch (error) {
      const failure = classifyVulnActionFailure("apply", error);
      setActionState(failure.state);
      pushToast({ title: failure.toastTitle, message: failure.toastMessage, tone: "error" });
    }
  }

  async function syncExposureIntelligence() {
    if (!canOperateVuln) return;
    setActionState("Synchronizing CISA KEV and FIRST EPSS intelligence...");
    try {
      const result = await api.vulnSyncIntelligence({ days: 30, limit: 500 });
      setActionState(`Intelligence sync: ${safeText(result.status, "completed")}`);
      setRefreshTick((value) => value + 1);
      pushToast({ title: "Exposure intelligence synchronized", message: safeText(result.status, "completed"), tone: "success" });
    } catch (error) {
      const failure = classifyVulnActionFailure("apply", error);
      setActionState(failure.state);
      pushToast({ title: "Intelligence sync failed", message: failure.toastMessage, tone: "error" });
    }
  }

  async function applyExposurePolicies() {
    if (!canOperateVuln) return;
    setActionState("Creating risk-based vulnerability remediation cases...");
    try {
      const result = await api.vulnApplyExposure({ days: 30, limit: 100 });
      setActionState(`Exposure policy: ${Number(result.created || 0).toLocaleString()} case(s) created`);
      setRefreshTick((value) => value + 1);
      pushToast({
        title: "Exposure policy applied",
        message: `${Number(result.created || 0).toLocaleString()} created / ${Number(result.skipped || 0).toLocaleString()} skipped`,
        tone: "success",
      });
    } catch (error) {
      const failure = classifyVulnActionFailure("apply", error);
      setActionState(failure.state);
      pushToast({ title: "Exposure policy failed", message: failure.toastMessage, tone: "error" });
    }
  }

  async function startTargetedScan(assetId: string) {
    if (!canOperateVuln || !assetId) return;
    setActionState(`Starting targeted scan for ${assetId}...`);
    try {
      const result = await api.vulnStartScans({ asset_ids: [assetId], limit: 1 });
      setActionState(`Targeted scan started: ${Number(result.started || 0).toLocaleString()}`);
      setRefreshTick((value) => value + 1);
      pushToast({ title: "Targeted scan requested", message: assetId, tone: "success" });
    } catch (error) {
      const failure = classifyVulnActionFailure("sync", error);
      setActionState(failure.state);
      pushToast({ title: "Targeted scan failed", message: failure.toastMessage, tone: "error" });
    }
  }

  async function saveUnmappedTargetOverride() {
    if (!overrideTarget.trim()) return;
    const matchedQueueItem =
      unmappedQueue.find((item) =>
        [item.target, item.hostname, item.ip, item.suggested_asset_id]
          .map((value) => String(value || "").trim())
          .filter(Boolean)
          .includes(overrideTarget.trim()),
      ) ||
      unmappedQueue[0] ||
      null;
    try {
      await api.saveAssetBindingOverride({
        target: overrideTarget,
        aliases: [overrideTarget, matchedQueueItem?.target, matchedQueueItem?.hostname, matchedQueueItem?.ip].filter(Boolean),
        hostname: matchedQueueItem?.hostname || overrideTarget,
        ip: matchedQueueItem?.ip,
        scope: "vulnerability",
        note: overrideNote || matchedQueueItem?.reason || "",
        enabled: true,
      });
      setActionState(`Binding override saved for ${overrideTarget}`);
      setRefreshTick((value) => value + 1);
      pushToast({ title: "Binding override saved", message: overrideTarget, tone: "success" });
    } catch (error) {
      const message = error instanceof Error ? error.message : "Unable to save binding override";
      setActionState(message);
      pushToast({ title: "Binding override failed", message, tone: "error" });
    }
  }

  const maturityMetrics = [
    {
      label: t(lang, { en: "Asset binding", ru: "Связь с активами" }),
      value: `${Math.round(Number(vulnMaturity.asset_binding_coverage || 0) * 100)}%`,
      hint: t(lang, { en: "Coverage of findings bound to assets/entities.", ru: "Покрытие находок, связанных с активами и сущностями." }),
      tone: Number(vulnMaturity.asset_binding_coverage || 0) >= 0.8 ? ("success" as const) : ("warning" as const),
    },
    {
      label: t(lang, { en: "Critical candidates", ru: "Критичные кандидаты" }),
      value: vulnMaturity.critical_candidates_total || 0,
      hint: t(lang, { en: "Findings eligible for case/policy creation.", ru: "Находки, подходящие для создания кейсов и политик." }),
      tone: Number(vulnMaturity.critical_candidates_total || 0) > 0 ? ("critical" as const) : ("default" as const),
    },
    {
      label: t(lang, { en: "Ready for policies", ru: "Готово для политик" }),
      value: vulnMaturity.ready_for_incident_policies ? "yes" : "no",
      hint: t(lang, { en: "Whether critical findings are ready for automated incident policies.", ru: "Готовность критичных findings к автоматическим incident policies." }),
      tone: vulnMaturity.ready_for_incident_policies ? ("warning" as const) : ("default" as const),
    },
    {
      label: t(lang, { en: "Structured reports", ru: "Structured reports" }),
      value: vulnRuntime.structured_reports?.count || 0,
      hint: t(lang, { en: "Recently imported structured scanner reports.", ru: "Недавно импортированные structured scanner reports." }),
      tone: vulnRuntime.healthy ? ("success" as const) : ("warning" as const),
    },
    {
      label: t(lang, { en: "Fleet scanned", ru: "Покрыто сканированием" }),
      value: `${Number(fleetCoverage.recently_scanned_guests || 0)}/${Number(fleetCoverage.scannable_guests || 0)}`,
      hint: t(lang, {
        en: "Recently scanned guests against the scannable fleet.",
        ru: "Недавно просканированные узлы относительно доступного для сканирования флота.",
      }),
      tone:
        Number(fleetCoverage.scannable_guests || 0) > 0 &&
        Number(fleetCoverage.recently_scanned_guests || 0) >= Number(fleetCoverage.scannable_guests || 0)
          ? ("success" as const)
          : ("warning" as const),
    },
  ];
  const scannerStatusItems = [
    {
      label: "Probe",
      value: safeText(probeState.status || (vulnRuntime.greenbone?.enabled ? "configured" : "disabled")),
    },
    {
      label: "Target sync",
      value: safeText(targetSyncState.status || "idle"),
    },
    {
      label: "Report import",
      value: safeText(reportImportState.status || "idle"),
    },
    {
      label: "Last successful import",
      value: safeText(vulnRuntime.last_successful_import_ts ? formatTimestamp(vulnRuntime.last_successful_import_ts, "compact") : "", "n/a"),
    },
    {
      label: "Last error",
      value: safeText(vulnRuntime.last_error || "", "none"),
    },
    {
      label: "Scanner mix",
      value:
        Object.entries(vulnRuntime.scanner_family_breakdown || {})
          .sort((left, right) => scannerPriority({ scanner_family: left[0] }) - scannerPriority({ scanner_family: right[0] }))
          .map(([family, count]) => `${scannerLabel({ scanner_family: family })} ${Number(count || 0)}`)
          .join(" | ") || "no structured runs",
    },
  ];

  return (
    <AsyncGate
      states={[reportsState, overviewState, assetsState, integrationsState, contractState, runtimeState, maturityState, workbenchState]}
      loadingMessage="Loading vulnerability module..."
    >
      <div className="react-page react-page-vuln">
      <SectionIntro
        kicker={t(lang, { en: "Vulnerabilities", ru: "Уязвимости" })}
        title={t(lang, { en: "Exposure and scan intelligence", ru: "Экспозиция и результаты сканирования" })}
        subtitle={t(lang, {
          en: "Host, software, CVE and report views over imported scanner findings.",
          ru: "Представления по хостам, ПО, CVE и отчетам поверх импортированных результатов сканирования.",
        })}
        icon="vuln"
        actions={
          <input
            className="react-input react-input-grow"
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            placeholder={t(lang, {
              en: "Search host, software, CVE, port or report...",
              ru: "Поиск по хосту, ПО, CVE, порту или отчету...",
            })}
          />
        }
      />

      <div className="react-grid react-grid-5">
        <StatCard label={t(lang, { en: "Reports", ru: "Отчеты" })} value={overview.summary.reports || reports.length || 0} hint={t(lang, { en: "Imported scan sessions and parsed datasets.", ru: "Импортированные сессии сканирования и разобранные наборы данных." })} />
        <StatCard label={t(lang, { en: "Targets", ru: "Цели" })} value={overview.summary.targets || hosts.length || 0} hint={t(lang, { en: "Unique hosts with exposed services or findings.", ru: "Уникальные хосты с открытыми сервисами или находками." })} />
        <StatCard label={t(lang, { en: "Findings", ru: "Находки" })} value={overview.summary.findings || findings.length || 0} hint={t(lang, { en: "Service and vulnerability findings across scanners.", ru: "Сервисные и уязвимые находки по всем сканерам." })} />
        <StatCard label="CVEs" value={cveRows.length || 0} hint={t(lang, { en: "Distinct CVE markers extracted from evidence.", ru: "Уникальные CVE, извлеченные из результатов." })} />
        <StatCard label={t(lang, { en: "Software", ru: "ПО / сервисы" })} value={softwareRows.length || 0} hint={t(lang, { en: "Software and service families detected in imported reports.", ru: "Семейства ПО и сервисов, найденные в импортированных отчетах." })} />
      </div>

      {VulnTabs(lang)}

      {mode === "overview" ? <MetricStrip items={maturityMetrics} /> : null}

      {mode === "overview" ? (
        <section className="react-card">
          <PanelHeader
            title="Risk-based exposure queue"
            subtitle="KEV, EPSS, asset criticality, SLA and remediation status over current scanner findings."
            actions={
              canOperateVuln ? (
                <div className="react-actions react-wrap">
                  <button type="button" className="react-link-button" onClick={() => void syncExposureIntelligence()}>
                    Sync intelligence
                  </button>
                  <button type="button" className="react-link-button" onClick={() => void applyExposurePolicies()}>
                    Create remediation cases
                  </button>
                </div>
              ) : (
                <span className="react-chip">Read only</span>
              )
            }
          />
          <div className="react-chip-row">
            <span className="react-chip">Actionable: {Number(vulnWorkbench.summary?.actionable || 0)}</span>
            <span className="react-chip">Urgent: {Number(vulnWorkbench.summary?.urgent || 0)}</span>
            <span className="react-chip">KEV: {Number(vulnWorkbench.summary?.kev || 0)}</span>
            <span className="react-chip">SLA breached: {Number(vulnWorkbench.summary?.sla_breached || 0)}</span>
            <span className="react-chip">Stale targets: {Number(vulnWorkbench.summary?.stale_targets || 0)}</span>
          </div>
          <div className="react-table-wrap" style={{ marginTop: 16 }}>
            <table className="react-table">
              <thead>
                <tr>
                  <th>Asset</th>
                  <th>Risk</th>
                  <th>KEV / EPSS</th>
                  <th>SLA</th>
                  <th>Remediation</th>
                  <th>Validation</th>
                </tr>
              </thead>
              <tbody>
                {(vulnWorkbench.items || []).slice(0, 12).map((item) => (
                  <tr key={item.finding_key}>
                    <td>
                      <strong>{safeText(item.asset_hostname || item.target || item.asset_id)}</strong>
                      {item.stale_target ? <div className="react-cell-muted">stale target {safeText(item.target_ip)}</div> : null}
                    </td>
                    <td>
                      <strong>{Number(item.priority_score || 0).toFixed(1)}</strong>
                      <div className="react-cell-muted">{safeText(item.priority_band)}</div>
                    </td>
                    <td>{item.kev ? "KEV" : "no"} / {Number(item.epss || 0).toFixed(3)}</td>
                    <td>{item.sla_breached ? "breached" : safeText(item.due_ts ? formatTimestamp(item.due_ts, "compact") : "")}</td>
                    <td className="react-cell-clamp">{safeText(item.remediation?.action)}</td>
                    <td>
                      {item.case_id ? (
                        <span className="react-chip">{safeText(item.case_status, "case")}</span>
                      ) : canOperateVuln && item.asset_id && !item.stale_target ? (
                        <button type="button" className="react-link-button" onClick={() => void startTargetedScan(String(item.asset_id))}>
                          Rescan
                        </button>
                      ) : (
                        <span className="react-chip">{item.stale_target ? "sync target" : "case required"}</span>
                      )}
                    </td>
                  </tr>
                ))}
                {!(vulnWorkbench.items || []).length ? (
                  <tr>
                    <td colSpan={6}>No vulnerability findings in the selected window.</td>
                  </tr>
                ) : null}
              </tbody>
            </table>
          </div>
        </section>
      ) : null}

      {mode === "overview" ? (
        <div className="react-grid react-grid-3">
          <section className="react-card">
            <PanelHeader
              title="Scanner runtime"
              subtitle="Live scanner, sync and import health for the vulnerability pipeline."
              actions={
                canOperateVuln ? (
                  <div className="react-actions react-wrap">
                    <button type="button" className="react-link-button" onClick={() => void syncTargets()}>
                      Sync targets
                    </button>
                    <button type="button" className="react-link-button" onClick={() => void importReports()}>
                      Import reports
                    </button>
                  </div>
                ) : (
                  <span className="react-chip">Read only</span>
                )
              }
            />
            <DrawerFieldGrid>
              <KeyValue label="Runtime health" value={vulnRuntime.healthy ? "healthy" : "degraded"} />
              <KeyValue label="Probe" value={safeText(probeState.status || "", vulnRuntime.greenbone?.enabled ? "configured" : "disabled")} />
              <KeyValue label="Structured reports" value={vulnRuntime.structured_reports?.count || 0} />
              <KeyValue label="Last sync" value={safeText(vulnRuntime.last_target_sync_ts ? formatTimestamp(vulnRuntime.last_target_sync_ts, "compact") : "")} />
              <KeyValue label="Last import" value={safeText(vulnRuntime.last_import_ts ? formatTimestamp(vulnRuntime.last_import_ts, "compact") : "")} />
              <KeyValue label="Fleet total" value={Number(fleetCoverage.total_guests || 0)} />
              <KeyValue label="Reachable fleet" value={Number(fleetCoverage.reachable_guests || 0)} />
            </DrawerFieldGrid>
            <div className="react-chip-row" style={{ marginTop: 16 }}>
              {scannerStatusItems.map((item) => (
                <span key={item.label} className="react-chip">
                  {item.label}: {item.value}
                </span>
              ))}
            </div>
            <div className="react-info-list" style={{ marginTop: 16 }}>
              {!canOperateVuln ? (
                <div className="react-history-item">Scanner control actions require the vuln:operate permission.</div>
              ) : null}
              {vulnRuntime.last_error ? <div className="react-history-item">{String(vulnRuntime.last_error)}</div> : null}
              <div className="react-history-item">{actionState || "No recent scanner action in this session."}</div>
            </div>
          </section>
          <section className="react-card">
            <PanelHeader
              title="Fleet coverage"
              subtitle="How OpenVAS coverage maps to the current Proxmox-backed fleet, including honest offline and unresolved accounting."
            />
            <DrawerFieldGrid>
              <KeyValue label="Scannable" value={Number(fleetCoverage.scannable_guests || 0)} />
              <KeyValue label="Scanned recently" value={Number(fleetCoverage.recently_scanned_guests || 0)} />
              <KeyValue label="Offline" value={Number(fleetCoverage.offline_guests || 0)} />
              <KeyValue label="Unresolved" value={Number(fleetCoverage.unresolved_guests || 0)} />
              <KeyValue label="Last import" value={safeText(fleetCoverage.last_successful_import)} />
            </DrawerFieldGrid>
            <div className="react-chip-row" style={{ marginTop: 16 }}>
              <span className="react-chip">OpenVAS primary</span>
              <span className="react-chip">Nmap supplemental</span>
              <span className="react-chip">Fleet-aware coverage</span>
            </div>
          </section>
          <section className="react-card">
            <PanelHeader
              title="Maturity and binding"
              subtitle="Coverage of asset/entity binding and readiness for automated incident policies."
            />
            <DrawerFieldGrid>
              <KeyValue label="Reports total" value={vulnMaturity.reports_total || 0} />
              <KeyValue label="Findings total" value={vulnMaturity.findings_total || 0} />
              <KeyValue label="Reports bound" value={vulnMaturity.reports_with_asset_binding || 0} />
              <KeyValue label="Findings bound" value={vulnMaturity.findings_with_asset_binding || 0} />
              <KeyValue label="Asset coverage" value={`${Math.round(Number(vulnMaturity.asset_binding_coverage || 0) * 100)}%`} />
              <KeyValue label="Policy ready" value={vulnMaturity.ready_for_incident_policies ? "yes" : "no"} />
            </DrawerFieldGrid>
            <div className="react-chip-row" style={{ marginTop: 16 }}>
              {Object.entries(vulnMaturity.severity_counts || {}).map(([severity, count]) => (
                <span key={severity} className="react-chip">
                  {severity}: {Number(count || 0).toLocaleString()}
                </span>
              ))}
              {!Object.keys(vulnMaturity.severity_counts || {}).length ? <span className="react-chip">no severity data</span> : null}
            </div>
          </section>
          <section className="react-card">
            <PanelHeader
              title="Critical candidates"
              subtitle="Highest-priority findings eligible for vuln-to-incident automation."
              actions={
                canOperateVuln ? (
                  <button type="button" className="react-link-button" onClick={() => void applyPolicies()}>
                    Apply policies
                  </button>
                ) : (
                  <span className="react-chip">Read only</span>
                )
              }
            />
            <div className="react-table-wrap">
              <table className="react-table">
                <thead>
                  <tr>
                    <th>Target</th>
                    <th>Severity</th>
                    <th>Score</th>
                    <th>Reason</th>
                  </tr>
                </thead>
                <tbody>
                  {(vulnMaturity.critical_candidates || []).slice(0, 8).map((item, index) => (
                    <tr key={`${item.target || item.asset || index}-${index}`} onClick={() => item.target && setEntity("host", String(item.target))}>
                      <td><strong>{safeText(item.target || item.asset || item.entity || item.host_name)}</strong></td>
                      <td>{item.severity ? <SeverityBadge value={String(item.severity)} /> : "n/a"}</td>
                      <td>{safeText(item.score)}</td>
                      <td className="react-cell-clamp">{safeText(item.reason || item.summary || item.message)}</td>
                    </tr>
                  ))}
                  {!(vulnMaturity.critical_candidates || []).length ? (
                    <tr>
                      <td colSpan={4}>No critical candidates in the selected window.</td>
                    </tr>
                  ) : null}
                </tbody>
              </table>
            </div>
          </section>
          <section className="react-card">
            <PanelHeader
              title="Unmapped target queue"
              subtitle="Targets still missing an asset binding. Use overrides to close the gap without leaving the product."
              actions={
                <button type="button" className="react-link-button" onClick={() => void saveUnmappedTargetOverride()} disabled={!overrideTarget.trim()}>
                  Save override
                </button>
              }
            />
            <DrawerFieldGrid>
              <KeyValue label="Unmapped total" value={Number(vulnMaturity.unmapped_targets_total || unmappedQueue.length || 0)} />
              <KeyValue label="Binding overrides" value={Number(vulnMaturity.binding_overrides_active || 0)} />
              <KeyValue label="Suggested target" value={overrideTarget || "n/a"} />
            </DrawerFieldGrid>
            <div className="react-form-grid" style={{ marginTop: 16 }}>
              <input className="react-input" value={overrideTarget} onChange={(event) => setOverrideTarget(event.target.value)} placeholder="Asset target or hostname" />
              <input className="react-input react-input-full" value={overrideNote} onChange={(event) => setOverrideNote(event.target.value)} placeholder="Operator note" />
            </div>
            <div className="react-list react-list-compact" style={{ marginTop: 16 }}>
              {unmappedQueue.slice(0, 8).map((target) => (
                <button
                  key={target.finding_key || target.target}
                  type="button"
                  className="react-list-item"
                  onClick={() => {
                    setOverrideTarget(String(target.suggested_asset_id || target.target || ""));
                    setOverrideNote(String(target.reason || ""));
                  }}
                >
                  <strong>{target.target}</strong>
                  <span>
                    {[
                      target.severity ? `Severity ${target.severity}` : "",
                      target.suggested_asset_id ? `Suggested asset ${target.suggested_asset_id}` : "",
                      target.reason || "",
                    ]
                      .filter(Boolean)
                      .join(" | ")}
                  </span>
                </button>
              ))}
              {!unmappedQueue.length ? <EmptyState message="No unmapped targets in the current maturity window." /> : null}
            </div>
          </section>
          <section className="react-card">
            <PanelHeader title={t(lang, { en: "Top targets", ru: "Топ целей" })} subtitle={t(lang, { en: "Hosts with the largest amount of exposure.", ru: "Хосты с наибольшей экспозицией." })} />
            <div className="react-table-wrap">
              <table className="react-table">
                <thead>
                  <tr>
                    <th>{t(lang, { en: "Target", ru: "Цель" })}</th>
                    <th>{t(lang, { en: "Findings", ru: "Находки" })}</th>
                    <th>{t(lang, { en: "Ports", ru: "Порты" })}</th>
                    <th>{t(lang, { en: "Services", ru: "Сервисы" })}</th>
                  </tr>
                </thead>
                <tbody>
                  {hosts.slice(0, 10).map((row: VulnHostRow) => (
                    <tr key={row.target} onClick={() => setEntity("host", String(row.target || ""))}>
                      <td><strong>{row.target}</strong></td>
                      <td>{row.findings}</td>
                      <td>{row.open_ports}</td>
                      <td>{(row.services || []).join(", ") || "n/a"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
          <section className="react-card">
            <PanelHeader title={t(lang, { en: "Service exposure", ru: "Экспозиция сервисов" })} subtitle={t(lang, { en: "Software and services most frequently exposed.", ru: "Наиболее часто встречающиеся сервисы и ПО." })} />
            <div className="react-table-wrap">
              <table className="react-table">
                <thead>
                  <tr>
                    <th>{t(lang, { en: "Service", ru: "Сервис" })}</th>
                    <th>{t(lang, { en: "Findings", ru: "Находки" })}</th>
                    <th>{t(lang, { en: "Hosts", ru: "Хосты" })}</th>
                    <th>{t(lang, { en: "Ports", ru: "Порты" })}</th>
                  </tr>
                </thead>
                <tbody>
                  {softwareRows.slice(0, 10).map((row: VulnSoftwareRow) => (
                    <tr key={row.service} onClick={() => setEntity("service", String(row.service || ""))}>
                      <td><strong>{row.service}</strong></td>
                      <td>{row.findings}</td>
                      <td>{row.hosts}</td>
                      <td>{(row.ports || []).join(", ") || "n/a"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
          <section className="react-card">
            <PanelHeader title={t(lang, { en: "Top CVEs", ru: "Топ CVE" })} subtitle={t(lang, { en: "Most frequent CVE markers extracted from reports.", ru: "Наиболее частые CVE, извлеченные из отчетов." })} />
            <div className="react-table-wrap">
              <table className="react-table">
                <thead>
                  <tr>
                    <th>CVE</th>
                    <th>{t(lang, { en: "Findings", ru: "Находки" })}</th>
                    <th>{t(lang, { en: "Hosts", ru: "Хосты" })}</th>
                  </tr>
                </thead>
                <tbody>
                  {cveRows.slice(0, 10).map((row: VulnCveRow) => (
                    <tr key={row.cve} onClick={() => setEntity("cve", String(row.cve || ""))}>
                      <td><strong>{row.cve}</strong></td>
                      <td>{row.findings}</td>
                      <td>{row.hosts}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </section>
          <section className="react-card react-widget-span-2">
            <PanelHeader
              title={t(lang, { en: "Scanner integrations", ru: "Интеграции сканеров" })}
              subtitle={t(lang, {
                en: "Prepared import paths for the external Vulnerability Manager and scanner ecosystems.",
                ru: "Подготовленные пути импорта для внешнего Vulnerability Manager и экосистемы сканеров.",
              })}
              actions={
                <div className="react-actions react-wrap">
                  <Link className="react-link-button" to="/sources?view=integrations">
                    {t(lang, { en: "Open Sources", ru: "Открыть источники" })}
                  </Link>
                  <Link className="react-link-button" to="/builders?kind=integration">
                    {t(lang, { en: "Open integration builder", ru: "Открыть конструктор интеграций" })}
                  </Link>
                </div>
              }
            />
            <div className="react-chip-grid">
              {vulnIntegrations.map((item: IntegrationTemplateRecord) => (
                <div key={item.id} className="react-chip-card">
                  <div className="react-top-kicker">{item.group || "integration"}</div>
                  <strong>{item.title}</strong>
                  <span>{item.description}</span>
                  <span>{(item.protocols || []).join(", ") || "n/a"}</span>
                  <Link className="react-link-button" to={`/builders?kind=integration&template=${encodeURIComponent(String(item.id || ""))}`}>
                    {t(lang, { en: "Use template", ru: "Использовать шаблон" })}
                  </Link>
                </div>
              ))}
            </div>
          </section>
          <section className="react-card">
            <PanelHeader
              title={t(lang, { en: "Import contract", ru: "Контракт импорта" })}
              subtitle={t(lang, {
                en: "Entity contract that the external Vulnerability Manager can target.",
                ru: "Контракт сущностей, на который может опираться внешний Vulnerability Manager.",
              })}
            />
            <div className="react-list react-list-compact">
              {(integrationContract.entities || []).map((item) => (
                <div key={item.id} className="react-list-item">
                  <strong>{item.id}</strong>
                  <span>{t(lang, { en: "Required", ru: "Обязательные" })}: {(item.required || []).join(", ") || "n/a"}</span>
                  <span>{t(lang, { en: "Optional", ru: "Дополнительные" })}: {(item.optional || []).join(", ") || "n/a"}</span>
                </div>
              ))}
            </div>
          </section>
          <section className="react-card">
            <PanelHeader
              title={t(lang, { en: "Transport modes", ru: "Транспортные режимы" })}
              subtitle={t(lang, {
                en: "Prepared connection paths and hand-off notes for the future external manager.",
                ru: "Подготовленные пути подключения и заметки для будущей интеграции.",
              })}
            />
            <div className="react-chip-row">
              {(integrationContract.transport_modes || []).map((mode, index) => {
                const label =
                  typeof mode === "string"
                    ? mode
                    : String(mode.mode || mode.id || mode.title || `mode-${index}`);
                return (
                  <span key={label} className="react-chip">{label}</span>
                );
              })}
            </div>
            <div className="react-info-list" style={{ marginTop: 16 }}>
              {(integrationContract.notes || []).map((note) => (
                <div key={note} className="react-history-item">{note}</div>
              ))}
            </div>
          </section>
          <section className="react-card react-widget-span-2">
            <PanelHeader
              title="Scheduled workflows and playbooks"
              subtitle="Release-grade vulnerability workflows, scheduled exposure checks and critical response playbooks."
            />
            <div className="react-grid react-grid-2">
              <section className="react-card react-card-nested">
                <PanelHeader title="Scheduled workflows" subtitle="Automated exposure and reporting routines." />
                <div className="react-list react-list-compact">
                  {(vulnMaturity.scheduled_workflows || []).map((item, index) => (
                    <div key={`${item.name || item.id || index}`} className="react-list-item">
                      <strong>{safeText(item.name || item.id, `workflow-${index + 1}`)}</strong>
                      <span>{safeText(item.schedule || item.cadence || item.status, "n/a")}</span>
                      <span>{safeText(item.description || item.summary, "n/a")}</span>
                    </div>
                  ))}
                  {!(vulnMaturity.scheduled_workflows || []).length ? (
                    <div className="react-list-item">
                      <strong>none</strong>
                      <span>No scheduled workflows are registered.</span>
                    </div>
                  ) : null}
                </div>
              </section>
              <section className="react-card react-card-nested">
                <PanelHeader title="Critical playbooks" subtitle="Operator response guidance for high-severity findings." />
                <div className="react-list react-list-compact">
                  {(vulnMaturity.playbooks || []).map((item, index) => (
                    <div key={`${item.slug || item.name || index}`} className="react-list-item">
                      <strong>{safeText(item.name || item.slug, `playbook-${index + 1}`)}</strong>
                      <span>{safeText(item.trigger || item.severity || item.kind, "n/a")}</span>
                      <span>{safeText(item.description || item.summary, "n/a")}</span>
                    </div>
                  ))}
                  {!(vulnMaturity.playbooks || []).length ? (
                    <div className="react-list-item">
                      <strong>none</strong>
                      <span>No playbooks are linked yet.</span>
                    </div>
                  ) : null}
                </div>
              </section>
            </div>
          </section>
        </div>
      ) : null}

      {mode === "hosts" ? (
        <section className="react-card">
          <PanelHeader title={t(lang, { en: "Host exposure explorer", ru: "Обзор экспозиции хостов" })} subtitle={t(lang, { en: "Per-host vulnerability and service exposure view.", ru: "Представление по хостам, уязвимостям и открытым сервисам." })} />
          <div className="react-table-wrap">
            <table className="react-table">
              <thead>
                <tr>
                  <th>{t(lang, { en: "Target", ru: "Цель" })}</th>
                  <th>{t(lang, { en: "Findings", ru: "Находки" })}</th>
                  <th>{t(lang, { en: "Open ports", ru: "Открытые порты" })}</th>
                  <th>{t(lang, { en: "Reports", ru: "Отчеты" })}</th>
                  <th>{t(lang, { en: "Services", ru: "Сервисы" })}</th>
                  <th>{t(lang, { en: "Last seen", ru: "Последняя активность" })}</th>
                </tr>
              </thead>
              <tbody>
                {hosts.map((row: VulnHostRow) => (
                  <tr key={row.target} onClick={() => setEntity("host", String(row.target || ""))}>
                    <td><strong>{row.target}</strong></td>
                    <td>{row.findings}</td>
                    <td>{row.open_ports}</td>
                    <td>{row.reports}</td>
                    <td>{(row.services || []).join(", ") || "n/a"}</td>
                    <td>{row.last_seen || "n/a"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      ) : null}

      {mode === "software" ? (
        <section className="react-card">
          <PanelHeader title={t(lang, { en: "Software explorer", ru: "Обзор ПО и сервисов" })} subtitle={t(lang, { en: "Service and software families across imported scanner findings.", ru: "Сервисы и семейства ПО по импортированным находкам сканеров." })} />
          <div className="react-table-wrap">
            <table className="react-table">
              <thead>
                <tr>
                  <th>{t(lang, { en: "Service", ru: "Сервис" })}</th>
                  <th>{t(lang, { en: "Findings", ru: "Находки" })}</th>
                  <th>{t(lang, { en: "Hosts", ru: "Хосты" })}</th>
                  <th>{t(lang, { en: "Host samples", ru: "Примеры хостов" })}</th>
                  <th>{t(lang, { en: "Ports", ru: "Порты" })}</th>
                  <th>{t(lang, { en: "Last seen", ru: "Последняя активность" })}</th>
                </tr>
              </thead>
              <tbody>
                {softwareRows.map((row: VulnSoftwareRow) => (
                  <tr key={row.service} onClick={() => setEntity("service", String(row.service || ""))}>
                    <td><strong>{row.service}</strong></td>
                    <td>{row.findings}</td>
                    <td>{row.hosts}</td>
                    <td>{(row.host_samples || []).join(", ") || "n/a"}</td>
                    <td>{(row.ports || []).join(", ") || "n/a"}</td>
                    <td>{row.last_seen || "n/a"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      ) : null}

      {mode === "cves" ? (
        <section className="react-card">
          <PanelHeader title={t(lang, { en: "CVE explorer", ru: "Обзор CVE" })} subtitle={t(lang, { en: "CVE markers extracted and linked to hosts and services.", ru: "CVE, извлеченные из отчетов и привязанные к хостам и сервисам." })} />
          <div className="react-table-wrap">
            <table className="react-table">
              <thead>
                <tr>
                  <th>CVE</th>
                  <th>{t(lang, { en: "Findings", ru: "Находки" })}</th>
                  <th>{t(lang, { en: "Hosts", ru: "Хосты" })}</th>
                  <th>{t(lang, { en: "Host samples", ru: "Примеры хостов" })}</th>
                  <th>{t(lang, { en: "Services", ru: "Сервисы" })}</th>
                  <th>{t(lang, { en: "Last seen", ru: "Последняя активность" })}</th>
                </tr>
              </thead>
              <tbody>
                {cveRows.map((row: VulnCveRow) => (
                  <tr key={row.cve} onClick={() => setEntity("cve", String(row.cve || ""))}>
                    <td><strong>{row.cve}</strong></td>
                    <td>{row.findings}</td>
                    <td>{row.hosts}</td>
                    <td>{(row.host_samples || []).join(", ") || "n/a"}</td>
                    <td>{(row.services || []).join(", ") || "n/a"}</td>
                    <td>{row.last_seen || "n/a"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      ) : null}

      {mode === "findings" ? (
        <section className="react-card">
          <PanelHeader title={t(lang, { en: "Finding explorer", ru: "Обзор находок" })} subtitle={t(lang, { en: "Searchable vulnerability evidence with pivots by host, service and report.", ru: "Поиск по evidence сканера с переходами по хостам, сервисам и отчетам." })} />
          <div className="react-table-wrap">
            <table className="react-table">
              <thead>
                <tr>
                  <th>{t(lang, { en: "Time", ru: "Время" })}</th>
                  <th>{t(lang, { en: "Report", ru: "Отчет" })}</th>
                  <th>{t(lang, { en: "Host", ru: "Хост" })}</th>
                  <th>{t(lang, { en: "Port", ru: "Порт" })}</th>
                  <th>{t(lang, { en: "Severity", ru: "Важность" })}</th>
                  <th>{t(lang, { en: "Service", ru: "Сервис" })}</th>
                  <th>CVE</th>
                  <th>{t(lang, { en: "Message", ru: "Сообщение" })}</th>
                </tr>
              </thead>
              <tbody>
                {findings.map((row: VulnFindingRow, index: number) => (
                  <tr key={`${row.ts}-${row.report_id}-${index}`}>
                    <td>{row.ts || "n/a"}</td>
                    <td>
                      <button type="button" className="react-inline-action" onClick={() => navigate(`/vuln/reports/${encodeURIComponent(String(row.report_id || ""))}`)}>
                        {row.report_id || "n/a"}
                      </button>
                    </td>
                    <td>
                      <button type="button" className="react-inline-action" onClick={() => setEntity("host", safeText(row.dst_ip || row.host_name || row.source, ""))}>
                        {safeText(row.dst_ip || row.host_name || row.source)}
                      </button>
                    </td>
                    <td>{row.dst_port || "n/a"}</td>
                    <td>{row.severity ? <SeverityBadge value={row.severity} /> : "n/a"}</td>
                    <td>
                      {row.service ? (
                        <button type="button" className="react-inline-action" onClick={() => setEntity("service", String(row.service))}>
                          {row.service}
                        </button>
                      ) : (
                        "n/a"
                      )}
                    </td>
                    <td>
                      {arrayOfStrings(row.cves).length ? (
                        <button type="button" className="react-inline-action" onClick={() => setEntity("cve", arrayOfStrings(row.cves)[0] || "")}>
                          {arrayOfStrings(row.cves).join(", ")}
                        </button>
                      ) : (
                        "n/a"
                      )}
                    </td>
                    <td className="react-cell-clamp">{row.message || "n/a"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </section>
      ) : null}

      {mode === "reports" ? (
        <>
        <section className="react-card">
          <PanelHeader
            title="OpenVAS report workspace"
            subtitle="Scanner reports are grouped by scanner, target coverage and import freshness before opening raw findings."
            actions={
              <div className="react-actions react-wrap">
                {canOperateVuln ? <button type="button" className="react-link-button" onClick={() => void importReports()}>Import latest</button> : null}
                {canOperateVuln ? <button type="button" className="react-link-button" onClick={() => void applyPolicies()}>Apply policies</button> : null}
              </div>
            }
          />
          <div className="react-grid react-grid-5">
            <StatCard label="Reports" value={reportSummaries.length} hint="Imported Greenbone/OpenVAS and supplemental reports." />
            <StatCard label="Scanners" value={reportCatalogStats.scanners} hint="Distinct scanner families represented in the catalog." />
            <StatCard label="Targets" value={reportCatalogStats.targets} hint="Unique targets referenced by imported reports." />
            <StatCard label="Findings" value={reportCatalogStats.findingsTotal.toLocaleString()} hint="Findings counted from report summaries when available." />
            <StatCard label="Newest" value={reportCatalogStats.newest ? formatTimestamp(reportCatalogStats.newest, "compact") : "n/a"} hint="Newest report timestamp in the current catalog." />
          </div>
        </section>
        <div className="react-split react-split-xl">
          <section className="react-card">
            <PanelHeader title={t(lang, { en: "Report catalog", ru: "Каталог отчетов" })} subtitle={t(lang, { en: "Imported scans and normalized vulnerability reports.", ru: "Импортированные сканы и нормализованные отчеты по уязвимостям." })} />
            <div className="react-list">
              {reportSummaries.map((item: ReportSummaryCard) => (
                <button
                  key={item.report_id}
                  type="button"
                  className={`react-card react-card-button ${reportId === item.report_id ? "active" : ""}`}
                  onClick={() => navigate(item.reportPath)}
                >
                  <strong>{item.report_id}</strong>
                  <span>{item.summary_message || t(lang, { en: "Imported vulnerability report", ru: "Импортированный отчет об уязвимостях" })}</span>
                  <span>{scannerLabel(item)} | {(item.targets || []).join(", ") || "no targets"}</span>
                  <div className="react-card-button-grid">
                    <span>Targets</span><strong>{(item.targets || []).length}</strong>
                    <span>Last seen</span><strong>{item.ts_last ? formatTimestamp(item.ts_last, "compact") : "n/a"}</strong>
                    <span>Source</span><strong>{String(item.scanner_source || item.scanner_family || "scanner")}</strong>
                  </div>
                </button>
              ))}
              {!reportSummaries.length ? <EmptyState message="No OpenVAS reports are imported yet." /> : null}
            </div>
          </section>
          <section className="react-card">
            <PanelHeader
              title={reportId || t(lang, { en: "Report detail", ru: "Детали отчета" })}
              subtitle={t(lang, { en: "Host, service, software and CVE-linked findings.", ru: "Находки, связанные с хостами, сервисами, ПО и CVE." })}
              actions={
                reportId ? (
                  <div className="react-actions react-wrap">
                    <Link className="react-link-button" to={`/events?q=${encodeURIComponent(`event_code = '${sqlLiteral(reportId)}'`)}`}>{t(lang, { en: "Open in Events", ru: "Открыть в событиях" })}</Link>
                    <Link className="react-link-button" to={`/vuln/findings?q=${encodeURIComponent(reportId)}`}>{t(lang, { en: "Findings", ru: "Находки" })}</Link>
                  </div>
                ) : null
              }
            />
            {!reportId ? (
              <EmptyState message={t(lang, { en: "Select a report from the catalog.", ru: "Выберите отчет в каталоге." })} />
            ) : reportDetailState.loading ? (
              <EmptyState message={t(lang, { en: "Loading selected report...", ru: "Загружаю выбранный отчет..." })} />
            ) : reportDetailState.error ? (
              <EmptyState message={reportDetailState.error} />
            ) : normalizedReportDetail ? (
              <div className="react-page">
                <DrawerFieldGrid>
                  <KeyValue label={t(lang, { en: "Summary", ru: "Сводка" })} value={normalizedReportDetail.summary_message || "n/a"} />
                  <KeyValue label={t(lang, { en: "Scanner", ru: "Сканер" })} value={scannerLabel(normalizedReportDetail)} />
                  <KeyValue label={t(lang, { en: "Targets", ru: "Цели" })} value={normalizedReportDetail.target_count || 0} />
                  <KeyValue label="CVEs" value={normalizedReportDetail.cves.join(", ") || "n/a"} />
                  <KeyValue label={t(lang, { en: "Ports", ru: "Порты" })} value={normalizedReportDetail.ports.join(", ") || "n/a"} />
                  <KeyValue label={t(lang, { en: "Findings", ru: "Находки" })} value={normalizedReportDetail.finding_count || 0} />
                </DrawerFieldGrid>

                <section className="react-card react-card-nested">
                  <PanelHeader title={t(lang, { en: "Targets", ru: "Цели" })} subtitle={t(lang, { en: "Hosts referenced by this report.", ru: "Хосты, фигурирующие в этом отчете." })} />
                  <div className="react-chip-row">
                    {normalizedReportDetail.targets.map((target: string) => (
                      <button key={target} type="button" className="react-chip" onClick={() => setEntity("host", target)}>
                        {target}
                      </button>
                    ))}
                  </div>
                </section>

                <section className="react-card react-card-nested">
                  <PanelHeader title={t(lang, { en: "Findings", ru: "Находки" })} subtitle={t(lang, { en: "Normalized report evidence with pivots.", ru: "Нормализованные evidence отчета с быстрыми переходами." })} />
                  <div className="react-table-wrap">
                    <table className="react-table">
                      <thead>
                        <tr>
                          <th>{t(lang, { en: "Host", ru: "Хост" })}</th>
                          <th>{t(lang, { en: "Port", ru: "Порт" })}</th>
                          <th>{t(lang, { en: "Service", ru: "Сервис" })}</th>
                          <th>CVE</th>
                          <th>{t(lang, { en: "Message", ru: "Сообщение" })}</th>
                        </tr>
                      </thead>
                      <tbody>
                        {normalizedReportDetail.findings.map((row: NormalizedReportDetail["findings"][number], index: number) => (
                          <tr key={`${row.host_name || row.dst_ip || index}-${index}`}>
                            <td>
                              <button type="button" className="react-inline-action" onClick={() => setEntity("host", safeText(row.host_name || row.dst_ip || row.target, ""))}>
                                {safeText(row.host_name || row.dst_ip || row.target)}
                              </button>
                            </td>
                            <td>{row.dst_port || row.port || "n/a"}</td>
                            <td>
                              {row.service ? (
                                <button type="button" className="react-inline-action" onClick={() => setEntity("service", String(row.service))}>
                                  {row.service}
                                </button>
                              ) : (
                                "n/a"
                              )}
                            </td>
                            <td>
                              {row.cves.length ? (
                                <button type="button" className="react-inline-action" onClick={() => setEntity("cve", row.cves[0] || "")}>
                                  {row.cves.join(", ")}
                                </button>
                              ) : (
                                "n/a"
                              )}
                            </td>
                            <td className="react-cell-clamp">{row.message || row.summary_message || "n/a"}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </section>
                <section className="react-card react-card-nested">
                  <PanelHeader
                    title={t(lang, { en: "External manager hand-off", ru: "Контракт для внешнего менеджера" })}
                    subtitle={t(lang, {
                      en: "How this report maps into the shared Vulnerability Manager import contract.",
                      ru: "Как этот отчет ложится в общий контракт импорта для внешнего Vulnerability Manager.",
                    })}
                  />
                  <DrawerFieldGrid>
                    <KeyValue label={t(lang, { en: "Contract version", ru: "Версия контракта" })} value={integrationContract.version || "vuln-import-v1"} />
                    <KeyValue label={t(lang, { en: "Entities", ru: "Сущности" })} value={(integrationContract.entities || []).length} />
                    <KeyValue label={t(lang, { en: "Transport paths", ru: "Транспортные пути" })} value={(integrationContract.transport_modes || []).map((item) => String(item)).join(", ") || "n/a"} />
                    <KeyValue label={t(lang, { en: "Templates", ru: "Шаблоны" })} value={(integrationContract.templates || []).map((item: VulnIntegrationTemplate) => item.title).join(", ") || "n/a"} />
                  </DrawerFieldGrid>
                  <div className="react-chip-row">
                    {(integrationContract.templates || []).map((item: VulnIntegrationTemplate) => (
                      <Link
                        key={item.id}
                        className="react-link-button"
                        to={`/builders?kind=integration&template=${encodeURIComponent(String(item.id || ""))}`}
                      >
                        {item.title}
                      </Link>
                    ))}
                  </div>
                </section>
              </div>
            ) : (
              <EmptyState message={t(lang, { en: "Report details are unavailable.", ru: "Детали отчета недоступны." })} />
            )}
          </section>
        </div>
        </>
      ) : null}

      <DrawerOverlay
        open={Boolean(selectedEntity)}
        title={selectedEntity ? `${vulnEntityTitle(lang, selectedEntity.kind)}: ${selectedEntity.value}` : "Entity"}
        subtitle={t(lang, { en: "Context, assets, reports and evidence for the selected entity.", ru: "Контекст, активы, отчеты и evidence для выбранной сущности." })}
        onClose={clearEntity}
      >
        {selectedEntity ? (
          <>
            <DrawerFieldGrid>
              <KeyValue label={t(lang, { en: "Entity", ru: "Сущность" })} value={selectedEntity.value} />
              <KeyValue label={t(lang, { en: "Kind", ru: "Тип" })} value={selectedEntity.kind} />
              <KeyValue label={t(lang, { en: "Findings", ru: "Находки" })} value={entitySummary.findings} />
              <KeyValue label={t(lang, { en: "Reports", ru: "Отчеты" })} value={entitySummary.reportIds.length} />
              <KeyValue label={t(lang, { en: "Hosts", ru: "Хосты" })} value={entitySummary.hosts.length} />
              <KeyValue label={t(lang, { en: "Ports", ru: "Порты" })} value={entitySummary.ports.join(", ") || "n/a"} />
            </DrawerFieldGrid>

            <div className="react-chip-row">
              <Link className="react-link-button" to={`/events?q=${encodeURIComponent(buildEventPivot(selectedEntity.kind, selectedEntity.value))}`} onClick={clearEntity}>
                {t(lang, { en: "Open related events", ru: "Открыть связанные события" })}
              </Link>
              <Link className="react-link-button" to={`/incidents?q=${encodeURIComponent(selectedEntity.value)}`} onClick={clearEntity}>
                {t(lang, { en: "Related incidents", ru: "Связанные инциденты" })}
              </Link>
              {relatedAssets[0] ? (
                <Link className="react-link-button" to={`/assets?q=${encodeURIComponent(relatedAssets[0].asset)}&view=inventory&focus=${encodeURIComponent(relatedAssets[0].asset)}`} onClick={clearEntity}>
                  {t(lang, { en: "Open asset", ru: "Открыть актив" })}
                </Link>
              ) : null}
            </div>

            {relatedAssets.length ? (
              <section className="react-card react-card-nested">
                <PanelHeader title={t(lang, { en: "Related assets", ru: "Связанные активы" })} subtitle={t(lang, { en: "CMDB assets matching hostnames and aliases.", ru: "CMDB-активы, совпавшие по имени хоста и alias." })} />
                <div className="react-list react-list-compact">
                  {relatedAssets.map((item: AssetRecord) => (
                    <Link
                      key={item.asset}
                      className="react-list-item"
                      to={`/assets?q=${encodeURIComponent(item.asset)}&view=inventory&focus=${encodeURIComponent(item.asset)}`}
                      onClick={clearEntity}
                    >
                      <strong>{item.asset}</strong>
                      <span>{item.cmdb_service || "unassigned service"} / {item.cmdb_owner || "no owner"}</span>
                      <span>{item.cmdb_criticality || "n/a"} / {item.last_seen || "n/a"}</span>
                    </Link>
                  ))}
                </div>
              </section>
            ) : null}

            <section className="react-card react-card-nested">
          <PanelHeader title={t(lang, { en: "Evidence", ru: "Доказательства" })} subtitle={t(lang, { en: "Recent findings tied to the selected entity.", ru: "Недавние находки, связанные с выбранной сущностью." })} />
              <div className="react-table-wrap">
                <table className="react-table">
                  <thead>
                    <tr>
                      <th>{t(lang, { en: "Time", ru: "Время" })}</th>
                      <th>{t(lang, { en: "Report", ru: "Отчет" })}</th>
                      <th>{t(lang, { en: "Host", ru: "Хост" })}</th>
                      <th>{t(lang, { en: "Service", ru: "Сервис" })}</th>
                      <th>CVE</th>
                      <th>{t(lang, { en: "Message", ru: "Сообщение" })}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {entitySummary.sample.map((row: VulnFindingRow, index: number) => (
                      <tr key={`${row.ts}-${row.report_id}-${index}`}>
                        <td>{row.ts || "n/a"}</td>
                        <td>{row.report_id || "n/a"}</td>
                        <td>{safeText(row.dst_ip || row.host_name || row.source)}</td>
                        <td>{row.service || "n/a"}</td>
                        <td>{arrayOfStrings(row.cves).join(", ") || "n/a"}</td>
                        <td className="react-cell-clamp">{row.message || "n/a"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>
          </>
        ) : (
          <EmptyState message={t(lang, { en: "Choose a host, service or CVE to inspect it.", ru: "Выберите хост, сервис или CVE для просмотра." })} />
        )}
      </DrawerOverlay>
      </div>
    </AsyncGate>
  );
}
