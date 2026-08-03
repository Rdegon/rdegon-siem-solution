import type {
  ActiveListImportResponse,
  ActiveListMutationResponse,
  ActiveListRecord,
  ActiveListsResponse,
  AccessGrantRecord,
  AccessGrantsResponse,
  AccessSystemsResponse,
  AssetCatalogResponse,
  AssetBindingOverrideRecord,
  AssetBindingOverridesResponse,
  AssetInventoryResponse,
  AuthPermissionInventoryResponse,
  AuthProvidersResponse,
  AuthMeResponse,
  AuthGovernanceResponse,
  BuilderDraftRecord,
  BuilderDraftsResponse,
  BuilderPublishResponse,
  BuilderTestResponse,
  BuilderValidationResponse,
  CaseDetailResponse,
  CaseMutationResponse,
  CaseRecord,
  CasesResponse,
  CollectorsInventoryResponse,
  CollectorDeploymentResponse,
  ConnectorDetailResponse,
  ConnectorListResponse,
  ConnectorRecord,
  ConnectorRunResponse,
  ConnectorsOverviewResponse,
  CorrelationPackDetailResponse,
  CorrelationPackRecord,
  CorrelationPacksResponse,
  CorrelationPackTestResponse,
  CertificationHealthResponse,
  ComplianceEvidencePackResponse,
  ContentBundleRecord,
  ContentBundlesResponse,
  DashboardDefinition,
  DashboardSummaryResponse,
  DashboardsRegistryResponse,
  DocsIndexResponse,
  DocumentDetailResponse,
  EnterpriseReleaseGatesResponse,
  EntitiesResponse,
  EntityDetailResponse,
  EventsFacetsResponse,
  EventsQueryResponse,
  HuntingCapabilitiesResponse,
  HuntingEventDetailResponse,
  HuntingFacetsResponse,
  HuntingQueryResponse,
  HuntingSavedSearchRecord,
  HuntingSavedSearchesResponse,
  GeoCountryDetailResponse,
  GeoSourcesResponse,
  GeoVpnResponse,
  GeneratedReportDetailResponse,
  GeneratedReportsResponse,
  RetroscanCapabilities,
  RetroscanCreateResponse,
  RetroscanRunDetailResponse,
  RetroscanRunsResponse,
  HostAccessProfileRecord,
  HostAccessProfilesResponse,
  HostRuntimeOverviewResponse,
  IncidentDetailResponse,
  IncidentHostActionResponse,
  IncidentListResponse,
  IncidentUpdateResponse,
  IncidentWorkflowResponse,
  RuleTestResponse,
  HealthOverviewResponse,
  IngestDlqResponse,
  IngestHeartbeatResponse,
  IngestOverviewResponse,
  IntegrationsCatalogResponse,
  KeycloakClientDetailResponse,
  KeycloakClientRecord,
  KeycloakClientsResponse,
  KeycloakGroupRecord,
  KeycloakGroupsResponse,
  KeycloakRoleRecord,
  KeycloakRolesResponse,
  KeycloakStatusResponse,
  KeycloakUserDetailResponse,
  KeycloakUserRecord,
  KeycloakUsersResponse,
  PlaybookDetailResponse,
  PlaybookSummary,
  PlatformStatusResponse,
  ProxmoxFleetResponse,
  RecordRiskSignalResponse,
  ReplayDlqResponse,
  ResourceCatalogRecord,
  ResourceCatalogResponse,
  ResourceLifecycleMutationResponse,
  ResourcePackageImportResponse,
  ResourcePublishResponse,
  ResourceValidationResponse,
  ResourceVersionCompareResponse,
  ResourceVersionsResponse,
  RemoteAccessProfileRecord,
  RemoteAccessStateResponse,
  XuiStateResponse,
  ReportTemplateRecord,
  ReportTemplatesResponse,
  ReportRunCreateResponse,
  ReportSchedule,
  ReportingCapabilities,
  ResponseAnalyticsResponse,
  ResponseActionsResponse,
  ResponseActionRecord,
  ResponseDlqResponse,
  ResponseExecutionRecord,
  ResponseExecutionMutationResponse,
  ResponseExecutionsResponse,
  SavedSearchesResponse,
  SavedSearchMutationResponse,
  SecretsRequiredResponse,
  SecurityServiceDetailResponse,
  SecurityServiceControlResponse,
  SecurityControlMutationResponse,
  SecurityServicesResponse,
  ServiceLifecycleAction,
  ServiceLifecycleActionResponse,
  ServiceLifecycleInstance,
  ServiceLifecycleRegistryResponse,
  ServiceAccountDetailResponse,
  ServiceAccountsResponse,
  ServiceAccountSummary,
  ServiceAccountTokenIssueResponse,
  ServiceAccountTokenRevokeResponse,
  SourceDiscoveryResponse,
  SourceDiscoveryScanResponse,
  SourceMonitoringPoliciesResponse,
  SourceMonitoringPolicyRecord,
  SourceOnboardingExecutionResponse,
  SourceOnboardingPreparedResponse,
  SourceOnboardingVerificationResponse,
  SourcesInventoryResponse,
  ThreatIntelGeoDetailResponse,
  ThreatIntelOverviewResponse,
  LocalUserDetailResponse,
  LocalUserRecord,
  LocalUsersResponse,
  NetworkTopologyResponse,
  TopologyLayoutResponse,
  VulnCveRow,
  VulnExposureWorkbenchResponse,
  VulnFindingRow,
  VulnHostRow,
  VulnIntegrationContractResponse,
  VulnMaturityResponse,
  VulnOverviewResponse,
  VulnPolicyApplyResponse,
  VulnReportDetailResponse,
  VulnReportsResponse,
  VulnRuntimeResponse,
  VulnRowsResponse,
  VulnSoftwareRow,
  VulnSyncResponse,
  UnifiedRuleMutationResponse,
  UnifiedRuleRecord,
  UnifiedRulesResponse,
  RuntimeBlob,
  KumaResourcesResponse,
  KumaStatusResponse,
  BreakGlassResponse,
} from "./types";

export type BootstrapResponse = {
  user: {
    username: string;
    role: string;
    permissions: string[];
    principal_type: string;
    service_account_id: string;
    auth_mechanism: string;
    issuer?: string;
    groups?: string[];
    break_glass?: boolean;
    session_expires_ts?: string;
    section_access?: string[];
    system_grants?: RuntimeBlob[];
  };
  ui_lang: "ru" | "en";
  theme: string;
  labels: Record<string, string>;
};

export type TenantScopeResponse = {
  available: Array<{
    id: string;
    name: string;
    description?: string;
    source_count: number;
    incident_count: number;
  }>;
  default: string[];
  generated_ts: string;
  issues?: string[];
};

type QueryValue = string | number | boolean | undefined | null;

let activeTenantScope: string[] = [];

export function setApiTenantScope(tenantIds: string[]) {
  activeTenantScope = [...new Set(tenantIds.map((item) => String(item || "").trim()).filter(Boolean))];
}

function scopedHeaders(headers: Record<string, string>) {
  if (!activeTenantScope.length) return headers;
  return {
    ...headers,
    "X-SIEM-Tenant-Scope": activeTenantScope.join(","),
  };
}

function toQuery(params: Record<string, QueryValue>) {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === null || value === "") continue;
    search.set(key, String(value));
  }
  const text = search.toString();
  return text ? `?${text}` : "";
}

function readCookie(name: string) {
  if (typeof document === "undefined") return "";
  const prefix = `${name}=`;
  return document.cookie
    .split(";")
    .map((item) => item.trim())
    .find((item) => item.startsWith(prefix))
    ?.slice(prefix.length) || "";
}

function buildMutationHeaders(contentType = "application/json") {
  const headers: Record<string, string> = {
    Accept: "application/json",
  };
  if (contentType) {
    headers["Content-Type"] = contentType;
  }
  const csrfToken = readCookie("csrf_token");
  if (csrfToken) {
    headers["X-CSRF-Token"] = decodeURIComponent(csrfToken);
  }
  return headers;
}

async function parseResponse<T>(response: Response): Promise<T> {
  if (response.redirected && response.url.includes("/auth/login")) {
    window.location.assign(response.url);
    throw new Error("Redirecting to login");
  }
  const contentType = response.headers.get("content-type") || "";
  const text = await response.text();
  if (contentType.includes("text/html") && /\/auth\/login(?:$|\?)/.test(response.url)) {
    window.location.assign(response.url);
    throw new Error("Redirecting to login");
  }
  let payload: unknown = {};
  if (text) {
    try {
      payload = JSON.parse(text);
    } catch {
      payload = { error: text };
    }
  }
  const payloadRecord =
    payload && typeof payload === "object" ? (payload as Record<string, unknown>) : {};
  if (!response.ok) {
    const message = typeof payloadRecord.error === "string" ? payloadRecord.error : `Request failed: ${response.status}`;
    throw new Error(message);
  }
  return payload as T;
}

async function getJson<T>(url: string): Promise<T> {
  const controller = new AbortController();
  const timeoutMs = 15_000;
  const timeout = globalThis.setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, {
      credentials: "include",
      headers: scopedHeaders({
        Accept: "application/json",
      }),
      signal: controller.signal,
    });
    return await parseResponse<T>(response);
  } catch (error) {
    if (controller.signal.aborted) {
      throw new Error(`Request timed out after ${Math.round(timeoutMs / 1000)} seconds`);
    }
    throw error;
  } finally {
    globalThis.clearTimeout(timeout);
  }
}

async function postJson<T>(url: string, body: Record<string, unknown>): Promise<T> {
  const response = await fetch(url, {
    method: "POST",
    credentials: "include",
    headers: scopedHeaders(buildMutationHeaders()),
    body: JSON.stringify(body),
  });
  return parseResponse<T>(response);
}

async function putJson<T>(url: string, body: Record<string, unknown>): Promise<T> {
  const response = await fetch(url, {
    method: "PUT",
    credentials: "include",
    headers: scopedHeaders(buildMutationHeaders()),
    body: JSON.stringify(body),
  });
  return parseResponse<T>(response);
}

async function deleteJson<T>(url: string): Promise<T> {
  const response = await fetch(url, {
    method: "DELETE",
    credentials: "include",
    headers: scopedHeaders(buildMutationHeaders()),
  });
  return parseResponse<T>(response);
}

async function patchJson<T>(url: string, body: Record<string, unknown>): Promise<T> {
  const response = await fetch(url, {
    method: "PATCH",
    credentials: "include",
    headers: scopedHeaders(buildMutationHeaders()),
    body: JSON.stringify(body),
  });
  return parseResponse<T>(response);
}

async function deleteJsonBody<T>(url: string, body: Record<string, unknown>): Promise<T> {
  const response = await fetch(url, {
    method: "DELETE",
    credentials: "include",
    headers: scopedHeaders(buildMutationHeaders()),
    body: JSON.stringify(body),
  });
  return parseResponse<T>(response);
}

async function downloadFile(url: string): Promise<{ filename: string }> {
  const response = await fetch(url, {
    credentials: "include",
    headers: scopedHeaders({ Accept: "application/json, text/csv" }),
  });
  if (!response.ok) await parseResponse<never>(response);
  const disposition = response.headers.get("content-disposition") || "";
  const filename = disposition.match(/filename="?([^";]+)"?/i)?.[1] || "download";
  const objectUrl = URL.createObjectURL(await response.blob());
  const link = document.createElement("a");
  link.href = objectUrl;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(objectUrl);
  return { filename };
}

function mutationKey(action: string, resourceId = "") {
  const random = typeof crypto.randomUUID === "function"
    ? crypto.randomUUID()
    : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
  return `ui:${action}:${resourceId || "package"}:${random}`;
}

function resourceLifecycleHeaders(action: string, resourceId = "", contentType = "application/json") {
  const tenantHeaders: Record<string, string> = {};
  if (activeTenantScope.length === 1) tenantHeaders["X-Tenant-Scope"] = activeTenantScope[0];
  return scopedHeaders({
    ...buildMutationHeaders(contentType),
    ...tenantHeaders,
    "Idempotency-Key": mutationKey(action, resourceId),
  });
}

async function getResourceLifecycleJson<T>(url: string): Promise<T> {
  const headers: Record<string, string> = { Accept: "application/json" };
  if (activeTenantScope.length === 1) headers["X-Tenant-Scope"] = activeTenantScope[0];
  const response = await fetch(url, {
    credentials: "include",
    headers: scopedHeaders(headers),
  });
  return parseResponse<T>(response);
}

async function saveDownload(response: Response): Promise<{ filename: string }> {
  if (!response.ok) await parseResponse<never>(response);
  const disposition = response.headers.get("content-disposition") || "";
  const filename = disposition.match(/filename="?([^";]+)"?/i)?.[1] || "sentinel-resources.json";
  const objectUrl = URL.createObjectURL(await response.blob());
  const link = document.createElement("a");
  link.href = objectUrl;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(objectUrl);
  return { filename };
}

export const api = {
  bootstrap: () => getJson<BootstrapResponse>("/api/ui/bootstrap"),
  tenantScope: () => getJson<TenantScopeResponse>("/api/ui/tenants"),
  resourceCatalog: (params: { kind?: string; include_runtime?: boolean } = {}) =>
    getJson<ResourceCatalogResponse>(`/api/resources/catalog${toQuery(params)}`),
  resourceDetail: (resourceId: string) =>
    getJson<ResourceCatalogRecord>(`/api/resources/catalog/${encodeURIComponent(resourceId)}`),
  saveResource: (body: Record<string, unknown>) =>
    postJson<ResourceCatalogRecord>("/api/resources/catalog", body),
  validateResource: (resourceId: string) =>
    postJson<ResourceValidationResponse>(`/api/resources/catalog/${encodeURIComponent(resourceId)}/validate`, {}),
  publishResource: (resourceId: string) =>
    postJson<ResourcePublishResponse>(`/api/resources/catalog/${encodeURIComponent(resourceId)}/publish`, {}),
  resourceDeployment: (resourceId: string) =>
    getJson<CollectorDeploymentResponse>(`/api/resources/catalog/${encodeURIComponent(resourceId)}/deployment`),
  duplicateResource: async (resourceId: string, body: { name?: string } = {}) => {
    const response = await fetch(`/api/resources/catalog/${encodeURIComponent(resourceId)}/duplicate`, {
      method: "POST",
      credentials: "include",
      headers: resourceLifecycleHeaders("duplicate", resourceId),
      body: JSON.stringify(body),
    });
    return parseResponse<ResourceLifecycleMutationResponse>(response);
  },
  resourceVersions: (resourceId: string) =>
    getResourceLifecycleJson<ResourceVersionsResponse>(`/api/resources/catalog/${encodeURIComponent(resourceId)}/versions`),
  compareResourceVersions: (resourceId: string, fromVersion: number, toVersion: number) =>
    getResourceLifecycleJson<ResourceVersionCompareResponse>(
      `/api/resources/catalog/${encodeURIComponent(resourceId)}/versions/compare${toQuery({ from_version: fromVersion, to_version: toVersion })}`,
    ),
  rollbackResource: async (resourceId: string, body: { target_version: number; expected_revision: number }) => {
    const response = await fetch(`/api/resources/catalog/${encodeURIComponent(resourceId)}/rollback`, {
      method: "POST",
      credentials: "include",
      headers: resourceLifecycleHeaders("rollback", resourceId),
      body: JSON.stringify(body),
    });
    return parseResponse<ResourceLifecycleMutationResponse>(response);
  },
  deleteResourceDraft: async (resourceId: string, expectedRevision: number) => {
    const response = await fetch(`/api/resources/catalog/${encodeURIComponent(resourceId)}`, {
      method: "DELETE",
      credentials: "include",
      headers: resourceLifecycleHeaders("delete-draft", resourceId),
      body: JSON.stringify({ expected_revision: expectedRevision }),
    });
    return parseResponse<ResourceLifecycleMutationResponse>(response);
  },
  exportResourcePackage: async (resourceIds: string[]) => {
    const response = await fetch("/api/resources/catalog/export", {
      method: "POST",
      credentials: "include",
      headers: resourceLifecycleHeaders("export-package"),
      body: JSON.stringify({ resource_ids: resourceIds }),
    });
    return saveDownload(response);
  },
  importResourcePackage: async (file: File) => {
    const form = new FormData();
    form.append("package", file);
    const response = await fetch("/api/resources/catalog/import", {
      method: "POST",
      credentials: "include",
      headers: resourceLifecycleHeaders("import-package", "", ""),
      body: form,
    });
    return parseResponse<ResourcePackageImportResponse>(response);
  },
  kumaStatus: () => getJson<KumaStatusResponse>("/api/integrations/kuma/status"),
  kumaResources: (params: { page?: number; kind?: string[]; tenant_id?: string; name?: string } = {}) => {
    const search = new URLSearchParams();
    if (params.page) search.set("page", String(params.page));
    for (const kind of params.kind || []) search.append("kind", kind);
    if (params.tenant_id) search.set("tenant_id", params.tenant_id);
    if (params.name) search.set("name", params.name);
    const query = search.toString();
    return getJson<KumaResourcesResponse>(`/api/integrations/kuma/resources${query ? `?${query}` : ""}`);
  },
  importKumaPackage: async (file: File, password: string, tenantId = "", actions: Record<string, number> = {}) => {
    const form = new FormData();
    form.append("package", file);
    form.append("password", password);
    form.append("tenant_id", tenantId);
    form.append("actions_json", JSON.stringify(actions));
    const response = await fetch("/api/integrations/kuma/import", {
      method: "POST",
      credentials: "include",
      headers: scopedHeaders(buildMutationHeaders("")),
      body: form,
    });
    return parseResponse<RuntimeBlob>(response);
  },
  exportKumaResources: async (resourceIds: string[], password: string, tenantId = "") => {
    const response = await fetch("/api/integrations/kuma/export", {
      method: "POST",
      credentials: "include",
      headers: scopedHeaders(buildMutationHeaders()),
      body: JSON.stringify({ resource_ids: resourceIds, password, tenant_id: tenantId }),
    });
    if (!response.ok) {
      await parseResponse<RuntimeBlob>(response);
    }
    return {
      blob: await response.blob(),
      fileId: response.headers.get("X-KUMA-File-ID") || "",
    };
  },
  authMe: () => getJson<AuthMeResponse>("/api/auth/me"),
  authProviders: () => getJson<AuthProvidersResponse>("/api/auth/providers"),
  authGovernance: () => getJson<AuthGovernanceResponse>("/api/auth/governance"),
  authPermissions: () => getJson<AuthPermissionInventoryResponse>("/api/auth/permissions"),
  accessSystems: (params: { grantable_only?: boolean } = {}) =>
    getJson<AccessSystemsResponse>(`/api/auth/access-systems${toQuery(params)}`),
  accessGrants: (params: { principal_kind?: string; principal_id?: string; include_disabled?: boolean } = {}) =>
    getJson<AccessGrantsResponse>(`/api/auth/access-grants${toQuery(params)}`),
  saveAccessGrant: (body: Record<string, unknown>) =>
    postJson<AccessGrantRecord>("/api/auth/access-grants", body),
  updateAccessGrant: (grantId: string, body: Record<string, unknown>) =>
    postJson<AccessGrantRecord>(`/api/auth/access-grants/${encodeURIComponent(grantId)}`, body),
  deleteAccessGrant: async (grantId: string) => {
    const response = await fetch(`/api/auth/access-grants/${encodeURIComponent(grantId)}`, {
      method: "DELETE",
      credentials: "include",
      headers: scopedHeaders(buildMutationHeaders("")),
    });
    return parseResponse<AccessGrantRecord>(response);
  },
  keycloakStatus: () => getJson<KeycloakStatusResponse>("/api/auth/keycloak/status"),
  keycloakUsers: (params: { search?: string; limit?: number } = {}) =>
    getJson<KeycloakUsersResponse>(`/api/auth/keycloak/users${toQuery(params)}`),
  keycloakUserDetail: (userId: string) =>
    getJson<KeycloakUserDetailResponse>(`/api/auth/keycloak/users/${encodeURIComponent(userId)}`),
  createKeycloakUser: (body: Record<string, unknown>) =>
    postJson<KeycloakUserRecord>("/api/auth/keycloak/users", body),
  updateKeycloakUser: (userId: string, body: Record<string, unknown>) =>
    postJson<KeycloakUserRecord>(`/api/auth/keycloak/users/${encodeURIComponent(userId)}`, body),
  deleteKeycloakUser: async (userId: string) => {
    const response = await fetch(`/api/auth/keycloak/users/${encodeURIComponent(userId)}`, {
      method: "DELETE",
      credentials: "include",
      headers: scopedHeaders(buildMutationHeaders("")),
    });
    return parseResponse<RuntimeBlob>(response);
  },
  setKeycloakUserPassword: (userId: string, body: Record<string, unknown>) =>
    postJson<KeycloakUserRecord>(`/api/auth/keycloak/users/${encodeURIComponent(userId)}/password`, body),
  setKeycloakUserGroups: (userId: string, body: Record<string, unknown>) =>
    postJson<KeycloakUserRecord>(`/api/auth/keycloak/users/${encodeURIComponent(userId)}/groups`, body),
  setKeycloakUserRoles: (userId: string, body: Record<string, unknown>) =>
    postJson<KeycloakUserRecord>(`/api/auth/keycloak/users/${encodeURIComponent(userId)}/roles`, body),
  keycloakGroups: () => getJson<KeycloakGroupsResponse>("/api/auth/keycloak/groups"),
  saveKeycloakGroup: (body: Record<string, unknown>) =>
    postJson<KeycloakGroupRecord>("/api/auth/keycloak/groups", body),
  updateKeycloakGroup: (groupId: string, body: Record<string, unknown>) =>
    postJson<KeycloakGroupRecord>(`/api/auth/keycloak/groups/${encodeURIComponent(groupId)}`, body),
  keycloakRoles: () => getJson<KeycloakRolesResponse>("/api/auth/keycloak/roles"),
  saveKeycloakRole: (body: Record<string, unknown>) =>
    postJson<KeycloakRoleRecord>("/api/auth/keycloak/roles", body),
  updateKeycloakRole: (roleName: string, body: Record<string, unknown>) =>
    postJson<KeycloakRoleRecord>(`/api/auth/keycloak/roles/${encodeURIComponent(roleName)}`, body),
  keycloakClients: () => getJson<KeycloakClientsResponse>("/api/auth/keycloak/clients"),
  keycloakClientDetail: (clientId: string) =>
    getJson<KeycloakClientDetailResponse>(`/api/auth/keycloak/clients/${encodeURIComponent(clientId)}`),
  saveKeycloakClient: (body: Record<string, unknown>) =>
    postJson<KeycloakClientRecord>("/api/auth/keycloak/clients", body),
  updateKeycloakClient: (clientId: string, body: Record<string, unknown>) =>
    postJson<KeycloakClientRecord>(`/api/auth/keycloak/clients/${encodeURIComponent(clientId)}`, body),
  rotateKeycloakClientSecret: (clientId: string) =>
    postJson<RuntimeBlob>(`/api/auth/keycloak/clients/${encodeURIComponent(clientId)}/secret/rotate`, {}),
  authUsers: (params: { include_disabled?: boolean } = {}) =>
    getJson<LocalUsersResponse>(`/api/auth/users${toQuery(params)}`),
  authUserDetail: (username: string) =>
    getJson<LocalUserDetailResponse>(`/api/auth/users/${encodeURIComponent(username)}`),
  saveLocalUser: (body: Record<string, unknown>) => postJson<LocalUserRecord>("/api/auth/users", body),
  setLocalUserPassword: (username: string, body: Record<string, unknown>) =>
    postJson<LocalUserRecord>(`/api/auth/users/${encodeURIComponent(username)}/password`, body),
  deleteLocalUser: async (username: string) => {
    const response = await fetch(`/api/auth/users/${encodeURIComponent(username)}`, {
      method: "DELETE",
      credentials: "include",
      headers: scopedHeaders(buildMutationHeaders("")),
    });
    return parseResponse<LocalUserRecord>(response);
  },
  serviceAccounts: () => getJson<ServiceAccountsResponse>("/api/auth/service-accounts"),
  serviceAccountDetail: (serviceAccountId: string) =>
    getJson<ServiceAccountDetailResponse>(`/api/auth/service-accounts/${encodeURIComponent(serviceAccountId)}`),
  saveServiceAccount: (body: Record<string, unknown>) => postJson<ServiceAccountSummary>("/api/auth/service-accounts", body),
  deleteServiceAccount: async (serviceAccountId: string) => {
    const response = await fetch(`/api/auth/service-accounts/${encodeURIComponent(serviceAccountId)}`, {
      method: "DELETE",
      credentials: "include",
      headers: scopedHeaders(buildMutationHeaders("")),
    });
    return parseResponse<ServiceAccountSummary>(response);
  },
  issueServiceAccountToken: (serviceAccountId: string, body: Record<string, unknown>) =>
    postJson<ServiceAccountTokenIssueResponse>(`/api/auth/service-accounts/${encodeURIComponent(serviceAccountId)}/tokens`, body),
  rotateServiceAccountToken: (serviceAccountId: string, body: Record<string, unknown>) =>
    postJson<ServiceAccountTokenIssueResponse & RuntimeBlob>(`/api/auth/service-accounts/${encodeURIComponent(serviceAccountId)}/rotate`, body),
  revokeServiceAccountToken: (serviceAccountId: string, tokenId: string) =>
    postJson<ServiceAccountTokenRevokeResponse>(`/api/auth/service-accounts/${encodeURIComponent(serviceAccountId)}/tokens/${encodeURIComponent(tokenId)}/revoke`, {}),
  breakGlassSessions: (params: { active_only?: boolean; limit?: number } = {}) =>
    getJson<BreakGlassResponse>(`/api/auth/break-glass${toQuery(params)}`),
  mutateBreakGlass: (body: Record<string, unknown>) =>
    postJson<RuntimeBlob>("/api/auth/break-glass", body),
  dashboard: (params: { window?: string; from_ts?: string; to_ts?: string; bucket_minutes?: number; recent_limit?: number } = {}) =>
    getJson<DashboardSummaryResponse>(`/api/dashboard/summary${toQuery(params)}`),
  dashboards: () => getJson<DashboardsRegistryResponse>("/api/dashboards"),
  saveDashboard: (body: Record<string, unknown>) => postJson<DashboardDefinition>("/api/dashboards", body),
  deleteDashboard: async (dashboardId: string) => {
    const response = await fetch(`/api/dashboards/${encodeURIComponent(dashboardId)}`, {
      method: "DELETE",
      credentials: "include",
      headers: scopedHeaders(buildMutationHeaders("")),
    });
    return parseResponse<Record<string, unknown>>(response);
  },
  docsIndex: () => getJson<DocsIndexResponse>("/api/docs"),
  docDetail: (name: string) => getJson<DocumentDetailResponse>(`/api/docs/${encodeURIComponent(name)}`),
  playbooks: () => getJson<PlaybookSummary[]>("/api/playbooks"),
  playbookDetail: (slug: string) => getJson<PlaybookDetailResponse>(`/api/playbooks/${encodeURIComponent(slug)}`),
  reports: () => getJson<VulnReportsResponse>("/api/reports"),
  reportDetail: (reportId: string) => getJson<VulnReportDetailResponse>(`/api/reports/${encodeURIComponent(reportId)}`),
  reportingCapabilities: () => getJson<ReportingCapabilities>("/api/reporting/capabilities"),
  reportTemplates: () => getJson<ReportTemplatesResponse>("/api/reporting/templates"),
  saveReportTemplate: (body: Record<string, unknown>) =>
    postJson<ReportTemplateRecord>("/api/reporting/templates", body),
  deleteReportTemplate: async (templateId: string) => {
    const response = await fetch(`/api/reporting/templates/${encodeURIComponent(templateId)}`, {
      method: "DELETE",
      credentials: "include",
      headers: scopedHeaders(buildMutationHeaders("")),
    });
    return parseResponse<{ deleted: boolean; id: string }>(response);
  },
  updateReportSchedule: async (templateId: string, body: Partial<ReportSchedule>) => {
    const response = await fetch(`/api/reporting/templates/${encodeURIComponent(templateId)}/schedule`, {
      method: "PATCH",
      credentials: "include",
      headers: scopedHeaders(buildMutationHeaders()),
      body: JSON.stringify(body),
    });
    return parseResponse<ReportTemplateRecord>(response);
  },
  generatedReports: (params: { limit?: number } = {}) =>
    getJson<GeneratedReportsResponse>(`/api/reporting/runs${toQuery(params)}`),
  generatedReportDetail: (runId: string) =>
    getJson<GeneratedReportDetailResponse>(`/api/reporting/runs/${encodeURIComponent(runId)}`),
  runReportTemplate: (templateId: string, body: Record<string, unknown> = {}) =>
    postJson<ReportRunCreateResponse>(`/api/reporting/templates/${encodeURIComponent(templateId)}/run`, body),
  retroscanCapabilities: () => getJson<RetroscanCapabilities>("/api/retroscan/capabilities"),
  retroscanRuns: (params: { limit?: number; status?: string } = {}) =>
    getJson<RetroscanRunsResponse>(`/api/retroscan/runs${toQuery(params)}`),
  retroscanRunDetail: (runId: string) =>
    getJson<RetroscanRunDetailResponse>(`/api/retroscan/runs/${encodeURIComponent(runId)}`),
  createRetroscan: (body: Record<string, unknown>) =>
    postJson<RetroscanCreateResponse>("/api/retroscan/runs", body),
  cancelRetroscan: (runId: string) =>
    postJson<RetroscanRunDetailResponse>(`/api/retroscan/runs/${encodeURIComponent(runId)}/cancel`, {}),
  vulnOverview: (params: { days?: number; limit?: number } = {}) =>
    getJson<VulnOverviewResponse>(`/api/vuln/overview${toQuery(params)}`),
  vulnRuntime: (params: { days?: number } = {}) =>
    getJson<VulnRuntimeResponse>(`/api/vuln/runtime${toQuery(params)}`),
  vulnMaturity: (params: { days?: number; limit?: number } = {}) =>
    getJson<VulnMaturityResponse>(`/api/vuln/maturity${toQuery(params)}`),
  vulnApplyPolicies: (body: Record<string, unknown>) =>
    postJson<VulnPolicyApplyResponse>("/api/vuln/policies/apply", body),
  vulnWorkbench: (params: { days?: number; limit?: number } = {}) =>
    getJson<VulnExposureWorkbenchResponse>(`/api/vuln/workbench${toQuery(params)}`),
  vulnSyncIntelligence: (body: Record<string, unknown>) =>
    postJson<RuntimeBlob>("/api/vuln/intelligence/sync", body),
  vulnApplyExposure: (body: Record<string, unknown>) =>
    postJson<VulnPolicyApplyResponse>("/api/vuln/exposure/apply", body),
  vulnStartScans: (body: { asset_ids: string[]; limit?: number }) =>
    postJson<VulnSyncResponse>("/api/vuln/scans/start", body),
  vulnSync: (body: Record<string, unknown>) => postJson<VulnSyncResponse>("/api/vuln/sync", body),
  vulnImport: (body: Record<string, unknown>) => postJson<VulnSyncResponse>("/api/vuln/import", body),
  vulnIntegrationContract: () => getJson<VulnIntegrationContractResponse>("/api/vuln/integration-contract"),
  vulnHosts: (params: { q?: string; days?: number; limit?: number } = {}) =>
    getJson<VulnRowsResponse<VulnHostRow>>(`/api/vuln/hosts${toQuery(params)}`),
  vulnSoftware: (params: { q?: string; days?: number; limit?: number } = {}) =>
    getJson<VulnRowsResponse<VulnSoftwareRow>>(`/api/vuln/software${toQuery(params)}`),
  vulnCves: (params: { q?: string; days?: number; limit?: number } = {}) =>
    getJson<VulnRowsResponse<VulnCveRow>>(`/api/vuln/cves${toQuery(params)}`),
  vulnFindings: (params: { q?: string; days?: number; limit?: number } = {}) =>
    getJson<VulnRowsResponse<VulnFindingRow>>(`/api/vuln/findings${toQuery(params)}`),
  assetCatalog: () => getJson<AssetCatalogResponse>("/api/assets/catalog"),
  assetInventory: (params: { hours?: number; limit?: number } = {}) =>
    getJson<AssetInventoryResponse>(`/api/assets/inventory${toQuery(params)}`),
  assetBindingOverrides: (params: { scope?: string; include_disabled?: boolean; limit?: number } = {}) =>
    getJson<AssetBindingOverridesResponse>(`/api/assets/binding-overrides${toQuery(params)}`),
  saveAssetBindingOverride: (body: Record<string, unknown>) =>
    postJson<AssetBindingOverrideRecord>("/api/assets/binding-overrides", body),
  updateAssetBindingOverride: (overrideId: string, body: Record<string, unknown>) =>
    postJson<AssetBindingOverrideRecord>(`/api/assets/binding-overrides/${encodeURIComponent(overrideId)}`, body),
  deleteAssetBindingOverride: async (overrideId: string) => {
    const response = await fetch(`/api/assets/binding-overrides/${encodeURIComponent(overrideId)}`, {
      method: "DELETE",
      credentials: "include",
      headers: scopedHeaders(buildMutationHeaders("")),
    });
    return parseResponse<AssetBindingOverrideRecord>(response);
  },
  sourcesInventory: (params: { hours?: number; limit?: number } = {}) =>
    getJson<SourcesInventoryResponse>(`/api/sources${toQuery(params)}`),
  sourcePolicies: () =>
    getJson<SourceMonitoringPoliciesResponse>("/api/sources/policies"),
  saveSourcePolicy: (body: Record<string, unknown>) =>
    postJson<SourceMonitoringPolicyRecord>("/api/sources/policies", body),
  deleteSourcePolicy: async (policyId: string) => {
    const response = await fetch(`/api/sources/policies/${encodeURIComponent(policyId)}`, {
      method: "DELETE",
      credentials: "include",
      headers: scopedHeaders(buildMutationHeaders("")),
    });
    return parseResponse<{ deleted: boolean; id: string }>(response);
  },
  proxmoxFleet: (params: { limit?: number } = {}) =>
    getJson<ProxmoxFleetResponse>(`/api/sources/proxmox-fleet${toQuery(params)}`),
  syncProxmoxFleet: () => postJson<ProxmoxFleetResponse>("/api/sources/proxmox-fleet/sync", {}),
  sourceDiscovery: (params: { limit?: number } = {}) =>
    getJson<SourceDiscoveryResponse>(`/api/sources/discovery${toQuery(params)}`),
  networkTopology: (params: { hours?: number; limit?: number } = {}) =>
    getJson<NetworkTopologyResponse>(`/api/topology/network${toQuery(params)}`),
  topologyLayout: (workspace = "network") =>
    getJson<TopologyLayoutResponse>(`/api/topology/layout${toQuery({ workspace })}`),
  saveTopologyLayout: (body: Record<string, unknown>) =>
    putJson<TopologyLayoutResponse>("/api/topology/layout", body),
  hostAccessProfiles: (params: { limit?: number; host_id?: string; ip?: string } = {}) =>
    getJson<HostAccessProfilesResponse>(`/api/topology/host-access${toQuery(params)}`),
  saveHostAccessProfile: (body: Record<string, unknown>) =>
    postJson<HostAccessProfileRecord>("/api/topology/host-access", body),
  deleteHostAccessProfile: async (profileId: string) => {
    const response = await fetch(`/api/topology/host-access/${encodeURIComponent(profileId)}`, {
      method: "DELETE",
      credentials: "include",
      headers: scopedHeaders(buildMutationHeaders("")),
    });
    return parseResponse<HostAccessProfileRecord>(response);
  },
  scanSourceDiscovery: (body: Record<string, unknown>) =>
    postJson<SourceDiscoveryScanResponse>("/api/sources/discovery/scan", body),
  prepareSourceOnboarding: (candidateId: string, body: Record<string, unknown> = {}) =>
    postJson<SourceOnboardingPreparedResponse>(`/api/sources/discovery/${encodeURIComponent(candidateId)}/prepare`, body),
  executeSourceOnboarding: (jobId: string, body: Record<string, unknown>) =>
    postJson<SourceOnboardingExecutionResponse>(`/api/sources/discovery/jobs/${encodeURIComponent(jobId)}/execute`, body),
  verifySourceOnboarding: (jobId: string) =>
    postJson<SourceOnboardingVerificationResponse>(`/api/sources/discovery/jobs/${encodeURIComponent(jobId)}/verify`, {}),
  sourceOnboardingPackageUrl: (jobId: string) =>
    `/api/sources/discovery/jobs/${encodeURIComponent(jobId)}/package`,
  collectorsInventory: (params: { hours?: number } = {}) =>
    getJson<CollectorsInventoryResponse>(`/api/collectors${toQuery(params)}`),
  integrationsCatalog: () => getJson<IntegrationsCatalogResponse>("/api/integrations/catalog"),
  geoSources: (params: { hours?: number; limit?: number } = {}) =>
    getJson<GeoSourcesResponse>(`/api/geo/sources${toQuery(params)}`),
  geoCountryDetail: (country: string, params: { kind?: "source" | "vpn"; hours?: number; limit?: number } = {}) =>
    getJson<GeoCountryDetailResponse>(`/api/geo/countries/${encodeURIComponent(country)}${toQuery(params)}`),
  geoIpDetail: (ip: string, params: { hours?: number } = {}) =>
    getJson<ThreatIntelGeoDetailResponse>(`/api/geo/ip/${encodeURIComponent(ip)}${toQuery(params)}`),
  geoVpn: (params: { hours?: number; limit?: number } = {}) =>
    getJson<GeoVpnResponse>(`/api/geo/vpn${toQuery(params)}`),
  threatIntelOverview: (params: { hours?: number; limit?: number } = {}) =>
    getJson<ThreatIntelOverviewResponse>(`/api/threat-intel/overview${toQuery(params)}`),
  builderDrafts: () => getJson<BuilderDraftsResponse>("/api/builders/drafts"),
  saveBuilderDraft: (body: Record<string, unknown>) => postJson<BuilderDraftRecord>("/api/builders/drafts", body),
  validateBuilder: (body: Record<string, unknown>) => postJson<BuilderValidationResponse>("/api/builders/validate", body),
  testBuilder: (body: Record<string, unknown>) => postJson<BuilderTestResponse>("/api/builders/test", body),
  publishBuilder: (draftId: string) => postJson<BuilderPublishResponse>(`/api/builders/publish/${encodeURIComponent(draftId)}`, {}),
  correlationPacks: () => getJson<CorrelationPacksResponse>("/api/correlation/packs"),
  correlationPackDetail: (packId: string) =>
    getJson<CorrelationPackDetailResponse>(`/api/correlation/packs/${encodeURIComponent(packId)}`),
  saveCorrelationPack: (body: Record<string, unknown>) =>
    postJson<CorrelationPackRecord>("/api/correlation/packs", body),
  validateCorrelationPack: (packId: string, body: Record<string, unknown>) =>
    postJson<BuilderValidationResponse>(`/api/correlation/packs/${encodeURIComponent(packId)}/validate`, body),
  testCorrelationPack: (packId: string, body: Record<string, unknown>) =>
    postJson<CorrelationPackTestResponse>(`/api/correlation/packs/${encodeURIComponent(packId)}/test`, body),
  publishCorrelationPack: (packId: string) =>
    postJson<BuilderPublishResponse & RuntimeBlob>(`/api/correlation/packs/${encodeURIComponent(packId)}/publish`, {}),
  deleteBuilderDraft: async (draftId: string) => {
    const response = await fetch(`/api/builders/drafts/${encodeURIComponent(draftId)}`, {
      method: "DELETE",
      credentials: "include",
      headers: scopedHeaders(buildMutationHeaders("")),
    });
    return parseResponse<Record<string, unknown>>(response);
  },
  platformStatus: () => getJson<PlatformStatusResponse>("/api/platform/status"),
  healthOverview: () => getJson<HealthOverviewResponse>("/api/health/overview"),
  certificationHealth: () => getJson<CertificationHealthResponse>("/api/health/certification"),
  hostRuntimeOverview: (params: { hours?: number; limit?: number } = {}) =>
    getJson<HostRuntimeOverviewResponse>(`/api/health/hosts/runtime${toQuery(params)}`),
  serviceLifecycle: (params: { refresh_live?: boolean } = {}) =>
    getJson<ServiceLifecycleRegistryResponse>(`/api/service-lifecycle${toQuery(params)}`),
  serviceLifecycleDetail: (instanceId: string, params: { refresh_live?: boolean } = {}) =>
    getJson<ServiceLifecycleInstance>(`/api/service-lifecycle/${encodeURIComponent(instanceId)}${toQuery(params)}`),
  executeServiceLifecycleAction: (instanceId: string, action: ServiceLifecycleAction, idempotencyKey: string) =>
    postJson<ServiceLifecycleActionResponse>(
      `/api/service-lifecycle/${encodeURIComponent(instanceId)}/actions/${encodeURIComponent(action)}`,
      { idempotency_key: idempotencyKey },
    ),
  ingestOverview: () => getJson<IngestOverviewResponse>("/api/ingest/overview"),
  ingestSources: (params: { limit?: number } = {}) => getJson<IngestHeartbeatResponse>(`/api/ingest/sources${toQuery(params)}`),
  ingestCollectors: (params: { limit?: number } = {}) => getJson<IngestHeartbeatResponse>(`/api/ingest/collectors${toQuery(params)}`),
  ingestDlq: (params: { limit?: number } = {}) => getJson<IngestDlqResponse>(`/api/ingest/dlq${toQuery(params)}`),
  replayIngestDlq: (body: Record<string, unknown>) => postJson<ReplayDlqResponse>("/api/ingest/dlq/replay", body),
  suppressIngestDlq: (body: Record<string, unknown>) => postJson<ReplayDlqResponse>("/api/ingest/dlq/suppress", body),
  remediateIngestDlq: (body: Record<string, unknown>) => postJson<ReplayDlqResponse>("/api/ingest/dlq/remediate", body),
  connectors: () => getJson<ConnectorListResponse>("/api/connectors"),
  connectorsOverview: () => getJson<ConnectorsOverviewResponse>("/api/connectors/overview"),
  enterpriseReleaseGates: () => getJson<EnterpriseReleaseGatesResponse>("/api/enterprise/release-gates"),
  complianceEvidencePack: () => getJson<ComplianceEvidencePackResponse>("/api/compliance/evidence-pack"),
  connectorDetail: (connectorId: string) => getJson<ConnectorDetailResponse>(`/api/connectors/${encodeURIComponent(connectorId)}`),
  saveConnector: (body: Record<string, unknown>) => postJson<ConnectorRecord>("/api/connectors", body),
  runConnector: (connectorId: string, body: Record<string, unknown>) =>
    postJson<ConnectorRunResponse>(`/api/connectors/${encodeURIComponent(connectorId)}/run`, body),
  cases: (params: { status?: string; assignee?: string; q?: string; limit?: number } = {}) =>
    getJson<CasesResponse>(`/api/cases${toQuery(params)}`),
  caseDetail: (caseId: string) => getJson<CaseDetailResponse>(`/api/cases/${encodeURIComponent(caseId)}`),
  saveCase: (body: Record<string, unknown>) => postJson<CaseRecord>("/api/cases", body),
  addCaseComment: (caseId: string, body: Record<string, unknown>) =>
    postJson<CaseMutationResponse>(`/api/cases/${encodeURIComponent(caseId)}/comments`, body),
  addCaseTask: (caseId: string, body: Record<string, unknown>) =>
    postJson<CaseMutationResponse>(`/api/cases/${encodeURIComponent(caseId)}/tasks`, body),
  addCaseEvidence: (caseId: string, body: Record<string, unknown>) =>
    postJson<CaseMutationResponse>(`/api/cases/${encodeURIComponent(caseId)}/evidence`, body),
  entities: (params: { entity_type?: string; q?: string; limit?: number } = {}) =>
    getJson<EntitiesResponse>(`/api/entities${toQuery(params)}`),
  entityDetail: (entityId: string) => getJson<EntityDetailResponse>(`/api/entities/${encodeURIComponent(entityId)}`),
  recordRiskSignal: (body: Record<string, unknown>) => postJson<RecordRiskSignalResponse>("/api/entities/signals", body),
  promoteEntityToCase: (entityId: string, body: Record<string, unknown>) =>
    postJson<CaseRecord>(`/api/entities/${encodeURIComponent(entityId)}/promote`, body),
  responseActions: () => getJson<ResponseActionsResponse>("/api/response/actions"),
  saveResponseAction: (body: Record<string, unknown>) => postJson<ResponseActionRecord>("/api/response/actions", body),
  executeResponseAction: (actionId: string, body: Record<string, unknown>) =>
    postJson<ResponseExecutionMutationResponse>(`/api/response/actions/${encodeURIComponent(actionId)}/execute`, body),
  approveResponseExecution: (executionId: string, body: Record<string, unknown> = {}) =>
    postJson<ResponseExecutionRecord>(`/api/response/executions/${encodeURIComponent(executionId)}/approve`, body),
  rejectResponseExecution: (executionId: string, body: Record<string, unknown>) =>
    postJson<ResponseExecutionRecord>(`/api/response/executions/${encodeURIComponent(executionId)}/reject`, body),
  retryResponseExecution: (executionId: string) =>
    postJson<ResponseExecutionMutationResponse>(`/api/response/executions/${encodeURIComponent(executionId)}/retry`, {}),
  responseExecutions: (params: { action_id?: string; limit?: number } = {}) =>
    getJson<ResponseExecutionsResponse>(`/api/response/executions${toQuery(params)}`),
  responseDlq: (params: { limit?: number } = {}) =>
    getJson<ResponseDlqResponse>(`/api/response/dlq${toQuery(params)}`),
  responseLedger: (params: { limit?: number } = {}) =>
    getJson<{ items: RuntimeBlob[] }>(`/api/response/ledger${toQuery(params)}`),
  responseAnalytics: (params: { limit?: number } = {}) =>
    getJson<ResponseAnalyticsResponse>(`/api/response/analytics${toQuery(params)}`),
  replayResponseDlq: (dlqId: string) =>
    postJson<ResponseExecutionMutationResponse>(`/api/response/dlq/${encodeURIComponent(dlqId)}/replay`, {}),
  contentBundles: () => getJson<ContentBundlesResponse>("/api/content/bundles"),
  saveContentBundle: (body: Record<string, unknown>) => postJson<ContentBundleRecord>("/api/content/bundles", body),
  promoteContentBundle: (bundleId: string, body: Record<string, unknown>) =>
    postJson<ContentBundleRecord>(`/api/content/bundles/${encodeURIComponent(bundleId)}/promote`, body),
  savedSearches: () => getJson<SavedSearchesResponse>("/api/search/saved"),
  saveSavedSearch: (body: Record<string, unknown>) => postJson<SavedSearchMutationResponse>("/api/search/saved", body),
  activeLists: (params: { list_name?: string; limit?: number } = {}) =>
    getJson<ActiveListsResponse>(`/api/lists/active${toQuery(params)}`),
  saveActiveList: (body: Record<string, unknown>) => postJson<ActiveListRecord>("/api/lists/active", body),
  deleteActiveList: (body: Record<string, unknown>) =>
    deleteJsonBody<ActiveListMutationResponse>("/api/lists/active", body),
  toggleActiveList: (body: Record<string, unknown>) =>
    patchJson<ActiveListMutationResponse>("/api/lists/active", body),
  importActiveLists: (body: Record<string, unknown>) =>
    postJson<ActiveListImportResponse>("/api/lists/active/import", body),
  exportActiveLists: (listName: string, format: "csv" | "json") =>
    downloadFile(`/api/lists/active/export${toQuery({ list_name: listName, format })}`),
  unifiedRules: (params: {
    search?: string;
    status?: string;
    engine?: string;
    pack_id?: string;
    limit?: number;
    offset?: number;
    noise_days?: number;
  } = {}) => getJson<UnifiedRulesResponse>(`/api/rules/unified${toQuery(params)}`),
  unifiedRule: (identity: string) =>
    getJson<UnifiedRuleRecord>(`/api/rules/unified/${encodeURIComponent(identity)}`),
  publishUnifiedRule: (identity: string) =>
    postJson<UnifiedRuleMutationResponse>(`/api/rules/unified/${encodeURIComponent(identity)}/publish`, {}),
  setUnifiedRuleEnabled: (
    identity: string,
    body: { enabled: boolean; reason?: string; replacement_identity?: string },
  ) => postJson<UnifiedRuleMutationResponse>(
    `/api/rules/unified/${encodeURIComponent(identity)}/enabled`,
    body,
  ),
  secretsRequired: () => getJson<SecretsRequiredResponse>("/api/secrets/required"),
  securityServices: () => getJson<SecurityServicesResponse>("/api/security-services"),
  securityService: (serviceId: string) =>
    getJson<SecurityServiceDetailResponse>(`/api/security-services/${encodeURIComponent(serviceId)}`),
  securityServiceControl: (serviceId: string, q = "") =>
    getJson<SecurityServiceControlResponse>(
      `/api/security-services/${encodeURIComponent(serviceId)}/control${toQuery({ q })}`,
    ),
  mutateFirewall: (operation: string, body: Record<string, unknown>) =>
    postJson<SecurityControlMutationResponse>(
      `/api/security-services/ngfw/firewall/${encodeURIComponent(operation)}`,
      body,
    ),
  mutateIds: (operation: string, body: Record<string, unknown> = {}) =>
    postJson<SecurityControlMutationResponse>(
      `/api/security-services/ips/${encodeURIComponent(operation)}`,
      body,
    ),
  remoteAccessState: () => getJson<RemoteAccessStateResponse>("/api/security-services/vpn/remote-access"),
  saveRemoteAccessProfile: (body: Record<string, unknown>) => postJson<RemoteAccessProfileRecord>("/api/security-services/vpn/remote-access", body),
  deleteRemoteAccessProfile: async (profileId: string) => {
    const response = await fetch(`/api/security-services/vpn/remote-access/${encodeURIComponent(profileId)}`, { method: "DELETE", credentials: "include", headers: scopedHeaders(buildMutationHeaders("")) });
    return parseResponse<{ deleted: boolean; id: string }>(response);
  },
  xuiState: () => getJson<XuiStateResponse>("/api/security-services/vpn/vless"),
  createXuiInbound: (body: Record<string, unknown>) =>
    postJson<RuntimeBlob>("/api/security-services/vpn/vless/inbounds", body),
  updateXuiInbound: (inboundId: number, body: Record<string, unknown>) =>
    putJson<RuntimeBlob>(`/api/security-services/vpn/vless/inbounds/${inboundId}`, body),
  deleteXuiInbound: async (inboundId: number) => {
    const response = await fetch(`/api/security-services/vpn/vless/inbounds/${inboundId}`, {
      method: "DELETE",
      credentials: "include",
      headers: scopedHeaders(buildMutationHeaders()),
    });
    return parseResponse<RuntimeBlob>(response);
  },
  createXuiClient: (inboundId: number, body: Record<string, unknown>) =>
    postJson<RuntimeBlob>(`/api/security-services/vpn/vless/inbounds/${inboundId}/clients`, body),
  updateXuiClient: (inboundId: number, clientId: string, body: Record<string, unknown>) =>
    putJson<RuntimeBlob>(
      `/api/security-services/vpn/vless/inbounds/${inboundId}/clients/${encodeURIComponent(clientId)}`,
      body,
    ),
  deleteXuiClient: async (inboundId: number, clientId: string) => {
    const response = await fetch(
      `/api/security-services/vpn/vless/inbounds/${inboundId}/clients/${encodeURIComponent(clientId)}`,
      { method: "DELETE", credentials: "include", headers: scopedHeaders(buildMutationHeaders()) },
    );
    return parseResponse<RuntimeBlob>(response);
  },
  xuiClientProfile: (inboundId: number, clientId: string) =>
    getJson<{ profile?: string; issue?: string }>(
      `/api/security-services/vpn/vless/inbounds/${inboundId}/clients/${encodeURIComponent(clientId)}/profile`,
    ),
  resetXuiClientTraffic: (inboundId: number, clientId: string) =>
    postJson<RuntimeBlob>(
      `/api/security-services/vpn/vless/inbounds/${inboundId}/clients/${encodeURIComponent(clientId)}/reset-traffic`,
      {},
    ),
  resetXuiInboundTraffic: (inboundId: number) =>
    postJson<RuntimeBlob>(`/api/security-services/vpn/vless/inbounds/${inboundId}/reset-traffic`, {}),
  incidents: (params: { view?: string; q?: string; scope?: string; window?: string; limit?: number; from_ts?: string; to_ts?: string; include_terminal?: boolean } = {}) =>
    getJson<IncidentListResponse>(`/api/incidents${toQuery(params)}`),
  incidentDetail: (
    view: string,
    recordId: string,
    params?: { window?: string; from_ts?: string; to_ts?: string; event_limit?: number; alert_limit?: number; include_evidence?: boolean },
  ) =>
    getJson<IncidentDetailResponse>(
      `/api/incidents/${encodeURIComponent(view)}/${encodeURIComponent(recordId)}${toQuery(params || {})}`,
    ),
  runIncidentHostAction: (view: string, recordId: string, body: Record<string, unknown>) =>
    postJson<IncidentHostActionResponse>(`/api/incident-ops/${encodeURIComponent(view)}/${encodeURIComponent(recordId)}/host-action`, body),
  updateIncident: (view: string, recordId: string, body: Record<string, unknown>) =>
    postJson<IncidentUpdateResponse>(`/api/alerts/${encodeURIComponent(view)}/${encodeURIComponent(recordId)}`, body),
  createManualIncident: (body: Record<string, unknown>) =>
    postJson<IncidentWorkflowResponse>("/api/incident-workflow/incidents", body),
  changeIncidentSeverity: (incidentId: string, body: Record<string, unknown>) =>
    postJson<IncidentWorkflowResponse>(
      `/api/incident-workflow/incidents/${encodeURIComponent(incidentId)}/severity`,
      body,
    ),
  linkIncidentAlert: (incidentId: string, body: Record<string, unknown>) =>
    postJson<IncidentWorkflowResponse>(
      `/api/incident-workflow/incidents/${encodeURIComponent(incidentId)}/alerts/link`,
      body,
    ),
  unlinkIncidentAlert: (incidentId: string, body: Record<string, unknown>) =>
    postJson<IncidentWorkflowResponse>(
      `/api/incident-workflow/incidents/${encodeURIComponent(incidentId)}/alerts/unlink`,
      body,
    ),
  mergeIncidents: (incidentId: string, body: Record<string, unknown>) =>
    postJson<IncidentWorkflowResponse>(
      `/api/incident-workflow/incidents/${encodeURIComponent(incidentId)}/merge`,
      body,
    ),
  eventsQuery: (body: Record<string, unknown>) => postJson<EventsQueryResponse>("/api/events/query", body),
  eventsFacets: (body: Record<string, unknown>) => postJson<EventsFacetsResponse>("/api/events/facets", body),
  huntingCapabilities: () => getJson<HuntingCapabilitiesResponse>("/api/hunting/capabilities"),
  huntingQuery: (body: Record<string, unknown>) => postJson<HuntingQueryResponse>("/api/hunting/events/query", body),
  huntingFacets: (body: Record<string, unknown>) => postJson<HuntingFacetsResponse>("/api/hunting/events/facets", body),
  huntingEventDetail: (eventId: string, eventTs: string, source: string) =>
    getJson<HuntingEventDetailResponse>(`/api/hunting/events/${encodeURIComponent(eventId)}${toQuery({ event_ts: eventTs, source })}`),
  huntingSavedSearches: () => getJson<HuntingSavedSearchesResponse>("/api/hunting/saved-searches"),
  huntingSaveSearch: (body: Record<string, unknown>) =>
    postJson<HuntingSavedSearchRecord>("/api/hunting/saved-searches", body),
  huntingDeleteSearch: (searchId: string) =>
    deleteJson<{ status: string; id: string; revision: number }>(`/api/hunting/saved-searches/${encodeURIComponent(searchId)}`),
  ruleTest: (ruleId: number) => postJson<RuleTestResponse>(`/api/rules/${ruleId}/test`, {}),
};
