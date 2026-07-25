import type {
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
  GeoCountryDetailResponse,
  GeoSourcesResponse,
  GeoVpnResponse,
  HostAccessProfileRecord,
  HostAccessProfilesResponse,
  HostRuntimeOverviewResponse,
  IncidentDetailResponse,
  IncidentHostActionResponse,
  IncidentListResponse,
  IncidentUpdateResponse,
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
  ServiceAccountDetailResponse,
  ServiceAccountsResponse,
  ServiceAccountSummary,
  ServiceAccountTokenIssueResponse,
  ServiceAccountTokenRevokeResponse,
  SourceDiscoveryResponse,
  SourceDiscoveryScanResponse,
  SourceOnboardingExecutionResponse,
  SourceOnboardingPreparedResponse,
  SourcesInventoryResponse,
  ThreatIntelGeoDetailResponse,
  ThreatIntelOverviewResponse,
  LocalUserDetailResponse,
  LocalUserRecord,
  LocalUsersResponse,
  NetworkTopologyResponse,
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
  RuntimeBlob,
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

type QueryValue = string | number | boolean | undefined | null;

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
  const response = await fetch(url, {
    credentials: "include",
    headers: {
      Accept: "application/json",
    },
  });
  return parseResponse<T>(response);
}

async function postJson<T>(url: string, body: Record<string, unknown>): Promise<T> {
  const response = await fetch(url, {
    method: "POST",
    credentials: "include",
    headers: buildMutationHeaders(),
    body: JSON.stringify(body),
  });
  return parseResponse<T>(response);
}

export const api = {
  bootstrap: () => getJson<BootstrapResponse>("/api/ui/bootstrap"),
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
      headers: buildMutationHeaders(""),
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
      headers: buildMutationHeaders(""),
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
      headers: buildMutationHeaders(""),
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
      headers: buildMutationHeaders(""),
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
      headers: buildMutationHeaders(""),
    });
    return parseResponse<Record<string, unknown>>(response);
  },
  docsIndex: () => getJson<DocsIndexResponse>("/api/docs"),
  docDetail: (name: string) => getJson<DocumentDetailResponse>(`/api/docs/${encodeURIComponent(name)}`),
  playbooks: () => getJson<PlaybookSummary[]>("/api/playbooks"),
  playbookDetail: (slug: string) => getJson<PlaybookDetailResponse>(`/api/playbooks/${encodeURIComponent(slug)}`),
  reports: () => getJson<VulnReportsResponse>("/api/reports"),
  reportDetail: (reportId: string) => getJson<VulnReportDetailResponse>(`/api/reports/${encodeURIComponent(reportId)}`),
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
      headers: buildMutationHeaders(""),
    });
    return parseResponse<AssetBindingOverrideRecord>(response);
  },
  sourcesInventory: (params: { hours?: number; limit?: number } = {}) =>
    getJson<SourcesInventoryResponse>(`/api/sources${toQuery(params)}`),
  proxmoxFleet: (params: { limit?: number } = {}) =>
    getJson<ProxmoxFleetResponse>(`/api/sources/proxmox-fleet${toQuery(params)}`),
  syncProxmoxFleet: () => postJson<ProxmoxFleetResponse>("/api/sources/proxmox-fleet/sync", {}),
  sourceDiscovery: (params: { limit?: number } = {}) =>
    getJson<SourceDiscoveryResponse>(`/api/sources/discovery${toQuery(params)}`),
  networkTopology: (params: { hours?: number; limit?: number } = {}) =>
    getJson<NetworkTopologyResponse>(`/api/topology/network${toQuery(params)}`),
  hostAccessProfiles: (params: { limit?: number; host_id?: string; ip?: string } = {}) =>
    getJson<HostAccessProfilesResponse>(`/api/topology/host-access${toQuery(params)}`),
  saveHostAccessProfile: (body: Record<string, unknown>) =>
    postJson<HostAccessProfileRecord>("/api/topology/host-access", body),
  deleteHostAccessProfile: async (profileId: string) => {
    const response = await fetch(`/api/topology/host-access/${encodeURIComponent(profileId)}`, {
      method: "DELETE",
      credentials: "include",
      headers: buildMutationHeaders(""),
    });
    return parseResponse<HostAccessProfileRecord>(response);
  },
  scanSourceDiscovery: (body: Record<string, unknown>) =>
    postJson<SourceDiscoveryScanResponse>("/api/sources/discovery/scan", body),
  prepareSourceOnboarding: (candidateId: string, body: Record<string, unknown> = {}) =>
    postJson<SourceOnboardingPreparedResponse>(`/api/sources/discovery/${encodeURIComponent(candidateId)}/prepare`, body),
  executeSourceOnboarding: (jobId: string, body: Record<string, unknown>) =>
    postJson<SourceOnboardingExecutionResponse>(`/api/sources/discovery/jobs/${encodeURIComponent(jobId)}/execute`, body),
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
      headers: buildMutationHeaders(""),
    });
    return parseResponse<Record<string, unknown>>(response);
  },
  platformStatus: () => getJson<PlatformStatusResponse>("/api/platform/status"),
  healthOverview: () => getJson<HealthOverviewResponse>("/api/health/overview"),
  certificationHealth: () => getJson<CertificationHealthResponse>("/api/health/certification"),
  hostRuntimeOverview: (params: { hours?: number; limit?: number } = {}) =>
    getJson<HostRuntimeOverviewResponse>(`/api/health/hosts/runtime${toQuery(params)}`),
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
  activeLists: () => getJson<ActiveListsResponse>("/api/lists/active"),
  saveActiveList: (body: Record<string, unknown>) => postJson<ActiveListRecord>("/api/lists/active", body),
  secretsRequired: () => getJson<SecretsRequiredResponse>("/api/secrets/required"),
  incidents: (params: { view?: string; q?: string; scope?: string; window?: string; limit?: number; from_ts?: string; to_ts?: string } = {}) =>
    getJson<IncidentListResponse>(`/api/incidents${toQuery(params)}`),
  incidentDetail: (
    view: string,
    recordId: string,
    params?: { window?: string; from_ts?: string; to_ts?: string; event_limit?: number; alert_limit?: number },
  ) =>
    getJson<IncidentDetailResponse>(
      `/api/incidents/${encodeURIComponent(view)}/${encodeURIComponent(recordId)}${toQuery(params || {})}`,
    ),
  runIncidentHostAction: (view: string, recordId: string, body: Record<string, unknown>) =>
    postJson<IncidentHostActionResponse>(`/api/incident-ops/${encodeURIComponent(view)}/${encodeURIComponent(recordId)}/host-action`, body),
  updateIncident: (view: string, recordId: string, body: Record<string, unknown>) =>
    postJson<IncidentUpdateResponse>(`/api/alerts/${encodeURIComponent(view)}/${encodeURIComponent(recordId)}`, body),
  eventsQuery: (body: Record<string, unknown>) => postJson<EventsQueryResponse>("/api/events/query", body),
  eventsFacets: (body: Record<string, unknown>) => postJson<EventsFacetsResponse>("/api/events/facets", body),
  ruleTest: (ruleId: number) => postJson<RuleTestResponse>(`/api/rules/${ruleId}/test`, {}),
};
