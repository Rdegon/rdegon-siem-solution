export type RuntimeBlob = Record<string, unknown>;

export type StringArray = string[];

export type PlatformStatusResponse = {
  clickhouse_ok?: boolean;
  clickhouse_runtime?: {
    healthy?: boolean;
    [key: string]: unknown;
  };
  [key: string]: unknown;
};

export type PrincipalRecord = {
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
  break_glass_session_id?: string;
  section_access?: string[];
  system_grants?: RuntimeBlob[];
};

export type AuthMeResponse = {
  principal: PrincipalRecord;
};

export type EventRow = {
  ts?: string;
  log_source?: string;
  collector_profile?: string;
  observer_collector?: string;
  severity?: string;
  category?: string;
  subcategory?: string;
  src_ip?: string | number;
  dst_ip?: string | number;
  dst_port?: string | number;
  user_name?: string;
  target_user?: string;
  asset_id?: string;
  device_product?: string;
  message?: string;
  process_name?: string;
  process_executable?: string;
  ti_indicator?: string;
  normalized_json?: unknown;
  [key: string]: unknown;
};

export type TimeBucketRecord = {
  ts?: string;
  bucket?: string;
  bucket_start?: string;
  bucket_end?: string;
  count?: number;
  cnt?: number;
  __value?: number;
  [key: string]: unknown;
};

export type GeoCountrySummaryRow = {
  country?: string;
  country_code?: string;
  events?: number;
  ips?: number;
  count?: number;
  visits?: number;
  [key: string]: unknown;
};

export type GeoActivityRow = {
  label?: string;
  ip?: string;
  domain?: string;
  org?: string;
  country?: string;
  country_code?: string;
  events?: number;
  visits?: number;
  last_seen?: string;
  target_ports?: string;
  [key: string]: unknown;
};

export type GeoSourcesResponse = {
  items?: GeoActivityRow[];
  countries?: GeoCountrySummaryRow[];
  summary?: {
    countries?: number;
    ips?: number;
    requested_window_hours?: number;
    observed_window_hours?: number;
    fallback_applied?: boolean;
    [key: string]: unknown;
  };
  [key: string]: unknown;
};

export type GeoVpnResponse = {
  items?: GeoActivityRow[];
  countries?: GeoCountrySummaryRow[];
  summary?: {
    countries?: number;
    items?: number;
    destinations?: number;
    requested_window_hours?: number;
    observed_window_hours?: number;
    fallback_applied?: boolean;
    [key: string]: unknown;
  };
  [key: string]: unknown;
};

export type GeoCountryDetailItem = {
  label?: string;
  ip?: string;
  org?: string;
  events?: number;
  visits?: number;
  last_seen?: string;
  country?: string;
  country_code?: string;
  ports?: string[];
  target_ports?: string;
  sources?: string[];
  incidents?: RuntimeBlob[];
  assets?: RuntimeBlob[];
  [key: string]: unknown;
};

export type GeoCountryDetailResponse = {
  kind?: "source" | "vpn" | string;
  country?: string;
  summary?: {
    items?: number;
    events?: number;
    organizations?: number;
    incidents?: number;
    assets?: number;
    [key: string]: unknown;
  };
  items?: GeoCountryDetailItem[];
  [key: string]: unknown;
};

export type IncidentCluster = RuntimeBlob & {
  sources?: string[];
  actors?: string[];
  assets?: string[];
  iocs?: string[];
  campaigns?: string[];
  rule_names?: string[];
};

export type IncidentRecord = RuntimeBlob & {
  alert_id?: string | number;
  agg_id?: string | number;
  rule_name?: string;
  severity_agg?: string;
  severity?: string;
  source_summary?: string;
  source?: string;
  status?: string;
  assignee?: string;
  ts_last?: string;
  ts_first?: string;
  ts?: string;
  entity_key?: string;
  raw_hits_total?: number;
  hits?: number;
  context?: RuntimeBlob;
  samples?: RuntimeBlob[];
  cluster?: IncidentCluster;
};

export type IncidentHistoryEntry = {
  changed_ts?: string;
  changed_by?: string;
  previous_status?: string;
  next_status?: string;
  previous_assignee?: string;
  next_assignee?: string;
  note?: string;
  [key: string]: unknown;
};

export type IncidentStatusTransitions = Record<string, string[]>;

export type IncidentHostActionResponse = RuntimeBlob & {
  incident_ref?: string;
  requested_by?: string;
  action?: string;
  generated_ts?: string;
  results?: RuntimeBlob[];
};

export type DashboardSummaryResponse = RuntimeBlob & {
  metrics?: {
    events_1h?: number;
    events_24h?: number;
    open_incidents_24h?: number;
    ti_hits_24h?: number;
    active_sources_24h?: number;
    [key: string]: unknown;
  };
  timeline_window?: {
    window?: string;
    bucket_minutes?: number;
    from_ts?: string;
    to_ts?: string;
    [key: string]: unknown;
  };
  severity_breakdown?: BreakdownRecord[];
  alert_severity_breakdown?: BreakdownRecord[];
  alert_status_breakdown?: BreakdownRecord[];
  timeline?: TimeBucketRecord[];
  alert_timeline?: TimeBucketRecord[];
  top_categories?: BreakdownRecord[];
  top_sources?: Array<{
    log_source?: string;
    events?: number;
    last_seen?: string;
    [key: string]: unknown;
  }>;
  top_target_ports?: Array<{
    dst_port?: string | number;
    service?: string;
    attempts?: number;
    unique_sources?: number;
    signal?: string;
    [key: string]: unknown;
  }>;
  top_vpn_sites?: Array<{
    domain?: string;
    visits?: number;
    client_id?: string;
    last_seen?: string;
    [key: string]: unknown;
  }>;
  recent_alerts?: IncidentRecord[];
  geo_sources?: GeoSourcesResponse;
  geo_vpn_destinations?: GeoVpnResponse;
  threat_intel?: ThreatIntelOverviewResponse;
  [key: string]: unknown;
};

export type DashboardLayoutItemRecord = {
  widget: string;
  span?: number;
};

export type DashboardDefinition = {
  id: string;
  title: string;
  description?: string;
  built_in?: boolean;
  layout?: DashboardLayoutItemRecord[];
  [key: string]: unknown;
};

export type DashboardWidgetCatalogRecord = {
  id: string;
  title: string;
  description?: string;
  default_span?: number;
  [key: string]: unknown;
};

export type DashboardsRegistryResponse = {
  dashboards: DashboardDefinition[];
  widget_catalog: DashboardWidgetCatalogRecord[];
};

export type TocItem = {
  id: string;
  name: string;
  level: number;
};

export type DocIndexItem = {
  name: string;
  modified_ts?: string;
};

export type DocSectionRecord = {
  id: string;
  title: string;
  subtitle?: string;
  items: DocIndexItem[];
};

export type PlaybookSummary = {
  slug: string;
  title: string;
  summary?: string;
};

export type DocsIndexResponse = {
  doc_sections: DocSectionRecord[];
  playbooks: PlaybookSummary[];
};

export type DocumentDetailResponse = {
  content_html?: string;
  html?: string;
  toc?: TocItem[];
  [key: string]: unknown;
};

export type PlaybookDetailResponse = {
  title?: string;
  content_html?: string;
  html?: string;
  toc?: TocItem[];
  [key: string]: unknown;
};

export type ServiceAccountSummary = {
  id: string;
  name: string;
  description?: string;
  enabled: boolean;
  permissions: string[];
  permission_bundles?: string[];
  tags?: string[];
  active_tokens?: number;
  token_count?: number;
  last_used_ts?: string;
  created_ts?: string;
  updated_ts?: string;
  next_token_expiry_ts?: string;
  last_rotation_ts?: string;
};

export type ServiceAccountsResponse = {
  items: ServiceAccountSummary[];
  available_permissions: string[];
  available_roles?: string[];
  permission_bundles?: AuthPermissionBundleRecord[];
  permission_categories?: AuthPermissionCategoryRecord[];
  metrics: {
    service_accounts_total?: number;
    enabled_service_accounts?: number;
    active_tokens?: number;
    tokens_expiring_14d?: number;
  };
};

export type ServiceAccountToken = {
  id: string;
  title: string;
  prefix?: string;
  status: string;
  expires_ts?: string;
  last_used_ts?: string;
  token?: string;
};

export type ServiceAccountDetailResponse = {
  item: ServiceAccountSummary | null;
  tokens: ServiceAccountToken[];
};

export type ServiceAccountTokenIssueResponse = {
  token: ServiceAccountToken;
};

export type ServiceAccountTokenRevokeResponse = {
  item: ServiceAccountToken;
};

export type AuthProviderRecord = RuntimeBlob & {
  id: string;
  title?: string;
  kind?: string;
  enabled?: boolean;
  healthy?: boolean;
  issuer?: string;
  issues?: string[];
};

export type AuthProvidersResponse = {
  items: AuthProviderRecord[];
};

export type BreakGlassSessionRecord = RuntimeBlob & {
  id: string;
  username?: string;
  role?: string;
  actor?: string;
  status?: string;
  active?: boolean;
  reason?: string;
  created_ts?: string;
  expires_ts?: string;
  revoked_ts?: string;
};

export type BreakGlassResponse = {
  items: BreakGlassSessionRecord[];
  metrics?: RuntimeBlob;
};

export type AuthGovernanceResponse = {
  providers?: AuthProviderRecord[];
  oidc?: RuntimeBlob;
  vault?: RuntimeBlob;
  service_accounts?: RuntimeBlob & {
    items?: ServiceAccountSummary[];
    metrics?: RuntimeBlob;
    rotations?: RuntimeBlob;
  };
  break_glass?: RuntimeBlob & {
    items?: BreakGlassSessionRecord[];
    metrics?: RuntimeBlob;
  };
  local_auth?: RuntimeBlob;
  secrets?: RuntimeBlob;
  [key: string]: unknown;
};

export type KeycloakStatusResponse = RuntimeBlob & {
  healthy?: boolean;
  admin_ready?: boolean;
  realm?: string;
  base_url?: string;
  admin_client_id?: string;
  issues?: string[];
  inventory?: RuntimeBlob;
};

export type KeycloakGroupRecord = {
  id: string;
  name: string;
  path?: string;
  sub_group_count?: number;
};

export type KeycloakRoleRecord = {
  id?: string;
  name: string;
  description?: string;
  composite?: boolean;
  client_role?: boolean;
};

export type KeycloakClientRecord = {
  id: string;
  client_id: string;
  name?: string;
  description?: string;
  enabled?: boolean;
  protocol?: string;
  public_client?: boolean;
  service_accounts_enabled?: boolean;
  redirect_uris?: string[];
  web_origins?: string[];
  root_url?: string;
  base_url?: string;
  secret_type?: string;
  has_secret?: boolean;
};

export type KeycloakUserSessionRecord = RuntimeBlob & {
  id?: string;
  ipAddress?: string;
  start?: number | string;
  lastAccess?: number | string;
  clients?: RuntimeBlob;
};

export type KeycloakUserRecord = {
  id: string;
  username: string;
  email?: string;
  first_name?: string;
  last_name?: string;
  enabled?: boolean;
  email_verified?: boolean;
  created_ts?: number;
  groups?: KeycloakGroupRecord[];
  roles?: KeycloakRoleRecord[];
  sessions?: KeycloakUserSessionRecord[];
  attributes?: Record<string, unknown>;
};

export type KeycloakUsersResponse = {
  items: KeycloakUserRecord[];
};

export type KeycloakUserDetailResponse = {
  item: KeycloakUserRecord | null;
};

export type KeycloakGroupsResponse = {
  items: KeycloakGroupRecord[];
};

export type KeycloakRolesResponse = {
  items: KeycloakRoleRecord[];
};

export type KeycloakClientsResponse = {
  items: KeycloakClientRecord[];
};

export type KeycloakClientDetailResponse = {
  item: KeycloakClientRecord | null;
};

export type AccessSystemSectionRecord = {
  id: string;
  title?: string;
};

export type AccessSystemRoleRecord = {
  id: string;
  title?: string;
};

export type AccessSystemRecord = {
  id: string;
  title: string;
  kind?: string;
  grantable?: boolean;
  mode?: string;
  sso_supported?: boolean;
  enforcement_mode?: string;
  client_id?: string;
  internal_url?: string;
  roles?: AccessSystemRoleRecord[];
  sections?: AccessSystemSectionRecord[];
};

export type AccessSystemsResponse = {
  items: AccessSystemRecord[];
};

export type AccessGrantRecord = {
  id: string;
  principal_kind?: string;
  principal_id?: string;
  system_id?: string;
  system_title?: string;
  role?: string;
  sections?: string[];
  enabled?: boolean;
  sync_status?: string;
  last_synced_ts?: string;
  created_ts?: string;
  updated_ts?: string;
};

export type AccessGrantsResponse = {
  items: AccessGrantRecord[];
};

export type AuthPermissionBundleRecord = {
  id: string;
  title: string;
  permissions: string[];
};

export type AuthPermissionCategoryRecord = {
  id: string;
  title: string;
  permissions: string[];
};

export type AuthPermissionInventoryResponse = {
  available_permissions: string[];
  available_roles: string[];
  permission_bundles: AuthPermissionBundleRecord[];
  permission_categories: AuthPermissionCategoryRecord[];
};

export type LocalUserRecord = {
  username: string;
  role: string;
  enabled: boolean;
  permissions: string[];
  permission_bundles?: string[];
  created_ts?: string;
  updated_ts?: string;
  password_updated_ts?: string;
  source?: string;
};

export type LocalUsersResponse = AuthPermissionInventoryResponse & {
  items: LocalUserRecord[];
};

export type LocalUserDetailResponse = AuthPermissionInventoryResponse & {
  item: LocalUserRecord | null;
};

export type CaseComment = {
  id: string;
  author: string;
  body: string;
  ts: string;
};

export type CaseTask = {
  id: string;
  title: string;
  status: string;
};

export type CaseEvidence = {
  id: string;
  title: string;
  kind: string;
};

export type CaseRecord = {
  id: string;
  title: string;
  summary?: string;
  severity?: string;
  status?: string;
  assignee?: string;
  updated_ts?: string;
  created_ts?: string;
  comments?: CaseComment[];
  tasks?: CaseTask[];
  evidence?: CaseEvidence[];
  audit_trail?: unknown[];
  related_entities?: unknown[];
  source_alerts?: unknown[];
};

export type CasesResponse = {
  items: CaseRecord[];
};

export type CaseDetailResponse = {
  item: CaseRecord | null;
};

export type CaseMutationResponse = RuntimeBlob & {
  item?: CaseRecord | null;
  comments?: CaseComment[];
  tasks?: CaseTask[];
  evidence?: CaseEvidence[];
};

export type ConnectorSecretRequirement = {
  env: string;
  label: string;
  required?: boolean;
};

export type ConnectorRecord = {
  id: string;
  title: string;
  description?: string;
  family?: string;
  source_family?: string;
  group?: string;
  mode?: string;
  status?: string;
  updated_ts?: string;
  secret_requirements?: ConnectorSecretRequirement[];
  mappings?: RuntimeBlob;
  runtime?: RuntimeBlob;
  telemetry?: RuntimeBlob;
  operations?: RuntimeBlob;
  release_gate?: RuntimeBlob;
};

export type ConnectorRunRecord = {
  id: string;
  connector_id: string;
  status: string;
  finished_ts?: string;
  message?: string;
  trigger?: string;
};

export type ResponseActionSummary = {
  id: string;
  title: string;
};

export type BreakdownRecord = {
  label?: string;
  severity?: string;
  status?: string;
  count?: number;
  cnt?: number;
  events?: number;
  [key: string]: unknown;
};

export type ConnectorsOverviewResponse = {
  items: ConnectorRecord[];
  recent_runs: ConnectorRunRecord[];
  actions: ResponseActionSummary[];
  bundles?: ContentBundleRecord[];
  metrics: {
    total?: number;
    healthy?: number;
    degraded?: number;
    planned?: number;
    telemetry_coverage_avg?: number;
    enterprise_ready?: number;
    managed_by_bundle?: number;
    playbook_bound?: number;
    compliance_mapped?: number;
    realtime_ready?: number;
    actor_ip_ready?: number;
    host_telemetry_ready?: number;
    evidence_ready?: number;
    parsing_coverage_avg?: number;
    telemetry_quality_avg?: number;
    investigation_ready?: number;
    runbook_ready?: number;
    onboarding_ready?: number;
    release_gate_ready?: number;
    ecosystem_present?: number;
    ecosystem_live_ready?: number;
  };
  breakdowns?: {
    status?: BreakdownRecord[];
    group?: BreakdownRecord[];
    family?: BreakdownRecord[];
    collection_depth?: BreakdownRecord[];
    release_stage?: BreakdownRecord[];
  };
  posture?: RuntimeBlob;
};

export type ConnectorListResponse = {
  items: ConnectorRecord[];
};

export type ConnectorDetailResponse = {
  item: ConnectorRecord | null;
};

export type ConnectorRunResponse = RuntimeBlob & {
  run?: ConnectorRunRecord;
  accepted_events?: number;
  preview?: unknown[];
};

export type HealthOverviewResponse = {
  issues?: string[];
  secrets?: {
    items?: Array<{
      label: string;
      status: string;
      required?: boolean;
    }>;
  };
  content?: {
    bundles?: Array<{
      id: string;
      title: string;
      bundle_type: string;
      version: string;
    }>;
  };
  [key: string]: unknown;
};

export type SavedSearchRecord = {
  id: string;
  title: string;
  description?: string;
  storage?: string;
  window?: string;
  query?: string;
  schedule?: string;
  tags?: string[];
  owner?: string;
  persona?: string;
  lifecycle_stage?: string;
  bundle_ids?: string[];
};

export type SavedSearchesResponse = {
  items: SavedSearchRecord[];
};

export type SavedSearchMutationResponse = SavedSearchRecord;

export type AssetRecord = {
  asset: string;
  aliases?: string[];
  cmdb_owner?: string;
  cmdb_service?: string;
  cmdb_environment?: string;
  cmdb_criticality?: string;
  cmdb_asset_id?: string;
  cmdb_tags?: string[];
  cmdb_expected_ports?: Array<string | number>;
  last_seen?: string;
  events?: number;
  notable_events?: number;
  audit_events?: number;
  categories?: string[];
  products?: string[];
  [key: string]: unknown;
};

export type AssetInventoryResponse = {
  items: AssetRecord[];
};

export type AssetCatalogResponse = {
  detection_rules?: unknown[];
  normalizers?: unknown[];
  active_lists?: unknown[];
  threat_intel?: unknown[];
  [key: string]: unknown;
};

export type IntegrationTemplateRecord = {
  id: string;
  title: string;
  description?: string;
  family?: string;
  group?: string;
  mode?: string;
  protocols?: string[];
  block_type?: string;
  stage?: string;
  [key: string]: unknown;
};

export type IntegrationsCatalogResponse = {
  items: IntegrationTemplateRecord[];
};

export type CollectorInventoryRecord = {
  collector_id: string;
  name: string;
  description?: string;
  role?: string;
  node?: string;
  status?: string;
  protocols?: string[];
  source_classes?: string[];
  covered_sources?: string[];
  sources_count?: number;
  events?: number;
  last_seen?: string;
  [key: string]: unknown;
};

export type CollectorsInventoryResponse = {
  items: CollectorInventoryRecord[];
  issues?: string[];
  generated_ts?: string;
};

export type SourceInventoryRecord = {
  source_name: string;
  source_type?: string;
  collector_name?: string;
  collector_id?: string;
  status?: string;
  events?: number;
  auth_events?: number;
  audit_events?: number;
  ti_hits?: number;
  notable_events?: number;
  last_seen?: string;
  products?: string[];
  services?: string[];
  categories?: string[];
  aliases?: string[];
  source_ips?: string[];
  observed_ips?: string[];
  cmdb_ip?: string;
  cmdb_asset_id?: string;
  cmdb_owner?: string;
  cmdb_criticality?: string;
  cmdb_environment?: string;
  cmdb_service?: string;
  [key: string]: unknown;
};

export type SourcesInventoryResponse = {
  items: SourceInventoryRecord[];
  issues?: string[];
  generated_ts?: string;
};

export type DiscoveryOpenPort = {
  port?: number | string;
  service?: string;
  server?: string;
  banner?: string;
  title?: string;
};

export type DiscoveryRecommendation = {
  title?: string;
  collector_profile?: string;
  integration_template?: string;
  auto_monitoring_method?: string;
  auto_monitoring_supported?: boolean;
};

export type DiscoveryCandidate = {
  id: string;
  ip: string;
  hostname?: string;
  connected?: boolean;
  connected_source?: string;
  status?: string;
  os_family?: string;
  probable_role?: string;
  port_summary?: string;
  monitoring_status?: string;
  recommendation?: DiscoveryRecommendation;
  last_job_id?: string;
  last_seen_ts?: string;
  source_family?: string;
  confidence?: number;
  open_ports?: DiscoveryOpenPort[];
  binding_target?: string;
  binding_override_id?: string;
  binding_override?: AssetBindingOverrideRecord | null;
  [key: string]: unknown;
};

export type DiscoveryJob = {
  id: string;
  candidate_id?: string;
  summary?: string;
  method?: string;
  ip?: string;
  collector_profile?: string;
  status?: string;
  updated_ts?: string;
  created_ts?: string;
  execution_supported?: boolean;
  credential_requirements?: Array<{ id?: string; label?: string; required?: boolean }>;
  requested_telemetry?: string[];
  telemetry_selection?: string[];
  command_preview?: string[];
  config_preview?: RuntimeBlob | string;
  network_vendor?: string;
  network_commands?: string[];
  last_execution?: RuntimeBlob;
  [key: string]: unknown;
};

export type DiscoveryMetrics = {
  total?: number;
  unmanaged?: number;
  auto_ready?: number;
  prepared?: number;
  binding_overrides_total?: number;
  binding_overrides_applied?: number;
  unmanaged_without_override?: number;
  [key: string]: unknown;
};

export type AssetBindingOverrideRecord = {
  id: string;
  target?: string;
  aliases?: string[];
  asset_id?: string;
  hostname?: string;
  ip?: string;
  scope?: string;
  note?: string;
  enabled?: boolean;
  created_ts?: string;
  created_by?: string;
  updated_ts?: string;
  updated_by?: string;
};

export type AssetBindingOverridesResponse = {
  items: AssetBindingOverrideRecord[];
  metrics?: RuntimeBlob;
};

export type SourceDiscoveryResponse = {
  items: DiscoveryCandidate[];
  jobs: DiscoveryJob[];
  metrics?: DiscoveryMetrics;
};

export type ProxmoxFleetRecord = {
  id: string;
  vmid?: string;
  node?: string;
  guest_type?: string;
  name?: string;
  hostname?: string;
  source_name?: string;
  ip?: string;
  running?: boolean;
  state?: string;
  connected?: boolean;
  reachable?: boolean;
  monitoring_supported?: boolean;
  vuln_scannable?: boolean;
  host_runtime_enabled?: boolean;
  os_family?: string;
  role?: string;
  business_service?: string;
  criticality?: string;
  tags?: string[];
  last_seen_ts?: string;
  max_memory_bytes?: number;
  used_memory_bytes?: number;
  cpu?: number;
  uptime_seconds?: number;
  asset_id?: string;
  updated_ts?: string;
  [key: string]: unknown;
};

export type ProxmoxFleetMetrics = {
  total?: number;
  connected?: number;
  onboardable?: number;
  scan_only?: number;
  inventory_only?: number;
  offline?: number;
  unsupported?: number;
  running?: number;
  reachable?: number;
  vuln_scannable?: number;
  host_runtime_enabled?: number;
  [key: string]: unknown;
};

export type ProxmoxFleetResponse = {
  generated_ts?: string;
  items: ProxmoxFleetRecord[];
  metrics?: ProxmoxFleetMetrics;
  sync?: RuntimeBlob;
};

export type TopologyNodeRecord = RuntimeBlob & {
  id: string;
  type: string;
  label: string;
  x?: number;
  y?: number;
  status?: string;
  role?: string;
  ip?: string;
  events?: number;
  href?: string;
  access_profile_count?: number;
  access_status?: string;
  access_profiles?: HostAccessProfileSummary[];
};

export type TopologyEdgeRecord = RuntimeBlob & {
  id: string;
  source: string;
  target: string;
  type: string;
  label?: string;
  status?: string;
  events?: number;
};

export type NetworkPacketFlowRecord = RuntimeBlob & {
  id: string;
  order?: number;
  title?: string;
  from?: string;
  to?: string;
  protocols?: string[];
  ports?: string[];
  events?: number;
  nodes?: number;
  source_layer?: string;
  target_layer?: string;
  description?: string;
};

export type NetworkTopologyResponse = {
  generated_ts?: string;
  window_hours?: number;
  protected_public_ips?: string[];
  metrics?: RuntimeBlob;
  layers?: Array<{ id?: string; title?: string; count?: number }>;
  nodes: TopologyNodeRecord[];
  edges: TopologyEdgeRecord[];
  packet_flows?: NetworkPacketFlowRecord[];
  host_access_profiles?: HostAccessProfileRecord[];
  attention?: RuntimeBlob[];
  issues?: string[];
};

export type HostAccessProfileSummary = RuntimeBlob & {
  profile_id?: string;
  protocol?: string;
  port?: number;
  username?: string;
  auth_method?: string;
  credential_label?: string;
  secret_status?: string;
  enabled?: boolean;
};

export type HostAccessProfileRecord = HostAccessProfileSummary & {
  host_id?: string;
  host_label?: string;
  hostname?: string;
  ip?: string;
  credential_ref?: string;
  private_key_ref?: string;
  certificate_ref?: string;
  jump_host?: string;
  scope?: string;
  allowed_actions?: string[];
  tags?: string[];
  notes?: string;
  last_validated_ts?: string;
  validation_status?: string;
  secret_fields?: string[];
  created_ts?: string;
  updated_ts?: string;
};

export type HostAccessProfilesResponse = {
  items: HostAccessProfileRecord[];
  metrics?: RuntimeBlob;
};

export type SourceDiscoveryScanResponse = {
  items?: DiscoveryCandidate[];
  scan?: {
    hosts_scanned?: number;
    discovered?: number;
    discovered_unmanaged?: number;
    [key: string]: unknown;
  };
};

export type SourceOnboardingPreparedResponse = {
  job?: DiscoveryJob;
};

export type SourceOnboardingExecutionResponse = {
  execution?: {
    summary?: string;
    status?: string;
    package_spec?: RuntimeBlob;
    artifacts?: RuntimeBlob;
    network_vendor?: string;
    commands?: string[];
    [key: string]: unknown;
  };
};

export type IngestOverviewResponse = {
  metrics?: {
    received_total?: number;
    accepted_total?: number;
    active_sources?: number;
    active_collectors?: number;
    last_event_ts?: string;
    last_source?: string;
    last_collector?: string;
    parser_errors_total?: number;
    replayed_total?: number;
    [key: string]: unknown;
  };
  dlq?: {
    outstanding?: number;
    [key: string]: unknown;
  };
  issues?: string[];
};

export type IngestHeartbeatRecord = {
  id?: string;
  source?: string;
  collector_profile?: string;
  status?: string;
  events_total?: number;
  [key: string]: unknown;
};

export type IngestHeartbeatResponse = {
  items: IngestHeartbeatRecord[];
  metrics?: {
    total?: number;
    healthy?: number;
    delayed?: number;
    stale?: number;
    events_total?: number;
    [key: string]: unknown;
  };
};

export type IngestDlqRecord = {
  id: string;
  reason?: string;
  collector_profile?: string;
  collector?: string;
  source_ip?: string;
  ingest_ts?: string;
  ingest_path?: string;
  payload?: unknown;
  metadata?: RuntimeBlob;
  replay?: {
    status?: string;
    [key: string]: unknown;
  };
  [key: string]: unknown;
};

export type IngestDlqResponse = {
  items: IngestDlqRecord[];
  metrics?: {
    visible?: number;
    outstanding?: number;
    replayed?: number;
    total?: number;
    [key: string]: unknown;
  };
};

export type ReplayDlqResponse = {
  replayed?: number;
  suppressed?: number;
  status?: string;
  replay?: RuntimeBlob;
  suppress?: RuntimeBlob;
};

export type EventsQueryResponse = {
  rows: EventRow[];
  row_count?: number;
  total_count?: number;
  total_count_is_estimate?: boolean;
  page?: number;
  total_pages?: number;
  offset?: number;
  elapsed_ms?: number;
  from_ts?: string;
  to_ts?: string;
  base_sql?: string;
  severity_stats?: BreakdownRecord[];
  source_stats?: BreakdownRecord[];
  host_stats?: BreakdownRecord[];
  histogram?: TimeBucketRecord[];
};

export type EventsFacetsResponse = {
  severity_stats?: BreakdownRecord[];
  source_stats?: BreakdownRecord[];
  host_stats?: BreakdownRecord[];
  histogram?: TimeBucketRecord[];
  elapsed_ms?: number;
  from_ts?: string;
  to_ts?: string;
  base_sql?: string;
};

export type ThreatIntelOverviewResponse = {
  summary?: {
    indicators?: number;
    providers?: number;
    matches_24h?: number;
    malicious_ips?: number;
  };
  providers?: Array<{ provider?: string; count?: number; [key: string]: unknown }>;
  severity?: BreakdownRecord[];
  countries?: Array<{ country?: string; events?: number; [key: string]: unknown }>;
  recent_matches?: ThreatIntelMatchRecord[];
  entries?: ThreatIntelCatalogEntry[];
  malicious_sources?: ThreatIntelMaliciousSource[];
};

export type ThreatIntelMatchRecord = {
  indicator?: string;
  indicator_type?: string;
  provider?: string;
  severity?: string;
  events?: number;
  sample_ip?: string;
  last_seen?: string;
  [key: string]: unknown;
};

export type ThreatIntelCatalogEntry = {
  indicator?: string;
  indicator_type?: string;
  provider?: string;
  severity?: string;
  confidence?: number;
  updated_ts?: string;
  [key: string]: unknown;
};

export type ThreatIntelMaliciousSource = {
  ip?: string;
  country?: string;
  reputation?: string;
  events?: number;
  auth_events?: number;
  ti_hits?: number;
  [key: string]: unknown;
};

export type ThreatIntelGeoDetailResponse = {
  ip?: string;
  geo?: {
    country?: string;
    city?: string;
    org?: string;
  };
  reputation?: {
    label?: string;
    sources?: string[];
  };
  summary?: {
    events?: number;
    as_source?: number;
    as_destination?: number;
    auth_events?: number;
    ti_events?: number;
    notable_events?: number;
    last_seen?: string;
    log_sources?: string[];
    categories?: string[];
    dst_ports?: Array<string | number>;
  };
  threat_intel?: Array<{
    provider?: string;
    severity?: string;
    confidence?: number;
    description?: string;
    [key: string]: unknown;
  }>;
  recent_events?: Array<{
    ts?: string;
    log_source?: string;
    category?: string;
    subcategory?: string;
    message?: string;
    [key: string]: unknown;
  }>;
  incidents?: Array<{
    agg_id?: string;
    rule_name?: string;
    status?: string;
    severity?: string;
    last_seen?: string;
    [key: string]: unknown;
  }>;
};

export type BuilderBlockRecord = {
  id: string;
  type: string;
  stage: string;
  label: string;
  config?: RuntimeBlob & {
    links_to?: string[];
  };
  [key: string]: unknown;
};

export type BuilderHistoryEntry = {
  ts?: string;
  action?: string;
  version?: number | string;
  status?: string;
  [key: string]: unknown;
};

export type BuilderDraftRecord = {
  id: string;
  title: string;
  description?: string;
  kind?: string;
  status?: string;
  version?: number | string;
  updated_ts?: string;
  published_ts?: string;
  blocks?: BuilderBlockRecord[];
  history?: BuilderHistoryEntry[];
  [key: string]: unknown;
};

export type BuilderDraftsResponse = {
  items: BuilderDraftRecord[];
};

export type BuilderValidationResponse = {
  valid?: boolean;
  errors?: unknown[];
  warnings?: unknown[];
  [key: string]: unknown;
};

export type BuilderTestResponse = {
  valid?: boolean;
  results?: unknown[];
  [key: string]: unknown;
};

export type BuilderPublishResponse = {
  status?: string;
  version?: number | string;
  published_ts?: string;
  [key: string]: unknown;
};

export type CorrelationRuleRecord = {
  id: number;
  title: string;
  severity?: string;
  window_s?: number;
  threshold?: number;
  entity_field?: string;
  suppression_key?: string;
  status?: string;
  operator_action?: string;
  sigma_yaml?: string;
  [key: string]: unknown;
};

export type CorrelationBatchRuleRecord = {
  id: number;
  title: string;
  severity?: string;
  status?: string;
  description?: string;
  [key: string]: unknown;
};

export type CorrelationPackRecord = {
  pack_id: string;
  title: string;
  version?: string;
  status?: string;
  owner?: string;
  notes?: string[];
  stream_rules?: CorrelationRuleRecord[];
  batch_rules?: CorrelationBatchRuleRecord[];
  rule_count?: number;
  active_stream_rules?: number;
  file_name?: string;
  updated_ts?: string;
  validation?: BuilderValidationResponse;
  [key: string]: unknown;
};

export type CorrelationPacksResponse = {
  items: CorrelationPackRecord[];
};

export type CorrelationPackDetailResponse = {
  item: CorrelationPackRecord | null;
};

export type CorrelationPackTestResult = {
  rule_id?: number;
  title?: string;
  status?: string;
  compile_error?: string;
  compiled_stream_rule?: RuntimeBlob;
  runtime_test?: RuntimeBlob;
  [key: string]: unknown;
};

export type CorrelationPackTestResponse = {
  status?: string;
  validation?: BuilderValidationResponse;
  items?: CorrelationPackTestResult[];
  [key: string]: unknown;
};

export type VulnHostRow = {
  target: string;
  findings?: number;
  open_ports?: number | string;
  reports?: number;
  services?: StringArray;
  last_seen?: string;
  [key: string]: unknown;
};

export type VulnSoftwareRow = {
  service: string;
  findings?: number;
  hosts?: number;
  host_samples?: string[];
  ports?: Array<string | number>;
  last_seen?: string;
  [key: string]: unknown;
};

export type VulnCveRow = {
  cve: string;
  findings?: number;
  hosts?: number;
  host_samples?: string[];
  services?: string[];
  last_seen?: string;
  [key: string]: unknown;
};

export type VulnFindingRow = {
  ts?: string;
  report_id?: string;
  dst_ip?: string;
  host_name?: string;
  target?: string;
  source?: string;
  dst_port?: string | number;
  port?: string | number;
  service?: string;
  process_name?: string;
  cves?: string[] | string;
  severity?: string;
  message?: string;
  summary_message?: string;
  [key: string]: unknown;
};

export type VulnOverviewResponse = {
  summary: {
    reports?: number;
    targets?: number;
    findings?: number;
    [key: string]: unknown;
  };
  hosts: VulnHostRow[];
  services: VulnSoftwareRow[];
  cves: VulnCveRow[];
};

export type VulnRowsResponse<TRow> = {
  items: TRow[];
};

export type VulnRuntimeResponse = {
  greenbone?: {
    enabled?: boolean;
    host?: string;
    port?: number;
    web_base_url?: string;
    artifact_dir?: string;
    state_path?: string;
    [key: string]: unknown;
  };
  runtime?: RuntimeBlob;
  probe?: RuntimeBlob;
  last_target_sync_ts?: string;
  last_import_ts?: string;
  last_successful_import_ts?: string;
  last_error?: string;
  scanner_family_breakdown?: Record<string, number>;
  structured_reports?: {
    days?: number;
    count?: number;
    latest_report_id?: string;
    latest_finished_at?: string;
    [key: string]: unknown;
  };
  fleet_coverage?: {
    total_guests?: number;
    reachable_guests?: number;
    scannable_guests?: number;
    recently_scanned_guests?: number;
    offline_guests?: number;
    unresolved_guests?: number;
    last_successful_import?: string;
    [key: string]: unknown;
  };
  healthy?: boolean;
};

export type VulnMaturityWorkflowRecord = {
  id: string;
  kind?: string;
  schedule?: string;
  target?: string;
  [key: string]: unknown;
};

export type VulnMaturityPlaybookRecord = {
  id: string;
  title?: string;
  steps?: string[];
  [key: string]: unknown;
};

export type VulnCriticalCandidateRecord = {
  finding_key: string;
  report_id?: string;
  external_report_id?: string;
  target?: string;
  service?: string;
  severity?: string;
  cvss_score?: number;
  cves?: string[];
  status?: string;
  delta_state?: string;
  asset_id?: string;
  auto_case_exists?: boolean;
  playbook?: string;
  [key: string]: unknown;
};

export type VulnUnmappedTargetRecord = {
  finding_key?: string;
  report_id?: string;
  target: string;
  hostname?: string;
  ip?: string;
  severity?: string;
  cvss_score?: number;
  reason?: string;
  suggested_asset_id?: string;
  suggested_hostname?: string;
  suggested_ip?: string;
  suggested_basis?: string;
  suggested_confidence?: number;
  matched_alias?: string;
  [key: string]: unknown;
};

export type VulnMaturityResponse = {
  runtime?: VulnRuntimeResponse;
  reports_total?: number;
  reports_with_asset_binding?: number;
  findings_total?: number;
  findings_with_asset_binding?: number;
  asset_binding_coverage?: number;
  severity_counts?: Record<string, number>;
  inventory_summary?: RuntimeBlob;
  critical_candidates?: VulnCriticalCandidateRecord[];
  critical_candidates_total?: number;
  unmapped_targets?: VulnUnmappedTargetRecord[];
  unmapped_targets_total?: number;
  binding_overrides_total?: number;
  binding_overrides_active?: number;
  fleet_coverage?: VulnRuntimeResponse["fleet_coverage"];
  scheduled_workflows?: VulnMaturityWorkflowRecord[];
  playbooks?: VulnMaturityPlaybookRecord[];
  ready_for_incident_policies?: boolean;
};

export type VulnPolicyApplyResponse = {
  created?: number;
  skipped?: number;
  created_cases?: Array<{
    case_id?: string;
    finding_key?: string;
    title?: string;
  }>;
  skipped_items?: Array<{
    finding_key?: string;
    reason?: string;
  }>;
};

export type VulnExposureItem = {
  finding_key: string;
  report_id?: string;
  asset_id?: string;
  asset_hostname?: string;
  asset_owner?: string;
  target?: string;
  target_ip?: string;
  current_asset_ip?: string;
  stale_target?: boolean;
  title?: string;
  severity?: string;
  cvss_score?: number;
  qod?: number;
  cves?: string[];
  kev?: boolean;
  epss?: number;
  epss_percentile?: number;
  priority_score?: number;
  priority_band?: string;
  priority_reasons?: string[];
  sla_hours?: number;
  due_ts?: string;
  sla_breached?: boolean;
  case_id?: string;
  case_status?: string;
  remediation?: {
    mode?: string;
    action?: string;
    package_name?: string;
    fixed_version?: string;
    approval_required?: boolean;
    validation_profile?: string;
    intrusive_validation_allowed?: boolean;
  };
};

export type VulnExposureWorkbenchResponse = {
  generated_ts?: string;
  intelligence?: {
    updated_ts?: string;
    sources?: RuntimeBlob;
    errors?: string[];
  };
  summary?: {
    findings?: number;
    actionable?: number;
    urgent?: number;
    kev?: number;
    epss_high?: number;
    sla_breached?: number;
    unowned?: number;
    unmapped?: number;
    stale_targets?: number;
    existing_cases?: number;
    fixed_findings?: number;
  };
  items?: VulnExposureItem[];
  fixed_finding_keys?: string[];
};

export type VulnSyncResponse = RuntimeBlob & {
  imported?: number;
  synced?: number;
  created?: number;
  updated?: number;
};

export type VulnReportSummary = {
  report_id: string;
  title?: string;
  targets?: string[] | string;
  summary_message?: string;
  ts_first?: string;
  ts_last?: string;
  scanner_family?: string;
  scanner_source?: string;
  reportPath?: string;
  [key: string]: unknown;
};

export type VulnReportsResponse = {
  items: VulnReportSummary[];
};

export type VulnReportDetailResponse = {
  report_id?: string;
  title?: string;
  cves?: string[] | string;
  targets?: string[] | string;
  ports?: string[] | string;
  findings?: VulnFindingRow[];
  summary_message?: string;
  scanner_family?: string;
  scanner_source?: string;
  target_count?: number;
  finding_count?: number;
  [key: string]: unknown;
};

export type VulnIntegrationContractEntity = {
  id: string;
  required?: string[];
  optional?: string[];
  [key: string]: unknown;
};

export type VulnIntegrationTemplate = {
  id?: string;
  title?: string;
  description?: string;
  block_type?: string;
  stage?: string;
  group?: string;
  family?: string;
  protocols?: string[];
  mode?: string;
  [key: string]: unknown;
};

export type VulnIntegrationContractResponse = {
  version?: string;
  entities?: VulnIntegrationContractEntity[];
  templates?: VulnIntegrationTemplate[];
  transport_modes?: Array<string | Record<string, unknown>>;
  notes?: string[];
  [key: string]: unknown;
};

export type EntityRecord = {
  id: string;
  display_name?: string;
  name?: string;
  entity_type?: string;
  risk_level?: string;
  risk_score?: number;
  signals_recent?: number;
  last_seen_ts?: string;
  criticality?: string;
  linked_cases?: Array<string | number>;
  timeline?: unknown[];
  signals?: RiskSignalRecord[];
  baseline?: RuntimeBlob;
  relationships?: {
    sources?: unknown[];
    actor_ips?: unknown[];
    users?: unknown[];
    destinations?: unknown[];
    services?: unknown[];
    assets?: unknown[];
    linked_cases?: unknown[];
    [key: string]: unknown;
  };
  evidence_graph?: {
    nodes?: RuntimeBlob[];
    edges?: RuntimeBlob[];
    [key: string]: unknown;
  };
  hypotheses?: RuntimeBlob[];
  investigation_bundle?: RuntimeBlob;
  [key: string]: unknown;
};

export type RiskSignalRecord = {
  id: string;
  entity_name?: string;
  summary?: string;
  kind?: string;
  score?: number;
  [key: string]: unknown;
};

export type EntitiesResponse = {
  items: EntityRecord[];
  signals?: RiskSignalRecord[];
  metrics?: {
    total?: number;
    high_risk?: number;
    open_signals?: number;
    promotion_candidates?: number;
    anomalous_entities?: number;
    privileged_entities?: number;
    graph_edges?: number;
    actor_context_ready?: number;
    destination_context_ready?: number;
    indicator_context_ready?: number;
    vuln_context_ready?: number;
    process_lineage_ready?: number;
    outbound_destination_ready?: number;
    behavioral_models_ready?: number;
    investigation_ready?: number;
  };
  breakdowns?: {
    risk_level?: BreakdownRecord[];
    entity_type?: BreakdownRecord[];
  };
};

export type RecordRiskSignalResponse = {
  entity?: EntityRecord;
};

export type EntityDetailResponse = {
  item: EntityRecord | null;
};

export type ResponseActionRecord = RuntimeBlob & {
  id: string;
  title?: string;
  description?: string;
  status?: string;
  kind?: string;
  action_type?: string;
  enabled?: boolean;
  dangerous?: boolean;
  approval_required?: boolean;
  requires_approval?: boolean;
  approval?: RuntimeBlob;
  message_template?: string;
  target?: RuntimeBlob;
  steps?: ResponseActionStepRecord[];
  secret_requirements?: ConnectorSecretRequirement[];
  health?: RuntimeBlob;
  policy_pack_id?: string;
  template_id?: string;
  trigger_kinds?: string[];
  owners?: string[];
  default_linkage?: RuntimeBlob;
  playbook_class?: string;
  governance_tier?: string;
  evidence_contract?: string[];
  rollback_contract?: string[];
  compliance_controls?: string[];
  preconditions?: string[];
  integration_targets?: string[];
  operator_notes?: string;
  rollback_notes?: string;
};

export type ResponseExecutionRecord = RuntimeBlob & {
  id: string;
  action_id?: string;
  kind?: string;
  status?: string;
  created_ts?: string;
  actor?: string;
  message?: string;
  error?: string;
  details?: RuntimeBlob;
  dry_run?: boolean;
  payload?: RuntimeBlob;
  attempts_total?: number;
  approved_by?: string;
  approved_ts?: string;
  executed_ts?: string;
  rejected_by?: string;
  rejected_ts?: string;
  approval?: RuntimeBlob;
  linkage?: RuntimeBlob;
  policy_pack_id?: string;
};

export type ResponseActionsResponse = {
  items: ResponseActionRecord[];
  executions?: ResponseExecutionRecord[];
  approval_queue?: ResponseExecutionRecord[];
  policy_packs?: RuntimeBlob[];
  ledger?: RuntimeBlob[];
  metrics?: RuntimeBlob;
  breakdowns?: {
    execution_status?: BreakdownRecord[];
    [key: string]: unknown;
  };
};

export type ResponseExecutionsResponse = {
  items: ResponseExecutionRecord[];
};

export type ResponseExecutionMutationResponse = RuntimeBlob & {
  execution?: ResponseExecutionRecord;
};

export type ResponseActionStepRecord = {
  id: string;
  title?: string;
  kind?: string;
  enabled?: boolean;
  continue_on_error?: boolean;
  message_template?: string;
  target?: RuntimeBlob;
  secret_requirements?: ConnectorSecretRequirement[];
};

export type ResponseDlqRecord = RuntimeBlob & {
  id: string;
  action_id?: string;
  execution_id?: string;
  created_ts?: string;
  actor?: string;
  status?: string;
  error?: string;
  attempts?: number;
  payload?: RuntimeBlob;
  linkage?: RuntimeBlob;
  approval?: RuntimeBlob;
  resume_from_step?: number;
  resume_payload?: RuntimeBlob;
  replayed_ts?: string;
  replayed_by?: string;
};

export type ResponseDlqResponse = {
  items: ResponseDlqRecord[];
};

export type ResponseAnalyticsResponse = {
  metrics?: {
    actions_total?: number;
    executions_total?: number;
    dlq_total?: number;
    pending_approvals?: number;
    partial_failures?: number;
    success_rate?: number;
    p95_latency_ms?: number;
    governed_actions?: number;
    owner_coverage_pct?: number;
    evidence_contract_pct?: number;
    rollback_ready_pct?: number;
    compliance_coverage_pct?: number;
    precondition_coverage_pct?: number;
    integration_target_pct?: number;
    [key: string]: unknown;
  };
  breakdowns?: {
    action_kinds?: BreakdownRecord[];
    execution_status?: BreakdownRecord[];
    step_status?: BreakdownRecord[];
    trigger_kinds?: BreakdownRecord[];
    policy_packs?: BreakdownRecord[];
    approval_modes?: BreakdownRecord[];
    playbook_classes?: BreakdownRecord[];
    [key: string]: unknown;
  };
  recent_executions?: ResponseExecutionRecord[];
  recent_dlq?: ResponseDlqRecord[];
  recent_ledger?: RuntimeBlob[];
  policy_packs?: RuntimeBlob[];
  governance?: RuntimeBlob;
  compliance?: RuntimeBlob;
  playbook_library?: RuntimeBlob[];
};

export type ContentBundleRecord = {
  id: string;
  title?: string;
  bundle_type?: string;
  version?: string;
  description?: string;
  objects?: number;
  signed?: boolean;
  status?: string;
  stage?: string;
  release_ring?: string;
  owner?: string;
  change_ticket?: string;
  linked_pack_id?: string;
  coverage_domains?: string[];
  personas?: string[];
  quality_gates?: RuntimeBlob;
  integrity?: RuntimeBlob;
  qa_datasets?: RuntimeBlob[];
  rollback_targets?: RuntimeBlob[];
  release_gate?: RuntimeBlob;
  last_validation_ts?: string;
  release_notes?: string;
  [key: string]: unknown;
};

export type ContentBundlesResponse = {
  items: ContentBundleRecord[];
};

export type EnterpriseReleaseGateRecord = {
  id: string;
  title?: string;
  status?: string;
  metric?: string;
  detail?: string;
  missing?: string[];
  [key: string]: unknown;
};

export type EnterpriseReleaseGatesResponse = {
  generated_ts?: string;
  summary?: {
    total?: number;
    passed?: number;
    failed?: number;
    blocked?: boolean;
  };
  gates?: EnterpriseReleaseGateRecord[];
  coverage?: RuntimeBlob;
  release_blocked?: boolean;
  next_actions?: string[];
};

export type ComplianceEvidencePackResponse = {
  generated_ts?: string;
  evidence_pack_id?: string;
  format?: string;
  title?: string;
  release_gates?: EnterpriseReleaseGatesResponse;
  content_bundles?: RuntimeBlob[];
  connector_registry?: RuntimeBlob[];
  response_library?: RuntimeBlob;
  entity_operations?: RuntimeBlob;
  governance?: RuntimeBlob;
};

export type HostRuntimeSnapshotRecord = RuntimeBlob & {
  ts?: string;
  message?: string;
  severity?: string;
  host_name?: string;
  host_role?: string;
  host_ip?: string;
  event_type?: string;
  cpu_pct?: number;
  memory_used_pct?: number;
  memory_available_bytes?: number;
  memory_available_pct?: number;
  memory_cache_bytes?: number;
  memory_cache_pct?: number;
  disk_used_pct?: number;
  load_ratio?: number;
  swap_used_pct?: number;
  memory_pressure_status?: string;
  inode_used_pct?: number;
  stale_age_seconds?: number;
};

export type HostRuntimeTargetRecord = {
  host_name: string;
  host_role?: string;
  host_ip?: string;
  last_seen_ts?: string;
  stale?: boolean;
  snapshot?: HostRuntimeSnapshotRecord;
};

export type HostRuntimeOverviewResponse = {
  generated_ts?: string;
  targets?: HostRuntimeTargetRecord[];
  latest_snapshots?: HostRuntimeSnapshotRecord[];
  recent_alerts?: HostRuntimeSnapshotRecord[];
  metrics?: {
    snapshot_events?: number;
    alert_events?: number;
    stale_targets?: number;
    cache_heavy_targets?: number;
    pressure_targets?: number;
    avg_memory_available_pct?: number;
    avg_memory_cache_pct?: number;
    stale_after_seconds?: number;
    [key: string]: unknown;
  };
  breakdowns?: {
    event_types?: BreakdownRecord[];
    [key: string]: unknown;
  };
  memory_truth?: RuntimeBlob;
};

export type CertificationHealthResponse = RuntimeBlob & {
  healthy?: boolean;
  latest_certified_ceiling_eps?: number;
  budgets?: RuntimeBlob;
  latest_benchmark?: RuntimeBlob;
  latest_drill?: RuntimeBlob;
  post_benchmark_health?: RuntimeBlob;
  last_failure_reason?: string;
  issues?: string[];
};

export type ActiveListRecord = {
  id?: string;
  list_name?: string;
  item_type?: string;
  item_value?: string;
  item_label?: string;
  tags?: string[] | string;
  [key: string]: unknown;
};

export type ActiveListsResponse = {
  items: ActiveListRecord[];
};

export type SecretRequirementRecord = {
  label: string;
  env?: string;
  status?: string;
  required?: boolean;
  description?: string;
  [key: string]: unknown;
};

export type SecretsRequiredResponse = {
  items: SecretRequirementRecord[];
};

export type SecurityServiceRecord = RuntimeBlob & {
  service_id: string;
  title: string;
  product: string;
  host_name: string;
  address: string;
  placement: string;
  role: string;
  asset_group: string;
  expected_products?: string[];
  capabilities?: string[];
  telemetry_state?: string;
  events_15m?: number;
  events_1h?: number;
  events_24h?: number;
  latest_event?: string;
  products?: string[];
  signal_types?: string[];
  pivots?: Record<string, string>;
};

export type SecurityServicesResponse = {
  generated_at?: string;
  healthy: number;
  total: number;
  items: SecurityServiceRecord[];
};

export type SecurityServiceDetailResponse = {
  generated_at?: string;
  service: SecurityServiceRecord;
  telemetry: RuntimeBlob;
  signal_breakdown: RuntimeBlob[];
  recent_events: RuntimeBlob[];
  recent_alerts: RuntimeBlob[];
};

export type IncidentListResponse = {
  view?: string;
  scope?: string;
  query?: string;
  window?: string;
  from_ts?: string;
  to_ts?: string;
  requested_limit?: number;
  available_count?: number;
  returned_count?: number;
  items: IncidentRecord[];
  metrics?: {
    agg_total?: number;
    agg_open?: number;
    raw_total?: number;
    critical_raw?: number;
    [key: string]: unknown;
  };
  status_transitions?: IncidentStatusTransitions;
  [key: string]: unknown;
};

export type IncidentDetailResponse = {
  view?: string;
  item: IncidentRecord | null;
  history?: IncidentHistoryEntry[];
  status_transitions?: IncidentStatusTransitions;
  summary?: RuntimeBlob;
  risk?: RuntimeBlob;
  entities?: RuntimeBlob;
  rules?: RuntimeBlob[];
  timeline_preview?: RuntimeBlob[];
  timeline?: RuntimeBlob[];
  raw_alerts?: {
    items?: RuntimeBlob[];
    total?: number;
    limit?: number;
    offset?: number;
    [key: string]: unknown;
  };
  related_events?: {
    items?: RuntimeBlob[];
    total?: number;
    limit?: number;
    offset?: number;
    query_scope?: RuntimeBlob;
    [key: string]: unknown;
  };
  command_evidence?: RuntimeBlob[];
  network_context?: RuntimeBlob;
  authentication_context?: RuntimeBlob;
  process_context?: RuntimeBlob;
  recommendations?: string[];
  comments?: RuntimeBlob[];
  audit_log?: RuntimeBlob[];
  technical_debug?: RuntimeBlob;
  json_view?: RuntimeBlob;
  permissions?: RuntimeBlob;
};

export type IncidentUpdateResponse = RuntimeBlob & {
  item?: IncidentRecord | null;
};

export type RuleTestResponse = RuntimeBlob;
