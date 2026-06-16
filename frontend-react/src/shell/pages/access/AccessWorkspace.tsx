import { useCallback, useEffect, useMemo, useState, type ReactNode } from "react";
import { useSearchParams } from "react-router-dom";
import { api } from "../../api";
import { AsyncGate } from "../../async";
import { t, useShellContext } from "../../context";
import { useFeedback } from "../../feedback";
import { useDebouncedValue, usePolledData } from "../../hooks";
import { describeIdentity } from "../../humanize";
import { DrawerFieldGrid, DrawerOverlay, EmptyState, InfoList, KeyValue, MetricStrip, PanelHeader, SectionIntro, StatusBadge, WorkspaceSection } from "../../ui";
import type {
  AccessGrantRecord,
  AccessSystemRecord,
  AuthGovernanceResponse,
  AuthPermissionBundleRecord,
  BreakGlassSessionRecord,
  KeycloakClientRecord,
  KeycloakUserRecord,
  LocalUsersResponse,
  RuntimeBlob,
  ServiceAccountsResponse,
} from "../../types";

type AccessTab = "overview" | "keycloak-users" | "keycloak-groups" | "keycloak-roles" | "keycloak-clients" | "recovery" | "service-accounts" | "secrets";
type KeycloakUserForm = { username: string; email: string; first_name: string; last_name: string; enabled: boolean; email_verified: boolean; password: string; group_names: string[]; roles: string[] };
type KeycloakClientForm = { client_id: string; name: string; description: string; enabled: boolean; public_client: boolean; service_accounts_enabled: boolean; redirect_uris: string; web_origins: string; root_url: string; base_url: string };
type LocalUserForm = { username: string; role: string; enabled: boolean; permissionBundles: string[]; password: string };
type ServiceAccountForm = { id: string; name: string; description: string; enabled: boolean; permissionBundles: string[] };
type AccessGrantForm = { id: string; system_id: string; role: string; sections: string[]; enabled: boolean };
type GroupMembershipFilter = "assigned" | "all" | "system" | "apps" | "realm";
type RoleMembershipFilter = "assigned" | "all" | "siem" | "defaults" | "realm";
type MembershipBucketItem = { key: string; name: string; meta: string; checked: boolean };
type MembershipBucket = { id: string; title: string; subtitle: string; items: MembershipBucketItem[] };
type UiLang = "en" | "ru";

const ACCESS_TABS: AccessTab[] = ["overview", "keycloak-users", "keycloak-groups", "keycloak-roles", "keycloak-clients", "recovery", "service-accounts", "secrets"];
const emptyKeycloakUserForm = (): KeycloakUserForm => ({ username: "", email: "", first_name: "", last_name: "", enabled: true, email_verified: false, password: "", group_names: [], roles: [] });
const emptyKeycloakClientForm = (): KeycloakClientForm => ({ client_id: "", name: "", description: "", enabled: true, public_client: false, service_accounts_enabled: false, redirect_uris: "", web_origins: "", root_url: "", base_url: "" });
const emptyLocalUserForm = (): LocalUserForm => ({ username: "", role: "viewer", enabled: true, permissionBundles: [], password: "" });
const emptyServiceAccountForm = (): ServiceAccountForm => ({ id: "", name: "", description: "", enabled: true, permissionBundles: [] });
const emptyAccessGrantForm = (): AccessGrantForm => ({ id: "", system_id: "siem", role: "", sections: [], enabled: true });
const EMPTY_LOCAL_USERS_RESPONSE: LocalUsersResponse = {
  items: [],
  available_permissions: [],
  available_roles: [],
  permission_bundles: [],
  permission_categories: [],
};
const EMPTY_SERVICE_ACCOUNTS_RESPONSE: ServiceAccountsResponse = {
  items: [],
  available_permissions: [],
  available_roles: [],
  permission_bundles: [],
  permission_categories: [],
  metrics: {},
};
const EMPTY_GOVERNANCE_RESPONSE: AuthGovernanceResponse = {};

const ACCESS_SYSTEM_TITLE_COPY: Record<string, { en: string; ru: string }> = {
  siem: { en: "SIEM", ru: "SIEM" },
  nextcloud: { en: "Nextcloud", ru: "Nextcloud" },
  gitea: { en: "Gitea", ru: "Gitea" },
  navidrome: { en: "Navidrome", ru: "Navidrome" },
  greenbone: { en: "Greenbone/OpenVAS", ru: "Greenbone/OpenVAS" },
};

const ACCESS_MODE_COPY: Record<string, { en: string; ru: string }> = {
  governance: { en: "Governance", ru: "Контур управления" },
  native_oidc: { en: "Native OIDC", ru: "Нативный OIDC" },
  proxy_extauth: { en: "Proxy external auth", ru: "Прокси с внешней аутентификацией" },
};

const ACCESS_ROLE_COPY: Record<string, Record<string, { en: string; ru: string }>> = {
  common: {
    viewer: { en: "Viewer", ru: "Наблюдатель" },
    analyst: { en: "Analyst", ru: "Аналитик" },
    operator: { en: "Operator", ru: "Оператор" },
    user: { en: "User", ru: "Пользователь" },
    admin: { en: "Admin", ru: "Администратор" },
  },
  siem: {
    viewer: { en: "Viewer", ru: "Наблюдатель" },
    analyst: { en: "Analyst", ru: "Аналитик" },
    admin: { en: "Admin", ru: "Администратор" },
  },
  nextcloud: {
    user: { en: "User", ru: "Пользователь" },
    admin: { en: "Admin", ru: "Администратор" },
  },
  gitea: {
    user: { en: "User", ru: "Пользователь" },
    admin: { en: "Admin", ru: "Администратор" },
  },
  navidrome: {
    user: { en: "User", ru: "Пользователь" },
    admin: { en: "Admin", ru: "Администратор" },
  },
};

const ACCESS_SECTION_COPY: Record<string, Record<string, { en: string; ru: string }>> = {
  siem: {
    overview: { en: "Overview", ru: "Обзор" },
    events: { en: "Events", ru: "События" },
    incidents: { en: "Incidents", ru: "Инциденты" },
    assets: { en: "Assets", ru: "Активы" },
    entities: { en: "Entities", ru: "Сущности" },
    "threat-intel": { en: "Threat Intel", ru: "Киберразведка" },
    sources: { en: "Sources", ru: "Источники" },
    builders: { en: "Builders", ru: "Конструкторы" },
    vuln: { en: "Vulnerability", ru: "Уязвимости" },
    connectors: { en: "Connectors", ru: "Коннекторы" },
    ingest: { en: "Ingest", ru: "Прием данных" },
    response: { en: "Response", ru: "Оркестрация" },
    "host-runtime": { en: "Host runtime", ru: "Состояние узлов" },
    access: { en: "Access", ru: "Доступ" },
    docs: { en: "Documentation", ru: "Документация" },
    control: { en: "Control", ru: "Управление" },
  },
  nextcloud: {
    files: { en: "Files", ru: "Файлы" },
    shares: { en: "Shares", ru: "Общий доступ" },
    groupware: { en: "Groupware", ru: "Groupware" },
    apps: { en: "Apps", ru: "Приложения" },
    admin: { en: "Admin", ru: "Администрирование" },
  },
  gitea: {
    repos: { en: "Repositories", ru: "Репозитории" },
    issues: { en: "Issues", ru: "Задачи" },
    wiki: { en: "Wiki", ru: "Wiki" },
    packages: { en: "Packages", ru: "Пакеты" },
    admin: { en: "Admin", ru: "Администрирование" },
  },
  navidrome: {
    library: { en: "Library", ru: "Медиатека" },
    playlists: { en: "Playlists", ru: "Плейлисты" },
    sharing: { en: "Sharing", ru: "Публикация" },
    admin: { en: "Admin", ru: "Администрирование" },
  },
};

function safeTab(value: string | null): AccessTab {
  return ACCESS_TABS.includes((value || "") as AccessTab) ? ((value || "") as AccessTab) : "overview";
}
function csvList(value: string) {
  return Array.from(new Set(String(value || "").split(",").map((item) => item.trim()).filter(Boolean)));
}
function joinCsv(items: string[] | undefined) {
  return (items || []).filter(Boolean).join(", ");
}
function toggleItem(current: string[], value: string) {
  return current.includes(value) ? current.filter((item) => item !== value) : [...current, value].sort();
}

function normalizeMembershipQuery(value: string) {
  return String(value || "").trim().toLowerCase();
}

function matchesMembershipQuery(parts: unknown[], query: string) {
  if (!query) return true;
  return parts.some((part) => String(part || "").toLowerCase().includes(query));
}

function classifyKeycloakGroup(name: string) {
  if (name.startsWith("sys:")) {
    return {
      filter: "system" as const,
      title: "Системные привязки",
      subtitle: "Группы управления доступом, зеркалируемые в разделы и внешние приложения.",
    };
  }
  if (/(^|[-:])(gitea|navidrome|nextcloud)([-:]|$)/i.test(name) || /-(users|admins)$/i.test(name)) {
    return {
      filter: "apps" as const,
      title: "Внешние приложения",
      subtitle: "Принадлежность к Gitea, Navidrome, Nextcloud и связанным сервисам.",
    };
  }
  return {
    filter: "realm" as const,
    title: "Группы realm",
    subtitle: "Группы Keycloak realm, не относящиеся к системным привязкам.",
  };
}

function classifyKeycloakRole(name: string) {
  if (name.startsWith("siem-")) {
    return {
      filter: "siem" as const,
      title: "Роли SIEM",
      subtitle: "Операторские роли, управляющие shell и доступом к разделам.",
    };
  }
  if (name.startsWith("default-roles-") || name === "offline_access" || name === "uma_authorization") {
    return {
      filter: "defaults" as const,
      title: "Стандартные роли Keycloak",
      subtitle: "Роли realm и протокольные роли, которые редко требуют ручного изменения.",
    };
  }
  return {
    filter: "realm" as const,
    title: "Роли realm",
    subtitle: "Пользовательские роли, не входящие в роли SIEM и стандартный набор Keycloak.",
  };
}

function describeKeycloakRole(value: unknown) {
  const description = String(value || "").trim();
  if (!description || /^\$\{.+\}$/.test(description) || description.includes("${role_")) {
    return "Стандартная роль Keycloak";
  }
  return description;
}

function localizeAccessSystemTitle(systemId: string, fallback: string | undefined, lang: UiLang) {
  const copy = ACCESS_SYSTEM_TITLE_COPY[systemId];
  if (copy) return copy[lang];
  return fallback || systemId || t(lang, { en: "System", ru: "Система" });
}

function localizeAccessMode(mode: string | undefined, lang: UiLang) {
  const key = String(mode || "governance");
  const copy = ACCESS_MODE_COPY[key];
  return copy ? copy[lang] : key.replace(/_/g, " ");
}

function localizeAccessRole(systemId: string, roleId: string, fallback: string | undefined, lang: UiLang) {
  const scoped = ACCESS_ROLE_COPY[systemId]?.[roleId];
  const common = ACCESS_ROLE_COPY.common?.[roleId];
  if (scoped) return scoped[lang];
  if (common) return common[lang];
  return fallback || roleId || t(lang, { en: "Role", ru: "Роль" });
}

function localizeAccessSection(systemId: string, sectionId: string, fallback: string | undefined, lang: UiLang) {
  const scoped = ACCESS_SECTION_COPY[systemId]?.[sectionId];
  if (scoped) return scoped[lang];
  return fallback || sectionId || t(lang, { en: "Section", ru: "Раздел" });
}

function MembershipFilterPills<T extends string>({
  value,
  onChange,
  options,
  label,
}: {
  value: T;
  onChange: (next: T) => void;
  options: Array<{ id: T; label: string }>;
  label: string;
}) {
  return (
    <div className="react-filter-chip-row" role="tablist" aria-label={label}>
      {options.map((option) => (
        <button
          key={option.id}
          type="button"
          role="tab"
          aria-selected={value === option.id}
          className={`react-filter-chip ${value === option.id ? "active" : ""}`}
          onClick={() => onChange(option.id)}
        >
          {option.label}
        </button>
      ))}
    </div>
  );
}

function CompactCard({ title, subtitle, status, children, selected = false, onClick }: { title: string; subtitle?: string; status?: string; children?: ReactNode; selected?: boolean; onClick?: () => void }) {
  const Tag = onClick ? "button" : "section";
  return (
    <Tag type={onClick ? "button" : undefined} className={`react-card react-card-button react-card-nested ${selected ? "active" : ""}`} onClick={onClick}>
      <div className="react-card-button-header">
        <div>
          <strong>{title}</strong>
          {subtitle ? <div className="react-card-button-copy">{subtitle}</div> : null}
        </div>
        {status ? <StatusBadge value={status} /> : null}
      </div>
      {children}
    </Tag>
  );
}

function BundleChecklist({ bundles, selected, onToggle }: { bundles: AuthPermissionBundleRecord[]; selected: string[]; onToggle: (bundleId: string) => void }) {
  const { lang } = useShellContext();
  return (
    <div className="react-grid react-grid-3" style={{ gap: 12 }}>
      {bundles.map((bundle) => (
        <label key={bundle.id} className="react-toggle react-toggle-card">
          <input type="checkbox" checked={selected.includes(bundle.id)} onChange={() => onToggle(bundle.id)} />
          <span><strong>{bundle.title}</strong><small>{bundle.permissions.length} {t(lang, { en: "permissions", ru: "разрешений" })}</small></span>
        </label>
      ))}
    </div>
  );
}

function WindowLauncher({
  title,
  subtitle,
  items,
  primaryLabel,
  onPrimary,
  secondary,
}: {
  title: string;
  subtitle: string;
  items: Array<{ label: string; value: ReactNode }>;
  primaryLabel: string;
  onPrimary: () => void;
  secondary?: ReactNode;
}) {
  const { lang } = useShellContext();
  return (
    <section className="react-card react-card-nested react-window-launcher">
      <div className="react-window-launcher-copy">
        <div className="react-top-kicker">{t(lang, { en: "Windowed control", ru: "Оконный режим" })}</div>
        <strong>{title}</strong>
        <p className="react-muted">{subtitle}</p>
      </div>
      <InfoList items={items} />
      <div className="react-actions react-wrap react-window-launcher-actions">
        <button type="button" className="react-primary-button" onClick={onPrimary}>
          {primaryLabel}
        </button>
        {secondary}
      </div>
    </section>
  );
}

export function AccessWorkspace() {
  const { lang, formatTimestamp } = useShellContext();
  const { pushToast } = useFeedback();
  const [searchParams, setSearchParams] = useSearchParams();
  const [refreshTick, setRefreshTick] = useState(0);
  const [creatingKeycloakUser, setCreatingKeycloakUser] = useState(false);
  const [selectedKeycloakUserId, setSelectedKeycloakUserId] = useState("");
  const [selectedClientId, setSelectedClientId] = useState("");
  const [selectedGroupId, setSelectedGroupId] = useState("");
  const [selectedRoleName, setSelectedRoleName] = useState("");
  const [selectedUsername, setSelectedUsername] = useState("");
  const [selectedServiceAccountId, setSelectedServiceAccountId] = useState("");
  const [keycloakSearch, setKeycloakSearch] = useState("");
  const [breakGlassReason, setBreakGlassReason] = useState("");
  const [breakGlassMinutes, setBreakGlassMinutes] = useState("60");
  const [tokenTitle, setTokenTitle] = useState("");
  const [tokenDays, setTokenDays] = useState("90");
  const [rotationOverlapMinutes, setRotationOverlapMinutes] = useState("15");
  const [issuedToken, setIssuedToken] = useState("");
  const [rotatedClientSecret, setRotatedClientSecret] = useState("");
  const [groupDraft, setGroupDraft] = useState("");
  const [roleDraft, setRoleDraft] = useState({ name: "", description: "" });
  const [keycloakUserForm, setKeycloakUserForm] = useState<KeycloakUserForm>(emptyKeycloakUserForm());
  const [keycloakClientForm, setKeycloakClientForm] = useState<KeycloakClientForm>(emptyKeycloakClientForm());
  const [localUserForm, setLocalUserForm] = useState<LocalUserForm>(emptyLocalUserForm());
  const [serviceAccountForm, setServiceAccountForm] = useState<ServiceAccountForm>(emptyServiceAccountForm());
  const [grantEditorOpen, setGrantEditorOpen] = useState(false);
  const [userEditorOpen, setUserEditorOpen] = useState(false);
  const [groupEditorOpen, setGroupEditorOpen] = useState(false);
  const [roleEditorOpen, setRoleEditorOpen] = useState(false);
  const [clientEditorOpen, setClientEditorOpen] = useState(false);
  const [recoveryEditorOpen, setRecoveryEditorOpen] = useState(false);
  const [serviceAccountEditorOpen, setServiceAccountEditorOpen] = useState(false);
  const [accessGrantForm, setAccessGrantForm] = useState<AccessGrantForm>(emptyAccessGrantForm());
  const [groupMembershipSearch, setGroupMembershipSearch] = useState("");
  const [roleMembershipSearch, setRoleMembershipSearch] = useState("");
  const [groupMembershipFilter, setGroupMembershipFilter] = useState<GroupMembershipFilter>("assigned");
  const [roleMembershipFilter, setRoleMembershipFilter] = useState<RoleMembershipFilter>("assigned");
  const activeTab = safeTab(searchParams.get("tab"));
  const debouncedKeycloakSearch = useDebouncedValue(keycloakSearch, 250);
  const bootstrapState = usePolledData(useCallback(() => api.bootstrap(), []), 30000);
  const bootstrapPermissions = useMemo(() => new Set(bootstrapState.data?.user?.permissions || []), [bootstrapState.data?.user?.permissions]);
  const canViewGovernance = bootstrapPermissions.has("auth:view") || bootstrapPermissions.has("auth:write");

  const setTab = useCallback((tab: AccessTab) => {
    const next = new URLSearchParams(searchParams);
    next.set("tab", tab);
    setSearchParams(next, { replace: true });
  }, [searchParams, setSearchParams]);

  const usersState = usePolledData<LocalUsersResponse>(useCallback(() => {
    void refreshTick;
    return canViewGovernance
      ? api.authUsers({ include_disabled: true })
      : Promise.resolve(EMPTY_LOCAL_USERS_RESPONSE);
  }, [canViewGovernance, refreshTick]), 30000);
  const accountsState = usePolledData<ServiceAccountsResponse>(useCallback(() => {
    void refreshTick;
    return canViewGovernance ? api.serviceAccounts() : Promise.resolve(EMPTY_SERVICE_ACCOUNTS_RESPONSE);
  }, [canViewGovernance, refreshTick]), 30000);
  const governanceState = usePolledData<AuthGovernanceResponse>(useCallback(() => {
    void refreshTick;
    return canViewGovernance ? api.authGovernance() : Promise.resolve(EMPTY_GOVERNANCE_RESPONSE);
  }, [canViewGovernance, refreshTick]), 30000);
  const providersState = usePolledData(useCallback(() => {
    void refreshTick;
    return canViewGovernance ? api.authProviders() : Promise.resolve({ items: [] });
  }, [canViewGovernance, refreshTick]), 30000);
  const certificationState = usePolledData(useCallback(() => {
    void refreshTick;
    return canViewGovernance ? api.certificationHealth() : Promise.resolve({ healthy: false, latest_certified_ceiling_eps: 0 });
  }, [canViewGovernance, refreshTick]), 30000);
  const keycloakStatusState = usePolledData(useCallback(() => {
    void refreshTick;
    return canViewGovernance ? api.keycloakStatus() : Promise.resolve({ healthy: false, admin_ready: false, inventory: {} });
  }, [canViewGovernance, refreshTick]), 30000);
  const keycloakUsersState = usePolledData(useCallback(() => {
    void refreshTick;
    return canViewGovernance ? api.keycloakUsers({ search: debouncedKeycloakSearch, limit: 250 }) : Promise.resolve({ items: [] });
  }, [canViewGovernance, debouncedKeycloakSearch, refreshTick]), 30000);
  const accessSystemsState = usePolledData(useCallback(() => {
    void refreshTick;
    return canViewGovernance ? api.accessSystems({ grantable_only: true }) : Promise.resolve({ items: [] });
  }, [canViewGovernance, refreshTick]), 30000);
  const keycloakUserDetailState = usePolledData(useCallback(() => {
    return canViewGovernance && selectedKeycloakUserId ? api.keycloakUserDetail(selectedKeycloakUserId) : Promise.resolve({ item: null });
  }, [canViewGovernance, selectedKeycloakUserId]), 30000);
  const accessGrantsState = usePolledData(useCallback(() => {
    const principalId = creatingKeycloakUser ? "" : String((keycloakUserDetailState.data?.item as RuntimeBlob | undefined)?.username || "");
    return canViewGovernance && principalId
      ? api.accessGrants({ principal_kind: "keycloak_user", principal_id: principalId, include_disabled: true })
      : Promise.resolve({ items: [] });
  }, [canViewGovernance, creatingKeycloakUser, keycloakUserDetailState.data?.item]), 30000);
  const keycloakGroupsState = usePolledData(useCallback(() => {
    void refreshTick;
    return canViewGovernance ? api.keycloakGroups() : Promise.resolve({ items: [] });
  }, [canViewGovernance, refreshTick]), 30000);
  const keycloakRolesState = usePolledData(useCallback(() => {
    void refreshTick;
    return canViewGovernance ? api.keycloakRoles() : Promise.resolve({ items: [] });
  }, [canViewGovernance, refreshTick]), 30000);
  const keycloakClientsState = usePolledData(useCallback(() => {
    void refreshTick;
    return canViewGovernance ? api.keycloakClients() : Promise.resolve({ items: [] });
  }, [canViewGovernance, refreshTick]), 30000);
  const keycloakClientDetailState = usePolledData(useCallback(() => {
    return canViewGovernance && selectedClientId ? api.keycloakClientDetail(selectedClientId) : Promise.resolve({ item: null });
  }, [canViewGovernance, selectedClientId]), 30000);
  const serviceAccountDetailState = usePolledData(useCallback(() => {
    return canViewGovernance && selectedServiceAccountId ? api.serviceAccountDetail(selectedServiceAccountId) : Promise.resolve({ item: null, tokens: [] });
  }, [canViewGovernance, selectedServiceAccountId]), 30000);

  const copy = useMemo(() => ({
    kicker: t(lang, { en: "Identity", ru: "Идентификация" }),
    title: t(lang, { en: "Identity control center", ru: "Центр управления идентификацией" }),
    subtitle: t(lang, { en: "Operate Keycloak realm identities, break-glass recovery, service accounts and vault-backed secret posture from one workspace.", ru: "Управляйте идентичностями Keycloak, аварийным доступом, сервисными учетными записями и состоянием секретов из защищенного хранилища в одном рабочем центре." }),
    labels: {
      overview: t(lang, { en: "Overview", ru: "Обзор" }),
      "keycloak-users": t(lang, { en: "Keycloak users", ru: "Пользователи Keycloak" }),
      "keycloak-groups": t(lang, { en: "Groups", ru: "Группы" }),
      "keycloak-roles": t(lang, { en: "Roles", ru: "Роли" }),
      "keycloak-clients": t(lang, { en: "Clients", ru: "Клиенты" }),
      recovery: t(lang, { en: "Recovery", ru: "Восстановление" }),
      "service-accounts": t(lang, { en: "Service accounts", ru: "Сервисные учетные записи" }),
      secrets: t(lang, { en: "Secrets", ru: "Секреты" }),
    } as Record<AccessTab, string>,
  }), [lang]);

  const localUsers = useMemo(() => usersState.data?.items || [], [usersState.data?.items]);
  const serviceAccounts = useMemo(() => accountsState.data?.items || [], [accountsState.data?.items]);
  const permissionBundles = (usersState.data?.permission_bundles || accountsState.data?.permission_bundles || []) as AuthPermissionBundleRecord[];
  const permissionCategories = usersState.data?.permission_categories || accountsState.data?.permission_categories || [];
  const providers = providersState.data?.items || [];
  const governance = governanceState.data || {};
  const breakGlassItems = (((governance.break_glass as RuntimeBlob | undefined)?.items as BreakGlassSessionRecord[]) || []) as BreakGlassSessionRecord[];
  const secretItems = (((governance.secrets as RuntimeBlob | undefined)?.items as RuntimeBlob[]) || []) as RuntimeBlob[];
  const secretSummary = ((governance.secrets as RuntimeBlob | undefined)?.summary || {}) as RuntimeBlob;
  const keycloakUsers = useMemo(() => keycloakUsersState.data?.items || [], [keycloakUsersState.data?.items]);
  const selectedKeycloakUser = (keycloakUserDetailState.data?.item || null) as KeycloakUserRecord | null;
  const selectedIdentity = useMemo(() => describeIdentity(selectedKeycloakUser || {}, lang), [lang, selectedKeycloakUser]);
  const keycloakGroups = useMemo(() => keycloakGroupsState.data?.items || [], [keycloakGroupsState.data?.items]);
  const keycloakRoles = useMemo(() => keycloakRolesState.data?.items || [], [keycloakRolesState.data?.items]);
  const keycloakClients = useMemo(() => keycloakClientsState.data?.items || [], [keycloakClientsState.data?.items]);
  const selectedKeycloakClient = (keycloakClientDetailState.data?.item || null) as KeycloakClientRecord | null;
  const accessSystems = useMemo(() => (accessSystemsState.data?.items || []) as AccessSystemRecord[], [accessSystemsState.data?.items]);
  const accessGrants = useMemo(() => (accessGrantsState.data?.items || []) as AccessGrantRecord[], [accessGrantsState.data?.items]);
  const accessSystemIndex = useMemo(
    () => new Map(accessSystems.map((item) => [String(item.id || ""), item])),
    [accessSystems],
  );

  const metrics = [
    { label: t(lang, { en: "SSO providers", ru: "Провайдеры SSO" }), value: providers.length, hint: t(lang, { en: "OIDC and recovery entry paths.", ru: "Точки входа OIDC и аварийного восстановления." }), tone: providers.some((item) => item.healthy) ? ("success" as const) : ("warning" as const) },
    { label: t(lang, { en: "Keycloak users", ru: "Пользователи Keycloak" }), value: Number((keycloakStatusState.data?.inventory as RuntimeBlob | undefined)?.users || keycloakUsers.length || 0), hint: t(lang, { en: "Realm identities visible to the admin client.", ru: "Идентичности realm, видимые админскому клиенту." }), tone: keycloakStatusState.data?.healthy ? ("success" as const) : ("warning" as const) },
    { label: t(lang, { en: "Vault refs", ru: "Vault-ссылки" }), value: Number(secretSummary.vault_backed || 0), hint: t(lang, { en: "Runtime secrets resolved through Vault.", ru: "Секреты runtime, разрешенные через Vault." }), tone: Number(secretSummary.vault_backed || 0) > 0 ? ("success" as const) : ("warning" as const) },
    { label: t(lang, { en: "Break-glass active", ru: "Аварийные сессии" }), value: Number((((governance.break_glass as RuntimeBlob | undefined)?.metrics as RuntimeBlob | undefined)?.active) || 0), hint: t(lang, { en: "Emergency local sessions currently open.", ru: "Локальные аварийные сессии, открытые сейчас." }), tone: Number((((governance.break_glass as RuntimeBlob | undefined)?.metrics as RuntimeBlob | undefined)?.active) || 0) ? ("warning" as const) : ("success" as const) },
    { label: t(lang, { en: "Service accounts", ru: "Сервисные учетные записи" }), value: serviceAccounts.length, hint: t(lang, { en: "Machine principals used by integrations and automation.", ru: "Машинные учетные записи интеграций и автоматизации." }), tone: "default" as const },
    { label: t(lang, { en: "Certified EPS", ru: "Сертифицированный EPS" }), value: Number((certificationState.data as RuntimeBlob | undefined)?.latest_certified_ceiling_eps || 0), hint: t(lang, { en: "Current certified operating ceiling.", ru: "Текущий сертифицированный рабочий потолок." }), tone: (certificationState.data as RuntimeBlob | undefined)?.healthy ? ("success" as const) : ("warning" as const) },
  ];

  useEffect(() => {
    if (!creatingKeycloakUser && !selectedKeycloakUserId && keycloakUsers.length) {
      setSelectedKeycloakUserId(String(keycloakUsers[0].id || ""));
    }
  }, [creatingKeycloakUser, keycloakUsers, selectedKeycloakUserId]);
  useEffect(() => { if (!selectedClientId && keycloakClients.length) setSelectedClientId(String(keycloakClients[0].client_id || keycloakClients[0].id || "")); }, [keycloakClients, selectedClientId]);
  useEffect(() => { if (!selectedUsername && localUsers.length) setSelectedUsername(localUsers[0].username); }, [localUsers, selectedUsername]);
  useEffect(() => { if (!selectedServiceAccountId && serviceAccounts.length) setSelectedServiceAccountId(String(serviceAccounts[0].id || "")); }, [selectedServiceAccountId, serviceAccounts]);
  useEffect(() => { if (!selectedGroupId && keycloakGroups.length) setSelectedGroupId(String(keycloakGroups[0].id || "")); }, [keycloakGroups, selectedGroupId]);
  useEffect(() => { if (!selectedRoleName && keycloakRoles.length) setSelectedRoleName(String(keycloakRoles[0].name || "")); }, [keycloakRoles, selectedRoleName]);
  useEffect(() => { setGroupDraft(String(keycloakGroups.find((item) => String(item.id || "") === selectedGroupId)?.name || "")); }, [keycloakGroups, selectedGroupId]);
  useEffect(() => { const item = keycloakRoles.find((entry) => String(entry.name || "") === selectedRoleName); setRoleDraft({ name: String(item?.name || ""), description: String(item?.description || "") }); }, [keycloakRoles, selectedRoleName]);
  useEffect(() => {
    if (!userEditorOpen) return;
    setGroupMembershipSearch("");
    setRoleMembershipSearch("");
    setGroupMembershipFilter(creatingKeycloakUser || !keycloakUserForm.group_names.length ? "all" : "assigned");
    setRoleMembershipFilter(creatingKeycloakUser || !keycloakUserForm.roles.length ? "all" : "assigned");
  }, [creatingKeycloakUser, keycloakUserForm.group_names.length, keycloakUserForm.roles.length, selectedKeycloakUserId, userEditorOpen]);

  const groupMembershipBuckets = useMemo<MembershipBucket[]>(() => {
    const query = normalizeMembershipQuery(groupMembershipSearch);
    const buckets = new Map<string, MembershipBucket>([
      ["system", { id: "system", title: "Системные привязки", subtitle: "Группы управления доступом, зеркалируемые в разделы и внешние приложения.", items: [] }],
      ["apps", { id: "apps", title: "Внешние приложения", subtitle: "App-facing membership для Gitea, Navidrome, Nextcloud и связанных клиентов.", items: [] }],
      ["realm", { id: "realm", title: "Группы realm", subtitle: "Прямые группы Keycloak realm вне слоя системных привязок.", items: [] }],
    ]);
    const seen = new Set<string>();
    keycloakGroups.forEach((group) => {
      const name = String(group.name || "");
      if (!name) return;
      const path = String(group.path || "/");
      const checked = keycloakUserForm.group_names.includes(name);
      const classification = classifyKeycloakGroup(name);
      if (groupMembershipFilter === "assigned" && !checked) return;
      if (groupMembershipFilter !== "all" && groupMembershipFilter !== "assigned" && classification.filter !== groupMembershipFilter) return;
      if (!matchesMembershipQuery([name, path, classification.title], query)) return;
      seen.add(name);
      buckets.get(classification.filter)?.items.push({
        key: String(group.id || name),
        name,
        meta: path,
        checked,
      });
    });
    keycloakUserForm.group_names
      .filter((name) => !seen.has(name))
      .forEach((name) => {
        if (groupMembershipFilter !== "all" && groupMembershipFilter !== "assigned" && groupMembershipFilter !== "realm") return;
        if (!matchesMembershipQuery([name, "Назначено вне текущего инвентаря", "Группы realm"], query)) return;
        buckets.get("realm")?.items.push({
          key: `missing-${name}`,
          name,
          meta: "Назначено вне текущего инвентаря",
          checked: true,
        });
      });
    return Array.from(buckets.values())
      .map((bucket) => ({
        ...bucket,
        items: bucket.items.sort((left, right) => Number(right.checked) - Number(left.checked) || left.name.localeCompare(right.name)),
      }))
      .filter((bucket) => bucket.items.length);
  }, [groupMembershipFilter, groupMembershipSearch, keycloakGroups, keycloakUserForm.group_names]);
  const roleMembershipBuckets = useMemo<MembershipBucket[]>(() => {
    const query = normalizeMembershipQuery(roleMembershipSearch);
    const buckets = new Map<string, MembershipBucket>([
      ["siem", { id: "siem", title: "Роли SIEM", subtitle: "Операторские роли, управляющие shell и доступом к разделам.", items: [] }],
      ["defaults", { id: "defaults", title: "Стандартные роли Keycloak", subtitle: "Роли realm и протокольные роли, которые редко требуют ручного изменения.", items: [] }],
      ["realm", { id: "realm", title: "Роли realm", subtitle: "Пользовательские роли вне ролей SIEM и стандартного набора Keycloak.", items: [] }],
    ]);
    const seen = new Set<string>();
    keycloakRoles.forEach((role) => {
      const name = String(role.name || "");
      if (!name) return;
      const description = describeKeycloakRole(role.description);
      const checked = keycloakUserForm.roles.includes(name);
      const classification = classifyKeycloakRole(name);
      if (roleMembershipFilter === "assigned" && !checked) return;
      if (roleMembershipFilter !== "all" && roleMembershipFilter !== "assigned" && classification.filter !== roleMembershipFilter) return;
      if (!matchesMembershipQuery([name, description, classification.title], query)) return;
      seen.add(name);
      buckets.get(classification.filter)?.items.push({
        key: name,
        name,
        meta: description,
        checked,
      });
    });
    keycloakUserForm.roles
      .filter((name) => !seen.has(name))
      .forEach((name) => {
        if (roleMembershipFilter !== "all" && roleMembershipFilter !== "assigned" && roleMembershipFilter !== "realm") return;
        if (!matchesMembershipQuery([name, "Назначено вне текущего инвентаря", "Роли realm"], query)) return;
        buckets.get("realm")?.items.push({
          key: `missing-${name}`,
          name,
          meta: "Назначено вне текущего инвентаря",
          checked: true,
        });
      });
    return Array.from(buckets.values())
      .map((bucket) => ({
        ...bucket,
        items: bucket.items.sort((left, right) => Number(right.checked) - Number(left.checked) || left.name.localeCompare(right.name)),
      }))
      .filter((bucket) => bucket.items.length);
  }, [keycloakRoles, keycloakUserForm.roles, roleMembershipFilter, roleMembershipSearch]);
  const visibleGroupMembershipCount = groupMembershipBuckets.reduce((total, bucket) => total + bucket.items.length, 0);
  const visibleRoleMembershipCount = roleMembershipBuckets.reduce((total, bucket) => total + bucket.items.length, 0);
  useEffect(() => {
    if (creatingKeycloakUser) {
      setKeycloakUserForm(emptyKeycloakUserForm());
      return;
    }
    if (!selectedKeycloakUser) {
      setKeycloakUserForm(emptyKeycloakUserForm());
      return;
    }
    setKeycloakUserForm({
      username: String(selectedKeycloakUser.username || ""),
      email: String(selectedKeycloakUser.email || ""),
      first_name: String(selectedKeycloakUser.first_name || ""),
      last_name: String(selectedKeycloakUser.last_name || ""),
      enabled: Boolean(selectedKeycloakUser.enabled),
      email_verified: Boolean(selectedKeycloakUser.email_verified),
      password: "",
      group_names: (selectedKeycloakUser.groups || []).map((item) => String(item.name || "")).filter(Boolean),
      roles: (selectedKeycloakUser.roles || []).map((item) => String(item.name || "")).filter(Boolean),
    });
  }, [creatingKeycloakUser, selectedKeycloakUser]);
  useEffect(() => { if (!selectedKeycloakClient) { setKeycloakClientForm(emptyKeycloakClientForm()); return; } setKeycloakClientForm({ client_id: String(selectedKeycloakClient.client_id || ""), name: String(selectedKeycloakClient.name || ""), description: String(selectedKeycloakClient.description || ""), enabled: Boolean(selectedKeycloakClient.enabled ?? true), public_client: Boolean(selectedKeycloakClient.public_client), service_accounts_enabled: Boolean(selectedKeycloakClient.service_accounts_enabled), redirect_uris: joinCsv(selectedKeycloakClient.redirect_uris), web_origins: joinCsv(selectedKeycloakClient.web_origins), root_url: String(selectedKeycloakClient.root_url || ""), base_url: String(selectedKeycloakClient.base_url || "") }); }, [selectedKeycloakClient]);
  useEffect(() => { const localUser = localUsers.find((item) => item.username === selectedUsername); setLocalUserForm(localUser ? { username: localUser.username, role: localUser.role || "viewer", enabled: Boolean(localUser.enabled), permissionBundles: localUser.permission_bundles || [], password: "" } : emptyLocalUserForm()); }, [localUsers, selectedUsername]);
  useEffect(() => { const account = serviceAccounts.find((item) => String(item.id || "") === selectedServiceAccountId); setServiceAccountForm(account ? { id: String(account.id || ""), name: String(account.name || ""), description: String(account.description || ""), enabled: Boolean(account.enabled), permissionBundles: account.permission_bundles || [] } : emptyServiceAccountForm()); }, [selectedServiceAccountId, serviceAccounts]);
  useEffect(() => {
    const selectedSystem = accessSystems.find((item) => item.id === accessGrantForm.system_id) || accessSystems[0] || null;
    if (!selectedSystem) return;
    const roleOptions = (selectedSystem.roles || []).map((item) => item.id).filter(Boolean);
    const sectionOptions = (selectedSystem.sections || []).map((item) => item.id).filter(Boolean);
    const nextSystemId = accessGrantForm.system_id || String(selectedSystem.id || "siem");
    const nextRole = roleOptions.includes(accessGrantForm.role) ? accessGrantForm.role : String(roleOptions[0] || "");
    const nextSections = accessGrantForm.sections.filter((item) => sectionOptions.includes(item)).length
      ? accessGrantForm.sections.filter((item) => sectionOptions.includes(item))
      : [...sectionOptions];
    if (
      nextSystemId === accessGrantForm.system_id &&
      nextRole === accessGrantForm.role &&
      nextSections.join("|") === accessGrantForm.sections.join("|")
    ) {
      return;
    }
    setAccessGrantForm((current) => ({
      ...current,
      system_id: nextSystemId,
      role: nextRole,
      sections: nextSections,
    }));
  }, [accessGrantForm.role, accessGrantForm.sections, accessGrantForm.system_id, accessSystems]);

  async function saveKeycloakUser() {
    try {
      const payload = {
        username: keycloakUserForm.username,
        email: keycloakUserForm.email,
        first_name: keycloakUserForm.first_name,
        last_name: keycloakUserForm.last_name,
        enabled: keycloakUserForm.enabled,
        email_verified: keycloakUserForm.email_verified,
        group_names: keycloakUserForm.group_names,
        roles: keycloakUserForm.roles,
        ...(keycloakUserForm.password.trim() ? { password: keycloakUserForm.password } : {}),
      };
      const saved =
        !creatingKeycloakUser && selectedKeycloakUser
          ? await api.updateKeycloakUser(String(selectedKeycloakUser.id || ""), payload)
          : await api.createKeycloakUser(payload);
      setCreatingKeycloakUser(false);
      setSelectedKeycloakUserId(String(saved.id || ""));
      setKeycloakUserForm((current) => ({ ...current, password: "" }));
      setUserEditorOpen(false);
      setRefreshTick((value) => value + 1);
      pushToast({ title: !creatingKeycloakUser && selectedKeycloakUser ? t(lang, { en: "Keycloak user saved", ru: "Пользователь Keycloak сохранен" }) : t(lang, { en: "Keycloak user created", ru: "Пользователь Keycloak создан" }), message: String(saved.username || saved.id || ""), tone: "success" });
    } catch (error) {
      pushToast({ title: t(lang, { en: "Keycloak user save failed", ru: "Не удалось сохранить пользователя Keycloak" }), message: error instanceof Error ? error.message : t(lang, { en: "Save failed", ru: "Сохранение не удалось" }), tone: "error" });
    }
  }
  async function deleteSelectedKeycloakUser() { if (!selectedKeycloakUser) return; try { const result = await api.deleteKeycloakUser(String(selectedKeycloakUser.id || "")); const deletedName = String((result as RuntimeBlob).username || selectedKeycloakUser.username || selectedKeycloakUser.id || "user"); setCreatingKeycloakUser(false); setSelectedKeycloakUserId(""); setKeycloakUserForm(emptyKeycloakUserForm()); setUserEditorOpen(false); setRefreshTick((value) => value + 1); pushToast({ title: t(lang, { en: "Keycloak user deleted", ru: "Пользователь Keycloak удален" }), message: deletedName, tone: "success" }); } catch (error) { pushToast({ title: t(lang, { en: "Keycloak user delete failed", ru: "Не удалось удалить пользователя Keycloak" }), message: error instanceof Error ? error.message : t(lang, { en: "Delete failed", ru: "Удаление не удалось" }), tone: "error" }); } }
  async function rotateKeycloakPassword() { if (!selectedKeycloakUser || !keycloakUserForm.password.trim()) return; try { await api.setKeycloakUserPassword(String(selectedKeycloakUser.id || ""), { password: keycloakUserForm.password, temporary: false }); setKeycloakUserForm((current) => ({ ...current, password: "" })); setUserEditorOpen(false); setRefreshTick((value) => value + 1); pushToast({ title: t(lang, { en: "Password rotated", ru: "Пароль обновлен" }), message: String(selectedKeycloakUser.username || selectedKeycloakUser.id || ""), tone: "success" }); } catch (error) { pushToast({ title: t(lang, { en: "Password rotation failed", ru: "Не удалось обновить пароль" }), message: error instanceof Error ? error.message : t(lang, { en: "Rotate failed", ru: "Обновление не удалось" }), tone: "error" }); } }
  async function saveGroup() { if (!groupDraft.trim()) return; try { const saved = selectedGroupId ? await api.updateKeycloakGroup(selectedGroupId, { name: groupDraft }) : await api.saveKeycloakGroup({ name: groupDraft }); setSelectedGroupId(String(saved.id || "")); setGroupEditorOpen(false); setRefreshTick((value) => value + 1); pushToast({ title: t(lang, { en: "Group saved", ru: "Группа сохранена" }), message: String(saved.name || saved.id || ""), tone: "success" }); } catch (error) { pushToast({ title: t(lang, { en: "Group save failed", ru: "Не удалось сохранить группу" }), message: error instanceof Error ? error.message : t(lang, { en: "Save failed", ru: "Сохранение не удалось" }), tone: "error" }); } }
  async function saveRole() { if (!roleDraft.name.trim()) return; try { const saved = selectedRoleName ? await api.updateKeycloakRole(selectedRoleName, roleDraft) : await api.saveKeycloakRole(roleDraft); setSelectedRoleName(String(saved.name || "")); setRoleEditorOpen(false); setRefreshTick((value) => value + 1); pushToast({ title: t(lang, { en: "Role saved", ru: "Роль сохранена" }), message: String(saved.name || ""), tone: "success" }); } catch (error) { pushToast({ title: t(lang, { en: "Role save failed", ru: "Не удалось сохранить роль" }), message: error instanceof Error ? error.message : t(lang, { en: "Save failed", ru: "Сохранение не удалось" }), tone: "error" }); } }
  async function saveClient() { try { const payload = { client_id: keycloakClientForm.client_id, name: keycloakClientForm.name, description: keycloakClientForm.description, enabled: keycloakClientForm.enabled, public_client: keycloakClientForm.public_client, service_accounts_enabled: keycloakClientForm.service_accounts_enabled, redirect_uris: csvList(keycloakClientForm.redirect_uris), web_origins: csvList(keycloakClientForm.web_origins), root_url: keycloakClientForm.root_url, base_url: keycloakClientForm.base_url }; const saved = selectedKeycloakClient ? await api.updateKeycloakClient(String(selectedKeycloakClient.client_id || selectedKeycloakClient.id || ""), payload) : await api.saveKeycloakClient(payload); setSelectedClientId(String(saved.client_id || saved.id || "")); setClientEditorOpen(false); setRefreshTick((value) => value + 1); pushToast({ title: t(lang, { en: "Client saved", ru: "Клиент сохранен" }), message: String(saved.client_id || saved.id || ""), tone: "success" }); } catch (error) { pushToast({ title: t(lang, { en: "Client save failed", ru: "Не удалось сохранить клиент" }), message: error instanceof Error ? error.message : t(lang, { en: "Save failed", ru: "Сохранение не удалось" }), tone: "error" }); } }
  async function rotateClientSecret() { if (!selectedKeycloakClient) return; try { const result = await api.rotateKeycloakClientSecret(String(selectedKeycloakClient.client_id || selectedKeycloakClient.id || "")); setRotatedClientSecret(String(result.secret || "")); setClientEditorOpen(false); setRefreshTick((value) => value + 1); pushToast({ title: t(lang, { en: "Client secret rotated", ru: "Секрет клиента обновлен" }), message: String(result.client_id || selectedKeycloakClient.client_id || ""), tone: "success" }); } catch (error) { pushToast({ title: t(lang, { en: "Client secret rotation failed", ru: "Не удалось обновить секрет клиента" }), message: error instanceof Error ? error.message : t(lang, { en: "Rotate failed", ru: "Обновление не удалось" }), tone: "error" }); } }
  async function saveLocalUser() { try { const saved = await api.saveLocalUser({ username: localUserForm.username, role: localUserForm.role, enabled: localUserForm.enabled, permission_bundles: localUserForm.permissionBundles, ...(localUserForm.password.trim() ? { password: localUserForm.password } : {}) }); setSelectedUsername(saved.username); setLocalUserForm((current) => ({ ...current, password: "" })); setRecoveryEditorOpen(false); setRefreshTick((value) => value + 1); pushToast({ title: t(lang, { en: "Break-glass user saved", ru: "Аварийный пользователь сохранен" }), message: saved.username, tone: "success" }); } catch (error) { pushToast({ title: t(lang, { en: "Break-glass user save failed", ru: "Не удалось сохранить аварийного пользователя" }), message: error instanceof Error ? error.message : t(lang, { en: "Save failed", ru: "Сохранение не удалось" }), tone: "error" }); } }
  async function rotateLocalPassword() { if (!selectedUsername || !localUserForm.password.trim()) return; try { await api.setLocalUserPassword(selectedUsername, { password: localUserForm.password }); setLocalUserForm((current) => ({ ...current, password: "" })); setRecoveryEditorOpen(false); setRefreshTick((value) => value + 1); pushToast({ title: t(lang, { en: "Recovery password rotated", ru: "Пароль аварийного доступа обновлен" }), message: selectedUsername, tone: "success" }); } catch (error) { pushToast({ title: t(lang, { en: "Recovery password rotation failed", ru: "Не удалось обновить пароль аварийного доступа" }), message: error instanceof Error ? error.message : t(lang, { en: "Rotate failed", ru: "Обновление не удалось" }), tone: "error" }); } }
  async function openBreakGlass() { try { const principalName = selectedUsername || localUsers[0]?.username || "admin"; await api.mutateBreakGlass({ action: "open", username: principalName, reason: breakGlassReason || t(lang, { en: "Manual recovery session", ru: "Ручная аварийная сессия" }), expires_minutes: Number(breakGlassMinutes || 60) }); setBreakGlassReason(""); setRecoveryEditorOpen(false); setRefreshTick((value) => value + 1); pushToast({ title: t(lang, { en: "Break-glass session opened", ru: "Аварийная сессия открыта" }), message: principalName, tone: "success" }); } catch (error) { pushToast({ title: t(lang, { en: "Break-glass session open failed", ru: "Не удалось открыть аварийную сессию" }), message: error instanceof Error ? error.message : t(lang, { en: "Open failed", ru: "Открытие не удалось" }), tone: "error" }); } }
  async function revokeBreakGlass(sessionId: string) { try { await api.mutateBreakGlass({ action: "revoke", session_id: sessionId, reason: t(lang, { en: "Closed from control center", ru: "Закрыто из центра управления" }) }); setRefreshTick((value) => value + 1); pushToast({ title: t(lang, { en: "Break-glass revoked", ru: "Аварийная сессия закрыта" }), message: sessionId, tone: "success" }); } catch (error) { pushToast({ title: t(lang, { en: "Break-glass revoke failed", ru: "Не удалось закрыть аварийную сессию" }), message: error instanceof Error ? error.message : t(lang, { en: "Revoke failed", ru: "Закрытие не удалось" }), tone: "error" }); } }
  async function saveServiceAccount() { try { const saved = await api.saveServiceAccount({ id: serviceAccountForm.id || undefined, name: serviceAccountForm.name, description: serviceAccountForm.description, enabled: serviceAccountForm.enabled, permission_bundles: serviceAccountForm.permissionBundles }); setSelectedServiceAccountId(String(saved.id || "")); setServiceAccountEditorOpen(false); setRefreshTick((value) => value + 1); pushToast({ title: t(lang, { en: "Service account saved", ru: "Сервисная учетная запись сохранена" }), message: saved.name, tone: "success" }); } catch (error) { pushToast({ title: t(lang, { en: "Service account save failed", ru: "Не удалось сохранить сервисную учетную запись" }), message: error instanceof Error ? error.message : t(lang, { en: "Save failed", ru: "Сохранение не удалось" }), tone: "error" }); } }
  async function issueServiceToken() { if (!selectedServiceAccountId) return; try { const result = await api.issueServiceAccountToken(selectedServiceAccountId, { title: tokenTitle || t(lang, { en: "Rotation token", ru: "Токен ротации" }), expires_days: Number(tokenDays || 90) }); setIssuedToken(String(result.token?.token || "")); setTokenTitle(""); setServiceAccountEditorOpen(false); setRefreshTick((value) => value + 1); pushToast({ title: t(lang, { en: "Service token issued", ru: "Сервисный токен выпущен" }), message: String(result.token?.title || result.token?.id || ""), tone: "success" }); } catch (error) { pushToast({ title: t(lang, { en: "Token issue failed", ru: "Не удалось выпустить токен" }), message: error instanceof Error ? error.message : t(lang, { en: "Issue failed", ru: "Выпуск не удался" }), tone: "error" }); } }
  async function rotateServiceToken() { if (!selectedServiceAccountId) return; try { const result = await api.rotateServiceAccountToken(selectedServiceAccountId, { title: tokenTitle || `rotation-${Date.now()}`, expires_days: Number(tokenDays || 90), overlap_minutes: Number(rotationOverlapMinutes || 15), revoke_predecessor: true }); setIssuedToken(String(((result as RuntimeBlob).token as RuntimeBlob | undefined)?.token || "")); setServiceAccountEditorOpen(false); setRefreshTick((value) => value + 1); pushToast({ title: t(lang, { en: "Service token rotated", ru: "Сервисный токен обновлен" }), message: selectedServiceAccountId, tone: "success" }); } catch (error) { pushToast({ title: t(lang, { en: "Token rotation failed", ru: "Не удалось обновить токен" }), message: error instanceof Error ? error.message : t(lang, { en: "Rotate failed", ru: "Обновление не удалось" }), tone: "error" }); } }
  async function revokeServiceToken(tokenId: string) { if (!selectedServiceAccountId) return; try { await api.revokeServiceAccountToken(selectedServiceAccountId, tokenId); setRefreshTick((value) => value + 1); pushToast({ title: t(lang, { en: "Token revoked", ru: "Токен отозван" }), message: tokenId, tone: "success" }); } catch (error) { pushToast({ title: t(lang, { en: "Token revoke failed", ru: "Не удалось отозвать токен" }), message: error instanceof Error ? error.message : t(lang, { en: "Revoke failed", ru: "Отзыв не удался" }), tone: "error" }); } }
  function openNewAccessGrant() {
    const defaultSystem = accessSystems[0] || null;
    setAccessGrantForm({
      id: "",
      system_id: String(defaultSystem?.id || "siem"),
      role: String(defaultSystem?.roles?.[0]?.id || ""),
      sections: (defaultSystem?.sections || []).map((item) => String(item.id || "")).filter(Boolean),
      enabled: true,
    });
    setGrantEditorOpen(true);
  }
  function openExistingAccessGrant(grant: AccessGrantRecord) {
    setAccessGrantForm({
      id: String(grant.id || ""),
      system_id: String(grant.system_id || "siem"),
      role: String(grant.role || ""),
      sections: [...(grant.sections || [])],
      enabled: Boolean(grant.enabled ?? true),
    });
    setGrantEditorOpen(true);
  }
  async function saveAccessGrant() {
    if (!selectedKeycloakUser && !creatingKeycloakUser) return;
    const principalId = String(selectedKeycloakUser?.username || "");
    if (!principalId) {
        pushToast({ title: t(lang, { en: "Create the user first", ru: "Сначала создайте пользователя" }), message: t(lang, { en: "System grants can be added after the Keycloak user exists.", ru: "Системные права можно назначить только после создания пользователя Keycloak." }), tone: "warning" });
      return;
    }
    try {
      const payload = {
        principal_kind: "keycloak_user",
        principal_id: principalId,
        system_id: accessGrantForm.system_id,
        role: accessGrantForm.role,
        sections: accessGrantForm.sections,
        enabled: accessGrantForm.enabled,
      };
      const saved = accessGrantForm.id ? await api.updateAccessGrant(accessGrantForm.id, payload) : await api.saveAccessGrant(payload);
      setGrantEditorOpen(false);
      setAccessGrantForm(emptyAccessGrantForm());
      setRefreshTick((value) => value + 1);
      pushToast({ title: t(lang, { en: "System access saved", ru: "Системный доступ сохранен" }), message: `${localizeAccessSystemTitle(String(saved.system_id || ""), String(saved.system_title || saved.system_id || ""), lang)}: ${localizeAccessRole(String(saved.system_id || ""), String(saved.role || ""), String(saved.role || ""), lang)}`, tone: "success" });
    } catch (error) {
      pushToast({ title: t(lang, { en: "System access save failed", ru: "Не удалось сохранить системный доступ" }), message: error instanceof Error ? error.message : t(lang, { en: "Save failed", ru: "Сохранение не удалось" }), tone: "error" });
    }
  }
  async function removeAccessGrant(grantId: string) {
    try {
      const deleted = await api.deleteAccessGrant(grantId);
      setRefreshTick((value) => value + 1);
      pushToast({ title: t(lang, { en: "System access removed", ru: "Системный доступ удален" }), message: localizeAccessSystemTitle(String(deleted.system_id || ""), String(deleted.system_title || deleted.system_id || grantId), lang), tone: "success" });
    } catch (error) {
      pushToast({ title: t(lang, { en: "System access delete failed", ru: "Не удалось удалить системный доступ" }), message: error instanceof Error ? error.message : t(lang, { en: "Delete failed", ru: "Удаление не удалось" }), tone: "error" });
    }
  }

  return (
    <AsyncGate
      states={[
        bootstrapState,
        usersState,
        accountsState,
        governanceState,
        providersState,
        certificationState,
        keycloakStatusState,
        keycloakUsersState,
        accessSystemsState,
        keycloakUserDetailState,
        accessGrantsState,
        keycloakGroupsState,
        keycloakRolesState,
        keycloakClientsState,
        keycloakClientDetailState,
        serviceAccountDetailState,
      ]}
      loadingMessage="Loading identity control center..."
    >
      <div className="react-page react-page-access">
        <SectionIntro kicker={copy.kicker} title={copy.title} subtitle={copy.subtitle} icon="access" />
        <MetricStrip items={metrics} />
        {!canViewGovernance ? (
          <div className="react-grid react-grid-2">
            <WorkspaceSection title="Identity workspace" subtitle="The Access section remains visible in the shell, but realm-governance operations are limited to governance roles." icon="access" tone="emphasis">
              <InfoList items={[
                { label: "Current user", value: String(bootstrapState.data?.user?.username || "operator") },
                { label: "Role", value: String(bootstrapState.data?.user?.role || "viewer") },
                { label: "Auth", value: String(bootstrapState.data?.user?.auth_mechanism || "session") },
                { label: "Realm admin", value: "Required for Keycloak, break-glass and service-account operations" },
              ]} />
            </WorkspaceSection>
            <WorkspaceSection title="Why this page is still present" subtitle="Shell navigation keeps every major workspace discoverable instead of hiding governance behind role-specific navigation drift." icon="docs">
              <InfoList items={[
                { label: "Visible section", value: "Access stays in the product shell" },
                { label: "Restricted actions", value: "Keycloak, break-glass, secrets and token rotation" },
                { label: "Next step", value: "Open with an admin or governance role to manage SSO and recovery" },
              ]} />
            </WorkspaceSection>
          </div>
        ) : (
        <>
        <div className="react-tab-rail">
          {ACCESS_TABS.map((tab) => (
            <button key={tab} type="button" className={`react-tab-rail-button ${activeTab === tab ? "active" : ""}`} onClick={() => setTab(tab)}>
              {copy.labels[tab]}
            </button>
          ))}
        </div>

        {activeTab === "overview" ? (
          <div className="react-grid react-grid-2">
            <WorkspaceSection title="Keycloak control plane" subtitle="Realm-admin automation state, inventory and provider posture." icon="control" tone="emphasis">
              <InfoList items={[
                { label: "Healthy", value: keycloakStatusState.data?.healthy ? "yes" : "no" },
                { label: "Admin ready", value: keycloakStatusState.data?.admin_ready ? "yes" : "no" },
                { label: "Realm", value: String(keycloakStatusState.data?.realm || "siem") },
                { label: "Users", value: Number((keycloakStatusState.data?.inventory as RuntimeBlob | undefined)?.users || 0) },
                { label: "Groups", value: Number((keycloakStatusState.data?.inventory as RuntimeBlob | undefined)?.groups || 0) },
                { label: "Clients", value: Number((keycloakStatusState.data?.inventory as RuntimeBlob | undefined)?.clients || 0) },
              ]} />
            </WorkspaceSection>
            <WorkspaceSection title="Provider and vault posture" subtitle="Human auth, break-glass posture and secret runtime readiness." icon="docs">
              <InfoList items={[
                { label: "Providers", value: providers.length },
                { label: "Vault healthy", value: ((governance.vault as RuntimeBlob | undefined)?.healthy ? "yes" : "no") },
                { label: "Vault refs", value: Number(secretSummary.vault_backed || 0) },
                { label: "Required missing", value: Number(secretSummary.required_missing || 0) },
                { label: "Break-glass active", value: Number((((governance.break_glass as RuntimeBlob | undefined)?.metrics as RuntimeBlob | undefined)?.active) || 0) },
                { label: "Certified EPS", value: Number((certificationState.data as RuntimeBlob | undefined)?.latest_certified_ceiling_eps || 0) },
              ]} />
              <div className="react-list" style={{ marginTop: 16 }}>
                {providers.map((item) => (
                  <CompactCard key={String(item.id || item.title || "provider")} title={String(item.title || item.id || "provider")} subtitle={String(item.issuer || item.kind || "provider")} status={item.healthy ? "healthy" : "degraded"}>
                    <div className="react-card-button-grid"><span>Enabled</span><strong>{item.enabled ? "yes" : "no"}</strong><span>Issues</span><strong>{(item.issues || []).length}</strong></div>
                  </CompactCard>
                ))}
              </div>
            </WorkspaceSection>
            <WorkspaceSection title="Recovery posture" subtitle="Break-glass sessions, local recovery accounts and governance drift." icon="incidents" tone="emphasis">
              <div className="react-list react-list-compact">
                {breakGlassItems.slice(0, 5).map((item) => (
                  <div key={String(item.id || "session")} className="react-list-item"><strong>{String(item.username || item.id || "session")}</strong><span>{String(item.reason || "recovery")} | {item.expires_ts ? formatTimestamp(item.expires_ts, "compact") : "n/a"}</span></div>
                ))}
                {!breakGlassItems.length ? <div className="react-list-item"><strong>none</strong><span>No active recovery sessions.</span></div> : null}
              </div>
            </WorkspaceSection>
            <WorkspaceSection title="Machine identity lane" subtitle="Service account scope, tokens and automation lifecycle." icon="connectors">
              <InfoList items={[
                { label: "Service accounts", value: serviceAccounts.length },
                { label: "Active tokens", value: Number((accountsState.data?.metrics as RuntimeBlob | undefined)?.active_tokens || 0) },
                { label: "Expiring in 14d", value: Number((accountsState.data?.metrics as RuntimeBlob | undefined)?.tokens_expiring_14d || 0) },
                { label: "Selected tokens", value: (serviceAccountDetailState.data?.tokens || []).length },
              ]} />
            </WorkspaceSection>
          </div>
        ) : null}

        {activeTab === "keycloak-users" ? (
          <div className="react-grid react-grid-2">
            <WorkspaceSection title={t(lang, { en: "Realm users", ru: "Пользователи realm" })} subtitle={t(lang, { en: "Search and select identities from the live Keycloak realm.", ru: "Ищите и выбирайте идентичности из живого Keycloak realm." })} icon="access" tone="emphasis">
              <div className="react-actions react-wrap">
                <input className="react-input react-input-grow" value={keycloakSearch} onChange={(event) => setKeycloakSearch(event.target.value)} placeholder={t(lang, { en: "Search username or email...", ru: "Поиск по имени пользователя или email..." })} />
                <span className="react-badge soft">{t(lang, { en: "Live", ru: "В live" })}: {keycloakUsers.length}</span>
                <button type="button" className="react-link-button" onClick={() => setRefreshTick((value) => value + 1)}>{t(lang, { en: "Refresh", ru: "Обновить" })}</button>
                <button type="button" className="react-link-button" onClick={() => { setCreatingKeycloakUser(true); setSelectedKeycloakUserId(""); setKeycloakUserForm(emptyKeycloakUserForm()); setUserEditorOpen(true); }}>{t(lang, { en: "New user", ru: "Новый пользователь" })}</button>
              </div>
              <div className="react-list" style={{ marginTop: 16 }}>
                {keycloakUsers.map((item) => {
                  const identity = describeIdentity(item, lang);
                  return (
                    <CompactCard
                      key={String(item.id || item.username)}
                      title={identity.title}
                      subtitle={identity.subtitle || identity.technical}
                      status={item.enabled ? "active" : "disabled"}
                      selected={!creatingKeycloakUser && selectedKeycloakUserId === item.id}
                      onClick={() => {
                        setCreatingKeycloakUser(false);
                        setSelectedKeycloakUserId(String(item.id || ""));
                        setUserEditorOpen(true);
                      }}
                    >
                      <div className="react-card-button-grid">
                        <span>{t(lang, { en: "Handle", ru: "Логин" })}</span>
                        <strong>{identity.title}</strong>
                        <span>{t(lang, { en: "Created", ru: "Создан" })}</span>
                        <strong>{item.created_ts ? formatTimestamp(item.created_ts, "compact") : t(lang, { en: "n/a", ru: "н/д" })}</strong>
                        <span>{t(lang, { en: "Verified", ru: "Подтвержден" })}</span>
                        <strong>{item.email_verified ? t(lang, { en: "yes", ru: "да" }) : t(lang, { en: "no", ru: "нет" })}</strong>
                      </div>
                    </CompactCard>
                  );
                })}
                {!keycloakUsers.length ? <EmptyState message={t(lang, { en: "No Keycloak users found for the current search.", ru: "По текущему запросу пользователи Keycloak не найдены." })} /> : null}
              </div>
            </WorkspaceSection>
            <WorkspaceSection title={t(lang, { en: "User editor", ru: "Редактор пользователя" })} subtitle={t(lang, { en: "Create, enable, disable, reset password and control group/role membership.", ru: "Создавайте, включайте, отключайте, обновляйте пароль и управляйте членством в группах и ролях." })} icon="builders">
              <WindowLauncher
                title={creatingKeycloakUser ? t(lang, { en: "New realm user", ru: "Новый пользователь realm" }) : selectedIdentity.title || t(lang, { en: "No user selected", ru: "Пользователь не выбран" })}
                subtitle={t(lang, { en: "Use the side window to edit identity fields, reset password, and align group and role membership.", ru: "Используйте боковое окно, чтобы изменить поля идентичности, обновить пароль и выровнять членство в группах и ролях." })}
                items={[
                  { label: t(lang, { en: "Display", ru: "Отображение" }), value: selectedIdentity.subtitle || selectedIdentity.technical || t(lang, { en: "n/a", ru: "н/д" }) },
                  { label: t(lang, { en: "Email", ru: "Email" }), value: keycloakUserForm.email || t(lang, { en: "n/a", ru: "н/д" }) },
                  { label: t(lang, { en: "Groups", ru: "Группы" }), value: keycloakUserForm.group_names.length },
                  { label: t(lang, { en: "Roles", ru: "Роли" }), value: keycloakUserForm.roles.length },
                  { label: t(lang, { en: "State", ru: "Состояние" }), value: keycloakUserForm.enabled ? t(lang, { en: "enabled", ru: "включен" }) : t(lang, { en: "disabled", ru: "отключен" }) },
                ]}
                primaryLabel={t(lang, { en: "Open user window", ru: "Открыть окно пользователя" })}
                onPrimary={() => setUserEditorOpen(true)}
                secondary={
                  !creatingKeycloakUser && selectedKeycloakUser ? (
                    <button type="button" className="react-link-button" onClick={() => void deleteSelectedKeycloakUser()}>
                      {t(lang, { en: "Delete user", ru: "Удалить пользователя" })}
                    </button>
                  ) : null
                }
              />
              <div className="react-divider" style={{ marginTop: 20, marginBottom: 16 }} />
              <div className="react-actions react-wrap">
                <strong>{t(lang, { en: "System access", ru: "Системный доступ" })}</strong>
                <span className="react-badge soft">{t(lang, { en: "Deny by default", ru: "Запрет по умолчанию" })}</span>
                <button type="button" className="react-link-button" onClick={openNewAccessGrant} disabled={creatingKeycloakUser}>{t(lang, { en: "Add access", ru: "Добавить доступ" })}</button>
              </div>
              <div className="react-list react-list-compact" style={{ marginTop: 16 }}>
                {accessGrants.map((grant) => (
                  <div key={grant.id} className="react-list-item react-list-item-stack">
                    <div>
                      <strong>{localizeAccessSystemTitle(String(grant.system_id || ""), String(grant.system_title || grant.system_id || ""), lang)}</strong>
                      <div className="react-card-button-copy">
                        {localizeAccessRole(String(grant.system_id || ""), String(grant.role || ""), String(grant.role || ""), lang)} | {(grant.sections || []).map((sectionId) => localizeAccessSection(String(grant.system_id || ""), sectionId, sectionId, lang)).join(", ") || t(lang, { en: "all sections", ru: "все разделы" })}
                      </div>
                      <div className="react-card-button-copy">
                        {localizeAccessMode(accessSystemIndex.get(String(grant.system_id || ""))?.enforcement_mode, lang)}
                        {accessSystemIndex.get(String(grant.system_id || ""))?.internal_url ? ` | ${accessSystemIndex.get(String(grant.system_id || ""))?.internal_url}` : ""}
                      </div>
                    </div>
                    <div className="react-actions react-wrap">
                      <StatusBadge value={grant.enabled ? (grant.sync_status || "active") : "disabled"} />
                      <button type="button" className="react-link-button" onClick={() => openExistingAccessGrant(grant)}>{t(lang, { en: "Edit", ru: "Изменить" })}</button>
                      <button type="button" className="react-link-button" onClick={() => void removeAccessGrant(String(grant.id || ""))}>{t(lang, { en: "Remove", ru: "Удалить" })}</button>
                    </div>
                  </div>
                ))}
                {!accessGrants.length ? <EmptyState message={t(lang, { en: "No system grants are assigned to this Keycloak user yet.", ru: "Этому пользователю Keycloak еще не назначены системные права." })} /> : null}
              </div>
            </WorkspaceSection>
          </div>
        ) : null}

        {activeTab === "keycloak-groups" ? (
          <div className="react-grid react-grid-2">
            <WorkspaceSection title={t(lang, { en: "Realm groups", ru: "Группы realm" })} subtitle={t(lang, { en: "Manage group structure used by the OIDC mapping layer.", ru: "Управляйте структурой групп, используемой слоем OIDC-привязок." })} icon="entities" tone="emphasis">
              <div className="react-actions react-wrap">
                <button type="button" className="react-link-button" onClick={() => { setSelectedGroupId(""); setGroupDraft(""); setGroupEditorOpen(true); }}>{t(lang, { en: "New group", ru: "Новая группа" })}</button>
              </div>
              <div className="react-list" style={{ marginTop: 16 }}>
                {keycloakGroups.map((group) => (
                  <CompactCard key={group.id} title={group.name} subtitle={group.path || "/"} status={Number(group.sub_group_count || 0) ? "nested" : "ready"} selected={selectedGroupId === group.id} onClick={() => { setSelectedGroupId(String(group.id || "")); setGroupEditorOpen(true); }}>
                    <div className="react-card-button-grid"><span>{t(lang, { en: "Child groups", ru: "Дочерние группы" })}</span><strong>{Number(group.sub_group_count || 0)}</strong></div>
                  </CompactCard>
                ))}
              </div>
            </WorkspaceSection>
            <WorkspaceSection title={t(lang, { en: "Group editor", ru: "Редактор групп" })} subtitle={t(lang, { en: "Control Keycloak group names used by access policy and app mappings.", ru: "Управляйте именами групп Keycloak, используемых политиками доступа и привязками приложений." })} icon="builders">
              <WindowLauncher
                title={groupDraft || t(lang, { en: "New group", ru: "Новая группа" })}
                subtitle={t(lang, { en: "Group edits now live in a side window to keep the identity workspace readable while you pivot between members and mappings.", ru: "Изменения групп вынесены в боковое окно, чтобы рабочее пространство идентификации оставалось читаемым при переходе между участниками и привязками." })}
                items={[
                  { label: t(lang, { en: "Name", ru: "Имя" }), value: groupDraft || t(lang, { en: "n/a", ru: "н/д" }) },
                  { label: t(lang, { en: "Path", ru: "Путь" }), value: String(keycloakGroups.find((item) => String(item.id || "") === selectedGroupId)?.path || "/") },
                  { label: t(lang, { en: "Child groups", ru: "Дочерние группы" }), value: Number(keycloakGroups.find((item) => String(item.id || "") === selectedGroupId)?.sub_group_count || 0) },
                ]}
                primaryLabel={t(lang, { en: "Open group window", ru: "Открыть окно группы" })}
                onPrimary={() => setGroupEditorOpen(true)}
              />
            </WorkspaceSection>
          </div>
        ) : null}

        {activeTab === "keycloak-roles" ? (
          <div className="react-grid react-grid-2">
            <WorkspaceSection title={t(lang, { en: "Realm roles", ru: "Роли realm" })} subtitle={t(lang, { en: "Roles exposed to OIDC claims and application clients.", ru: "Роли, публикуемые в OIDC-клеймы и клиенты приложений." })} icon="control" tone="emphasis">
              <div className="react-actions react-wrap">
                <button type="button" className="react-link-button" onClick={() => { setSelectedRoleName(""); setRoleDraft({ name: "", description: "" }); setRoleEditorOpen(true); }}>{t(lang, { en: "New role", ru: "Новая роль" })}</button>
              </div>
              <div className="react-list" style={{ marginTop: 16 }}>
                {keycloakRoles.map((role) => (
                  <CompactCard key={role.name} title={role.name} subtitle={describeKeycloakRole(role.description)} status="ready" selected={selectedRoleName === role.name} onClick={() => { setSelectedRoleName(String(role.name || "")); setRoleEditorOpen(true); }} />
                ))}
              </div>
            </WorkspaceSection>
            <WorkspaceSection title={t(lang, { en: "Role editor", ru: "Редактор ролей" })} subtitle={t(lang, { en: "Align realm roles with SIEM bundles and downstream clients.", ru: "Согласуйте роли realm с наборами прав SIEM и внешними клиентами." })} icon="builders">
              <WindowLauncher
                title={roleDraft.name || t(lang, { en: "New role", ru: "Новая роль" })}
                subtitle={t(lang, { en: "Role metadata and downstream bundle alignment open in a side window instead of stretching the workspace.", ru: "Метаданные роли и привязка к наборам прав вынесены в боковое окно, чтобы не растягивать страницу." })}
                items={[
                  { label: t(lang, { en: "Role", ru: "Роль" }), value: roleDraft.name || t(lang, { en: "n/a", ru: "н/д" }) },
                  { label: t(lang, { en: "Description", ru: "Описание" }), value: roleDraft.description || t(lang, { en: "n/a", ru: "н/д" }) },
                  { label: t(lang, { en: "Bundle catalog", ru: "Каталог наборов прав" }), value: permissionBundles.length },
                ]}
                primaryLabel={t(lang, { en: "Open role window", ru: "Открыть окно роли" })}
                onPrimary={() => setRoleEditorOpen(true)}
              />
            </WorkspaceSection>
          </div>
        ) : null}

        {activeTab === "keycloak-clients" ? (
          <div className="react-grid react-grid-2">
            <WorkspaceSection title={t(lang, { en: "OIDC clients", ru: "OIDC-клиенты" })} subtitle={t(lang, { en: "Manage Keycloak clients for SIEM and external system integrations.", ru: "Управляйте клиентами Keycloak для SIEM и внешних интеграций." })} icon="connectors" tone="emphasis">
              <div className="react-actions react-wrap">
                <button type="button" className="react-link-button" onClick={() => { setSelectedClientId(""); setKeycloakClientForm(emptyKeycloakClientForm()); setClientEditorOpen(true); }}>{t(lang, { en: "New client", ru: "Новый клиент" })}</button>
              </div>
              <div className="react-list" style={{ marginTop: 16 }}>
                {keycloakClients.map((client) => (
                  <CompactCard key={String(client.client_id || client.id)} title={String(client.client_id || client.id || "client")} subtitle={client.description || client.name || client.protocol || "client"} status={client.enabled ? "active" : "disabled"} selected={selectedClientId === String(client.client_id || client.id || "")} onClick={() => { setSelectedClientId(String(client.client_id || client.id || "")); setClientEditorOpen(true); }}>
                    <div className="react-card-button-grid"><span>{t(lang, { en: "Service accounts", ru: "Сервисные учетные записи" })}</span><strong>{client.service_accounts_enabled ? t(lang, { en: "on", ru: "вкл" }) : t(lang, { en: "off", ru: "выкл" })}</strong><span>{t(lang, { en: "Secret", ru: "Секрет" })}</span><strong>{client.has_secret ? t(lang, { en: "managed", ru: "управляется" }) : t(lang, { en: "none", ru: "нет" })}</strong></div>
                  </CompactCard>
                ))}
              </div>
            </WorkspaceSection>
            <WorkspaceSection title={t(lang, { en: "Client editor", ru: "Редактор клиента" })} subtitle={t(lang, { en: "Configure redirect URIs, origins, service-account mode and client secret lifecycle.", ru: "Настраивайте redirect URI, origins, режим сервисных учетных записей и жизненный цикл секрета клиента." })} icon="builders">
              <WindowLauncher
                title={keycloakClientForm.client_id || t(lang, { en: "New client", ru: "Новый клиент" })}
                subtitle={t(lang, { en: "Redirects, origins and service-account controls now open in a side window with execute-and-close actions.", ru: "Redirect URI, origins и управление сервисными учетными записями теперь открываются в боковом окне с действиями по принципу выполнить и закрыть." })}
                items={[
                  { label: t(lang, { en: "Display name", ru: "Отображаемое имя" }), value: keycloakClientForm.name || t(lang, { en: "n/a", ru: "н/д" }) },
                  { label: t(lang, { en: "Enabled", ru: "Включен" }), value: keycloakClientForm.enabled ? t(lang, { en: "yes", ru: "да" }) : t(lang, { en: "no", ru: "нет" }) },
                  { label: t(lang, { en: "Public", ru: "Публичный" }), value: keycloakClientForm.public_client ? t(lang, { en: "yes", ru: "да" }) : t(lang, { en: "no", ru: "нет" }) },
                  { label: t(lang, { en: "Service accounts", ru: "Сервисные учетные записи" }), value: keycloakClientForm.service_accounts_enabled ? t(lang, { en: "enabled", ru: "включены" }) : t(lang, { en: "disabled", ru: "отключены" }) },
                ]}
                primaryLabel={t(lang, { en: "Open client window", ru: "Открыть окно клиента" })}
                onPrimary={() => setClientEditorOpen(true)}
                secondary={
                  selectedKeycloakClient ? (
                    <button type="button" className="react-link-button" onClick={() => void rotateClientSecret()}>
                      {t(lang, { en: "Rotate client secret", ru: "Обновить секрет клиента" })}
                    </button>
                  ) : null
                }
              />
              {rotatedClientSecret ? <div className="react-callout react-callout-warning" style={{ marginTop: 16 }}><strong>{t(lang, { en: "Latest rotated secret", ru: "Последний обновленный секрет" })}</strong><pre className="react-pre">{rotatedClientSecret}</pre></div> : null}
            </WorkspaceSection>
          </div>
        ) : null}

        {activeTab === "recovery" ? (
          <div className="react-grid react-grid-2">
            <WorkspaceSection title={t(lang, { en: "Break-glass local users", ru: "Локальные аварийные пользователи" })} subtitle={t(lang, { en: "These accounts exist for recovery only and should stay tightly controlled.", ru: "Эти учетные записи существуют только для восстановления и должны строго контролироваться." })} icon="access" tone="emphasis">
              <div className="react-actions react-wrap">
                <button type="button" className="react-link-button" onClick={() => { setSelectedUsername(""); setLocalUserForm(emptyLocalUserForm()); setRecoveryEditorOpen(true); }}>{t(lang, { en: "New recovery user", ru: "Новый аварийный пользователь" })}</button>
              </div>
              <div className="react-list" style={{ marginTop: 16 }}>
                {localUsers.map((item) => (
                  <CompactCard key={item.username} title={item.username} subtitle={item.role} status={item.enabled ? "active" : "disabled"} selected={selectedUsername === item.username} onClick={() => { setSelectedUsername(item.username); setRecoveryEditorOpen(true); }}>
                    <div className="react-card-button-grid"><span>{t(lang, { en: "Bundles", ru: "Наборы прав" })}</span><strong>{(item.permission_bundles || []).length}</strong><span>{t(lang, { en: "Password", ru: "Пароль" })}</span><strong>{item.password_updated_ts ? formatTimestamp(item.password_updated_ts, "compact") : t(lang, { en: "n/a", ru: "н/д" })}</strong></div>
                  </CompactCard>
                ))}
              </div>
            </WorkspaceSection>
            <WorkspaceSection title={t(lang, { en: "Recovery workflow", ru: "Контур восстановления" })} subtitle={t(lang, { en: "Edit recovery users and control temporary emergency sessions.", ru: "Редактируйте аварийных пользователей и управляйте временными аварийными сессиями." })} icon="builders">
              <WindowLauncher
                title={localUserForm.username || t(lang, { en: "Recovery control", ru: "Контроль восстановления" })}
                subtitle={t(lang, { en: "Local break-glass identities and emergency sessions now open in a focused side window.", ru: "Локальные аварийные идентичности и экстренные сессии теперь открываются в сфокусированном боковом окне." })}
                items={[
                  { label: t(lang, { en: "Role", ru: "Роль" }), value: localUserForm.role || "viewer" },
                  { label: t(lang, { en: "Bundles", ru: "Наборы прав" }), value: localUserForm.permissionBundles.length },
                  { label: t(lang, { en: "Break-glass minutes", ru: "Минуты аварийной сессии" }), value: breakGlassMinutes || "60" },
                  { label: t(lang, { en: "Active sessions", ru: "Активные сессии" }), value: breakGlassItems.length },
                ]}
                primaryLabel={t(lang, { en: "Open recovery window", ru: "Открыть окно восстановления" })}
                onPrimary={() => setRecoveryEditorOpen(true)}
                secondary={
                  <button type="button" className="react-link-button" onClick={() => void openBreakGlass()}>
                    {t(lang, { en: "Open break-glass session", ru: "Открыть аварийную сессию" })}
                  </button>
                }
              />
              <div className="react-list react-list-compact" style={{ marginTop: 16 }}>
                {breakGlassItems.map((item) => (
                  <div key={String(item.id || "session")} className="react-list-item"><strong>{String(item.username || item.id || "session")}</strong><span>{item.reason || t(lang, { en: "recovery", ru: "восстановление" })} | {item.expires_ts ? formatTimestamp(item.expires_ts, "compact") : t(lang, { en: "n/a", ru: "н/д" })}</span><button type="button" className="react-link-button" onClick={() => void revokeBreakGlass(String(item.id || ""))}>{t(lang, { en: "Revoke", ru: "Закрыть" })}</button></div>
                ))}
                {!breakGlassItems.length ? <EmptyState message={t(lang, { en: "No active break-glass sessions.", ru: "Нет активных аварийных сессий." })} /> : null}
              </div>
            </WorkspaceSection>
          </div>
        ) : null}

        {activeTab === "service-accounts" ? (
          <div className="react-grid react-grid-2">
            <WorkspaceSection title={t(lang, { en: "Machine identities", ru: "Машинные идентичности" })} subtitle={t(lang, { en: "Service accounts back automation, connectors, CI and downstream integrations.", ru: "Сервисные учетные записи обслуживают автоматизацию, коннекторы, CI и внешние интеграции." })} icon="connectors" tone="emphasis">
              <div className="react-actions react-wrap">
                <button type="button" className="react-link-button" onClick={() => { setSelectedServiceAccountId(""); setServiceAccountForm(emptyServiceAccountForm()); setServiceAccountEditorOpen(true); }}>{t(lang, { en: "New service account", ru: "Новая сервисная учетная запись" })}</button>
              </div>
              <div className="react-list" style={{ marginTop: 16 }}>
                {serviceAccounts.map((item) => (
                  <CompactCard key={String(item.id || item.name)} title={String(item.name || item.id || "service-account")} subtitle={item.description || item.id} status={item.enabled ? "active" : "disabled"} selected={selectedServiceAccountId === String(item.id || "")} onClick={() => { setSelectedServiceAccountId(String(item.id || "")); setServiceAccountEditorOpen(true); }}>
                    <div className="react-card-button-grid"><span>{t(lang, { en: "Bundles", ru: "Наборы прав" })}</span><strong>{(item.permission_bundles || []).length}</strong><span>{t(lang, { en: "Tokens", ru: "Токены" })}</span><strong>{Number(item.active_tokens || item.token_count || 0)}</strong></div>
                  </CompactCard>
                ))}
              </div>
            </WorkspaceSection>
            <WorkspaceSection title={t(lang, { en: "Service-account lifecycle", ru: "Жизненный цикл сервисной учетной записи" })} subtitle={t(lang, { en: "Bundle assignment, issuance and rotation with overlap windows.", ru: "Назначение наборов прав, выпуск и ротация с окнами перекрытия." })} icon="builders">
              <WindowLauncher
                title={serviceAccountForm.name || t(lang, { en: "Service-account control", ru: "Управление сервисной учетной записью" })}
                subtitle={t(lang, { en: "Bundle assignment, token issuance and overlap rotation now open in a side window.", ru: "Назначение наборов прав, выпуск токенов и ротация с перекрытием теперь открываются в боковом окне." })}
                items={[
                  { label: t(lang, { en: "Description", ru: "Описание" }), value: serviceAccountForm.description || t(lang, { en: "n/a", ru: "н/д" }) },
                  { label: t(lang, { en: "Bundles", ru: "Наборы прав" }), value: serviceAccountForm.permissionBundles.length },
                  { label: t(lang, { en: "Active tokens", ru: "Активные токены" }), value: Number((serviceAccountDetailState.data?.tokens || []).length) },
                  { label: t(lang, { en: "Overlap minutes", ru: "Минуты перекрытия" }), value: rotationOverlapMinutes || "15" },
                ]}
                primaryLabel={t(lang, { en: "Open service-account window", ru: "Открыть окно сервисной учетной записи" })}
                onPrimary={() => setServiceAccountEditorOpen(true)}
                secondary={
                  <button type="button" className="react-link-button" onClick={() => void issueServiceToken()} disabled={!selectedServiceAccountId}>
                    {t(lang, { en: "Issue token", ru: "Выпустить токен" })}
                  </button>
                }
              />
              {issuedToken ? <div className="react-callout react-callout-warning" style={{ marginTop: 16 }}><strong>{t(lang, { en: "Issued token", ru: "Выпущенный токен" })}</strong><pre className="react-pre">{issuedToken}</pre></div> : null}
              <div className="react-list react-list-compact" style={{ marginTop: 16 }}>
                {(serviceAccountDetailState.data?.tokens || []).map((token) => (
                  <div key={String(token.id || token.title || "token")} className="react-list-item"><strong>{String(token.title || token.id || "token")}</strong><span>{token.expires_ts ? formatTimestamp(token.expires_ts, "compact") : t(lang, { en: "no expiry", ru: "без срока" })}</span><button type="button" className="react-link-button" onClick={() => void revokeServiceToken(String(token.id || ""))}>{t(lang, { en: "Revoke", ru: "Отозвать" })}</button></div>
                ))}
              </div>
            </WorkspaceSection>
          </div>
        ) : null}

        {activeTab === "secrets" ? (
          <div className="react-grid react-grid-2">
            <WorkspaceSection title={t(lang, { en: "Vault-backed runtime posture", ru: "Состояние runtime-секретов через Vault" })} subtitle={t(lang, { en: "Inventory of resolved refs, missing requirements and operator-visible secret posture.", ru: "Инвентарь разрешенных ссылок, отсутствующих обязательных значений и состояния секретов, видимого оператору." })} icon="docs" tone="emphasis">
              <InfoList items={[
                { label: t(lang, { en: "Total refs", ru: "Всего ссылок" }), value: Number(secretSummary.total || secretItems.length || 0) },
                { label: t(lang, { en: "Vault-backed", ru: "Через Vault" }), value: Number(secretSummary.vault_backed || 0) },
                { label: t(lang, { en: "Resolved", ru: "Разрешено" }), value: Number(secretSummary.resolved || 0) },
                { label: t(lang, { en: "Required missing", ru: "Обязательных не хватает" }), value: Number(secretSummary.required_missing || 0) },
              ]} />
              <div className="react-list react-list-compact" style={{ marginTop: 16 }}>
                {secretItems.map((item, index) => (
                  <div key={`${String(item.name || item.key || "secret")}-${index}`} className="react-list-item"><strong>{String(item.name || item.key || "secret")}</strong><span>{String(item.ref || item.path || item.status || t(lang, { en: "inventory entry", ru: "элемент инвентаря" }))}</span></div>
                ))}
                {!secretItems.length ? <EmptyState message={t(lang, { en: "No secret inventory entries returned by governance runtime.", ru: "Контур управления не вернул записей инвентаря секретов." })} /> : null}
              </div>
            </WorkspaceSection>
            <WorkspaceSection title={t(lang, { en: "Governance signals", ru: "Сигналы контура управления" })} subtitle={t(lang, { en: "Bundle inventory and role taxonomy currently exposed to operators.", ru: "Инвентарь наборов прав и таксономия ролей, доступные операторам сейчас." })} icon="control">
              <InfoList items={[
                { label: t(lang, { en: "Permission bundles", ru: "Наборы прав" }), value: permissionBundles.length },
                { label: t(lang, { en: "Permission categories", ru: "Категории прав" }), value: permissionCategories.length },
                { label: t(lang, { en: "Recovery users", ru: "Аварийные пользователи" }), value: localUsers.length },
                { label: t(lang, { en: "Service accounts", ru: "Сервисные учетные записи" }), value: serviceAccounts.length },
              ]} />
              <div className="react-list react-list-compact" style={{ marginTop: 16 }}>
                {permissionBundles.map((bundle) => (
                  <div key={bundle.id} className="react-list-item"><strong>{bundle.title}</strong><span>{bundle.permissions.length} {t(lang, { en: "permissions", ru: "разрешений" })} | {bundle.id}</span></div>
                ))}
              </div>
            </WorkspaceSection>
          </div>
        ) : null}
        </>
        )}
        <DrawerOverlay
          open={userEditorOpen}
          title={creatingKeycloakUser ? t(lang, { en: "Create Keycloak user", ru: "Создать пользователя Keycloak" }) : `${t(lang, { en: "User window", ru: "Окно пользователя" })}: ${selectedIdentity.title || t(lang, { en: "identity", ru: "идентичность" })}`}
          subtitle={t(lang, { en: "Edit the identity, adjust group and role membership, then execute the change from this side window.", ru: "Изменяйте идентичность, корректируйте членство в группах и ролях, а затем выполняйте действие из этого бокового окна." })}
          onClose={() => setUserEditorOpen(false)}
        >
          {!creatingKeycloakUser ? (
            <section className="react-card react-card-nested" style={{ marginBottom: 16 }}>
              <PanelHeader
                title={t(lang, { en: "Identity summary", ru: "Сводка по идентичности" })}
                subtitle={t(lang, { en: "Human-facing profile first, technical identifiers second.", ru: "Сначала профиль для оператора, затем технические идентификаторы." })}
              />
              <DrawerFieldGrid>
                <KeyValue label={t(lang, { en: "Display name", ru: "Отображаемое имя" })} value={selectedIdentity.title || t(lang, { en: "n/a", ru: "н/д" })} />
                <KeyValue label={t(lang, { en: "Profile", ru: "Профиль" })} value={selectedIdentity.subtitle || t(lang, { en: "n/a", ru: "н/д" })} />
                <KeyValue label={t(lang, { en: "Technical", ru: "Технически" })} value={selectedIdentity.technical || t(lang, { en: "n/a", ru: "н/д" })} />
                <KeyValue label={t(lang, { en: "Access grants", ru: "Назначения доступа" })} value={accessGrants.length} />
              </DrawerFieldGrid>
            </section>
          ) : null}
          <div className="react-form-grid">
            <input className="react-input" value={keycloakUserForm.username} onChange={(event) => setKeycloakUserForm((current) => ({ ...current, username: event.target.value }))} placeholder={t(lang, { en: "Username", ru: "Имя пользователя" })} />
            <input className="react-input" value={keycloakUserForm.email} onChange={(event) => setKeycloakUserForm((current) => ({ ...current, email: event.target.value }))} placeholder="Email" />
            <input className="react-input" value={keycloakUserForm.first_name} onChange={(event) => setKeycloakUserForm((current) => ({ ...current, first_name: event.target.value }))} placeholder={t(lang, { en: "First name", ru: "Имя" })} />
            <input className="react-input" value={keycloakUserForm.last_name} onChange={(event) => setKeycloakUserForm((current) => ({ ...current, last_name: event.target.value }))} placeholder={t(lang, { en: "Last name", ru: "Фамилия" })} />
            <input className="react-input" type="password" value={keycloakUserForm.password} onChange={(event) => setKeycloakUserForm((current) => ({ ...current, password: event.target.value }))} placeholder={selectedKeycloakUser ? t(lang, { en: "New password", ru: "Новый пароль" }) : t(lang, { en: "Initial password", ru: "Начальный пароль" })} />
            <label className="react-toggle"><input type="checkbox" checked={keycloakUserForm.enabled} onChange={(event) => setKeycloakUserForm((current) => ({ ...current, enabled: event.target.checked }))} /><span>{t(lang, { en: "Enabled", ru: "Включен" })}</span></label>
            <label className="react-toggle"><input type="checkbox" checked={keycloakUserForm.email_verified} onChange={(event) => setKeycloakUserForm((current) => ({ ...current, email_verified: event.target.checked }))} /><span>{t(lang, { en: "Email verified", ru: "Email подтвержден" })}</span></label>
          </div>
          <section className="react-card react-card-nested react-membership-panel" style={{ marginTop: 16 }}>
            <PanelHeader title={t(lang, { en: "Group membership", ru: "Членство в группах" })} subtitle={t(lang, { en: "Filter the realm inventory down to assigned groups, system mappings or downstream app groups before you change the user.", ru: "Отфильтруйте инвентарь realm до назначенных групп, системных привязок или групп внешних приложений перед изменением пользователя." })} />
            <div className="react-membership-toolbar">
              <input
                className="react-input react-input-full"
                value={groupMembershipSearch}
                onChange={(event) => setGroupMembershipSearch(event.target.value)}
                placeholder={t(lang, { en: "Search group names or paths", ru: "Поиск по именам групп и путям" })}
              />
              <MembershipFilterPills
                value={groupMembershipFilter}
                onChange={setGroupMembershipFilter}
                label={t(lang, { en: "Group membership filters", ru: "Фильтры членства в группах" })}
                options={[
                  { id: "assigned", label: t(lang, { en: "Assigned", ru: "Назначено" }) },
                  { id: "system", label: t(lang, { en: "System", ru: "Система" }) },
                  { id: "apps", label: t(lang, { en: "Apps", ru: "Приложения" }) },
                  { id: "realm", label: t(lang, { en: "Realm", ru: "Realm" }) },
                  { id: "all", label: t(lang, { en: "All", ru: "Все" }) },
                ]}
              />
            </div>
            <InfoList
              items={[
                { label: t(lang, { en: "Assigned", ru: "Назначено" }), value: keycloakUserForm.group_names.length },
                { label: t(lang, { en: "Visible", ru: "Видимо" }), value: visibleGroupMembershipCount },
                { label: t(lang, { en: "Buckets", ru: "Категории" }), value: groupMembershipBuckets.length || 0 },
              ]}
            />
            <div className="react-membership-buckets">
              {groupMembershipBuckets.map((bucket) => (
                <section key={bucket.id} className="react-card react-card-nested react-membership-bucket">
                  <PanelHeader title={bucket.title} subtitle={bucket.subtitle} actions={<StatusBadge value={`${bucket.items.length} ${t(lang, { en: "items", ru: "элементов" })}`} />} />
                  <div className="react-list react-list-compact">
                    {bucket.items.map((item) => (
                      <label key={item.key} className={`react-toggle react-toggle-card ${item.checked ? "react-toggle-card-selected" : ""}`}>
                        <input type="checkbox" checked={item.checked} onChange={() => setKeycloakUserForm((current) => ({ ...current, group_names: toggleItem(current.group_names, item.name) }))} />
                        <span><strong>{item.name}</strong><small>{item.meta}</small></span>
                      </label>
                    ))}
                  </div>
                </section>
              ))}
              {!groupMembershipBuckets.length ? <EmptyState message={t(lang, { en: "No groups match the current membership filter.", ru: "Под текущий фильтр группы не найдены." })} /> : null}
            </div>
          </section>
          <section className="react-card react-card-nested react-membership-panel" style={{ marginTop: 16 }}>
            <PanelHeader title={t(lang, { en: "Role membership", ru: "Членство в ролях" })} subtitle={t(lang, { en: "Keep the operational roles close to the current user instead of scanning the entire realm role catalog.", ru: "Держите рабочие роли рядом с текущим пользователем, не просматривая весь каталог ролей realm." })} />
            <div className="react-membership-toolbar">
              <input
                className="react-input react-input-full"
                value={roleMembershipSearch}
                onChange={(event) => setRoleMembershipSearch(event.target.value)}
                placeholder={t(lang, { en: "Search role names or descriptions", ru: "Поиск по именам ролей и описаниям" })}
              />
              <MembershipFilterPills
                value={roleMembershipFilter}
                onChange={setRoleMembershipFilter}
                label={t(lang, { en: "Role membership filters", ru: "Фильтры членства в ролях" })}
                options={[
                  { id: "assigned", label: t(lang, { en: "Assigned", ru: "Назначено" }) },
                  { id: "siem", label: "SIEM" },
                  { id: "defaults", label: t(lang, { en: "Defaults", ru: "По умолчанию" }) },
                  { id: "realm", label: t(lang, { en: "Realm", ru: "Realm" }) },
                  { id: "all", label: t(lang, { en: "All", ru: "Все" }) },
                ]}
              />
            </div>
            <InfoList
              items={[
                { label: t(lang, { en: "Assigned", ru: "Назначено" }), value: keycloakUserForm.roles.length },
                { label: t(lang, { en: "Visible", ru: "Видимо" }), value: visibleRoleMembershipCount },
                { label: t(lang, { en: "Buckets", ru: "Категории" }), value: roleMembershipBuckets.length || 0 },
              ]}
            />
            <div className="react-membership-buckets">
              {roleMembershipBuckets.map((bucket) => (
                <section key={bucket.id} className="react-card react-card-nested react-membership-bucket">
                  <PanelHeader title={bucket.title} subtitle={bucket.subtitle} actions={<StatusBadge value={`${bucket.items.length} ${t(lang, { en: "items", ru: "элементов" })}`} />} />
                  <div className="react-list react-list-compact">
                    {bucket.items.map((item) => (
                      <label key={item.key} className={`react-toggle react-toggle-card ${item.checked ? "react-toggle-card-selected" : ""}`}>
                        <input type="checkbox" checked={item.checked} onChange={() => setKeycloakUserForm((current) => ({ ...current, roles: toggleItem(current.roles, item.name) }))} />
                        <span><strong>{item.name}</strong><small>{item.meta}</small></span>
                      </label>
                    ))}
                  </div>
                </section>
              ))}
              {!roleMembershipBuckets.length ? <EmptyState message={t(lang, { en: "No roles match the current membership filter.", ru: "Под текущий фильтр роли не найдены." })} /> : null}
            </div>
          </section>
          <div className="react-actions react-wrap" style={{ marginTop: 20 }}>
            <button type="button" className="react-primary-button" onClick={() => void saveKeycloakUser()}>{!creatingKeycloakUser && selectedKeycloakUser ? t(lang, { en: "Save user", ru: "Сохранить пользователя" }) : t(lang, { en: "Create user", ru: "Создать пользователя" })}</button>
            <button type="button" className="react-link-button" onClick={() => void rotateKeycloakPassword()} disabled={creatingKeycloakUser || !selectedKeycloakUser || !keycloakUserForm.password.trim()}>{t(lang, { en: "Rotate password", ru: "Обновить пароль" })}</button>
            <button type="button" className="react-link-button" onClick={() => void deleteSelectedKeycloakUser()} disabled={creatingKeycloakUser || !selectedKeycloakUser}>{t(lang, { en: "Delete user", ru: "Удалить пользователя" })}</button>
          </div>
        </DrawerOverlay>
        <DrawerOverlay
          open={groupEditorOpen}
          title={groupDraft ? `${t(lang, { en: "Group window", ru: "Окно группы" })}: ${groupDraft}` : t(lang, { en: "Create Keycloak group", ru: "Создать группу Keycloak" })}
          subtitle={t(lang, { en: "Use the side window to keep group edits separate from the live realm inventory.", ru: "Используйте боковое окно, чтобы держать изменения групп отдельно от живого инвентаря realm." })}
          onClose={() => setGroupEditorOpen(false)}
        >
          <div className="react-form-grid">
            <input className="react-input" value={groupDraft} onChange={(event) => setGroupDraft(event.target.value)} placeholder={t(lang, { en: "Group name", ru: "Имя группы" })} />
          </div>
          <div className="react-actions react-wrap" style={{ marginTop: 20 }}>
            <button type="button" className="react-primary-button" onClick={() => void saveGroup()}>{t(lang, { en: "Save group", ru: "Сохранить группу" })}</button>
          </div>
        </DrawerOverlay>
        <DrawerOverlay
          open={roleEditorOpen}
          title={roleDraft.name ? `${t(lang, { en: "Role window", ru: "Окно роли" })}: ${roleDraft.name}` : t(lang, { en: "Create Keycloak role", ru: "Создать роль Keycloak" })}
          subtitle={t(lang, { en: "Edit role metadata and use the bundle catalog as the alignment reference.", ru: "Изменяйте метаданные роли и используйте каталог наборов прав как опорную модель выравнивания." })}
          onClose={() => setRoleEditorOpen(false)}
        >
          <div className="react-form-grid">
            <input className="react-input" value={roleDraft.name} onChange={(event) => setRoleDraft((current) => ({ ...current, name: event.target.value }))} placeholder={t(lang, { en: "Role name", ru: "Имя роли" })} />
            <input className="react-input" value={roleDraft.description} onChange={(event) => setRoleDraft((current) => ({ ...current, description: event.target.value }))} placeholder={t(lang, { en: "Role description", ru: "Описание роли" })} />
          </div>
          <section className="react-card react-card-nested" style={{ marginTop: 16 }}>
            <PanelHeader title={t(lang, { en: "Bundle catalog", ru: "Каталог наборов прав" })} subtitle={t(lang, { en: "Governance bundles currently exposed to operators.", ru: "Наборы прав контура управления, доступные операторам сейчас." })} />
            <div className="react-list react-list-compact">
              {permissionBundles.map((bundle) => (
                <div key={bundle.id} className="react-list-item"><strong>{bundle.title}</strong><span>{bundle.id}</span></div>
              ))}
            </div>
          </section>
          <div className="react-actions react-wrap" style={{ marginTop: 20 }}>
            <button type="button" className="react-primary-button" onClick={() => void saveRole()}>Save role</button>
          </div>
        </DrawerOverlay>
        <DrawerOverlay
          open={clientEditorOpen}
          title={keycloakClientForm.client_id ? `Client window: ${keycloakClientForm.client_id}` : "Create OIDC client"}
          subtitle="Redirects, origins and service-account controls execute from this side window."
          onClose={() => setClientEditorOpen(false)}
        >
          <div className="react-form-grid">
            <input className="react-input" value={keycloakClientForm.client_id} onChange={(event) => setKeycloakClientForm((current) => ({ ...current, client_id: event.target.value }))} placeholder="Client ID" />
            <input className="react-input" value={keycloakClientForm.name} onChange={(event) => setKeycloakClientForm((current) => ({ ...current, name: event.target.value }))} placeholder="Display name" />
            <input className="react-input react-input-full" value={keycloakClientForm.description} onChange={(event) => setKeycloakClientForm((current) => ({ ...current, description: event.target.value }))} placeholder="Description" />
            <input className="react-input react-input-full" value={keycloakClientForm.redirect_uris} onChange={(event) => setKeycloakClientForm((current) => ({ ...current, redirect_uris: event.target.value }))} placeholder="Redirect URIs (comma separated)" />
            <input className="react-input react-input-full" value={keycloakClientForm.web_origins} onChange={(event) => setKeycloakClientForm((current) => ({ ...current, web_origins: event.target.value }))} placeholder={t(lang, { en: "Web origins (comma separated)", ru: "Web origins (через запятую)" })} />
            <input className="react-input" value={keycloakClientForm.root_url} onChange={(event) => setKeycloakClientForm((current) => ({ ...current, root_url: event.target.value }))} placeholder={t(lang, { en: "Root URL", ru: "Корневой URL" })} />
            <input className="react-input" value={keycloakClientForm.base_url} onChange={(event) => setKeycloakClientForm((current) => ({ ...current, base_url: event.target.value }))} placeholder={t(lang, { en: "Base URL", ru: "Базовый URL" })} />
            <label className="react-toggle"><input type="checkbox" checked={keycloakClientForm.enabled} onChange={(event) => setKeycloakClientForm((current) => ({ ...current, enabled: event.target.checked }))} /><span>{t(lang, { en: "Enabled", ru: "Включен" })}</span></label>
            <label className="react-toggle"><input type="checkbox" checked={keycloakClientForm.public_client} onChange={(event) => setKeycloakClientForm((current) => ({ ...current, public_client: event.target.checked }))} /><span>{t(lang, { en: "Public client", ru: "Публичный клиент" })}</span></label>
            <label className="react-toggle"><input type="checkbox" checked={keycloakClientForm.service_accounts_enabled} onChange={(event) => setKeycloakClientForm((current) => ({ ...current, service_accounts_enabled: event.target.checked }))} /><span>{t(lang, { en: "Service accounts enabled", ru: "Сервисные учетные записи включены" })}</span></label>
          </div>
          {rotatedClientSecret ? <div className="react-callout react-callout-warning" style={{ marginTop: 16 }}><strong>{t(lang, { en: "Latest rotated secret", ru: "Последний обновленный секрет" })}</strong><pre className="react-pre">{rotatedClientSecret}</pre></div> : null}
          <div className="react-actions react-wrap" style={{ marginTop: 20 }}>
            <button type="button" className="react-primary-button" onClick={() => void saveClient()}>{selectedKeycloakClient ? t(lang, { en: "Save client", ru: "Сохранить клиента" }) : t(lang, { en: "Create client", ru: "Создать клиента" })}</button>
            <button type="button" className="react-link-button" onClick={() => void rotateClientSecret()} disabled={!selectedKeycloakClient}>{t(lang, { en: "Rotate client secret", ru: "Обновить секрет клиента" })}</button>
          </div>
        </DrawerOverlay>
        <DrawerOverlay
          open={recoveryEditorOpen}
          title={localUserForm.username ? `${t(lang, { en: "Recovery window", ru: "Окно восстановления" })}: ${localUserForm.username}` : t(lang, { en: "Recovery control window", ru: "Окно управления восстановлением" })}
          subtitle={t(lang, { en: "Break-glass user edits and emergency session controls are executed here.", ru: "Здесь выполняются изменения аварийных пользователей и управление экстренными сессиями." })}
          onClose={() => setRecoveryEditorOpen(false)}
        >
          <div className="react-form-grid">
            <input className="react-input" value={localUserForm.username} onChange={(event) => setLocalUserForm((current) => ({ ...current, username: event.target.value }))} placeholder={t(lang, { en: "Username", ru: "Имя пользователя" })} />
            <select className="react-select" value={localUserForm.role} onChange={(event) => setLocalUserForm((current) => ({ ...current, role: event.target.value }))}>{(usersState.data?.available_roles || ["viewer", "analyst", "admin"]).map((role) => <option key={role}>{role}</option>)}</select>
            <input className="react-input" type="password" value={localUserForm.password} onChange={(event) => setLocalUserForm((current) => ({ ...current, password: event.target.value }))} placeholder={t(lang, { en: "Password", ru: "Пароль" })} />
            <label className="react-toggle"><input type="checkbox" checked={localUserForm.enabled} onChange={(event) => setLocalUserForm((current) => ({ ...current, enabled: event.target.checked }))} /><span>{t(lang, { en: "Enabled", ru: "Включен" })}</span></label>
          </div>
          <section className="react-card react-card-nested" style={{ marginTop: 16 }}>
            <PanelHeader title={t(lang, { en: "Permission bundles", ru: "Наборы прав" })} subtitle={t(lang, { en: "Assign recovery scope without leaving the current lane.", ru: "Назначайте область аварийного доступа, не покидая текущее окно." })} />
            <BundleChecklist bundles={permissionBundles} selected={localUserForm.permissionBundles} onToggle={(bundleId) => setLocalUserForm((current) => ({ ...current, permissionBundles: toggleItem(current.permissionBundles, bundleId) }))} />
          </section>
          <div className="react-grid react-grid-2" style={{ marginTop: 20 }}>
            <input className="react-input" value={breakGlassReason} onChange={(event) => setBreakGlassReason(event.target.value)} placeholder={t(lang, { en: "Break-glass reason", ru: "Причина аварийного доступа" })} />
            <input className="react-input" value={breakGlassMinutes} onChange={(event) => setBreakGlassMinutes(event.target.value)} placeholder={t(lang, { en: "Expiry minutes", ru: "Минуты до истечения" })} />
          </div>
          <div className="react-actions react-wrap" style={{ marginTop: 20 }}>
            <button type="button" className="react-primary-button" onClick={() => void saveLocalUser()}>{t(lang, { en: "Save recovery user", ru: "Сохранить аварийного пользователя" })}</button>
            <button type="button" className="react-link-button" onClick={() => void rotateLocalPassword()} disabled={!selectedUsername || !localUserForm.password.trim()}>{t(lang, { en: "Rotate password", ru: "Обновить пароль" })}</button>
            <button type="button" className="react-link-button" onClick={() => void openBreakGlass()}>{t(lang, { en: "Open break-glass session", ru: "Открыть аварийную сессию" })}</button>
          </div>
        </DrawerOverlay>
        <DrawerOverlay
          open={serviceAccountEditorOpen}
          title={serviceAccountForm.name ? `${t(lang, { en: "Service-account window", ru: "Окно сервисной учетной записи" })}: ${serviceAccountForm.name}` : t(lang, { en: "Service-account control", ru: "Управление сервисной учетной записью" })}
          subtitle={t(lang, { en: "Bundle assignment, token issuance and overlap rotation execute from this side window.", ru: "Назначение наборов прав, выпуск токенов и ротация с перекрытием выполняются из этого бокового окна." })}
          onClose={() => setServiceAccountEditorOpen(false)}
        >
          <div className="react-form-grid">
            <input className="react-input" value={serviceAccountForm.name} onChange={(event) => setServiceAccountForm((current) => ({ ...current, name: event.target.value }))} placeholder={t(lang, { en: "Service account name", ru: "Имя сервисной учетной записи" })} />
            <input className="react-input" value={serviceAccountForm.description} onChange={(event) => setServiceAccountForm((current) => ({ ...current, description: event.target.value }))} placeholder={t(lang, { en: "Description", ru: "Описание" })} />
            <label className="react-toggle"><input type="checkbox" checked={serviceAccountForm.enabled} onChange={(event) => setServiceAccountForm((current) => ({ ...current, enabled: event.target.checked }))} /><span>{t(lang, { en: "Enabled", ru: "Включена" })}</span></label>
          </div>
          <section className="react-card react-card-nested" style={{ marginTop: 16 }}>
            <PanelHeader title={t(lang, { en: "Permission bundles", ru: "Наборы прав" })} subtitle={t(lang, { en: "Attach machine scope and automation rights before issuing tokens.", ru: "Подключайте машинную область прав и автоматизацию до выпуска токенов." })} />
            <BundleChecklist bundles={permissionBundles} selected={serviceAccountForm.permissionBundles} onToggle={(bundleId) => setServiceAccountForm((current) => ({ ...current, permissionBundles: toggleItem(current.permissionBundles, bundleId) }))} />
          </section>
          <div className="react-grid react-grid-3" style={{ marginTop: 20 }}>
            <input className="react-input" value={tokenTitle} onChange={(event) => setTokenTitle(event.target.value)} placeholder={t(lang, { en: "Token title", ru: "Название токена" })} />
            <input className="react-input" value={tokenDays} onChange={(event) => setTokenDays(event.target.value)} placeholder={t(lang, { en: "Expires in days", ru: "Истекает через дней" })} />
            <input className="react-input" value={rotationOverlapMinutes} onChange={(event) => setRotationOverlapMinutes(event.target.value)} placeholder={t(lang, { en: "Rotation overlap minutes", ru: "Минуты перекрытия ротации" })} />
          </div>
          {issuedToken ? <div className="react-callout react-callout-warning" style={{ marginTop: 16 }}><strong>{t(lang, { en: "Issued token", ru: "Выпущенный токен" })}</strong><pre className="react-pre">{issuedToken}</pre></div> : null}
          <div className="react-actions react-wrap" style={{ marginTop: 20 }}>
            <button type="button" className="react-primary-button" onClick={() => void saveServiceAccount()}>{t(lang, { en: "Save service account", ru: "Сохранить сервисную учетную запись" })}</button>
            <button type="button" className="react-link-button" onClick={() => void issueServiceToken()} disabled={!selectedServiceAccountId}>{t(lang, { en: "Issue token", ru: "Выпустить токен" })}</button>
            <button type="button" className="react-link-button" onClick={() => void rotateServiceToken()} disabled={!selectedServiceAccountId}>{t(lang, { en: "Rotate token", ru: "Обновить токен" })}</button>
          </div>
          <div className="react-list react-list-compact" style={{ marginTop: 16 }}>
            {(serviceAccountDetailState.data?.tokens || []).map((token) => (
              <div key={String(token.id || token.title || "token")} className="react-list-item"><strong>{String(token.title || token.id || "token")}</strong><span>{token.expires_ts ? formatTimestamp(token.expires_ts, "compact") : t(lang, { en: "no expiry", ru: "без срока" })}</span><button type="button" className="react-link-button" onClick={() => void revokeServiceToken(String(token.id || ""))}>{t(lang, { en: "Revoke", ru: "Отозвать" })}</button></div>
            ))}
          </div>
        </DrawerOverlay>
        <DrawerOverlay
          open={grantEditorOpen}
          title={t(lang, { en: "System access grant", ru: "Назначение системного доступа" })}
          subtitle={t(lang, { en: "Choose the system, role and section scope. Proxmox and infrastructure hosts stay monitored-only and are intentionally excluded.", ru: "Выберите систему, роль и область разделов. Proxmox и инфраструктурные узлы остаются только под мониторингом и намеренно исключены." })}
          onClose={() => {
            setGrantEditorOpen(false);
            setAccessGrantForm(emptyAccessGrantForm());
          }}
        >
          <DrawerFieldGrid>
            <KeyValue label={t(lang, { en: "Mode", ru: "Режим" })} value={localizeAccessMode(accessSystemIndex.get(accessGrantForm.system_id)?.enforcement_mode, lang)} />
            <KeyValue label={t(lang, { en: "Client", ru: "Клиент" })} value={accessSystemIndex.get(accessGrantForm.system_id)?.client_id || t(lang, { en: "n/a", ru: "н/д" })} />
            <KeyValue label={t(lang, { en: "Internal URL", ru: "Внутренний URL" })} value={accessSystemIndex.get(accessGrantForm.system_id)?.internal_url || t(lang, { en: "n/a", ru: "н/д" })} />
          </DrawerFieldGrid>
          <div className="react-form-grid">
            <label className="react-field">
              <span>{t(lang, { en: "System", ru: "Система" })}</span>
              <select
                className="react-select"
                value={accessGrantForm.system_id}
                onChange={(event) => setAccessGrantForm((current) => ({ ...current, system_id: event.target.value }))}
              >
                {accessSystems.map((system) => (
                  <option key={system.id} value={system.id}>
                    {localizeAccessSystemTitle(String(system.id || ""), String(system.title || system.id || ""), lang)}
                  </option>
                ))}
              </select>
            </label>
            <label className="react-field">
              <span>{t(lang, { en: "Role", ru: "Роль" })}</span>
              <select
                className="react-select"
                value={accessGrantForm.role}
                onChange={(event) => setAccessGrantForm((current) => ({ ...current, role: event.target.value }))}
              >
                {(accessSystems.find((item) => item.id === accessGrantForm.system_id)?.roles || []).map((role) => (
                  <option key={role.id} value={role.id}>
                    {localizeAccessRole(accessGrantForm.system_id, String(role.id || ""), String(role.title || role.id || ""), lang)}
                  </option>
                ))}
              </select>
            </label>
            <label className="react-toggle">
              <input
                type="checkbox"
                checked={accessGrantForm.enabled}
                onChange={(event) => setAccessGrantForm((current) => ({ ...current, enabled: event.target.checked }))}
              />
              <span>{t(lang, { en: "Enabled", ru: "Включено" })}</span>
            </label>
          </div>
          <div className="react-list react-list-compact" style={{ marginTop: 16 }}>
            {(accessSystems.find((item) => item.id === accessGrantForm.system_id)?.sections || []).map((section) => (
              <label key={section.id} className="react-toggle react-toggle-card">
                <input
                  type="checkbox"
                  checked={accessGrantForm.sections.includes(section.id)}
                  onChange={() =>
                    setAccessGrantForm((current) => ({
                      ...current,
                      sections: toggleItem(current.sections, section.id),
                    }))
                  }
                />
                <span>
                  <strong>{localizeAccessSection(accessGrantForm.system_id, String(section.id || ""), String(section.title || section.id || ""), lang)}</strong>
                  <small>{section.id}</small>
                </span>
              </label>
            ))}
          </div>
          <div className="react-actions" style={{ marginTop: 20 }}>
            <button type="button" className="react-primary-button" onClick={() => void saveAccessGrant()}>
              {accessGrantForm.id ? t(lang, { en: "Save grant", ru: "Сохранить назначение" }) : t(lang, { en: "Create grant", ru: "Создать назначение" })}
            </button>
            <button
              type="button"
              className="react-link-button"
              onClick={() => {
                setGrantEditorOpen(false);
                setAccessGrantForm(emptyAccessGrantForm());
              }}
            >
              {t(lang, { en: "Cancel", ru: "Отмена" })}
            </button>
          </div>
        </DrawerOverlay>
      </div>
    </AsyncGate>
  );
}
