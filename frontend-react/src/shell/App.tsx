import { Suspense, lazy, useCallback, useEffect, useMemo, useState, type ComponentType, type ReactNode } from "react";
import { Route, Routes, useLocation, useNavigate } from "react-router-dom";
import { api, setApiTenantScope, type BootstrapResponse, type TenantScopeResponse } from "./api";
import { useAsyncData, usePolledData } from "./hooks";
import { EmptyState, Icon, ReactErrorBoundary } from "./chrome";
import { ShellContext, TIMEZONE_OPTIONS, formatTimestampValue, t, toTimeZoneInputValue, toUtcQueryValue } from "./context";
import { FeedbackProvider } from "./feedback";
import { ShellSidebar } from "./ShellSidebar";
import { primaryNavigation, securityNavigation } from "./navigation";
import { DrawerOverlay, InfoList, PanelHeader } from "./surfaces";
import type { PlatformStatusResponse } from "./types";

function lazyPage<TModule extends Record<string, unknown>, TKey extends keyof TModule>(
  loader: () => Promise<TModule>,
  key: TKey,
) {
  return lazy(async () => {
    const module = await loader();
    return { default: module[key] as ComponentType };
  });
}

const AssetsPage = lazyPage(() => import("./pages/AssetsPage"), "AssetsPage");
const AccessPage = lazyPage(() => import("./pages/AccessPage"), "AccessPage");
const BuildersPage = lazyPage(() => import("./pages/builders/BuildersWorkbench"), "BuildersPage");
const CasesPage = lazyPage(() => import("./pages/CasesPage"), "CasesPage");
const CollectorsPage = lazyPage(() => import("./pages/CollectorsPage"), "CollectorsPage");
const ConnectorsPage = lazyPage(() => import("./pages/ConnectorsPage"), "ConnectorsPage");
const ControlPanelPage = lazyPage(() => import("./pages/ControlPanelPage"), "ControlPanelPage");
const DashboardPage = lazyPage(() => import("./pages/DashboardPage"), "DashboardPage");
const DocumentationPage = lazyPage(() => import("./pages/DocumentationPage"), "DocumentationPage");
const EntitiesPage = lazyPage(() => import("./pages/EntitiesPage"), "EntitiesPage");
const EventsPage = lazyPage(() => import("./pages/EventsPage"), "EventsPage");
const HostRuntimePage = lazyPage(() => import("./pages/HostRuntimePage"), "HostRuntimePage");
const IngestPage = lazyPage(() => import("./pages/IngestPage"), "IngestPage");
const IncidentsPage = lazyPage(() => import("./pages/IncidentsPage"), "IncidentsPage");
const ResponsePage = lazyPage(() => import("./pages/ResponsePage"), "ResponsePage");
const ResourceCatalogPage = lazyPage(() => import("./pages/ResourceCatalogPage"), "ResourceCatalogPage");
const SecurityServicePage = lazyPage(() => import("./pages/SecurityServicePage"), "SecurityServicePage");
const SourcesPage = lazyPage(() => import("./pages/SourcesPage"), "SourcesPage");
const ThreatIntelPage = lazyPage(() => import("./pages/ThreatIntelPage"), "ThreatIntelPage");
const TopologyPage = lazyPage(() => import("./pages/TopologyPage"), "TopologyPage");
const VulnPage = lazyPage(() => import("./pages/VulnPage"), "VulnPage");

type Lang = "en" | "ru";
type Theme = "dark" | "light";

function routeElement(title: string, node: ReactNode) {
  return (
    <ReactErrorBoundary title={`${title} route failed to render`}>
      <Suspense fallback={<EmptyState message={`Загрузка: ${title}...`} />}>{node}</Suspense>
    </ReactErrorBoundary>
  );
}

function readRequestedTenants(availableIds: string[]) {
  const params = new URLSearchParams(window.location.search);
  const requested = String(params.get("tenants") || window.localStorage.getItem("rdegon-tenant-scope") || "")
    .split(",")
    .map((item) => item.trim())
    .filter((item) => availableIds.includes(item));
  return requested.length ? [...new Set(requested)] : availableIds.slice(0, 1);
}

export function App() {
  const location = useLocation();
  const navigate = useNavigate();
  const loadBootstrap = useCallback(() => api.bootstrap(), []);
  const loadTenantScope = useCallback(() => api.tenantScope(), []);
  const loadPlatformStatus = useCallback(() => api.platformStatus(), []);
  const bootstrap = useAsyncData<BootstrapResponse>(loadBootstrap, []);
  const tenantScope = useAsyncData<TenantScopeResponse>(loadTenantScope, []);
  const platformStatus = usePolledData<PlatformStatusResponse>(loadPlatformStatus, 15000, []);
  const [theme, setTheme] = useState<Theme>(() => window.localStorage.getItem("rdegon-theme") === "dark" ? "dark" : "light");
  const [sidebarCollapsed, setSidebarCollapsed] = useState(() => window.localStorage.getItem("rdegon-sidebar-collapsed") === "true");
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [lang, setLangState] = useState<Lang>("ru");
  const [timezone, setTimezoneState] = useState(() => window.localStorage.getItem("rdegon-timezone") || "Europe/Moscow");
  const [shortcutsOpen, setShortcutsOpen] = useState(false);
  const [selectedTenantIds, setSelectedTenantIdsState] = useState<string[]>([]);

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
    window.localStorage.setItem("rdegon-theme", theme);
  }, [theme]);

  useEffect(() => {
    window.localStorage.setItem("rdegon-sidebar-collapsed", String(sidebarCollapsed));
  }, [sidebarCollapsed]);

  useEffect(() => {
    if (!bootstrap.data?.ui_lang) return;
    setLangState(bootstrap.data.ui_lang);
    document.documentElement.lang = bootstrap.data.ui_lang;
  }, [bootstrap.data?.ui_lang]);

  useEffect(() => {
    window.localStorage.setItem("rdegon-timezone", timezone);
  }, [timezone]);

  useEffect(() => {
    const availableIds = (tenantScope.data?.available || []).map((item) => item.id);
    if (!availableIds.length) return;
    const next = readRequestedTenants(availableIds);
    setApiTenantScope(next);
    setSelectedTenantIdsState(next);
  }, [tenantScope.data?.available]);

  const setSelectedTenantIds = useCallback((next: string[]) => {
    const availableIds = new Set((tenantScope.data?.available || []).map((item) => item.id));
    const selected = [...new Set(next.filter((item) => availableIds.has(item)))];
    if (!selected.length) return;
    setApiTenantScope(selected);
    setSelectedTenantIdsState(selected);
    window.localStorage.setItem("rdegon-tenant-scope", selected.join(","));
    const params = new URLSearchParams(location.search);
    params.set("tenants", selected.join(","));
    navigate({ pathname: location.pathname, search: `?${params.toString()}` }, { replace: true });
  }, [location.pathname, location.search, navigate, tenantScope.data?.available]);

  useEffect(() => {
    const isEditableTarget = (target: EventTarget | null) =>
      target instanceof HTMLElement &&
      (target.tagName === "INPUT" || target.tagName === "TEXTAREA" || target.tagName === "SELECT" || target.isContentEditable);
    const onKeyDown = (event: KeyboardEvent) => {
      if (isEditableTarget(event.target)) return;
      if (event.key === "?") {
        event.preventDefault();
        setShortcutsOpen(true);
        return;
      }
      if (!event.altKey) return;
      const targets: Record<string, string> = { "1": "/dashboards", "2": "/incidents", "3": "/events", "4": "/sources" };
      const target = targets[event.key];
      if (target) {
        event.preventDefault();
        navigate(target);
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [navigate]);

  const uiLang = lang;
  const sectionAccess = useMemo(() => new Set(bootstrap.data?.user?.section_access || []), [bootstrap.data?.user?.section_access]);
  const allNavigationItems = useMemo(
    () => [...primaryNavigation(uiLang).flatMap((group) => group.items), ...securityNavigation(uiLang).flatMap((group) => group.items)],
    [uiLang],
  );
  const activeItem = useMemo(() => {
    const sorted = [...allNavigationItems].sort((left, right) => right.to.length - left.to.length);
    return sorted.find((item) => location.pathname === item.to || location.pathname.startsWith(`${item.to}/`)) || sorted.find((item) => item.to === "/dashboards")!;
  }, [allNavigationItems, location.pathname]);
  const clickhouseHealthy =
    typeof platformStatus.data?.clickhouse_runtime?.healthy === "boolean"
      ? platformStatus.data.clickhouse_runtime.healthy
      : platformStatus.data?.clickhouse_ok;
  const contextValue = useMemo(
    () => ({
      lang: uiLang,
      setLang: (next: Lang) => {
        document.cookie = `ui_lang=${next}; path=/; max-age=31536000; SameSite=Lax`;
        document.documentElement.lang = next;
        setLangState(next);
      },
      theme,
      timezone,
      setTimezone: setTimezoneState,
      permissions: [...(bootstrap.data?.user?.permissions || [])],
      sectionAccess: [...(bootstrap.data?.user?.section_access || [])],
      tenants: tenantScope.data?.available || [],
      selectedTenantIds,
      setSelectedTenantIds,
      formatTimestamp: (value: unknown, style: "full" | "compact" | "date" | "time" = "full") =>
        formatTimestampValue(value, timezone, uiLang, style),
      toInputDateTime: (value: unknown) => toTimeZoneInputValue(value, timezone),
      toUtcQueryValue: (value: string) => toUtcQueryValue(value, timezone),
    }),
    [
      bootstrap.data?.user?.permissions,
      bootstrap.data?.user?.section_access,
      selectedTenantIds,
      setSelectedTenantIds,
      tenantScope.data?.available,
      theme,
      timezone,
      uiLang,
    ],
  );

  if (bootstrap.loading || tenantScope.loading) return <EmptyState message="Загрузка Rdegon Sentinel..." />;
  if (bootstrap.error || !bootstrap.data) return <EmptyState message={bootstrap.error || "Не удалось загрузить UI"} />;
  if (tenantScope.error || !tenantScope.data) return <EmptyState message={tenantScope.error || "Не удалось загрузить tenant scope"} />;
  if (!selectedTenantIds.length) return <EmptyState message="Применение tenant scope..." />;

  return (
    <ShellContext.Provider value={contextValue}>
      <FeedbackProvider>
        <a className="react-skip-link" href="#react-main-content">{t(uiLang, { en: "Skip to content", ru: "К содержимому" })}</a>
        <div className={`react-shell ${sidebarCollapsed ? "react-shell-collapsed" : ""} ${sidebarOpen ? "react-shell-mobile-open" : ""}`}>
          <ShellSidebar
            pathname={location.pathname}
            collapsed={sidebarCollapsed}
            mobileOpen={sidebarOpen}
            sectionAccess={sectionAccess}
            onCollapsedChange={setSidebarCollapsed}
            onMobileOpenChange={setSidebarOpen}
          />
          <main id="react-main-content" className="react-main" tabIndex={-1}>
            <header className="react-topbar">
              <div className="react-topbar-copy react-topbar-copy-compact">
                <button type="button" className="react-icon-button react-mobile-only" onClick={() => setSidebarOpen(true)} aria-label={t(uiLang, { en: "Open menu", ru: "Открыть меню" })}>☰</button>
                <div className="react-page-indicator react-page-indicator-plain"><Icon name={activeItem.icon} size={16} /><span>{activeItem.label}</span></div>
              </div>
              <div className="react-topbar-meta">
                <span className={`react-badge ${clickhouseHealthy === true ? "ok" : clickhouseHealthy === false ? "down" : "soft"}`}>
                  ClickHouse {clickhouseHealthy === true ? "LIVE" : clickhouseHealthy === false ? "DOWN" : "SYNC"}
                </span>
                <label className="react-topbar-select-shell" title={t(uiLang, { en: "Timezone", ru: "Часовой пояс" })}>
                  <Icon name="globe" size={14} />
                  <select className="react-select react-select-topbar" value={timezone} onChange={(event) => setTimezoneState(event.target.value)}>
                    {TIMEZONE_OPTIONS.map((item) => <option key={item.value} value={item.value}>{item.label}</option>)}
                  </select>
                </label>
                <button type="button" className="react-icon-button" onClick={() => setTheme((current) => current === "dark" ? "light" : "dark")} title={t(uiLang, { en: "Toggle theme", ru: "Сменить тему" })} aria-label={t(uiLang, { en: "Toggle theme", ru: "Сменить тему" })}>
                  {theme === "dark" ? "☀" : "◐"}
                </button>
                <button type="button" className="react-link-button" onClick={() => contextValue.setLang(uiLang === "ru" ? "en" : "ru")}>{uiLang.toUpperCase()}</button>
                <button type="button" className="react-link-button" onClick={() => setShortcutsOpen(true)}>?</button>
                <span className="react-user-badge" title={`${bootstrap.data.user.username} (${bootstrap.data.user.role})`}>
                  <b>{bootstrap.data.user.username.slice(0, 2).toUpperCase()}</b>
                  <span><strong>{bootstrap.data.user.username}</strong><small>{bootstrap.data.user.role}</small></span>
                </span>
                <button type="button" className="react-link-button react-logout-button" onClick={() => window.location.assign("/auth/logout")}>{t(uiLang, { en: "Logout", ru: "Выйти" })}</button>
              </div>
            </header>
            <div key={selectedTenantIds.join(",")} className="react-route-scope">
              <Routes>
                <Route path="/" element={routeElement("Мониторинг", <DashboardPage />)} />
                <Route path="/dashboards" element={routeElement("Мониторинг", <DashboardPage />)} />
                <Route path="/alerts" element={routeElement("Алерты", <IncidentsPage />)} />
                <Route path="/incidents" element={routeElement("Инциденты", <IncidentsPage />)} />
                <Route path="/events" element={routeElement("События", <EventsPage />)} />
                <Route path="/assets" element={routeElement("Активы", <AssetsPage />)} />
                <Route path="/entities" element={routeElement("Сущности", <EntitiesPage />)} />
                <Route path="/cases" element={routeElement("Кейсы", <CasesPage />)} />
                <Route path="/reports" element={routeElement("Отчеты", <VulnPage />)} />
                <Route path="/reports/:reportId" element={routeElement("Отчет", <VulnPage />)} />
                <Route path="/resources" element={routeElement("Ресурсы", <ResourceCatalogPage />)} />
                <Route path="/rules" element={routeElement("Контент детектирования", <BuildersPage />)} />
                <Route path="/tasks" element={routeElement("Диспетчер задач", <ResponsePage />)} />
                <Route path="/metrics" element={routeElement("Метрики", <HostRuntimePage />)} />
                <Route path="/control" element={routeElement("Control Plane", <ControlPanelPage />)} />
                <Route path="/ingest" element={routeElement("Прием данных", <IngestPage />)} />
                <Route path="/sources" element={routeElement("Источники", <SourcesPage />)} />
                <Route path="/collectors" element={routeElement("Коллекторы", <CollectorsPage />)} />
                <Route path="/connectors" element={routeElement("Коннекторы", <ConnectorsPage />)} />
                <Route path="/topology" element={routeElement("Топология", <TopologyPage />)} />
                <Route path="/response" element={routeElement("SOAR", <ResponsePage />)} />
                <Route path="/host-runtime" element={routeElement("Состояние узлов", <HostRuntimePage />)} />
                <Route path="/vuln" element={routeElement("Уязвимости", <VulnPage />)} />
                <Route path="/vuln/*" element={routeElement("Уязвимости", <VulnPage />)} />
                <Route path="/threat-intel" element={routeElement("Threat Intelligence", <ThreatIntelPage />)} />
                <Route path="/security/coverage" element={routeElement("Покрытие", <ConnectorsPage />)} />
                <Route path="/security/discovery" element={routeElement("Discovery", <SourcesPage />)} />
                <Route path="/security/identity" element={routeElement("Identity", <AccessPage />)} />
                <Route path="/security/:serviceId" element={routeElement("Средство защиты", <SecurityServicePage />)} />
                <Route path="/access" element={routeElement("Параметры", <AccessPage />)} />
                <Route path="/builders" element={routeElement("Конструкторы", <BuildersPage />)} />
                <Route path="/docs" element={routeElement("Документация", <DocumentationPage />)} />
                <Route path="/docs/page/:docName" element={routeElement("Документация", <DocumentationPage />)} />
                <Route path="/docs/playbooks/:playbookSlug" element={routeElement("Документация", <DocumentationPage />)} />
              </Routes>
            </div>
          </main>
        </div>
        <DrawerOverlay open={shortcutsOpen} title={t(uiLang, { en: "Keyboard shortcuts", ru: "Горячие клавиши" })} subtitle={t(uiLang, { en: "Global analyst navigation.", ru: "Глобальная навигация аналитика." })} onClose={() => setShortcutsOpen(false)}>
          <section className="react-card react-card-nested">
            <PanelHeader title={t(uiLang, { en: "Navigation", ru: "Навигация" })} icon="dashboard" />
            <InfoList items={[
              { label: "?", value: t(uiLang, { en: "Open shortcuts", ru: "Открыть горячие клавиши" }) },
              { label: "Alt + 1", value: t(uiLang, { en: "Monitoring", ru: "Мониторинг" }) },
              { label: "Alt + 2", value: t(uiLang, { en: "Incidents", ru: "Инциденты" }) },
              { label: "Alt + 3", value: t(uiLang, { en: "Events", ru: "События" }) },
              { label: "Alt + 4", value: t(uiLang, { en: "Sources", ru: "Источники" }) },
            ]} />
          </section>
        </DrawerOverlay>
      </FeedbackProvider>
    </ShellContext.Provider>
  );
}
