import { Suspense, lazy, useEffect, useMemo, useState, type ComponentType, type ReactNode } from "react";
import { NavLink, Route, Routes, useLocation, useNavigate } from "react-router-dom";
import { useCallback } from "react";
import { api, type BootstrapResponse } from "./api";
import { useAsyncData, usePolledData } from "./hooks";
import { EmptyState, Icon, ReactErrorBoundary } from "./chrome";
import { ShellContext, TIMEZONE_OPTIONS, formatTimestampValue, t, toTimeZoneInputValue, toUtcQueryValue } from "./context";
import { FeedbackProvider } from "./feedback";
import { DrawerOverlay, InfoList, PanelHeader } from "./surfaces";
import type { PlatformStatusResponse } from "./types";

const BRAND_ASSET_VERSION = "20260327j";
const brandMarkUrl = `/app/mark.svg?v=${BRAND_ASSET_VERSION}`;

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
const SecurityServicePage = lazyPage(() => import("./pages/SecurityServicePage"), "SecurityServicePage");
const SourcesPage = lazyPage(() => import("./pages/SourcesPage"), "SourcesPage");
const ThreatIntelPage = lazyPage(() => import("./pages/ThreatIntelPage"), "ThreatIntelPage");
const TopologyPage = lazyPage(() => import("./pages/TopologyPage"), "TopologyPage");
const VulnPage = lazyPage(() => import("./pages/VulnPage"), "VulnPage");

type Lang = "en" | "ru";
type Theme = "dark";

function shellText(lang: Lang) {
  return {
    menu: t(lang, { en: "Menu", ru: "\u041c\u0435\u043d\u044e" }),
    hide: t(lang, { en: "Hide", ru: "\u0421\u043a\u0440\u044b\u0442\u044c" }),
    show: t(lang, { en: "Show", ru: "\u041f\u043e\u043a\u0430\u0437\u0430\u0442\u044c" }),
    language: t(lang, { en: "Language", ru: "\u042f\u0437\u044b\u043a" }),
    settings: t(lang, { en: "Settings", ru: "\u041d\u0430\u0441\u0442\u0440\u043e\u0439\u043a\u0438" }),
    shortcuts: t(lang, { en: "Shortcuts", ru: "\u0428\u043e\u0440\u0442\u043a\u0430\u0442\u044b" }),
    clickhouseLive: t(lang, { en: "LIVE", ru: "\u041e\u041d\u041b\u0410\u0419\u041d" }),
    clickhouseDown: t(lang, { en: "DOWN", ru: "\u041d\u0415\u0414\u041e\u0421\u0422\u0423\u041f\u0415\u041d" }),
    clickhouseSync: t(lang, { en: "SYNCING", ru: "\u0421\u0418\u041d\u0425\u0420\u041e\u041d\u0418\u0417\u0410\u0426\u0418\u042f" }),
    account: t(lang, { en: "Account", ru: "\u0410\u043a\u043a\u0430\u0443\u043d\u0442" }),
    logout: t(lang, { en: "Logout", ru: "\u0412\u044b\u0439\u0442\u0438" }),
  };
}

function routeLoadingMessage(title: string) {
  const normalized = String(title || "").trim().toLowerCase();
  const known: Record<string, string> = {
    overview: "Загрузка обзора...",
    incidents: "Загрузка инцидентов...",
    events: "Загрузка событий...",
    assets: "Загрузка активов...",
    entities: "Загрузка сущностей...",
    cases: "Загрузка кейсов...",
    ingest: "Загрузка приема данных...",
    sources: "Загрузка источников...",
    topology: "Загрузка топологии...",
    collectors: "Загрузка коллекторов...",
    connectors: "Загрузка коннекторов...",
    vulnerabilities: "Загрузка раздела уязвимостей...",
    "threat intel": "Загрузка киберразведки...",
    access: "Загрузка раздела доступа...",
    response: "Загрузка оркестрации...",
    "host runtime": "Загрузка состояния узлов...",
    "security service": "Загрузка сервиса безопасности...",
    builders: "Загрузка конструкторов...",
    documentation: "Загрузка документации...",
    "control panel": "Загрузка панели управления...",
  };
  return known[normalized] || "Загрузка раздела...";
}

function routeElement(title: string, node: ReactNode) {
  return (
    <ReactErrorBoundary title={`${title} route failed to render`}>
      <Suspense fallback={<EmptyState message={routeLoadingMessage(title)} />}>{node}</Suspense>
    </ReactErrorBoundary>
  );
}

export function App() {
  const location = useLocation();
  const navigate = useNavigate();
  const loadBootstrap = useCallback(() => api.bootstrap(), []);
  const loadPlatformStatus = useCallback(() => api.platformStatus(), []);
  const bootstrap = useAsyncData<BootstrapResponse>(loadBootstrap, []);
  const platformStatus = usePolledData<PlatformStatusResponse>(loadPlatformStatus, 15000, []);
  const [theme] = useState<Theme>("dark");
  const [sidebarCollapsed, setSidebarCollapsed] = useState(() => window.localStorage.getItem("rdegon-sidebar-collapsed") === "true");
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [lang, setLangState] = useState<Lang>("ru");
  const [timezone, setTimezoneState] = useState(() => window.localStorage.getItem("rdegon-timezone") || "Europe/Moscow");
  const [shortcutsOpen, setShortcutsOpen] = useState(false);

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
    window.localStorage.setItem("rdegon-theme", theme);
  }, [theme]);

  useEffect(() => {
    window.localStorage.setItem("rdegon-sidebar-collapsed", String(sidebarCollapsed));
  }, [sidebarCollapsed]);

  useEffect(() => {
    if (bootstrap.data?.ui_lang) {
      setLangState(bootstrap.data.ui_lang);
      document.documentElement.lang = bootstrap.data.ui_lang;
    }
  }, [bootstrap.data?.ui_lang]);

  useEffect(() => {
    window.localStorage.setItem("rdegon-timezone", timezone);
  }, [timezone]);

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
      if (event.key === "1") {
        event.preventDefault();
        navigate("/dashboards");
      } else if (event.key === "2") {
        event.preventDefault();
        navigate("/incidents");
      } else if (event.key === "3") {
        event.preventDefault();
        navigate("/events");
      } else if (event.key === "4") {
        event.preventDefault();
        navigate("/sources");
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [navigate]);

  const uiLang = lang;
  const text = shellText(uiLang);
  const clickhouseState =
    typeof platformStatus.data?.clickhouse_runtime?.healthy === "boolean"
      ? (platformStatus.data.clickhouse_runtime.healthy ? "ok" : "down")
      : typeof platformStatus.data?.clickhouse_ok === "boolean"
        ? (platformStatus.data.clickhouse_ok ? "ok" : "down")
        : "loading";
  const sectionAccess = new Set(bootstrap.data?.user?.section_access || []);
  const routeSectionMap: Record<string, string> = {
    "/dashboards": "overview",
    "/incidents": "incidents",
    "/events": "events",
    "/assets": "assets",
    "/ingest": "ingest",
    "/sources": "sources",
    "/topology": "sources",
    "/collectors": "collectors",
    "/connectors": "connectors",
    "/vuln": "vuln",
    "/entities": "entities",
    "/cases": "cases",
    "/access": "access",
    "/response": "response",
    "/host-runtime": "host-runtime",
    "/security/ndr": "sources",
    "/security/dfir": "sources",
    "/security/analysis": "sources",
    "/security/threat-intel": "sources",
    "/security/pki": "sources",
    "/security/evidence": "sources",
    "/threat-intel": "threat-intel",
    "/builders": "builders",
    "/docs": "docs",
  };
  const allNavItems = [
    { to: "/dashboards", label: t(uiLang, { en: "Overview", ru: "\u041e\u0431\u0437\u043e\u0440" }), icon: "dashboard" as const },
    { to: "/control", label: t(uiLang, { en: "Control Panel", ru: "\u041f\u0430\u043d\u0435\u043b\u044c \u0443\u043f\u0440\u0430\u0432\u043b\u0435\u043d\u0438\u044f" }), icon: "control" as const },
    { to: "/incidents", label: t(uiLang, { en: "Incidents", ru: "\u0418\u043d\u0446\u0438\u0434\u0435\u043d\u0442\u044b" }), icon: "incidents" as const },
    { to: "/events", label: t(uiLang, { en: "Events", ru: "\u0421\u043e\u0431\u044b\u0442\u0438\u044f" }), icon: "events" as const },
    { to: "/assets", label: t(uiLang, { en: "Assets", ru: "\u0410\u043a\u0442\u0438\u0432\u044b" }), icon: "assets" as const },
    { to: "/ingest", label: t(uiLang, { en: "Ingest", ru: "Прием данных" }), icon: "ingest" as const },
    { to: "/sources", label: t(uiLang, { en: "Sources", ru: "\u0418\u0441\u0442\u043e\u0447\u043d\u0438\u043a\u0438" }), icon: "sources" as const },
    { to: "/topology", label: t(uiLang, { en: "Topology", ru: "\u0422\u043e\u043f\u043e\u043b\u043e\u0433\u0438\u044f" }), icon: "map" as const },
    { to: "/collectors", label: t(uiLang, { en: "Collectors", ru: "\u041a\u043e\u043b\u043b\u0435\u043a\u0442\u043e\u0440\u044b" }), icon: "collectors" as const },
    { to: "/connectors", label: t(uiLang, { en: "Connectors", ru: "\u041a\u043e\u043d\u043d\u0435\u043a\u0442\u043e\u0440\u044b" }), icon: "connectors" as const },
    { to: "/vuln", label: t(uiLang, { en: "Vulnerabilities", ru: "\u0423\u044f\u0437\u0432\u0438\u043c\u043e\u0441\u0442\u0438" }), icon: "vuln" as const },
    { to: "/entities", label: t(uiLang, { en: "Entities", ru: "\u0421\u0443\u0449\u043d\u043e\u0441\u0442\u0438" }), icon: "entities" as const },
    { to: "/cases", label: t(uiLang, { en: "Cases", ru: "\u041a\u0435\u0439\u0441\u044b" }), icon: "cases" as const },
    { to: "/access", label: t(uiLang, { en: "Access", ru: "\u0414\u043e\u0441\u0442\u0443\u043f" }), icon: "access" as const },
    { to: "/response", label: t(uiLang, { en: "SOAR", ru: "Оркестрация" }), icon: "control" as const },
    { to: "/host-runtime", label: t(uiLang, { en: "Host Runtime", ru: "Состояние узлов" }), icon: "dashboard" as const },
    { to: "/security/ndr", label: "NDR", icon: "map" as const },
    { to: "/security/dfir", label: "DFIR", icon: "incidents" as const },
    { to: "/security/analysis", label: t(uiLang, { en: "Analysis", ru: "Анализ файлов" }), icon: "vuln" as const },
    { to: "/security/threat-intel", label: "MISP", icon: "intel" as const },
    { to: "/security/pki", label: "PKI", icon: "access" as const },
    { to: "/security/evidence", label: t(uiLang, { en: "Evidence", ru: "Хранилище данных" }), icon: "cases" as const },
    { to: "/threat-intel", label: t(uiLang, { en: "Threat Intel", ru: "Киберразведка" }), icon: "intel" as const },
    { to: "/builders", label: t(uiLang, { en: "Builders", ru: "\u041a\u043e\u043d\u0441\u0442\u0440\u0443\u043a\u0442\u043e\u0440\u044b" }), icon: "builders" as const },
    { to: "/docs", label: t(uiLang, { en: "Documentation", ru: "\u0414\u043e\u043a\u0443\u043c\u0435\u043d\u0442\u0430\u0446\u0438\u044f" }), icon: "docs" as const },
  ];
  const navItems = allNavItems.filter((item) => {
    if (item.to === "/control") return false;
    if (!sectionAccess.size) return true;
    return sectionAccess.has(routeSectionMap[item.to] || "");
  });
  const navGroupDefinitions = [
    {
      id: "operations",
      title: t(uiLang, { en: "Operations", ru: "\u041e\u043f\u0435\u0440\u0430\u0446\u0438\u0438" }),
      routes: ["/dashboards", "/incidents", "/events", "/cases", "/entities", "/assets"],
    },
    {
      id: "data",
      title: t(uiLang, { en: "Data Plane", ru: "\u041f\u043e\u0442\u043e\u043a \u0434\u0430\u043d\u043d\u044b\u0445" }),
      routes: ["/ingest", "/sources", "/topology", "/collectors", "/connectors"],
    },
    {
      id: "exposure",
      title: t(uiLang, { en: "Exposure & Intel", ru: "\u0423\u044f\u0437\u0432\u0438\u043c\u043e\u0441\u0442\u0438 \u0438 \u043a\u0438\u0431\u0435\u0440\u0440\u0430\u0437\u0432\u0435\u0434\u043a\u0430" }),
      routes: ["/vuln", "/threat-intel"],
    },
    {
      id: "automation",
      title: t(uiLang, { en: "Response & Runtime", ru: "\u0420\u0435\u0430\u043a\u0446\u0438\u044f \u0438 \u0441\u043e\u0441\u0442\u043e\u044f\u043d\u0438\u0435" }),
      routes: ["/response", "/host-runtime", "/access"],
    },
    {
      id: "security-systems",
      title: t(uiLang, { en: "Security Systems", ru: "Системы безопасности" }),
      routes: ["/security/ndr", "/security/dfir", "/security/analysis", "/security/threat-intel", "/security/pki", "/security/evidence"],
    },
    {
      id: "content",
      title: t(uiLang, { en: "Content & Docs", ru: "\u041a\u043e\u043d\u0442\u0435\u043d\u0442 \u0438 \u0434\u043e\u043a\u0443\u043c\u0435\u043d\u0442\u0430\u0446\u0438\u044f" }),
      routes: ["/builders", "/docs"],
    },
  ];
  const mappedRoutes = new Set(navGroupDefinitions.flatMap((group) => group.routes));
  const navGroups = navGroupDefinitions
    .map((group) => ({
      id: group.id,
      title: group.title,
      items: navItems.filter((item) => group.routes.includes(item.to)),
    }))
    .filter((group) => group.items.length > 0);
  const uncategorizedItems = navItems.filter((item) => !mappedRoutes.has(item.to));
  if (uncategorizedItems.length) {
    navGroups.push({
      id: "more",
      title: t(uiLang, { en: "More", ru: "\u0415\u0449\u0451" }),
      items: uncategorizedItems,
    });
  }
  const activeItem =
    allNavItems.find((item) => {
      if (item.to === "/dashboards") {
        return location.pathname === "/" || location.pathname === "/dashboards";
      }
      return location.pathname === item.to || location.pathname.startsWith(`${item.to}/`);
    }) || allNavItems[0];
  const contextValue = useMemo(
    () => ({
      lang: uiLang,
      setLang: (next: Lang) => {
        document.cookie = `ui_lang=${next}; path=/; max-age=31536000; SameSite=Lax`;
        document.documentElement.lang = next;
        setLangState(next);
        window.location.reload();
      },
      theme,
      timezone,
      setTimezone: setTimezoneState,
      permissions: [...(bootstrap.data?.user?.permissions || [])],
      sectionAccess: [...(bootstrap.data?.user?.section_access || [])],
      formatTimestamp: (value: unknown, style: "full" | "compact" | "date" | "time" = "full") =>
        formatTimestampValue(value, timezone, uiLang, style),
      toInputDateTime: (value: unknown) => toTimeZoneInputValue(value, timezone),
      toUtcQueryValue: (value: string) => toUtcQueryValue(value, timezone),
    }),
    [bootstrap.data?.user?.permissions, bootstrap.data?.user?.section_access, theme, timezone, uiLang],
  );

  if (bootstrap.loading) return <EmptyState message="Loading Rdegon Sentinel shell..." />;
  if (bootstrap.error || !bootstrap.data) return <EmptyState message={bootstrap.error || "Unable to bootstrap UI"} />;

  return (
    <ShellContext.Provider value={contextValue}>
      <FeedbackProvider>
        <a className="react-skip-link" href="#react-main-content">
          {t(uiLang, { en: "Skip to content", ru: "\u041a \u0441\u043e\u0434\u0435\u0440\u0436\u0438\u043c\u043e\u043c\u0443" })}
        </a>
        <div className={`react-shell ${sidebarCollapsed ? "react-shell-collapsed" : ""} ${sidebarOpen ? "react-shell-mobile-open" : ""}`}>
        <button type="button" className={`react-sidebar-backdrop ${sidebarOpen ? "visible" : ""}`} onClick={() => setSidebarOpen(false)} aria-label="Close navigation" />
        <aside className="react-sidebar">
          <div className="react-brand">
            <div className="react-brand-mark" aria-hidden="true">
              <img className="react-brand-mark-image" src={brandMarkUrl} alt="" />
            </div>
            {!sidebarCollapsed ? <div className="react-brand-copy">
              <h1>Rdegon Sentinel</h1>
              <p>{t(uiLang, { en: "Instrument-grade SOC control plane", ru: "Инструментальный контур управления SOC" })}</p>
            </div> : null}
          </div>
          <nav className="react-nav" aria-label={t(uiLang, { en: "Primary navigation", ru: "\u041e\u0441\u043d\u043e\u0432\u043d\u0430\u044f \u043d\u0430\u0432\u0438\u0433\u0430\u0446\u0438\u044f" })}>
            {navGroups.map((group) => (
              <div key={group.id} className="react-nav-group">
                {!sidebarCollapsed ? <div className="react-nav-group-title">{group.title}</div> : null}
                <div className="react-nav-group-items">
                  {group.items.map((item) => (
                    <NavLink
                      key={item.to}
                      to={item.to}
                      onClick={() => setSidebarOpen(false)}
                      title={item.label}
                      aria-label={item.label}
                    >
                      <span className={`react-nav-link-content ${sidebarCollapsed ? "icon-only" : ""}`}>
                        <Icon name={item.icon} size={17} className="react-nav-link-icon" />
                        {!sidebarCollapsed ? <span className="react-nav-link-label">{item.label}</span> : null}
                      </span>
                    </NavLink>
                  ))}
                </div>
              </div>
            ))}
          </nav>
          <div className="react-sidebar-footer">
            <button
              type="button"
              className={`react-link-button react-sidebar-footer-button ${sidebarCollapsed ? "icon-only" : ""}`}
              onClick={() => setSidebarCollapsed((value) => !value)}
              title={sidebarCollapsed ? text.show : text.hide}
              aria-label={sidebarCollapsed ? text.show : text.hide}
            >
              <Icon name="control" size={15} />
              {!sidebarCollapsed ? <span>{text.hide}</span> : null}
            </button>
          </div>
        </aside>
        <main id="react-main-content" className="react-main" tabIndex={-1}>
          <header className="react-topbar">
            <div className="react-topbar-copy react-topbar-copy-compact">
              <div className="react-topbar-tools">
                <button type="button" className="react-icon-button react-icon-button-wide react-mobile-only" onClick={() => setSidebarOpen(true)}>
                  {text.menu}
                </button>
                <button
                  type="button"
                  className="react-link-button react-topbar-shell-toggle react-desktop-only"
                  onClick={() => setSidebarCollapsed((value) => !value)}
                  title={sidebarCollapsed ? text.show : text.hide}
                  aria-label={sidebarCollapsed ? text.show : text.hide}
                >
                  <Icon name="control" size={15} />
                  <span>{sidebarCollapsed ? text.show : text.hide}</span>
                </button>
              </div>
              <div className="react-page-indicator react-page-indicator-plain">
                <Icon name={activeItem.icon} size={16} />
                <span>{activeItem.label}</span>
              </div>
            </div>
            <div className="react-topbar-meta">
              <span className={`react-badge ${clickhouseState === "ok" ? "ok" : clickhouseState === "down" ? "down" : "soft"}`}>
                ClickHouse {clickhouseState === "ok" ? text.clickhouseLive : clickhouseState === "down" ? text.clickhouseDown : text.clickhouseSync}
              </span>
              <label className="react-topbar-select-shell" title={t(uiLang, { en: "Timezone", ru: "Часовой пояс" })}>
                <Icon name="globe" size={14} />
                <span className="react-topbar-select-label">TZ</span>
                <select className="react-select react-select-topbar" value={timezone} onChange={(event) => setTimezoneState(event.target.value)}>
                  {TIMEZONE_OPTIONS.map((item) => (
                    <option key={item.value} value={item.value}>{item.label}</option>
                  ))}
                </select>
              </label>
              <button type="button" className="react-link-button" onClick={() => contextValue.setLang(uiLang === "ru" ? "en" : "ru")}>
                {text.language} {uiLang.toUpperCase()}
              </button>
              <button type="button" className="react-link-button" onClick={() => setShortcutsOpen(true)}>
                {text.shortcuts}
              </button>
              <span className="react-badge soft" title={`${bootstrap.data.user.username} (${bootstrap.data.user.role})`}>
                {bootstrap.data.user.username}
              </span>
              <button
                type="button"
                className="react-link-button react-logout-button"
                onClick={() => window.location.assign("/auth/logout")}
              >
                {text.logout}
              </button>
            </div>
          </header>
          <Routes>
            <Route path="/" element={routeElement("overview", <DashboardPage />)} />
            <Route path="/dashboards" element={routeElement("overview", <DashboardPage />)} />
            <Route path="/control" element={routeElement("control panel", <ControlPanelPage />)} />
            <Route path="/docs" element={routeElement("documentation", <DocumentationPage />)} />
            <Route path="/docs/page/:docName" element={routeElement("documentation", <DocumentationPage />)} />
            <Route path="/docs/playbooks/:playbookSlug" element={routeElement("documentation", <DocumentationPage />)} />
            <Route path="/vuln" element={routeElement("vulnerabilities", <VulnPage />)} />
            <Route path="/vuln/hosts" element={routeElement("vulnerabilities", <VulnPage />)} />
            <Route path="/vuln/reports" element={routeElement("vulnerabilities", <VulnPage />)} />
            <Route path="/vuln/reports/:reportId" element={routeElement("vulnerabilities", <VulnPage />)} />
            <Route path="/vuln/findings" element={routeElement("vulnerabilities", <VulnPage />)} />
            <Route path="/vuln/cves" element={routeElement("vulnerabilities", <VulnPage />)} />
            <Route path="/vuln/software" element={routeElement("vulnerabilities", <VulnPage />)} />
            <Route path="/incidents" element={routeElement("incidents", <IncidentsPage />)} />
            <Route path="/events" element={routeElement("events", <EventsPage />)} />
            <Route path="/assets" element={routeElement("assets", <AssetsPage />)} />
            <Route path="/ingest" element={routeElement("ingest", <IngestPage />)} />
            <Route path="/sources" element={routeElement("sources", <SourcesPage />)} />
            <Route path="/topology" element={routeElement("topology", <TopologyPage />)} />
            <Route path="/collectors" element={routeElement("collectors", <CollectorsPage />)} />
            <Route path="/connectors" element={routeElement("connectors", <ConnectorsPage />)} />
            <Route path="/threat-intel" element={routeElement("threat intel", <ThreatIntelPage />)} />
            <Route path="/entities" element={routeElement("entities", <EntitiesPage />)} />
            <Route path="/cases" element={routeElement("cases", <CasesPage />)} />
            <Route path="/access" element={routeElement("access", <AccessPage />)} />
            <Route path="/response" element={routeElement("response orchestration", <ResponsePage />)} />
            <Route path="/host-runtime" element={routeElement("host runtime", <HostRuntimePage />)} />
            <Route path="/security/:serviceId" element={routeElement("security service", <SecurityServicePage />)} />
            <Route path="/builders" element={routeElement("builders", <BuildersPage />)} />
          </Routes>
        </main>
        </div>
        <DrawerOverlay
        open={shortcutsOpen}
        title={text.shortcuts}
        subtitle={t(uiLang, {
          en: "Shell-wide navigation and analyst flow shortcuts.",
          ru: "\u0413\u043e\u0440\u044f\u0447\u0438\u0435 \u043a\u043b\u0430\u0432\u0438\u0448\u0438 \u0434\u043b\u044f \u043d\u0430\u0432\u0438\u0433\u0430\u0446\u0438\u0438 \u0438 \u0440\u0430\u0431\u043e\u0442\u044b \u0430\u043d\u0430\u043b\u0438\u0442\u0438\u043a\u0430.",
        })}
        onClose={() => setShortcutsOpen(false)}
      >
        <section className="react-card react-card-nested">
          <PanelHeader
            title={t(uiLang, { en: "Navigation", ru: "\u041d\u0430\u0432\u0438\u0433\u0430\u0446\u0438\u044f" })}
            subtitle={t(uiLang, {
              en: "Move between the core analyst surfaces without reaching for the mouse.",
              ru: "\u041f\u0435\u0440\u0435\u0445\u043e\u0434 \u043c\u0435\u0436\u0434\u0443 \u043a\u043b\u044e\u0447\u0435\u0432\u044b\u043c\u0438 \u0440\u0430\u0431\u043e\u0447\u0438\u043c\u0438 \u043e\u0431\u043b\u0430\u0441\u0442\u044f\u043c\u0438 \u0431\u0435\u0437 \u043c\u044b\u0448\u0438.",
            })}
            icon="dashboard"
          />
          <InfoList
            items={[
              { label: "?", value: t(uiLang, { en: "Open this shortcuts panel", ru: "\u041e\u0442\u043a\u0440\u044b\u0442\u044c \u043f\u0430\u043d\u0435\u043b\u044c \u0448\u043e\u0440\u0442\u043a\u0430\u0442\u043e\u0432" }) },
              { label: "Alt + 1", value: t(uiLang, { en: "Overview", ru: "\u041e\u0431\u0437\u043e\u0440" }) },
              { label: "Alt + 2", value: t(uiLang, { en: "Incidents", ru: "\u0418\u043d\u0446\u0438\u0434\u0435\u043d\u0442\u044b" }) },
              { label: "Alt + 3", value: t(uiLang, { en: "Events", ru: "\u0421\u043e\u0431\u044b\u0442\u0438\u044f" }) },
              { label: "Alt + 4", value: t(uiLang, { en: "Sources", ru: "\u0418\u0441\u0442\u043e\u0447\u043d\u0438\u043a\u0438" }) },
            ]}
          />
        </section>
        <section className="react-card react-card-nested">
          <PanelHeader
            title={t(uiLang, { en: "Incident triage", ru: "\u0422\u0440\u0438\u0430\u0436 \u0438\u043d\u0446\u0438\u0434\u0435\u043d\u0442\u043e\u0432" })}
            subtitle={t(uiLang, {
              en: "Queue shortcuts available inside the incident console.",
              ru: "\u0428\u043e\u0440\u0442\u043a\u0430\u0442\u044b \u043e\u0447\u0435\u0440\u0435\u0434\u0438, \u0434\u043e\u0441\u0442\u0443\u043f\u043d\u044b\u0435 \u0432 \u043a\u043e\u043d\u0441\u043e\u043b\u0438 \u0438\u043d\u0446\u0438\u0434\u0435\u043d\u0442\u043e\u0432.",
            })}
            icon="incidents"
          />
          <InfoList
            items={[
              { label: "J / ArrowDown", value: t(uiLang, { en: "Next incident", ru: "\u0421\u043b\u0435\u0434\u0443\u044e\u0449\u0438\u0439 \u0438\u043d\u0446\u0438\u0434\u0435\u043d\u0442" }) },
              { label: "K / ArrowUp", value: t(uiLang, { en: "Previous incident", ru: "\u041f\u0440\u0435\u0434\u044b\u0434\u0443\u0449\u0438\u0439 \u0438\u043d\u0446\u0438\u0434\u0435\u043d\u0442" }) },
              { label: "Enter", value: t(uiLang, { en: "Open selected incident", ru: "\u041e\u0442\u043a\u0440\u044b\u0442\u044c \u0432\u044b\u0431\u0440\u0430\u043d\u043d\u044b\u0439 \u0438\u043d\u0446\u0438\u0434\u0435\u043d\u0442" }) },
              { label: "Esc", value: t(uiLang, { en: "Close drawer", ru: "\u0417\u0430\u043a\u0440\u044b\u0442\u044c \u043e\u043a\u043d\u043e" }) },
            ]}
          />
        </section>
        </DrawerOverlay>
      </FeedbackProvider>
    </ShellContext.Provider>
  );
}
