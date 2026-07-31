import { useCallback, useEffect, useMemo, useState } from "react";
import { api, setApiTenantScope, type BootstrapResponse, type TenantScopeResponse } from "./runtime/api";
import { mainNavigation, platformNavigation, securityNavigation, viewFromPath, viewMeta, type View } from "./model";
import { PrimaryView } from "./Views";
import { Icon, IconButton, Modal } from "./ui";

type Toast = { id: number; message: string; tone: string };

function BrandMark() {
  return <span aria-hidden="true" className="brand-mark"><i /><i /><i /></span>;
}

function Sidebar({ current, bootstrap, tenants, selectedTenants, onTenantChange, collapsed, setCollapsed, mobileOpen, setMobileOpen, darkTheme, toggleTheme, navigate }: {
  current: View; bootstrap: BootstrapResponse; tenants: TenantScopeResponse; selectedTenants: string[]; onTenantChange: (ids: string[]) => void;
  collapsed: boolean; setCollapsed: (value: boolean) => void; mobileOpen: boolean; setMobileOpen: (value: boolean) => void;
  darkTheme: boolean; toggleTheme: () => void; navigate: (view: View) => void;
}) {
  const [scopeOpen, setScopeOpen] = useState(false);
  const [securityOpen, setSecurityOpen] = useState(viewMeta[current].group === "security");
  const selected = tenants.available.filter((tenant) => selectedTenants.includes(tenant.id));
  const scopeLabel = selected.length === tenants.available.length ? "Все tenants" : selected.map((tenant) => tenant.name).join(", ") || "Без scope";
  const open = (view: View) => { navigate(view); setMobileOpen(false); };
  const navButton = (view: View) => <button aria-current={current === view ? "page" : undefined} className={current === view ? "active" : ""} key={view} onClick={() => open(view)} title={viewMeta[view].title} type="button"><Icon name={view} size={17} />{!collapsed ? <span>{viewMeta[view].short}</span> : null}</button>;
  return <>
    {mobileOpen ? <button aria-label="Закрыть меню" className="mobile-sidebar-scrim" onClick={() => setMobileOpen(false)} type="button" /> : null}
    <aside className={`app-sidebar ${collapsed ? "collapsed" : ""} ${mobileOpen ? "mobile-open" : ""}`}>
      <div className="brand"><BrandMark />{!collapsed ? <div><strong>RDEGON SENTINEL</strong><span>Security operations platform</span></div> : null}</div>
      <div className="scope-shell">
        <button className="scope-switcher" onClick={() => setScopeOpen((value) => !value)} title="Область данных" type="button"><Icon name="server" size={16} />{!collapsed ? <span><strong>{scopeLabel}</strong><small>{selected.reduce((sum, item) => sum + item.source_count, 0)} источников · {selected.reduce((sum, item) => sum + item.incident_count, 0)} инцидентов</small></span> : null}</button>
        {scopeOpen && !collapsed ? <div className="scope-popover"><header><strong>Область данных</strong><small>Scope передается серверу в каждом API-запросе.</small></header>{tenants.available.map((tenant) => <label key={tenant.id}><input checked={selectedTenants.includes(tenant.id)} onChange={(event) => { const next = event.target.checked ? [...selectedTenants, tenant.id] : selectedTenants.filter((id) => id !== tenant.id); if (next.length) onTenantChange(next); }} type="checkbox" /><span><strong>{tenant.name}</strong><small>{tenant.description || `${tenant.source_count} источников`}</small></span><b>{tenant.incident_count}</b></label>)}</div> : null}
      </div>
      <nav className="app-navigation">
        <section>{!collapsed ? <h2>SOC</h2> : null}{mainNavigation.map(navButton)}</section>
        <section>{!collapsed ? <h2>Средства защиты</h2> : null}<button aria-expanded={securityOpen} className={viewMeta[current].group === "security" ? "active security-nav-trigger" : "security-nav-trigger"} onClick={() => setSecurityOpen((value) => !value)} title="Средства защиты" type="button"><Icon name="coverage" size={17} />{!collapsed ? <span>Средства защиты</span> : null}{!collapsed ? <Icon name={securityOpen ? "previous" : "next"} size={13} /> : null}</button>{securityOpen && !collapsed ? <div className="sentinel-security-nav">{securityNavigation.map(navButton)}</div> : null}</section>
        <section>{!collapsed ? <h2>Платформа</h2> : null}{platformNavigation.map(navButton)}</section>
      </nav>
      <button aria-label={darkTheme ? "Светлая тема" : "Темная тема"} className="sidebar-theme-toggle" onClick={toggleTheme} title={darkTheme ? "Светлая тема" : "Темная тема"} type="button"><span aria-hidden="true" className="theme-glyph">{darkTheme ? "☀" : "☾"}</span>{!collapsed ? <span>{darkTheme ? "Светлая тема" : "Темная тема"}</span> : null}</button>
      <footer>{!collapsed ? <div className="signed-user"><span>{bootstrap.user.username.slice(0, 2).toUpperCase()}</span><div><strong>{bootstrap.user.username}</strong><small>{bootstrap.user.role} · {bootstrap.user.auth_mechanism}</small></div></div> : <span className="signed-avatar">{bootstrap.user.username.slice(0, 2).toUpperCase()}</span>}<button aria-label={collapsed ? "Развернуть меню" : "Свернуть меню"} className="sentinel-collapse" onClick={() => setCollapsed(!collapsed)} type="button"><Icon name={collapsed ? "expand" : "collapse"} /></button></footer>
    </aside>
  </>;
}

function CommandPalette({ open, onClose, navigate }: { open: boolean; onClose: () => void; navigate: (view: View) => void }) {
  const [query, setQuery] = useState("");
  const items = useMemo(() => (Object.keys(viewMeta) as View[]).filter((view) => `${viewMeta[view].title} ${viewMeta[view].short}`.toLowerCase().includes(query.toLowerCase())), [query]);
  return <Modal onClose={onClose} open={open} title="Быстрый переход"><label className="command-search"><Icon name="search" /><input autoFocus onChange={(event) => setQuery(event.target.value)} placeholder="Раздел платформы..." value={query} /><kbd>Esc</kbd></label><div className="command-results">{items.map((view) => <button key={view} onClick={() => { navigate(view); onClose(); }} type="button"><Icon name={view} /><span><strong>{viewMeta[view].title}</strong><small>{viewMeta[view].group}</small></span></button>)}</div></Modal>;
}

export function App() {
  const [pathname, setPathname] = useState(() => window.location.pathname);
  const view = viewFromPath(pathname);
  const [bootstrap, setBootstrap] = useState<BootstrapResponse | null>(null); const [tenants, setTenants] = useState<TenantScopeResponse | null>(null); const [fatal, setFatal] = useState("");
  const [selectedTenants, setSelectedTenants] = useState<string[]>([]); const [collapsed, setCollapsed] = useState(() => localStorage.getItem("sentinel-sidebar") === "collapsed");
  const [mobileOpen, setMobileOpen] = useState(false); const [darkTheme, setDarkTheme] = useState(() => localStorage.getItem("sentinel-theme") !== "light");
  const [commandOpen, setCommandOpen] = useState(false); const [toasts, setToasts] = useState<Toast[]>([]);
  const notify = useCallback((message: string, tone = "info") => { const id = Date.now(); setToasts((items) => [...items, { id, message, tone }]); window.setTimeout(() => setToasts((items) => items.filter((item) => item.id !== id)), 5000); }, []);
  const navigate = useCallback((next: View) => {
    const nextPath = next === "overview" ? "/app" : `/app/${next}`;
    window.history.pushState({}, "", nextPath);
    setPathname(nextPath);
  }, []);

  useEffect(() => { let active = true; Promise.all([api.bootstrap(), api.tenantScope()]).then(([nextBootstrap, nextTenants]) => { if (!active) return; setBootstrap(nextBootstrap); setTenants(nextTenants); const stored = (localStorage.getItem("sentinel-tenants") || "").split(",").filter((id) => nextTenants.available.some((tenant) => tenant.id === id)); const scope = stored.length ? stored : nextTenants.default.length ? nextTenants.default : nextTenants.available.map((tenant) => tenant.id); setSelectedTenants(scope); setApiTenantScope(scope); }, (error) => active && setFatal(error instanceof Error ? error.message : String(error))); return () => { active = false; }; }, []);
  useEffect(() => { setApiTenantScope(selectedTenants); if (selectedTenants.length) localStorage.setItem("sentinel-tenants", selectedTenants.join(",")); }, [selectedTenants]);
  useEffect(() => { localStorage.setItem("sentinel-sidebar", collapsed ? "collapsed" : "expanded"); }, [collapsed]);
  useEffect(() => { localStorage.setItem("sentinel-theme", darkTheme ? "dark" : "light"); }, [darkTheme]);
  useEffect(() => { const handler = (event: KeyboardEvent) => { if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") { event.preventDefault(); setCommandOpen(true); } if (event.key === "Escape") { setCommandOpen(false); setMobileOpen(false); } }; window.addEventListener("keydown", handler); return () => window.removeEventListener("keydown", handler); }, []);
  useEffect(() => { const handler = () => setPathname(window.location.pathname); window.addEventListener("popstate", handler); return () => window.removeEventListener("popstate", handler); }, []);

  if (fatal) return <div className="sentinel-bootstrap"><h1>Rdegon Sentinel</h1><p>{fatal}</p><a className="button button-primary" href="/auth/login">Войти повторно</a></div>;
  if (!bootstrap || !tenants) return <div className="sentinel-bootstrap"><BrandMark /><strong>Загрузка Rdegon Sentinel...</strong></div>;
  return <div className="app-shell" data-theme={darkTheme ? "dark" : "light"}>
    <Sidebar bootstrap={bootstrap} collapsed={collapsed} current={view} darkTheme={darkTheme} mobileOpen={mobileOpen} navigate={navigate} onTenantChange={setSelectedTenants} selectedTenants={selectedTenants} setCollapsed={setCollapsed} setMobileOpen={setMobileOpen} tenants={tenants} toggleTheme={() => setDarkTheme((value) => !value)} />
    <div className={`app-main ${collapsed ? "sidebar-collapsed" : ""}`}><div className="sentinel-mobile-bar"><IconButton icon="menu" label="Открыть меню" onClick={() => setMobileOpen(true)} /><strong>{viewMeta[view].title}</strong><IconButton icon="search" label="Быстрый переход" onClick={() => setCommandOpen(true)} /></div><main id="main-content"><PrimaryView navigate={navigate} notify={notify} view={view} /></main></div>
    <button aria-label="Быстрый переход" className="sentinel-command-trigger" onClick={() => setCommandOpen(true)} title="Быстрый переход · Ctrl K" type="button"><Icon name="search" /></button>
    <CommandPalette navigate={navigate} onClose={() => setCommandOpen(false)} open={commandOpen} />
    <div aria-live="polite" className="toast-stack">{toasts.map((toast) => <div className={`toast toast-${toast.tone}`} key={toast.id}><Icon name={toast.tone === "healthy" ? "check" : "warning"} /><span>{toast.message}</span><button aria-label="Закрыть" onClick={() => setToasts((items) => items.filter((item) => item.id !== toast.id))} type="button"><Icon name="close" /></button></div>)}</div>
  </div>;
}
