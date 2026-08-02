import { useCallback, useEffect, useMemo, useState } from "react";
import { api, setApiTenantScope, type BootstrapResponse, type TenantScopeResponse } from "./runtime/api";
import {
  commandHints, mainNavigation, platformNavigation, securityNavigation, securityNavigationGroups,
  viewFromPath, viewMeta, type View,
} from "./model";
import { PrimaryView } from "./Views";
import { Button, Icon, IconButton, Modal } from "./ui";

type Toast = { id: number; message: string; tone: string };

function BrandMark() {
  return <span aria-hidden="true" className="brand-mark"><i /><i /><i /></span>;
}

function scopeFromUrl(available: TenantScopeResponse["available"]) {
  const requested = new URLSearchParams(window.location.search).get("tenants")?.split(",") ?? [];
  return [...new Set(requested.map((item) => item.trim()).filter((id) => available.some((tenant) => tenant.id === id)))];
}

function Sidebar({ current, bootstrap, tenants, selectedTenants, onTenantChange, collapsed, setCollapsed, mobileOpen, setMobileOpen, darkTheme, toggleTheme, navigate }: {
  current: View;
  bootstrap: BootstrapResponse;
  tenants: TenantScopeResponse;
  selectedTenants: string[];
  onTenantChange: (ids: string[]) => void;
  collapsed: boolean;
  setCollapsed: (value: boolean) => void;
  mobileOpen: boolean;
  setMobileOpen: (value: boolean) => void;
  darkTheme: boolean;
  toggleTheme: () => void;
  navigate: (view: View) => void;
}) {
  const [tenantMenuOpen, setTenantMenuOpen] = useState(false);
  const [securityMenuOpen, setSecurityMenuOpen] = useState(() => viewMeta[current].group === "security");
  const [tenantDraft, setTenantDraft] = useState(selectedTenants);
  const securityActive = securityNavigation.includes(current);
  const selected = tenants.available.filter((tenant) => selectedTenants.includes(tenant.id));
  const draft = tenants.available.filter((tenant) => tenantDraft.includes(tenant.id));
  const scopeLabel = selected.length === tenants.available.length
    ? "Все рабочие пространства"
    : selected.length === 1 ? selected[0].name : `${selected.length} пространства`;
  const currentSecurityLabel = securityActive ? viewMeta[current].short : `${securityNavigation.length} модулей`;

  useEffect(() => {
    const closeTransientNavigation = (event: KeyboardEvent) => {
      if (event.key !== "Escape") return;
      setTenantMenuOpen(false);
      setSecurityMenuOpen(false);
    };
    window.addEventListener("keydown", closeTransientNavigation);
    return () => window.removeEventListener("keydown", closeTransientNavigation);
  }, []);

  function open(view: View) {
    navigate(view);
    if (window.matchMedia("(max-width: 820px)").matches) setMobileOpen(false);
  }

  function navButton(view: View) {
    return <button
      aria-current={current === view ? "page" : undefined}
      className={current === view ? "active" : ""}
      key={view}
      onClick={() => open(view)}
      title={viewMeta[view].title}
      type="button"
    >
      <Icon name={view} size={17} />
      {!collapsed ? <span>{viewMeta[view].short}</span> : null}
    </button>;
  }

  function openTenantMenu() {
    if (collapsed) setCollapsed(false);
    setTenantDraft(selectedTenants);
    setSecurityMenuOpen(false);
    setTenantMenuOpen((value) => !value);
  }

  function openSecurityMenu() {
    if (collapsed) setCollapsed(false);
    setTenantMenuOpen(false);
    setSecurityMenuOpen((value) => !value);
  }

  function toggleTenant(id: string) {
    setTenantDraft((items) => items.includes(id) ? items.filter((item) => item !== id) : [...items, id]);
  }

  return <>
    <button aria-label="Закрыть меню" className={`sidebar-backdrop ${mobileOpen ? "visible" : ""}`} onClick={() => setMobileOpen(false)} type="button" />
    <aside className={`app-sidebar ${collapsed ? "collapsed" : ""} ${mobileOpen ? "mobile-open" : ""}`}>
      <header className="brand">
        <IconButton
          icon={mobileOpen ? "close" : "menu"}
          label={mobileOpen ? "Закрыть меню" : collapsed ? "Развернуть меню" : "Свернуть меню"}
          onClick={() => {
            if (mobileOpen && window.matchMedia("(max-width: 820px)").matches) { setMobileOpen(false); return; }
            setSecurityMenuOpen(false);
            setTenantMenuOpen(false);
            setCollapsed(!collapsed);
          }}
        />
        <div className="brand-identity"><BrandMark />{!collapsed ? <div><strong>Rdegon Sentinel</strong><span>SIEM platform</span></div> : null}</div>
      </header>

      <button
        aria-controls="tenant-switcher-dialog"
        aria-expanded={tenantMenuOpen}
        aria-label="Выбрать область данных"
        className={`scope-switcher ${tenantMenuOpen ? "open" : ""}`}
        onClick={openTenantMenu}
        type="button"
      >
        <Icon name="layers" size={17} />
        {!collapsed ? <span><strong>{scopeLabel}</strong><small>{selected.length} выбрано · общий контекст SOC</small></span> : null}
        {!collapsed ? <Icon name="next" size={13} /> : null}
      </button>

      {tenantMenuOpen ? <section aria-labelledby="tenant-switcher-title" className="tenant-switcher-popover" id="tenant-switcher-dialog" role="dialog">
        <header>
          <div><span className="tenant-switcher-icon"><Icon name="layers" size={18} /></span><span><strong id="tenant-switcher-title">Рабочие пространства</strong><small>Фильтр применяется ко всем данным SOC-платформы</small></span></div>
          <IconButton icon="close" label="Закрыть выбор" onClick={() => setTenantMenuOpen(false)} />
        </header>
        <div className="tenant-switcher-summary">
          <span><strong>{draft.length}</strong><small>выбрано</small></span>
          <span><strong>{draft.reduce((sum, tenant) => sum + tenant.source_count, 0)}</strong><small>источников</small></span>
          <span><strong>{draft.reduce((sum, tenant) => sum + tenant.incident_count, 0)}</strong><small>инцидентов</small></span>
        </div>
        <div className="tenant-switcher-list">
          {tenants.available.map((tenant) => <label className={tenantDraft.includes(tenant.id) ? "selected" : ""} key={tenant.id}>
            <input checked={tenantDraft.includes(tenant.id)} onChange={() => toggleTenant(tenant.id)} type="checkbox" />
            <span><strong>{tenant.name}</strong><small>{tenant.description || "Production tenant"}</small></span>
            <span><b>{tenant.source_count}</b><small>источников</small></span>
          </label>)}
        </div>
        <footer>
          <button className="tenant-select-all" onClick={() => setTenantDraft(tenants.available.map((tenant) => tenant.id))} type="button">Выбрать все</button>
          <div><Button onClick={() => setTenantMenuOpen(false)}>Отмена</Button><Button disabled={!tenantDraft.length} onClick={() => { onTenantChange(tenantDraft); setTenantMenuOpen(false); }} tone="primary">Применить</Button></div>
        </footer>
      </section> : null}

      <nav aria-label="Основная навигация" className="app-navigation">
        {securityMenuOpen ? <div className="security-nav-subsection" id="security-systems-navigation">
          <header>
            <button aria-label="Вернуться в основную навигацию" className="security-nav-back" onClick={() => setSecurityMenuOpen(false)} type="button"><Icon name="next" size={15} /><span>Основная навигация</span></button>
            <div><Icon name="coverage" size={19} /><span><strong>Средства защиты</strong><small>Единая точка доступа к {securityNavigation.length} модулям</small></span></div>
          </header>
          {securityNavigationGroups.map((group) => <section key={group.id}><h2>{group.title}</h2>{group.items.map(navButton)}</section>)}
        </div> : <>
          <section>{!collapsed ? <h2>SOC</h2> : null}{mainNavigation.map(navButton)}</section>
          <section className="security-nav-cluster"><button aria-controls="security-systems-navigation" aria-expanded={securityMenuOpen} className={securityActive ? "active security-nav-trigger" : "security-nav-trigger"} onClick={openSecurityMenu} title="Средства защиты" type="button"><Icon name="coverage" size={17} />{!collapsed ? <span><strong>Средства защиты</strong><small>{currentSecurityLabel}</small></span> : null}{!collapsed ? <Icon name="next" size={13} /> : null}</button></section>
          <section>{!collapsed ? <h2>Платформа</h2> : null}{platformNavigation.map(navButton)}</section>
        </>}
      </nav>

      <button aria-label={darkTheme ? "Включить светлую тему" : "Включить темную тему"} className="sidebar-theme-toggle" onClick={toggleTheme} title={darkTheme ? "Светлая тема" : "Темная тема"} type="button"><span aria-hidden="true" className="theme-glyph">{darkTheme ? "☀" : "☾"}</span>{!collapsed ? <span>{darkTheme ? "Светлая тема" : "Темная тема"}</span> : null}</button>
      <footer>{!collapsed ? <div className="signed-user"><span>{bootstrap.user.username.slice(0, 2).toUpperCase()}</span><div><strong>{bootstrap.user.username}</strong><small>{bootstrap.user.role} · {bootstrap.user.auth_mechanism}</small></div></div> : <span className="signed-avatar">{bootstrap.user.username.slice(0, 2).toUpperCase()}</span>}</footer>
    </aside>
  </>;
}

function CommandPalette({ open, onClose, navigate }: { open: boolean; onClose: () => void; navigate: (view: View) => void }) {
  const [query, setQuery] = useState("");
  const items = useMemo(() => (Object.keys(viewMeta) as View[]).filter((view) => `${viewMeta[view].title} ${viewMeta[view].short} ${commandHints[view] ?? ""}`.toLowerCase().includes(query.toLowerCase())), [query]);
  const close = () => { setQuery(""); onClose(); };
  return <Modal onClose={close} open={open} title="Быстрый переход">
    <label className="command-search"><Icon name="search" /><input autoFocus onChange={(event) => setQuery(event.target.value)} placeholder="Раздел, объект или действие..." value={query} /><kbd>Esc</kbd></label>
    <div className="command-results">{items.map((view) => <button key={view} onClick={() => { navigate(view); close(); }} type="button"><Icon name={view} /><span><strong>{viewMeta[view].title}</strong><small>{commandHints[view] ?? viewMeta[view].group}</small></span><kbd>↵</kbd></button>)}</div>
    <div className="command-hint"><span><kbd>Ctrl K</kbd> открыть поиск</span><span><kbd>Esc</kbd> закрыть</span></div>
  </Modal>;
}

export function App() {
  const [pathname, setPathname] = useState(() => window.location.pathname);
  const view = viewFromPath(pathname);
  const [bootstrap, setBootstrap] = useState<BootstrapResponse | null>(null);
  const [tenants, setTenants] = useState<TenantScopeResponse | null>(null);
  const [fatal, setFatal] = useState("");
  const [selectedTenants, setSelectedTenants] = useState<string[]>([]);
  const [scopeVersion, setScopeVersion] = useState(0);
  const [collapsed, setCollapsed] = useState(() => localStorage.getItem("sentinel-sidebar") === "collapsed");
  const [mobileOpen, setMobileOpen] = useState(false);
  const [darkTheme, setDarkTheme] = useState(() => localStorage.getItem("sentinel-theme") === "dark");
  const [commandOpen, setCommandOpen] = useState(false);
  const [toasts, setToasts] = useState<Toast[]>([]);

  const notify = useCallback((message: string, tone = "info") => {
    const id = Date.now();
    setToasts((items) => [...items, { id, message, tone }]);
    window.setTimeout(() => setToasts((items) => items.filter((item) => item.id !== id)), 5000);
  }, []);

  const navigate = useCallback((next: View) => {
    const url = new URL(window.location.href);
    url.pathname = next === "overview" ? "/app" : `/app/${next}`;
    window.history.pushState({}, "", `${url.pathname}${url.search}${url.hash}`);
    setPathname(url.pathname);
  }, []);

  const applyTenantScope = useCallback((ids: string[]) => {
    const next = [...new Set(ids)];
    setApiTenantScope(next);
    setSelectedTenants(next);
    localStorage.setItem("sentinel-tenants", next.join(","));
    const url = new URL(window.location.href);
    url.searchParams.set("tenants", next.join(","));
    window.history.replaceState({}, "", `${url.pathname}${url.search}${url.hash}`);
    setScopeVersion((value) => value + 1);
  }, []);

  useEffect(() => {
    let active = true;
    Promise.all([api.bootstrap(), api.tenantScope()]).then(([nextBootstrap, nextTenants]) => {
      if (!active) return;
      setBootstrap(nextBootstrap);
      setTenants(nextTenants);
      const urlScope = scopeFromUrl(nextTenants.available);
      const stored = (localStorage.getItem("sentinel-tenants") || "").split(",").filter((id) => nextTenants.available.some((tenant) => tenant.id === id));
      const scope = urlScope.length ? urlScope : stored.length ? stored : nextTenants.default.length ? nextTenants.default : nextTenants.available.map((tenant) => tenant.id);
      setSelectedTenants(scope);
      setApiTenantScope(scope);
    }, (error) => active && setFatal(error instanceof Error ? error.message : String(error)));
    return () => { active = false; };
  }, []);

  useEffect(() => { localStorage.setItem("sentinel-sidebar", collapsed ? "collapsed" : "expanded"); }, [collapsed]);
  useEffect(() => { localStorage.setItem("sentinel-theme", darkTheme ? "dark" : "light"); }, [darkTheme]);
  useEffect(() => {
    const handler = (event: KeyboardEvent) => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") { event.preventDefault(); setCommandOpen(true); }
      if (event.key === "Escape") { setCommandOpen(false); setMobileOpen(false); }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, []);
  useEffect(() => {
    const handler = () => {
      setPathname(window.location.pathname);
      if (tenants) {
        const scope = scopeFromUrl(tenants.available);
        if (scope.length) applyTenantScope(scope);
      }
    };
    window.addEventListener("popstate", handler);
    return () => window.removeEventListener("popstate", handler);
  }, [applyTenantScope, tenants]);

  if (fatal) return <div className="sentinel-bootstrap"><h1>Rdegon Sentinel</h1><p>{fatal}</p><a className="button button-primary" href="/auth/login">Войти повторно</a></div>;
  if (!bootstrap || !tenants || !selectedTenants.length) return <div className="sentinel-bootstrap"><BrandMark /><strong>Загрузка Rdegon Sentinel...</strong></div>;

  return <div className="app-shell" data-theme={darkTheme ? "dark" : "light"}>
    <Sidebar bootstrap={bootstrap} collapsed={collapsed} current={view} darkTheme={darkTheme} mobileOpen={mobileOpen} navigate={navigate} onTenantChange={applyTenantScope} selectedTenants={selectedTenants} setCollapsed={setCollapsed} setMobileOpen={setMobileOpen} tenants={tenants} toggleTheme={() => setDarkTheme((value) => !value)} />
    <div className={`app-main ${collapsed ? "sidebar-collapsed" : ""}`}><div className="sentinel-mobile-bar"><IconButton icon="menu" label="Открыть меню" onClick={() => setMobileOpen(true)} /><strong>{viewMeta[view].title}</strong><IconButton icon="search" label="Быстрый переход" onClick={() => setCommandOpen(true)} /></div><main id="main-content"><PrimaryView key={`${view}:${scopeVersion}:${selectedTenants.join(",")}`} navigate={navigate} notify={notify} view={view} /></main></div>
    <button aria-label="Быстрый переход" className="sentinel-command-trigger" onClick={() => setCommandOpen(true)} title="Быстрый переход · Ctrl K" type="button"><Icon name="search" /></button>
    <CommandPalette navigate={navigate} onClose={() => setCommandOpen(false)} open={commandOpen} />
    <div aria-live="polite" className="toast-stack">{toasts.map((toast) => <div className={`toast toast-${toast.tone}`} key={toast.id}><Icon name={toast.tone === "healthy" ? "check" : "warning"} /><span>{toast.message}</span><button aria-label="Закрыть" onClick={() => setToasts((items) => items.filter((item) => item.id !== toast.id))} type="button"><Icon name="close" /></button></div>)}</div>
  </div>;
}
