import { useEffect, useMemo, useState } from "react";
import { NavLink } from "react-router-dom";
import { Icon } from "./chrome";
import { t, useShellContext } from "./context";
import { isSecurityPath, primaryNavigation, securityNavigation, type ShellNavItem } from "./navigation";

const brandMarkUrl = "/app/mark.svg?v=20260730";

type ShellSidebarProps = {
  pathname: string;
  collapsed: boolean;
  mobileOpen: boolean;
  sectionAccess: Set<string>;
  onCollapsedChange: (collapsed: boolean) => void;
  onMobileOpenChange: (open: boolean) => void;
};

function TenantSwitcher({ collapsed }: { collapsed: boolean }) {
  const { lang, tenants, selectedTenantIds, setSelectedTenantIds } = useShellContext();
  const [open, setOpen] = useState(false);
  const [draft, setDraft] = useState<string[]>(selectedTenantIds);
  const selected = tenants.filter((item) => selectedTenantIds.includes(item.id));
  const label = selected.length === tenants.length
    ? t(lang, { en: "All workspaces", ru: "Все пространства" })
    : selected.map((item) => item.name).join(", ");

  useEffect(() => {
    if (!open) setDraft(selectedTenantIds);
  }, [open, selectedTenantIds]);

  if (!tenants.length) return null;
  return (
    <div className="react-tenant-switcher">
      <button
        type="button"
        className={`react-tenant-trigger ${open ? "open" : ""}`}
        aria-expanded={open}
        aria-controls="react-tenant-popover"
        onClick={() => setOpen((value) => !value)}
        title={label}
      >
        <Icon name="globe" size={16} />
        {!collapsed ? (
          <span>
            <strong>{label}</strong>
            <small>{t(lang, { en: "Global data scope", ru: "Глобальный контекст данных" })}</small>
          </span>
        ) : null}
      </button>
      {open && !collapsed ? (
        <section id="react-tenant-popover" className="react-tenant-popover" role="dialog" aria-label={t(lang, { en: "Tenant scope", ru: "Область тенантов" })}>
          <header>
            <div>
              <strong>{t(lang, { en: "Workspaces", ru: "Рабочие пространства" })}</strong>
              <small>{t(lang, { en: "Applied to every platform request", ru: "Применяется ко всем запросам платформы" })}</small>
            </div>
            <button type="button" className="react-icon-button" onClick={() => setOpen(false)} aria-label={t(lang, { en: "Close", ru: "Закрыть" })}>×</button>
          </header>
          <div className="react-tenant-summary">
            <span><strong>{draft.length}</strong><small>{t(lang, { en: "selected", ru: "выбрано" })}</small></span>
            <span><strong>{tenants.filter((item) => draft.includes(item.id)).reduce((sum, item) => sum + item.source_count, 0)}</strong><small>{t(lang, { en: "sources", ru: "источников" })}</small></span>
            <span><strong>{tenants.filter((item) => draft.includes(item.id)).reduce((sum, item) => sum + item.incident_count, 0)}</strong><small>{t(lang, { en: "incidents", ru: "инцидентов" })}</small></span>
          </div>
          <div className="react-tenant-list">
            {tenants.map((tenant) => (
              <label key={tenant.id} className={draft.includes(tenant.id) ? "selected" : ""}>
                <input
                  type="checkbox"
                  checked={draft.includes(tenant.id)}
                  onChange={() => setDraft((items) => items.includes(tenant.id) ? items.filter((item) => item !== tenant.id) : [...items, tenant.id])}
                />
                <span><strong>{tenant.name}</strong><small>{tenant.description || tenant.id}</small></span>
                <b>{tenant.source_count}</b>
              </label>
            ))}
          </div>
          <footer>
            <button type="button" className="react-link-button" onClick={() => setOpen(false)}>{t(lang, { en: "Cancel", ru: "Отмена" })}</button>
            <button
              type="button"
              className="react-primary-button"
              disabled={!draft.length}
              onClick={() => {
                setSelectedTenantIds(draft);
                setOpen(false);
              }}
            >
              {t(lang, { en: "Apply", ru: "Применить" })}
            </button>
          </footer>
        </section>
      ) : null}
    </div>
  );
}

function allowedItem(item: ShellNavItem, sectionAccess: Set<string>) {
  return !sectionAccess.size || sectionAccess.has(item.section);
}

export function ShellSidebar({
  pathname,
  collapsed,
  mobileOpen,
  sectionAccess,
  onCollapsedChange,
  onMobileOpenChange,
}: ShellSidebarProps) {
  const { lang } = useShellContext();
  const securityActive = isSecurityPath(pathname);
  const [securityOpen, setSecurityOpen] = useState(() => securityActive || window.localStorage.getItem("rdegon-security-nav-open") === "true");
  const primaryGroups = useMemo(() => primaryNavigation(lang), [lang]);
  const securityGroups = useMemo(() => securityNavigation(lang), [lang]);

  useEffect(() => {
    if (securityActive) setSecurityOpen(true);
  }, [securityActive]);

  useEffect(() => {
    window.localStorage.setItem("rdegon-security-nav-open", String(securityOpen));
  }, [securityOpen]);

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape" && securityOpen) setSecurityOpen(false);
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [securityOpen]);

  return (
    <>
      <button type="button" className={`react-sidebar-backdrop ${mobileOpen ? "visible" : ""}`} onClick={() => onMobileOpenChange(false)} aria-label={t(lang, { en: "Close navigation", ru: "Закрыть навигацию" })} />
      <aside className="react-sidebar">
        <div className="react-brand">
          <button type="button" className="react-brand-menu-button" onClick={() => onCollapsedChange(!collapsed)} aria-label={collapsed ? t(lang, { en: "Expand navigation", ru: "Развернуть навигацию" }) : t(lang, { en: "Collapse navigation", ru: "Свернуть навигацию" })}>
            <Icon name="control" size={16} />
          </button>
          <div className="react-brand-mark" aria-hidden="true"><img className="react-brand-mark-image" src={brandMarkUrl} alt="" /></div>
          {!collapsed ? <div className="react-brand-copy"><h1>Rdegon Sentinel</h1><p>SIEM platform</p></div> : null}
        </div>
        <TenantSwitcher collapsed={collapsed} />
        <nav className="react-nav" aria-label={t(lang, { en: "Primary navigation", ru: "Основная навигация" })}>
          {securityOpen ? (
            <div className="react-security-nav">
              <button type="button" className="react-security-nav-back" onClick={() => setSecurityOpen(false)}>
                <span>‹</span>
                {!collapsed ? t(lang, { en: "Primary navigation", ru: "Основная навигация" }) : null}
              </button>
              {!collapsed ? <div className="react-security-nav-heading"><Icon name="access" size={18} /><span><strong>{t(lang, { en: "Security systems", ru: "Средства защиты" })}</strong><small>{t(lang, { en: "Operations and native controls", ru: "Операции и нативное управление" })}</small></span></div> : null}
              {securityGroups.map((group) => {
                const items = group.items.filter((item) => allowedItem(item, sectionAccess));
                if (!items.length) return null;
                return (
                  <div key={group.id} className="react-nav-group">
                    {!collapsed ? <div className="react-nav-group-title">{group.title}</div> : null}
                    <div className="react-nav-group-items">
                      {items.map((item) => (
                        <NavLink key={item.to} to={item.to} onClick={() => onMobileOpenChange(false)} title={item.label}>
                          <span className={`react-nav-link-content ${collapsed ? "icon-only" : ""}`}>
                            <Icon name={item.icon} size={17} />
                            {!collapsed ? <span className="react-nav-link-label">{item.label}</span> : null}
                          </span>
                        </NavLink>
                      ))}
                    </div>
                  </div>
                );
              })}
            </div>
          ) : (
            <>
              {primaryGroups.map((group, groupIndex) => (
                <div key={group.id} className="react-nav-group">
                  {!collapsed ? <div className="react-nav-group-title">{group.title}</div> : null}
                  <div className="react-nav-group-items">
                    {group.items.filter((item) => allowedItem(item, sectionAccess)).map((item) => (
                      <NavLink key={item.to} to={item.to} onClick={() => onMobileOpenChange(false)} title={item.label}>
                        <span className={`react-nav-link-content ${collapsed ? "icon-only" : ""}`}>
                          <Icon name={item.icon} size={17} />
                          {!collapsed ? <span className="react-nav-link-label">{item.label}</span> : null}
                        </span>
                      </NavLink>
                    ))}
                  </div>
                  {groupIndex === 0 ? (
                    <button type="button" className={`react-security-nav-trigger ${securityActive ? "active" : ""}`} onClick={() => { setSecurityOpen(true); if (collapsed) onCollapsedChange(false); }}>
                      <Icon name="access" size={17} />
                      {!collapsed ? <span><strong>{t(lang, { en: "Security systems", ru: "Средства защиты" })}</strong><small>{t(lang, { en: "16 operational modules", ru: "16 операционных модулей" })}</small></span> : null}
                      {!collapsed ? <b>›</b> : null}
                    </button>
                  ) : null}
                </div>
              ))}
            </>
          )}
        </nav>
        <div className="react-sidebar-footer">
          <button type="button" className={`react-link-button react-sidebar-footer-button ${collapsed ? "icon-only" : ""}`} onClick={() => onCollapsedChange(!collapsed)}>
            <Icon name="control" size={15} />
            {!collapsed ? <span>{t(lang, { en: "Collapse", ru: "Свернуть" })}</span> : null}
          </button>
        </div>
      </aside>
    </>
  );
}
