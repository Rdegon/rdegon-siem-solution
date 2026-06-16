import { useEffect, useId, useRef, useState, type KeyboardEvent as ReactKeyboardEvent, type ReactNode } from "react";
import { NavLink } from "react-router-dom";
import { Icon, type IconName } from "./chrome";
import { t, useShellContext } from "./context";
import type { SelectOption } from "./timeControls";

export function StatCard({
  label,
  value,
  hint,
}: {
  label: string;
  value: string | number;
  hint: string;
}) {
  return (
    <section className="react-stat-card">
      <div className="react-stat-label">{label}</div>
      <div className="react-stat-value">{value}</div>
      <div className="react-stat-hint">{hint}</div>
    </section>
  );
}

export function MetricStrip({
  items,
}: {
  items: Array<{
    label: string;
    value: ReactNode;
    hint?: ReactNode;
    tone?: "default" | "critical" | "warning" | "success" | "info";
  }>;
}) {
  return (
    <div className="react-metric-strip" role="list">
      {items.map((item) => (
        <section key={`${item.label}-${String(item.value)}`} className={`react-metric-tile tone-${item.tone || "default"}`} role="listitem">
          <div className="react-metric-label">{item.label}</div>
          <div className="react-metric-value">{item.value}</div>
          {item.hint ? <div className="react-metric-hint">{item.hint}</div> : null}
        </section>
      ))}
    </div>
  );
}

export function PanelHeader({
  title,
  subtitle,
  icon,
  actions,
}: {
  title: string;
  subtitle: string;
  icon?: IconName;
  actions?: ReactNode;
}) {
  return (
    <div className="react-card-head react-card-head-row">
      <div>
        <h3 className="react-title-with-icon">
          {icon ? <Icon name={icon} /> : null}
          <span>{title}</span>
        </h3>
        <p>{subtitle}</p>
      </div>
      {actions ? <div className="react-actions">{actions}</div> : null}
    </div>
  );
}

export function PageTabs({
  items,
}: {
  items: Array<{ to: string; label: string }>;
}) {
  return (
    <nav className="react-page-tabs">
      {items.map((item) => (
        <NavLink key={item.to} to={item.to} className={({ isActive }) => `react-page-tab ${isActive ? "active" : ""}`}>
          {item.label}
        </NavLink>
      ))}
    </nav>
  );
}

export function Breadcrumbs({
  items,
}: {
  items: Array<{ label: string; href?: string }>;
}) {
  return (
    <div className="react-breadcrumbs">
      {items.map((item, index) => (
        <span key={`${item.label}-${index}`} className="react-breadcrumb-item">
          {item.href ? <a href={item.href}>{item.label}</a> : <strong>{item.label}</strong>}
          {index < items.length - 1 ? <span className="react-breadcrumb-sep">/</span> : null}
        </span>
      ))}
    </div>
  );
}

export function SectionIntro({
  kicker,
  title,
  subtitle,
  icon,
  actions,
}: {
  kicker: string;
  title: string;
  subtitle?: string;
  icon?: IconName;
  actions?: ReactNode;
}) {
  return (
    <section className="react-hero-card">
      <div className="react-hero-copy">
        <div className="react-top-kicker">{kicker}</div>
        <h2 className="react-title-with-icon react-title-with-icon-hero">
          {icon ? <Icon name={icon} size={20} /> : null}
          <span>{title}</span>
        </h2>
        {subtitle ? <p className="react-muted">{subtitle}</p> : null}
      </div>
      {actions ? <div className="react-hero-actions">{actions}</div> : null}
    </section>
  );
}

export function WorkspaceHeader({
  kicker,
  title,
  subtitle,
  icon,
  actions,
  status,
}: {
  kicker: string;
  title: string;
  subtitle?: string;
  icon?: IconName;
  actions?: ReactNode;
  status?: ReactNode;
}) {
  return (
    <section className="react-workspace-header">
      <div className="react-workspace-header-copy">
        <div className="react-top-kicker">{kicker}</div>
        <h2 className="react-title-with-icon react-title-with-icon-hero">
          {icon ? <Icon name={icon} size={20} /> : null}
          <span>{title}</span>
        </h2>
        {subtitle ? <p className="react-muted">{subtitle}</p> : null}
      </div>
      <div className="react-workspace-header-side">
        {status ? <div className="react-workspace-header-status">{status}</div> : null}
        {actions ? <div className="react-workspace-header-actions">{actions}</div> : null}
      </div>
    </section>
  );
}

export function FilterBar({
  children,
  compact = false,
}: {
  children: ReactNode;
  compact?: boolean;
}) {
  return <section className={`react-filter-bar ${compact ? "compact" : ""}`}>{children}</section>;
}

export function FilterGroup({
  title,
  children,
}: {
  title?: string;
  children: ReactNode;
}) {
  return (
    <div className="react-filter-group">
      {title ? <div className="react-filter-group-title">{title}</div> : null}
      <div className="react-filter-group-body">{children}</div>
    </div>
  );
}

export function TimeScopePickerButton({
  label,
  value,
  options,
  onChange,
  customContent,
  footerContent,
  buttonLabel,
}: {
  label: string;
  value: string;
  options: SelectOption[];
  onChange: (value: string) => void;
  customContent?: ReactNode;
  footerContent?: ReactNode;
  buttonLabel?: ReactNode;
}) {
  const { lang } = useShellContext();
  const pickerRef = useRef<HTMLDivElement | null>(null);
  const pickerId = useId();
  const [pickerOpen, setPickerOpen] = useState(false);
  const activeOption = options.find((item) => item.value === value) || options[0];
  const activeLabel = activeOption?.label || value;

  useEffect(() => {
    if (!pickerOpen) return;
    function onPointerDown(event: MouseEvent) {
      if (pickerRef.current?.contains(event.target as Node)) return;
      setPickerOpen(false);
    }
    function onKeyDown(event: KeyboardEvent) {
      if (event.key === "Escape") {
        setPickerOpen(false);
      }
    }
    window.addEventListener("mousedown", onPointerDown);
    window.addEventListener("keydown", onKeyDown);
    return () => {
      window.removeEventListener("mousedown", onPointerDown);
      window.removeEventListener("keydown", onKeyDown);
    };
  }, [pickerOpen]);

  return (
    <div className="react-time-scope-item react-time-scope-picker" ref={pickerRef}>
      <span>{label}</span>
      <button
        type="button"
        className={`react-select react-time-scope-picker-trigger ${pickerOpen ? "active" : ""}`}
        aria-haspopup="dialog"
        aria-expanded={pickerOpen}
        aria-controls={pickerId}
        onClick={() => setPickerOpen((current) => !current)}
      >
        <span className="react-time-scope-picker-trigger-main">{buttonLabel || activeLabel}</span>
        <span className="react-time-scope-picker-trigger-icon" aria-hidden="true">
          {pickerOpen ? "▴" : "▾"}
        </span>
      </button>
      {pickerOpen ? (
        <div className="react-time-scope-picker-popover" id={pickerId} role="dialog" aria-label={label}>
          <div className="react-time-scope-picker-grid">
            <div className="react-time-scope-picker-presets" role="listbox" aria-label={label}>
              {options.map((item) => (
                <button
                  key={item.value}
                  type="button"
                  className={`react-time-scope-preset ${item.value === value ? "active" : ""}`}
                  onClick={() => {
                    onChange(item.value);
                    if (!customContent || item.value !== "custom") {
                      setPickerOpen(false);
                    }
                  }}
                >
                  {item.label}
                </button>
              ))}
            </div>
            {customContent || footerContent ? (
              <div className="react-time-scope-picker-custom">
                {customContent ? (
                  <>
                    <div className="react-time-scope-picker-custom-title">
                      {t(lang, { en: "Custom range", ru: "Свой диапазон" })}
                    </div>
                    <div className="react-time-scope-custom">{customContent}</div>
                  </>
                ) : null}
                {footerContent ? <div className="react-time-scope-picker-footer">{footerContent}</div> : null}
                {customContent ? (
                  <div className="react-actions react-wrap">
                    <button type="button" className="react-link-button" onClick={() => setPickerOpen(false)}>
                      {t(lang, { en: "Apply", ru: "Применить" })}
                    </button>
                  </div>
                ) : null}
              </div>
            ) : null}
          </div>
        </div>
      ) : null}
    </div>
  );
}

export function TimeScopeBar({
  rangeLabel,
  rangeValue,
  rangeOptions,
  onRangeChange,
  refreshLabel,
  refreshValue,
  refreshOptions,
  onRefreshChange,
  rowsLabel,
  rowsValue,
  rowsOptions,
  onRowsChange,
  customRangeFields,
  extraControls,
  summary,
}: {
  rangeLabel: string;
  rangeValue: string;
  rangeOptions: SelectOption[];
  onRangeChange: (value: string) => void;
  refreshLabel: string;
  refreshValue: string;
  refreshOptions: SelectOption[];
  onRefreshChange: (value: string) => void;
  rowsLabel: string;
  rowsValue: string | number;
  rowsOptions: SelectOption[];
  onRowsChange: (value: string) => void;
  customRangeFields?: ReactNode;
  extraControls?: ReactNode;
  summary?: ReactNode;
}) {
  return (
    <section className="react-time-scope-bar">
      <div className="react-time-scope-main">
        <TimeScopePickerButton
          label={rangeLabel}
          value={rangeValue}
          options={rangeOptions}
          onChange={onRangeChange}
          customContent={customRangeFields}
        />
        <label className="react-time-scope-item">
          <span>{refreshLabel}</span>
          <select className="react-select" value={refreshValue} onChange={(event) => onRefreshChange(event.target.value)}>
            {refreshOptions.map((item) => (
              <option key={item.value} value={item.value}>
                {item.label}
              </option>
            ))}
          </select>
        </label>
        <label className="react-time-scope-item">
          <span>{rowsLabel}</span>
          <select className="react-select" value={rowsValue} onChange={(event) => onRowsChange(event.target.value)}>
            {rowsOptions.map((item) => (
              <option key={item.value} value={item.value}>
                {item.label}
              </option>
            ))}
          </select>
        </label>
        {extraControls ? <div className="react-time-scope-extra">{extraControls}</div> : null}
      </div>
      {customRangeFields ? <div className="react-time-scope-custom">{customRangeFields}</div> : null}
      {summary ? <div className="react-inline-note react-time-scope-summary">{summary}</div> : null}
    </section>
  );
}

export function WorkspaceSection({
  title,
  subtitle,
  icon,
  actions,
  children,
  tone = "default",
}: {
  title: string;
  subtitle: string;
  icon?: IconName;
  actions?: ReactNode;
  children: ReactNode;
  tone?: "default" | "emphasis";
}) {
  return (
    <section className={`react-workspace-section tone-${tone}`}>
      <PanelHeader title={title} subtitle={subtitle} icon={icon} actions={actions} />
      <div className="react-workspace-section-body">{children}</div>
    </section>
  );
}

export function SeverityBadge({ value }: { value: string }) {
  const { lang } = useShellContext();
  const level = String(value || "info").toLowerCase();
  const localized = t(lang, {
    en: level,
    ru:
      {
        critical: "критично",
        high: "высокая",
        medium: "средняя",
        low: "низкая",
        info: "инфо",
        healthy: "норма",
        degraded: "деградация",
      }[level] || level,
  });
  return (
    <span className={`react-badge react-sev-${level}`} aria-label={`severity ${level}`}>
      {localized}
    </span>
  );
}

export function StatusBadge({ value }: { value: string }) {
  const { lang } = useShellContext();
  const status = String(value || "new").toLowerCase();
  const localized = t(lang, {
    en: status.replaceAll("_", " "),
    ru:
      {
        new: "новый",
        draft: "черновик",
        active: "активно",
        maintenance: "обслуживание",
        planned: "запланировано",
        planned_followup: "последующая проверка",
        validation_failed: "ошибка проверки",
        compiled: "собрано",
        compile_failed: "ошибка сборки",
        degraded: "деградация",
        healthy: "исправно",
        delayed: "задержка",
        stale: "устарело",
        published: "опубликовано",
        success: "успех",
        error: "ошибка",
        open: "открыто",
        closed: "закрыто",
        resolved: "устранено",
        acknowledged: "подтверждено",
        nested: "вложено",
        synced: "синхронизировано",
        ready: "готово",
        disabled: "отключено",
        enabled: "включено",
        ok: "норма",
        publish_ready_after_host_metrics: "готово после метрик узлов",
      }[status] || status.replaceAll("_", " "),
  });
  return (
    <span className={`react-badge react-status-${status}`} aria-label={`status ${status}`}>
      {localized}
    </span>
  );
}

export function KeyValue({ label, value }: { label: string; value: ReactNode }) {
  const { lang } = useShellContext();
  return (
    <div className="react-kv" role="row">
      <div className="react-kv-label" role="rowheader">{label}</div>
      <div className="react-kv-value" role="cell">{value || t(lang, { en: "n/a", ru: "н/д" })}</div>
    </div>
  );
}

export function JsonPreview({ value }: { value: unknown }) {
  return <pre className="react-pre">{JSON.stringify(value, null, 2)}</pre>;
}

export function DrawerFieldGrid({ children }: { children: ReactNode }) {
  return <div className="react-kv-grid" role="table">{children}</div>;
}

export function InfoList({
  items,
}: {
  items: Array<{ label: string; value: ReactNode }>;
}) {
  return (
    <div className="react-info-list" role="table">
      {items.map((item, index) => (
        <div className="react-info-row" role="row" key={`${item.label}-${index}`}>
          <span role="rowheader">{item.label}</span>
          <strong role="cell">{item.value}</strong>
        </div>
      ))}
    </div>
  );
}

export function interactiveRowKeyDown(event: ReactKeyboardEvent<HTMLElement>, activate: () => void) {
  if (event.key !== "Enter" && event.key !== " ") return;
  event.preventDefault();
  activate();
}

export function DrawerOverlay({
  open,
  title,
  subtitle,
  onClose,
  panelClassName,
  children,
}: {
  open: boolean;
  title: string;
  subtitle?: string;
  onClose: () => void;
  panelClassName?: string;
  children: ReactNode;
}) {
  const { lang } = useShellContext();
  const panelRef = useRef<HTMLElement | null>(null);
  const closeButtonRef = useRef<HTMLButtonElement | null>(null);
  const titleId = useId();
  const subtitleId = useId();

  useEffect(() => {
    if (!open) return undefined;
    const panel = panelRef.current;
    const previousFocus = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const previousOverflow = document.body.style.overflow;
    const focusableSelector = [
      "a[href]",
      "button:not([disabled])",
      "textarea:not([disabled])",
      "input:not([disabled])",
      "select:not([disabled])",
      "[tabindex]:not([tabindex='-1'])",
    ].join(",");
    const getFocusable = () =>
      Array.from(panel?.querySelectorAll<HTMLElement>(focusableSelector) || []).filter(
        (item) => !item.hasAttribute("disabled") && item.getAttribute("aria-hidden") !== "true",
      );

    document.body.style.overflow = "hidden";
    window.requestAnimationFrame(() => {
      (getFocusable()[0] || closeButtonRef.current || panel)?.focus();
    });

    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        onClose();
        return;
      }
      if (event.key !== "Tab") return;
      const focusable = getFocusable();
      if (!focusable.length) {
        event.preventDefault();
        panel?.focus();
        return;
      }
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      const active = document.activeElement;
      if (event.shiftKey && active === first) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && active === last) {
        event.preventDefault();
        first.focus();
      }
    };

    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.removeEventListener("keydown", onKeyDown);
      document.body.style.overflow = previousOverflow;
      previousFocus?.focus();
    };
  }, [onClose, open]);

  if (!open) return null;
  return (
    <div className="react-drawer-overlay">
      <button type="button" className="react-drawer-backdrop" onClick={onClose} aria-label="Close drawer" />
      <aside
        ref={panelRef}
        className={`react-drawer-panel${panelClassName ? ` ${panelClassName}` : ""}`}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={subtitle ? subtitleId : undefined}
        tabIndex={-1}
      >
        <div className="react-drawer-topbar">
          <div>
            <h3 id={titleId}>{title}</h3>
            {subtitle ? <p id={subtitleId}>{subtitle}</p> : null}
          </div>
          <button ref={closeButtonRef} type="button" className="react-icon-button react-icon-button-wide" onClick={onClose}>
            {t(lang, { en: "Close", ru: "\u0417\u0430\u043a\u0440\u044b\u0442\u044c" })}
          </button>
        </div>
        <div className="react-drawer-body">{children}</div>
      </aside>
    </div>
  );
}
