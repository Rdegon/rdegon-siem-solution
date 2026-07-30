import type { ReactNode } from "react";
import { Icon, type IconName } from "./chrome";

export function NativePageHeader({
  title,
  subtitle,
  icon,
  actions,
}: {
  title: ReactNode;
  subtitle?: ReactNode;
  icon?: IconName;
  actions?: ReactNode;
}) {
  return (
    <header className="native-page-header">
      <div className="native-page-heading">
        <h1>
          {icon ? <Icon name={icon} size={20} /> : null}
          <span>{title}</span>
        </h1>
        {subtitle ? <p>{subtitle}</p> : null}
      </div>
      {actions ? <div className="native-page-actions">{actions}</div> : null}
    </header>
  );
}

export function NativeActionBar({
  primary,
  meta,
}: {
  primary?: ReactNode;
  meta?: ReactNode;
}) {
  return (
    <div className="native-actionbar">
      <div className="native-actionbar-primary">{primary}</div>
      <div className="native-actionbar-meta">{meta}</div>
    </div>
  );
}

export function NativePager({
  shown,
  total,
  lang = "en",
  children,
}: {
  shown: number;
  total: number;
  lang?: "en" | "ru";
  children?: ReactNode;
}) {
  return (
    <footer className="native-pager">
      <span>
        {lang === "ru" ? "Показано" : "Showing"} <strong>{shown}</strong> {lang === "ru" ? "из" : "of"} <strong>{total}</strong>
      </span>
      {children ? <div className="native-pager-actions">{children}</div> : null}
    </footer>
  );
}
