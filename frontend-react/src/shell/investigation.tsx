import type { ReactNode } from "react";
import { Icon, type IconName } from "./chrome";

export type InvestigationTone = "default" | "critical" | "warning" | "success" | "info";

export type InvestigationFact = {
  label: string;
  value: ReactNode;
  tone?: InvestigationTone;
};

export type InvestigationAction = {
  label: string;
  href?: string;
  onClick?: () => void;
  tone?: InvestigationTone;
};

export type InvestigationTimelineEntry = {
  id: string;
  title: string;
  subtitle?: string;
  meta?: ReactNode;
  body?: ReactNode;
  tone?: InvestigationTone;
};

export function InvestigationSummaryStrip({ items }: { items: InvestigationFact[] }) {
  return (
    <div className="react-investigation-summary-strip" role="list">
      {items.map((item) => (
        <section key={`${item.label}-${String(item.value)}`} className={`react-investigation-summary tone-${item.tone || "default"}`} role="listitem">
          <div className="react-investigation-summary-label">{item.label}</div>
          <div className="react-investigation-summary-value">{item.value || "n/a"}</div>
        </section>
      ))}
    </div>
  );
}

export function InvestigationActionRail({ items }: { items: InvestigationAction[] }) {
  return (
    <div className="react-investigation-action-rail">
      {items.map((item, index) =>
        item.href ? (
          <a
            key={`${item.label}-${index}`}
            className={`react-link-button react-investigation-action tone-${item.tone || "default"}`}
            href={item.href}
          >
            {item.label}
          </a>
        ) : (
          <button
            key={`${item.label}-${index}`}
            type="button"
            className={`react-link-button react-investigation-action tone-${item.tone || "default"}`}
            onClick={item.onClick}
          >
            {item.label}
          </button>
        ),
      )}
    </div>
  );
}

export function InvestigationDrawerSection({
  title,
  subtitle,
  icon,
  children,
}: {
  title: string;
  subtitle: string;
  icon?: IconName;
  children: ReactNode;
}) {
  return (
    <section className="react-card react-card-nested react-investigation-section">
      <div className="react-card-head react-card-head-row react-card-head-tight">
        <div>
          <h3 className="react-title-with-icon">
            {icon ? <Icon name={icon} /> : null}
            <span>{title}</span>
          </h3>
          <p>{subtitle}</p>
        </div>
      </div>
      {children}
    </section>
  );
}

export function InvestigationTimeline({
  title,
  subtitle,
  icon,
  items,
  emptyMessage,
}: {
  title: string;
  subtitle: string;
  icon?: IconName;
  items: InvestigationTimelineEntry[];
  emptyMessage: string;
}) {
  return (
    <InvestigationDrawerSection title={title} subtitle={subtitle} icon={icon}>
      {items.length ? (
        <div className="react-investigation-timeline" role="list">
          {items.map((item) => (
            <article key={item.id} className={`react-investigation-entry tone-${item.tone || "default"}`} role="listitem">
              <div className="react-investigation-entry-rail" aria-hidden="true" />
              <div className="react-investigation-entry-body">
                <div className="react-investigation-entry-head">
                  <div>
                    <strong>{item.title}</strong>
                    {item.subtitle ? <p>{item.subtitle}</p> : null}
                  </div>
                  {item.meta ? <div className="react-investigation-entry-meta">{item.meta}</div> : null}
                </div>
                {item.body ? <div className="react-investigation-entry-copy">{item.body}</div> : null}
              </div>
            </article>
          ))}
        </div>
      ) : (
        <div className="react-page-settings-note">{emptyMessage}</div>
      )}
    </InvestigationDrawerSection>
  );
}

