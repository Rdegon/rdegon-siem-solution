import type { Meta, StoryObj } from "@storybook/react";
import { Link } from "react-router-dom";
import { Icon } from "../shell/chrome";
import { TimeScopePickerButton } from "../shell/ui";

const meta = {
  title: "Pages/Overview Surface",
  parameters: {
    layout: "fullscreen",
  },
} satisfies Meta;

export default meta;
type Story = StoryObj<typeof meta>;

export const CommandSurface: Story = {
  render: () => (
    <div className="react-page react-page-dashboard">
      <section className="react-card react-overview-hero-shell">
        <div className="react-overview-hero-top react-overview-heading-bar">
          <div className="react-overview-heading-controls">
            <label className="react-time-inline-select">
              <select className="react-select" defaultValue="30">
                <option value="0">No refresh</option>
                <option value="30">30s</option>
                <option value="60">60s</option>
              </select>
            </label>
            <TimeScopePickerButton
              label="Time focus"
              value="24h"
              options={[
                { value: "24h", label: "24h" },
                { value: "7d", label: "7d" },
                { value: "custom", label: "Custom" },
              ]}
              onChange={() => undefined}
              buttonLabel={
                <span className="react-time-focus-button-content">
                  <span className="react-time-focus-button-badge">24h</span>
                  <span className="react-time-focus-button-text">2026-03-27 00:00 - 2026-03-28 00:00</span>
                </span>
              }
            />
          </div>
          <div className="react-overview-hero-copy">
            <div className="react-top-kicker">Overview</div>
            <h2 className="react-title-with-icon react-title-with-icon-hero">
              <Icon name="dashboard" size={20} />
              <span>Security overview</span>
            </h2>
            <p className="react-muted">Curated first-screen operating surface for pressure, pivots and active work lanes.</p>
          </div>
        </div>
        <div className="react-overview-kpi-grid">
          {[
            ["Events 1h", "12,840", "Current normalized flow."],
            ["Open incidents", "7", "Analyst queue waiting for action."],
            ["TI hits", "12", "Matched intelligence signals."],
            ["Active sources", "28", "Reporting sources in the current window."],
          ].map(([label, value, hint]) => (
            <div key={label} className="react-overview-kpi-item">
              <div className="react-stat-label">{label}</div>
              <div className="react-overview-kpi-value">{value}</div>
              <div className="react-stat-hint">{hint}</div>
            </div>
          ))}
        </div>
        <div className="react-overview-pressure-grid">
          <div className="react-overview-pressure-item tone-warning">
            <div className="react-stat-label">Queue pressure</div>
            <strong>7</strong>
            <span>Open incident queue for the active window.</span>
          </div>
          <div className="react-overview-pressure-item tone-info">
            <div className="react-stat-label">Top source</div>
            <strong>dc-01</strong>
            <span>Highest-volume source right now.</span>
          </div>
          <div className="react-overview-pressure-item tone-critical">
            <div className="react-stat-label">Lead alert</div>
            <strong>Kerberos abuse</strong>
            <span>Freshest alert worth pivoting into.</span>
          </div>
        </div>
        <div className="react-overview-lane-grid">
          {[
            ["Triage queue", "Read ownership, severity and workflow state."],
            ["Event explorer", "Pivot from pressure into evidence."],
            ["Source health", "Check freshness, drift and onboarding gaps."],
            ["Exposure queue", "See what requires action now."],
          ].map(([title, hint]) => (
            <Link key={title} className="react-overview-lane-card" to="#">
              <div className="react-top-kicker">Operating lane</div>
              <strong>{title}</strong>
              <span>{hint}</span>
            </Link>
          ))}
        </div>
      </section>
    </div>
  ),
};
