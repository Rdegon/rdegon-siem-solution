import type { Meta, StoryObj } from "@storybook/react";
import { InvestigationActionRail, InvestigationSummaryStrip, InvestigationTimeline, SectionIntro } from "../shell/ui";
import { SeverityBadge } from "../shell/surfaces";

const meta = {
  title: "Patterns/Investigation",
  parameters: {
    layout: "padded",
  },
} satisfies Meta;

export default meta;
type Story = StoryObj<typeof meta>;

export const DrawerLanguage: Story = {
  render: () => (
    <div className="react-page" style={{ display: "grid", gap: 18 }}>
      <SectionIntro
        kicker="Investigation"
        title="Unified drawer language"
        subtitle="Shared evidence model for events, entities, assets and threat-intel pivots."
        icon="events"
      />
      <InvestigationSummaryStrip
        items={[
          { label: "Severity", value: <SeverityBadge value="critical" />, tone: "critical" },
          { label: "Source", value: "dc-01" },
          { label: "User", value: "svc_backup" },
          { label: "Asset", value: "asset-dc-01" },
          { label: "TI", value: "golden-ticket", tone: "warning" },
          { label: "Last seen", value: "2026-03-27 00:12" },
        ]}
      />
      <InvestigationActionRail
        items={[
          { label: "Open events", href: "#events" },
          { label: "Open incidents", href: "#incidents" },
          { label: "Open in TI", href: "#threat-intel", tone: "warning" },
        ]}
      />
      <InvestigationTimeline
        title="Investigation chain"
        subtitle="Evidence is organized as a readable chain instead of a raw field dump."
        icon="events"
        emptyMessage="No evidence loaded."
        items={[
          {
            id: "evt",
            title: "Observed Kerberos abuse",
            subtitle: "auth / kerberos / windows-event-log",
            meta: "2026-03-27 00:10",
            tone: "critical",
            body: "Service ticket request for privileged account with abnormal source context.",
          },
          {
            id: "identity",
            title: "Identity context",
            subtitle: "svc_backup · CORP · asset-dc-01",
            meta: "windows-security-http",
            body: "Mapped to domain controller ownership lane and analyst queue.",
          },
          {
            id: "network",
            title: "Network path",
            subtitle: "192.168.1.10 -> 192.168.1.11",
            meta: "port 88",
            tone: "warning",
            body: "Kerberos flow aligned with suspicious privileged sequence.",
          },
        ]}
      />
    </div>
  ),
};
