import type { Meta, StoryObj } from "@storybook/react";
import { MetricStrip, SectionIntro, StatusBadge, WorkspaceSection } from "../shell/ui";

const meta = {
  title: "Pages/Identity Workspace",
  parameters: {
    layout: "fullscreen",
  },
} satisfies Meta;

export default meta;
type Story = StoryObj<typeof meta>;

export const ControlCenter: Story = {
  render: () => (
    <div className="react-page react-page-access">
      <SectionIntro
        kicker="Identity"
        title="Identity control center"
        subtitle="Operate Keycloak realm identities, recovery, service accounts and Vault-backed secret posture from one workspace."
        icon="access"
      />
      <MetricStrip
        items={[
          { label: "SSO providers", value: 1, hint: "OIDC and recovery entry paths.", tone: "success" },
          { label: "Keycloak users", value: 14, hint: "Realm identities visible to the admin client.", tone: "success" },
          { label: "Vault refs", value: 17, hint: "Runtime secrets resolved through Vault.", tone: "success" },
        ]}
      />
      <div className="react-grid react-grid-2">
        <WorkspaceSection title="Keycloak plane" subtitle="Realm-admin automation state, inventory and provider posture." icon="control" tone="emphasis">
          <div className="react-list">
            <div className="react-list-item"><strong>siem</strong><span>Realm healthy</span><StatusBadge value="healthy" /></div>
            <div className="react-list-item"><strong>Users</strong><span>14 identities</span></div>
            <div className="react-list-item"><strong>Clients</strong><span>7 confidential/public clients</span></div>
          </div>
        </WorkspaceSection>
        <WorkspaceSection title="Recovery posture" subtitle="Break-glass visibility and machine identity lane." icon="incidents">
          <div className="react-list">
            <div className="react-list-item"><strong>Break-glass</strong><span>No active recovery sessions</span><StatusBadge value="healthy" /></div>
            <div className="react-list-item"><strong>Service accounts</strong><span>9 machine principals</span></div>
            <div className="react-list-item"><strong>Vault</strong><span>Refs green, rotation tracked</span><StatusBadge value="healthy" /></div>
          </div>
        </WorkspaceSection>
      </div>
    </div>
  ),
};

