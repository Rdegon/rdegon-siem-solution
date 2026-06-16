import { useCallback, useEffect, useMemo, useState } from "react";
import { api } from "../api";
import { AsyncGate } from "../async";
import { useShellContext } from "../context";
import { useFeedback } from "../feedback";
import { usePolledData } from "../hooks";
import { InfoList, MetricStrip, SectionIntro, StatusBadge, WorkspaceSection } from "../ui";
import type {
  AuthPermissionBundleRecord,
  AuthProviderRecord,
  BreakGlassSessionRecord,
  LocalUserRecord,
  RuntimeBlob,
  ServiceAccountSummary,
} from "../types";

type UserForm = {
  username: string;
  role: string;
  enabled: boolean;
  permissionBundles: string[];
  password: string;
};

type ServiceAccountForm = {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  permissionBundles: string[];
};

const emptyUserForm = (): UserForm => ({ username: "", role: "viewer", enabled: true, permissionBundles: [], password: "" });
const emptyServiceAccountForm = (): ServiceAccountForm => ({ id: "", name: "", description: "", enabled: true, permissionBundles: [] });

function toggleBundle(current: string[], bundleId: string) {
  return current.includes(bundleId) ? current.filter((item) => item !== bundleId) : [...current, bundleId].sort();
}

export function AccessPage() {
  const { formatTimestamp } = useShellContext();
  const { pushToast } = useFeedback();
  const [refreshTick, setRefreshTick] = useState(0);
  const [selectedUsername, setSelectedUsername] = useState("");
  const [selectedServiceAccountId, setSelectedServiceAccountId] = useState("");
  const [tokenTitle, setTokenTitle] = useState("");
  const [tokenDays, setTokenDays] = useState("90");
  const [rotationOverlapMinutes, setRotationOverlapMinutes] = useState("15");
  const [issuedToken, setIssuedToken] = useState("");
  const [userForm, setUserForm] = useState<UserForm>(emptyUserForm());
  const [serviceAccountForm, setServiceAccountForm] = useState<ServiceAccountForm>(emptyServiceAccountForm());

  const loadUsers = useCallback(() => { void refreshTick; return api.authUsers({ include_disabled: true }); }, [refreshTick]);
  const loadServiceAccounts = useCallback(() => { void refreshTick; return api.serviceAccounts(); }, [refreshTick]);
  const loadGovernance = useCallback(() => { void refreshTick; return api.authGovernance(); }, [refreshTick]);
  const loadProviders = useCallback(() => { void refreshTick; return api.authProviders(); }, [refreshTick]);
  const loadCertification = useCallback(() => { void refreshTick; return api.certificationHealth(); }, [refreshTick]);
  const loadServiceAccountDetail = useCallback(
    () => (selectedServiceAccountId ? api.serviceAccountDetail(selectedServiceAccountId) : Promise.resolve({ item: null, tokens: [] })),
    [selectedServiceAccountId],
  );

  const usersState = usePolledData(loadUsers, 30000);
  const accountsState = usePolledData(loadServiceAccounts, 30000);
  const governanceState = usePolledData(loadGovernance, 30000);
  const providersState = usePolledData(loadProviders, 30000);
  const certificationState = usePolledData(loadCertification, 30000);
  const detailsState = usePolledData(loadServiceAccountDetail, 30000);

  const users = useMemo(() => usersState.data?.items || [], [usersState.data?.items]);
  const accounts = useMemo(() => accountsState.data?.items || [], [accountsState.data?.items]);
  const permissionBundles = usersState.data?.permission_bundles || accountsState.data?.permission_bundles || [];
  const permissionCategories = usersState.data?.permission_categories || accountsState.data?.permission_categories || [];
  const availableRoles = usersState.data?.available_roles || ["viewer", "analyst", "admin"];
  const selectedUser = useMemo(() => users.find((item) => item.username === selectedUsername) || null, [selectedUsername, users]);
  const selectedServiceAccount = useMemo(
    () => accounts.find((item) => String(item.id || "") === selectedServiceAccountId) || null,
    [accounts, selectedServiceAccountId],
  );
  const tokens = detailsState.data?.tokens || [];
  const providers = useMemo(
    () => providersState.data?.items || (governanceState.data?.providers as AuthProviderRecord[] | undefined) || [],
    [governanceState.data?.providers, providersState.data?.items],
  );
  const breakGlassItems = useMemo(
    () => ((governanceState.data?.break_glass as RuntimeBlob | undefined)?.items as BreakGlassSessionRecord[] | undefined) || [],
    [governanceState.data?.break_glass],
  );
  const secretItems = useMemo(
    () => ((governanceState.data?.secrets as RuntimeBlob | undefined)?.items as RuntimeBlob[] | undefined) || [],
    [governanceState.data?.secrets],
  );
  const secretSummary = (governanceState.data?.secrets as RuntimeBlob | undefined)?.summary as RuntimeBlob | undefined;
  const vaultStatus = governanceState.data?.vault as RuntimeBlob | undefined;
  const certification = certificationState.data as RuntimeBlob | undefined;

  useEffect(() => {
    if (!selectedUsername && users.length) setSelectedUsername(users[0].username);
    if (!selectedServiceAccountId && accounts.length) setSelectedServiceAccountId(String(accounts[0].id || ""));
  }, [accounts, selectedServiceAccountId, selectedUsername, users]);

  useEffect(() => {
    setUserForm(
      selectedUser
        ? {
            username: selectedUser.username,
            role: selectedUser.role || "viewer",
            enabled: Boolean(selectedUser.enabled),
            permissionBundles: selectedUser.permission_bundles || [],
            password: "",
          }
        : emptyUserForm(),
    );
  }, [selectedUser]);

  useEffect(() => {
    setServiceAccountForm(
      selectedServiceAccount
        ? {
            id: String(selectedServiceAccount.id || ""),
            name: String(selectedServiceAccount.name || ""),
            description: String(selectedServiceAccount.description || ""),
            enabled: Boolean(selectedServiceAccount.enabled),
            permissionBundles: selectedServiceAccount.permission_bundles || [],
          }
        : emptyServiceAccountForm(),
    );
    setIssuedToken("");
  }, [selectedServiceAccount]);

  const metrics = [
    { label: "Providers", value: providers.length, hint: "Enterprise SSO and break-glass entry points.", tone: providers.some((item) => item.healthy) ? ("success" as const) : ("warning" as const) },
    { label: "Vault refs", value: Number(secretSummary?.vault_backed || 0), hint: "Production secrets resolved through vault:// references.", tone: Number(secretSummary?.vault_backed || 0) ? ("success" as const) : ("warning" as const) },
    { label: "Break-glass", value: Number(((governanceState.data?.break_glass as RuntimeBlob | undefined)?.metrics as RuntimeBlob | undefined)?.active || 0), hint: "Active emergency local sessions.", tone: Number(((governanceState.data?.break_glass as RuntimeBlob | undefined)?.metrics as RuntimeBlob | undefined)?.active || 0) ? ("warning" as const) : ("success" as const) },
    { label: "Certified EPS", value: Number(certification?.latest_certified_ceiling_eps || 0), hint: "Latest published production ceiling.", tone: certification?.healthy ? ("success" as const) : ("warning" as const) },
    { label: "Service accounts", value: accounts.length, hint: "Machine principals for connectors and automation.", tone: "default" as const },
    { label: "Active tokens", value: Number(accountsState.data?.metrics?.active_tokens || 0), hint: "Usable machine tokens.", tone: "warning" as const },
  ];

  async function saveUser() {
    try {
      const saved = await api.saveLocalUser({
        username: userForm.username,
        role: userForm.role,
        enabled: userForm.enabled,
        permission_bundles: userForm.permissionBundles,
        ...(userForm.password.trim() ? { password: userForm.password } : {}),
      });
      setSelectedUsername(saved.username);
      setUserForm((current) => ({ ...current, password: "" }));
      setRefreshTick((value) => value + 1);
      pushToast({ title: "User saved", message: saved.username, tone: "success" });
    } catch (error) {
      pushToast({ title: "User save failed", message: error instanceof Error ? error.message : "Save failed", tone: "error" });
    }
  }

  async function rotatePassword() {
    if (!selectedUser || !userForm.password.trim()) return;
    try {
      await api.setLocalUserPassword(selectedUser.username, { password: userForm.password });
      setUserForm((current) => ({ ...current, password: "" }));
      setRefreshTick((value) => value + 1);
      pushToast({ title: "Password rotated", message: selectedUser.username, tone: "success" });
    } catch (error) {
      pushToast({ title: "Password rotation failed", message: error instanceof Error ? error.message : "Password failed", tone: "error" });
    }
  }

  async function deleteUser(username: string) {
    try {
      await api.deleteLocalUser(username);
      setSelectedUsername("");
      setRefreshTick((value) => value + 1);
      pushToast({ title: "User deleted", message: username, tone: "success" });
    } catch (error) {
      pushToast({ title: "User delete failed", message: error instanceof Error ? error.message : "Delete failed", tone: "error" });
    }
  }

  async function saveServiceAccount() {
    try {
      const saved = await api.saveServiceAccount({
        id: serviceAccountForm.id || undefined,
        name: serviceAccountForm.name,
        description: serviceAccountForm.description,
        enabled: serviceAccountForm.enabled,
        permission_bundles: serviceAccountForm.permissionBundles,
      });
      setSelectedServiceAccountId(String(saved.id || ""));
      setRefreshTick((value) => value + 1);
      pushToast({ title: "Service account saved", message: saved.name, tone: "success" });
    } catch (error) {
      pushToast({ title: "Service account save failed", message: error instanceof Error ? error.message : "Save failed", tone: "error" });
    }
  }

  async function deleteServiceAccount(serviceAccountId: string) {
    try {
      await api.deleteServiceAccount(serviceAccountId);
      setSelectedServiceAccountId("");
      setRefreshTick((value) => value + 1);
      pushToast({ title: "Service account deleted", message: serviceAccountId, tone: "success" });
    } catch (error) {
      pushToast({ title: "Service account delete failed", message: error instanceof Error ? error.message : "Delete failed", tone: "error" });
    }
  }

  async function issueToken() {
    if (!selectedServiceAccount) return;
    try {
      const result = await api.issueServiceAccountToken(String(selectedServiceAccount.id || ""), { title: tokenTitle, expires_days: Number(tokenDays || 90) });
      setIssuedToken(String(result.token?.token || ""));
      setTokenTitle("");
      setRefreshTick((value) => value + 1);
      pushToast({ title: "Token issued", message: result.token?.title || result.token?.id || String(selectedServiceAccount.name || ""), tone: "success" });
    } catch (error) {
      pushToast({ title: "Token issuance failed", message: error instanceof Error ? error.message : "Issue failed", tone: "error" });
    }
  }

  async function rotateToken() {
    if (!selectedServiceAccount) return;
    try {
      const result = await api.rotateServiceAccountToken(String(selectedServiceAccount.id || ""), {
        title: tokenTitle || `rotation-${Date.now()}`,
        expires_days: Number(tokenDays || 90),
        overlap_minutes: Number(rotationOverlapMinutes || 15),
        revoke_predecessor: true,
      });
      setIssuedToken(String(((result as RuntimeBlob).token as RuntimeBlob | undefined)?.token || ""));
      setRefreshTick((value) => value + 1);
      pushToast({ title: "Token rotated", message: String(selectedServiceAccount.name || selectedServiceAccount.id || ""), tone: "success" });
    } catch (error) {
      pushToast({ title: "Token rotation failed", message: error instanceof Error ? error.message : "Rotate failed", tone: "error" });
    }
  }

  async function revokeToken(tokenId: string) {
    if (!selectedServiceAccount) return;
    try {
      await api.revokeServiceAccountToken(String(selectedServiceAccount.id || ""), tokenId);
      setRefreshTick((value) => value + 1);
      pushToast({ title: "Token revoked", message: tokenId, tone: "success" });
    } catch (error) {
      pushToast({ title: "Token revoke failed", message: error instanceof Error ? error.message : "Revoke failed", tone: "error" });
    }
  }

  async function revokeBreakGlass(sessionId: string) {
    try {
      await api.mutateBreakGlass({ action: "revoke", session_id: sessionId, reason: "Closed from Identity & Governance workspace" });
      setRefreshTick((value) => value + 1);
      pushToast({ title: "Break-glass session revoked", message: sessionId, tone: "success" });
    } catch (error) {
      pushToast({ title: "Break-glass revoke failed", message: error instanceof Error ? error.message : "Revoke failed", tone: "error" });
    }
  }

  return (
    <AsyncGate states={[usersState, accountsState, governanceState, providersState, certificationState, detailsState]} loadingMessage="Loading identity workspace...">
      <div className="react-page">
        <SectionIntro kicker="Identity" title="Identity and governance workspace" subtitle="Enterprise SSO, break-glass recovery, service-account rotation, vault-backed secrets and certification signals." icon="access" />
        <MetricStrip items={metrics} />

        <div className="react-grid react-grid-3">
          <WorkspaceSection title="Enterprise providers" subtitle="OIDC-first entrypoints and provider health." icon="control" tone="emphasis">
            <div className="react-list">
              {providers.map((item: AuthProviderRecord) => (
                <section key={String(item.id || item.title || "provider")} className="react-card react-card-nested">
                  <div className="react-card-button-header">
                    <div>
                      <strong>{String(item.title || item.id || "provider")}</strong>
                      <div className="react-card-button-copy">{String(item.kind || "provider")} {item.issuer ? `| ${String(item.issuer)}` : ""}</div>
                    </div>
                    <StatusBadge value={item.healthy ? "healthy" : "degraded"} />
                  </div>
                  <div className="react-card-button-grid">
                    <span>Enabled</span><strong>{item.enabled ? "yes" : "no"}</strong>
                    <span>Issues</span><strong>{Array.isArray(item.issues) ? item.issues.length : 0}</strong>
                    <span>Path</span><strong>{String(item.kind || "n/a")}</strong>
                  </div>
                </section>
              ))}
            </div>
          </WorkspaceSection>

          <WorkspaceSection title="Certification" subtitle="Published budgets and latest certified operating envelope." icon="dashboard">
            <InfoList items={[
              { label: "Healthy", value: certification?.healthy ? "yes" : "no" },
              { label: "Certified EPS", value: Number(certification?.latest_certified_ceiling_eps || 0) },
              { label: "Delivery min", value: Number(((certification?.budgets as RuntimeBlob | undefined)?.delivery_ratio_min) || 0).toFixed(3) },
              { label: "Kafka lag max", value: Number(((certification?.budgets as RuntimeBlob | undefined)?.kafka_lag_max) || 0) },
              { label: "Ingest p95 max", value: `${Number(((certification?.budgets as RuntimeBlob | undefined)?.ingest_p95_latency_ms_max) || 0).toFixed(0)} ms` },
            ]} />
            <div className="react-list react-list-compact" style={{ marginTop: 14 }}>
              {Array.isArray(certification?.issues) && certification.issues.length ? certification.issues.map((issue) => (
                <div key={String(issue)} className="react-list-item"><strong>Issue</strong><span>{String(issue)}</span></div>
              )) : <div className="react-list-item"><strong>Status</strong><span>Certification runtime is green.</span></div>}
            </div>
          </WorkspaceSection>

          <WorkspaceSection title="Vault and secrets" subtitle="Runtime ref health, missing requirements and rotation posture." icon="docs">
            <InfoList items={[
              { label: "Vault healthy", value: vaultStatus?.healthy ? "yes" : "no" },
              { label: "Configured", value: Number(secretSummary?.configured || 0) },
              { label: "Vault refs", value: Number(secretSummary?.vault_backed || 0) },
              { label: "Missing", value: Number(secretSummary?.required_missing || 0) },
            ]} />
            <div className="react-list react-list-compact" style={{ marginTop: 14 }}>
              {secretItems.slice(0, 6).map((item, index) => (
                <div key={`${String(item.env || item.label || "secret")}-${index}`} className="react-list-item">
                  <strong>{String(item.label || item.env || "secret")}</strong>
                  <span>{String(item.status || "unknown")} | {String(item.reference_type || item.source || "runtime")}</span>
                </div>
              ))}
            </div>
          </WorkspaceSection>
        </div>

        <div className="react-grid react-grid-2">
          <WorkspaceSection title="Break-glass sessions" subtitle="Emergency local sessions with expiry and revocation control." icon="incidents" tone="emphasis">
            <div className="react-list react-list-compact">
              {breakGlassItems.slice(0, 8).map((item: BreakGlassSessionRecord) => (
                <section key={String(item.id || "session")} className="react-card react-card-nested">
                  <div className="react-card-button-header">
                    <div>
                      <strong>{String(item.username || item.id || "break-glass")}</strong>
                      <div className="react-card-button-copy">{String(item.reason || "Emergency local access")}</div>
                    </div>
                    <StatusBadge value={String(item.status || (item.active ? "active" : "closed"))} />
                  </div>
                  <div className="react-card-button-grid">
                    <span>Actor</span><strong>{String(item.actor || "self")}</strong>
                    <span>Created</span><strong>{item.created_ts ? formatTimestamp(item.created_ts, "compact") : "n/a"}</strong>
                    <span>Expires</span><strong>{item.expires_ts ? formatTimestamp(item.expires_ts, "compact") : "n/a"}</strong>
                  </div>
                  {item.active ? <button type="button" className="react-link-button" onClick={() => void revokeBreakGlass(String(item.id || ""))}>Revoke</button> : null}
                </section>
              ))}
            </div>
          </WorkspaceSection>

          <WorkspaceSection title="Governance signals" subtitle="Identity drift, rotation health and local-account posture." icon="events">
            <InfoList items={[
              { label: "Providers healthy", value: `${Number(((governanceState.data?.service_accounts as RuntimeBlob | undefined)?.metrics as RuntimeBlob | undefined)?.providers_healthy || 0)}/${Number(((governanceState.data?.service_accounts as RuntimeBlob | undefined)?.metrics as RuntimeBlob | undefined)?.providers_enabled || 0)}` },
              { label: "Rotations 30d", value: Number(((governanceState.data?.service_accounts as RuntimeBlob | undefined)?.metrics as RuntimeBlob | undefined)?.service_account_rotations_30d || 0) },
              { label: "Local plaintext users", value: Number(((governanceState.data?.local_auth as RuntimeBlob | undefined)?.metrics as RuntimeBlob | undefined)?.local_users_plaintext || 0) },
              { label: "Blocked IPs", value: Number((((governanceState.data?.local_auth as RuntimeBlob | undefined)?.policy as RuntimeBlob | undefined)?.login_rate_limit as RuntimeBlob | undefined)?.blocked_ips || 0) },
            ]} />
          </WorkspaceSection>
        </div>

        <div className="react-grid react-grid-3">
          <WorkspaceSection title="Local users" subtitle="Break-glass-capable human accounts." icon="access" tone="emphasis">
            <div className="react-list">
              {users.map((item: LocalUserRecord) => (
                <button key={item.username} type="button" className={`react-card react-card-button ${selectedUsername === item.username ? "active" : ""}`} onClick={() => setSelectedUsername(item.username)}>
                  <div className="react-card-button-header"><div><strong>{item.username}</strong><div className="react-card-button-copy">{item.role}</div></div><StatusBadge value={item.enabled ? "active" : "disabled"} /></div>
                  <div className="react-card-button-grid"><span>Bundles</span><strong>{(item.permission_bundles || []).length}</strong><span>Password</span><strong>{item.password_updated_ts ? formatTimestamp(item.password_updated_ts, "compact") : "never"}</strong><span>Updated</span><strong>{item.updated_ts ? formatTimestamp(item.updated_ts, "compact") : "n/a"}</strong></div>
                </button>
              ))}
            </div>
          </WorkspaceSection>

          <WorkspaceSection title="User editor" subtitle="Create users, rotate passwords and tighten recovery posture." icon="builders">
            <div className="react-form-grid">
              <input className="react-input" value={userForm.username} onChange={(event) => setUserForm((current) => ({ ...current, username: event.target.value }))} placeholder="Username" />
              <select className="react-select react-select-inline" value={userForm.role} onChange={(event) => setUserForm((current) => ({ ...current, role: event.target.value }))}>{availableRoles.map((item) => <option key={item} value={item}>{item}</option>)}</select>
              <input className="react-input" type="password" value={userForm.password} onChange={(event) => setUserForm((current) => ({ ...current, password: event.target.value }))} placeholder={selectedUser ? "New password (optional on save)" : "Initial password"} />
              <label className="react-toggle"><input type="checkbox" checked={userForm.enabled} onChange={(event) => setUserForm((current) => ({ ...current, enabled: event.target.checked }))} /><span>Enabled</span></label>
              <div className="react-list react-list-compact">
                {permissionBundles.map((bundle: AuthPermissionBundleRecord) => (
                  <label key={bundle.id} className="react-list-item">
                    <strong>{bundle.title}</strong>
                    <span>{bundle.permissions.join(", ")}</span>
                    <input type="checkbox" checked={userForm.permissionBundles.includes(bundle.id)} onChange={() => setUserForm((current) => ({ ...current, permissionBundles: toggleBundle(current.permissionBundles, bundle.id) }))} />
                  </label>
                ))}
              </div>
              <div className="react-actions react-wrap">
                <button type="button" className="react-primary-button" onClick={saveUser} disabled={!userForm.username.trim() || (!selectedUser && !userForm.password.trim())}>Save user</button>
                <button type="button" className="react-link-button" onClick={rotatePassword} disabled={!selectedUser || !userForm.password.trim()}>Rotate password</button>
                <button type="button" className="react-link-button" onClick={() => setUserForm(emptyUserForm())}>New user</button>
                {selectedUser ? <button type="button" className="react-link-button" onClick={() => void deleteUser(selectedUser.username)}>Delete user</button> : null}
              </div>
            </div>
          </WorkspaceSection>

          <WorkspaceSection title="Permission inventory" subtitle="Current reusable bundles for the operator plane." icon="docs">
            <InfoList items={permissionCategories.map((item) => ({ label: item.title, value: item.permissions.length }))} />
            <div className="react-list react-list-compact" style={{ marginTop: 14 }}>
              {permissionBundles.map((bundle: AuthPermissionBundleRecord) => (
                <div key={bundle.id} className="react-list-item">
                  <strong>{bundle.title}</strong>
                  <span>{bundle.permissions.join(", ")}</span>
                </div>
              ))}
            </div>
          </WorkspaceSection>
        </div>

        <div className="react-grid react-grid-3">
          <WorkspaceSection title="Service accounts" subtitle="Scoped machine principals with rotation visibility." icon="control" tone="emphasis">
            <div className="react-list">
              {accounts.map((item: ServiceAccountSummary) => (
                <button key={item.id} type="button" className={`react-card react-card-button ${selectedServiceAccountId === item.id ? "active" : ""}`} onClick={() => setSelectedServiceAccountId(String(item.id || ""))}>
                  <div className="react-card-button-header"><div><strong>{item.name}</strong><div className="react-card-button-copy">{item.description || item.id}</div></div><StatusBadge value={item.enabled ? "active" : "disabled"} /></div>
                  <div className="react-card-button-grid"><span>Bundles</span><strong>{(item.permission_bundles || []).length}</strong><span>Tokens</span><strong>{item.active_tokens || 0}</strong><span>Rotated</span><strong>{item.last_rotation_ts ? formatTimestamp(item.last_rotation_ts, "compact") : "never"}</strong></div>
                </button>
              ))}
            </div>
          </WorkspaceSection>

          <WorkspaceSection title="Service account editor" subtitle="Machine identity editor with scoped bundles and lifecycle control." icon="connectors">
            <div className="react-form-grid">
              <input className="react-input" value={serviceAccountForm.name} onChange={(event) => setServiceAccountForm((current) => ({ ...current, name: event.target.value }))} placeholder="Service account name" />
              <input className="react-input" value={serviceAccountForm.description} onChange={(event) => setServiceAccountForm((current) => ({ ...current, description: event.target.value }))} placeholder="Description" />
              <label className="react-toggle"><input type="checkbox" checked={serviceAccountForm.enabled} onChange={(event) => setServiceAccountForm((current) => ({ ...current, enabled: event.target.checked }))} /><span>Enabled</span></label>
              <div className="react-list react-list-compact">
                {permissionBundles.map((bundle: AuthPermissionBundleRecord) => (
                  <label key={bundle.id} className="react-list-item">
                    <strong>{bundle.title}</strong>
                    <span>{bundle.permissions.join(", ")}</span>
                    <input type="checkbox" checked={serviceAccountForm.permissionBundles.includes(bundle.id)} onChange={() => setServiceAccountForm((current) => ({ ...current, permissionBundles: toggleBundle(current.permissionBundles, bundle.id) }))} />
                  </label>
                ))}
              </div>
              <div className="react-actions react-wrap">
                <button type="button" className="react-primary-button" onClick={saveServiceAccount} disabled={!serviceAccountForm.name.trim()}>Save service account</button>
                <button type="button" className="react-link-button" onClick={() => setServiceAccountForm(emptyServiceAccountForm())}>New service account</button>
                {selectedServiceAccount ? <button type="button" className="react-link-button" onClick={() => void deleteServiceAccount(String(selectedServiceAccount.id || ""))}>Delete service account</button> : null}
              </div>
            </div>
          </WorkspaceSection>

          <WorkspaceSection title="Tokens and rotation" subtitle="Issue, rotate and revoke service-account tokens with overlap control." icon="events">
            <div className="react-form-grid">
              <input className="react-input" value={tokenTitle} onChange={(event) => setTokenTitle(event.target.value)} placeholder="Token title" />
              <input className="react-input" value={tokenDays} onChange={(event) => setTokenDays(event.target.value)} placeholder="Expires in days" />
              <input className="react-input" value={rotationOverlapMinutes} onChange={(event) => setRotationOverlapMinutes(event.target.value)} placeholder="Overlap minutes" />
              <div className="react-actions react-wrap">
                <button type="button" className="react-primary-button" onClick={issueToken} disabled={!selectedServiceAccount}>Issue token</button>
                <button type="button" className="react-link-button" onClick={rotateToken} disabled={!selectedServiceAccount}>Rotate token</button>
              </div>
              {issuedToken ? <div className="react-list-item"><strong>Shown once</strong><span style={{ wordBreak: "break-all" }}>{issuedToken}</span></div> : null}
              <div className="react-list react-list-compact">
                {tokens.map((item) => (
                  <div key={item.id} className="react-list-item">
                    <strong>{item.title}</strong>
                    <span>{item.prefix}</span>
                    <span>{item.status}</span>
                    <span>{item.expires_ts ? formatTimestamp(item.expires_ts, "compact") : "never"}</span>
                    {item.status !== "revoked" ? <button type="button" className="react-link-button" onClick={() => void revokeToken(String(item.id || ""))}>Revoke</button> : null}
                  </div>
                ))}
              </div>
            </div>
          </WorkspaceSection>
        </div>
      </div>
    </AsyncGate>
  );
}
