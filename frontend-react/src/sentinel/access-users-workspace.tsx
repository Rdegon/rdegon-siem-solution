import { useState, type ReactNode } from "react";
import { api } from "./runtime/api";
import type { KeycloakRoleRecord, PrincipalRecord } from "./runtime/types";
import { formatTime, text, useQuery } from "./runtime/query";
import { Badge, Button, EmptyState, ErrorState, IconButton, LoadingState, Modal, SearchField, StatusCell } from "./ui";


type Notify = (message: string, tone?: string) => void;
type ManagedUser = {
  id?: string;
  username: string;
  email?: string;
  first_name?: string;
  last_name?: string;
  enabled?: boolean;
  email_verified?: boolean;
  roles?: KeycloakRoleRecord[];
  role?: string;
  created_ts?: string | number;
  management_backend?: string;
  siem_role?: string;
  siem_access_enabled?: boolean;
};
type WorkspaceData = {
  backend: "keycloak" | "local_fallback";
  principal: PrincipalRecord;
  users: ManagedUser[];
  roles: KeycloakRoleRecord[];
  realm: string;
  issue: string;
};


function Field({ label, children, wide = false }: { label: string; children: ReactNode; wide?: boolean }) {
  return <label className={wide ? "wide" : ""}><span>{label}</span>{children}</label>;
}


function userId(user: ManagedUser) {
  return text(user.id ?? user.username, "");
}


function errorMessage(error: unknown) {
  return error instanceof Error ? error.message : String(error);
}


export function AccessUsersWorkspace({ notify }: { notify: Notify }) {
  const [search, setSearch] = useState("");
  const [creating, setCreating] = useState(false);
  const [selected, setSelected] = useState<ManagedUser | null>(null);
  const [passwordUser, setPasswordUser] = useState<ManagedUser | null>(null);
  const [busy, setBusy] = useState(false);
  const state = useQuery<WorkspaceData>("access-managed-users", async () => {
    const [me, status] = await Promise.all([api.authMe(), api.keycloakStatus()]);
    if (status.admin_ready) {
      const [users, roles] = await Promise.all([api.keycloakUsers({ limit: 500 }), api.keycloakRoles()]);
      return {
        backend: "keycloak",
        principal: me.principal,
        users: users.items,
        roles: roles.items,
        realm: text(status.realm, "siem"),
        issue: "",
      };
    }
    if (!me.principal.break_glass) {
      throw new Error(`Keycloak Admin API недоступен. Локальный CRUD разрешен только в активной break-glass сессии. ${text(status.issues, "")}`.trim());
    }
    const users = await api.authUsers({ include_disabled: true });
    return {
      backend: "local_fallback",
      principal: me.principal,
      users: users.items,
      roles: [],
      realm: "",
      issue: text(status.issues, "Keycloak Admin API недоступен"),
    };
  }, 60_000);

  const filtered = (state.data?.users ?? []).filter((user) => {
    const needle = search.trim().toLowerCase();
    return !needle || `${user.username} ${user.email ?? ""} ${user.siem_role ?? user.role ?? ""}`.toLowerCase().includes(needle);
  });

  async function openUser(user: ManagedUser) {
    if (state.data?.backend !== "keycloak") {
      setSelected(user);
      return;
    }
    setBusy(true);
    try {
      const detail = await api.keycloakUserDetail(userId(user));
      if (!detail.item) throw new Error("Keycloak user not found");
      setSelected(detail.item);
    } catch (error) {
      notify(errorMessage(error), "critical");
    } finally {
      setBusy(false);
    }
  }

  async function createUser(form: HTMLFormElement) {
    if (!state.data) return;
    const values = new FormData(form);
    setBusy(true);
    try {
      if (state.data.backend === "keycloak") {
        await api.createKeycloakUser({
          username: text(values.get("username"), ""),
          email: text(values.get("email"), ""),
          first_name: text(values.get("first_name"), ""),
          last_name: text(values.get("last_name"), ""),
          password: text(values.get("password"), ""),
          temporary_password: values.get("temporary_password") === "on",
          enabled: values.get("enabled") === "on",
          email_verified: values.get("email_verified") === "on",
          roles: values.getAll("realm_roles").map(String),
          siem_role: text(values.get("siem_role"), ""),
        });
      } else {
        await api.saveLocalUser({
          username: text(values.get("username"), ""),
          password: text(values.get("password"), ""),
          role: text(values.get("siem_role"), "viewer"),
          enabled: values.get("enabled") === "on",
        });
      }
      notify("Пользователь создан", "healthy");
      setCreating(false);
      state.reload();
    } catch (error) {
      notify(errorMessage(error), "critical");
    } finally {
      setBusy(false);
    }
  }

  async function updateUser(form: HTMLFormElement) {
    if (!state.data || !selected) return;
    const values = new FormData(form);
    setBusy(true);
    try {
      let updated: ManagedUser;
      if (state.data.backend === "keycloak") {
        updated = await api.updateKeycloakUser(userId(selected), {
          email: text(values.get("email"), ""),
          first_name: text(values.get("first_name"), ""),
          last_name: text(values.get("last_name"), ""),
          enabled: values.get("enabled") === "on",
          email_verified: values.get("email_verified") === "on",
          roles: values.getAll("realm_roles").map(String),
          siem_role: text(values.get("siem_role"), ""),
        });
      } else {
        updated = await api.saveLocalUser({
          username: selected.username,
          role: text(values.get("siem_role"), "viewer"),
          enabled: values.get("enabled") === "on",
        });
      }
      setSelected({ ...selected, ...updated });
      notify("Пользователь обновлен", "healthy");
      state.reload();
    } catch (error) {
      notify(errorMessage(error), "critical");
    } finally {
      setBusy(false);
    }
  }

  async function resetPassword(form: HTMLFormElement) {
    if (!state.data || !passwordUser) return;
    const values = new FormData(form);
    const password = text(values.get("password"), "");
    setBusy(true);
    try {
      if (state.data.backend === "keycloak") {
        await api.setKeycloakUserPassword(userId(passwordUser), { password, temporary: values.get("temporary") === "on" });
      } else {
        await api.setLocalUserPassword(passwordUser.username, { password });
      }
      notify("Пароль сброшен", "healthy");
      setPasswordUser(null);
    } catch (error) {
      notify(errorMessage(error), "critical");
    } finally {
      setBusy(false);
    }
  }

  async function deleteUser() {
    if (!state.data || !selected || !window.confirm(`Удалить пользователя ${selected.username}?`)) return;
    setBusy(true);
    try {
      if (state.data.backend === "keycloak") await api.deleteKeycloakUser(userId(selected));
      else await api.deleteLocalUser(selected.username);
      notify("Пользователь удален", "healthy");
      setSelected(null);
      state.reload();
    } catch (error) {
      notify(errorMessage(error), "critical");
    } finally {
      setBusy(false);
    }
  }

  if (state.loading && !state.data) return <LoadingState label="Загрузка пользователей..." />;
  if (state.error) return <ErrorState error={state.error} retry={state.reload} />;
  if (!state.data) return <EmptyState detail="Identity backend не вернул данные" />;
  const data = state.data;
  const enabledCount = data.users.filter((user) => user.enabled !== false).length;
  const adminCount = data.users.filter((user) => (user.siem_role ?? user.role) === "admin" && user.enabled !== false).length;

  return <div className="view-stack">
    <section className="metric-grid">
      <div className="metric"><span>Backend</span><strong>{data.backend === "keycloak" ? `Keycloak · ${data.realm}` : "Break-glass fallback"}</strong><small>{data.backend === "keycloak" ? "Реальный realm inventory" : data.issue}</small></div>
      <div className="metric"><span>Пользователи</span><strong>{data.users.length}</strong><small>{enabledCount} активны</small></div>
      <div className="metric"><span>Администраторы</span><strong>{adminCount}</strong><small>Активные учетные записи</small></div>
    </section>
    <section className="panel panel-flush">
      <header className="panel-header"><div className="panel-title"><h2>Пользователи</h2><span>{data.backend === "keycloak" ? "Keycloak identities и роли Sentinel" : "Локальные учетные записи аварийного доступа"}</span></div><div className="panel-actions"><SearchField onChange={setSearch} placeholder="Поиск пользователей" value={search} /><Button icon="plus" onClick={() => setCreating(true)} tone="primary">Создать пользователя</Button><IconButton icon="refresh" label="Обновить" onClick={state.reload} /></div></header>
      {!filtered.length ? <EmptyState detail="Пользователи не найдены" /> : <div className="native-grid"><table><thead><tr><th>Статус</th><th>Username</th><th>Email</th><th>Роль Sentinel</th><th>Backend</th><th>Создан</th></tr></thead><tbody>{filtered.map((user) => <tr className="sentinel-clickable-row" key={userId(user)} onClick={() => void openUser(user)} tabIndex={0}><td><StatusCell value={user.enabled === false ? "Выключен" : "Активен"} /></td><td><strong>{user.username}</strong>{user.username === data.principal.username ? <Badge tone="info">Текущий</Badge> : null}</td><td>{text(user.email, "—")}</td><td>{text(user.siem_role ?? user.role, "Не назначена")}</td><td>{data.backend === "keycloak" ? "Keycloak" : "Local break-glass"}</td><td>{formatTime(user.created_ts)}</td></tr>)}</tbody></table></div>}
    </section>

    <Modal footer={<><Button disabled={busy} onClick={() => setCreating(false)}>Отмена</Button><Button disabled={busy} form="managed-user-create" tone="primary" type="submit">Создать</Button></>} onClose={() => setCreating(false)} open={creating} title={data.backend === "keycloak" ? "Новый пользователь Keycloak" : "Новый break-glass пользователь"}>
      <form className="kuma-form-grid" id="managed-user-create" onSubmit={(event) => { event.preventDefault(); void createUser(event.currentTarget); }}>
        <Field label="Username"><input name="username" required /></Field>
        {data.backend === "keycloak" ? <><Field label="Email"><input name="email" type="email" /></Field><Field label="Имя"><input name="first_name" /></Field><Field label="Фамилия"><input name="last_name" /></Field></> : null}
        <Field label="Начальный пароль"><input autoComplete="new-password" name="password" required type="password" /></Field>
        <Field label="Роль в Sentinel"><select defaultValue="viewer" name="siem_role" required><option value="viewer">Viewer</option><option value="analyst">Analyst</option><option value="admin">Admin</option></select></Field>
        <Field label="Учетная запись активна"><input defaultChecked name="enabled" type="checkbox" /></Field>
        {data.backend === "keycloak" ? <><Field label="Временный пароль"><input defaultChecked name="temporary_password" type="checkbox" /></Field><Field label="Email подтвержден"><input name="email_verified" type="checkbox" /></Field><fieldset className="wide"><legend>Realm roles</legend>{data.roles.map((role) => <label key={role.name}><input name="realm_roles" type="checkbox" value={role.name} /> {role.name}</label>)}</fieldset></> : null}
      </form>
    </Modal>

    <Modal footer={selected ? <><Button disabled={busy} onClick={() => void deleteUser()} tone="danger">Удалить</Button><Button disabled={busy} onClick={() => setPasswordUser(selected)}>Сбросить пароль</Button><Button disabled={busy} onClick={() => setSelected(null)}>Закрыть</Button><Button disabled={busy} form="managed-user-edit" tone="primary" type="submit">Сохранить</Button></> : null} onClose={() => setSelected(null)} open={Boolean(selected)} title={selected?.username ?? "Пользователь"}>
      {selected ? <form className="kuma-form-grid" id="managed-user-edit" key={`${userId(selected)}:${selected.enabled}`} onSubmit={(event) => { event.preventDefault(); void updateUser(event.currentTarget); }}>
        <Field label="Username"><input disabled value={selected.username} /></Field>
        {data.backend === "keycloak" ? <><Field label="Email"><input defaultValue={selected.email ?? ""} name="email" type="email" /></Field><Field label="Имя"><input defaultValue={selected.first_name ?? ""} name="first_name" /></Field><Field label="Фамилия"><input defaultValue={selected.last_name ?? ""} name="last_name" /></Field></> : null}
        <Field label="Роль в Sentinel"><select defaultValue={selected.siem_role ?? selected.role ?? "viewer"} name="siem_role" required><option value="viewer">Viewer</option><option value="analyst">Analyst</option><option value="admin">Admin</option></select></Field>
        <Field label="Учетная запись активна"><input defaultChecked={selected.enabled !== false} name="enabled" type="checkbox" /></Field>
        {data.backend === "keycloak" ? <><Field label="Email подтвержден"><input defaultChecked={Boolean(selected.email_verified)} name="email_verified" type="checkbox" /></Field><fieldset className="wide"><legend>Realm roles</legend>{data.roles.map((role) => <label key={role.name}><input defaultChecked={(selected.roles ?? []).some((item) => item.name === role.name)} name="realm_roles" type="checkbox" value={role.name} /> {role.name}</label>)}</fieldset></> : null}
      </form> : null}
    </Modal>

    <Modal footer={<><Button disabled={busy} onClick={() => setPasswordUser(null)}>Отмена</Button><Button disabled={busy} form="managed-user-password" tone="primary" type="submit">Применить</Button></>} onClose={() => setPasswordUser(null)} open={Boolean(passwordUser)} title="Сброс пароля">
      <form className="kuma-form-grid" id="managed-user-password" onSubmit={(event) => { event.preventDefault(); void resetPassword(event.currentTarget); }}><Field label="Новый пароль" wide><input autoComplete="new-password" name="password" required type="password" /></Field>{data.backend === "keycloak" ? <Field label="Потребовать смену при входе"><input defaultChecked name="temporary" type="checkbox" /></Field> : null}</form>
    </Modal>
  </div>;
}
