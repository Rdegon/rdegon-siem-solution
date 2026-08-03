# User Management In Access

## Runtime ownership

The `Access -> Users` workspace is Keycloak-first. It does not maintain a
frontend-only user list and does not synthesize identities.

| Data | System of record |
| --- | --- |
| Username, email, name, enabled status | Keycloak realm configured by `SIEM_KEYCLOAK_REALM` |
| Password and temporary-password flag | Keycloak credential API |
| Realm roles | Keycloak realm role mappings |
| Sentinel role and section permissions | Sentinel `access_grants`, linked by Keycloak username |
| Local emergency users | Existing Sentinel local-user store, break-glass only |

Creating a Keycloak user with `siem_role` creates both the Keycloak identity
and the explicit Sentinel grant. Listing and detail responses expose
`management_backend=keycloak`, `siem_role`, `siem_access_enabled`,
`siem_grant_id`, and `siem_sections` so the UI shows the real authorization
state.

## Supported operations

- create a Keycloak user, initial password, enabled state and Sentinel role;
- edit email, name, enabled state, realm roles and Sentinel role;
- reset a permanent or temporary Keycloak password;
- delete a Keycloak user and its Sentinel grants;
- manage local emergency users only when Keycloak Admin API is unavailable and
  the operator has an active break-glass session.

The backend rejects unknown Keycloak roles rather than silently ignoring them.
An explicit empty role list removes all realm roles that are currently assigned
to the user.

## Safety invariants

Mutations are rejected with HTTP `409` and
`code=identity_mutation_conflict` when they would:

- delete, disable, or demote the currently authenticated user;
- delete, disable, or demote the last enabled Keycloak realm administrator;
- delete, disable, or demote the last enabled Sentinel administrator;
- delete, disable, or demote the current or last local break-glass
  administrator.

These checks are enforced in the backend. Disabled buttons or confirmation
dialogs in the browser are not security boundaries.

## Local fallback

Local users are an established recovery path, not a substitute identity
backend. The UI enters local fallback only if both conditions are true:

1. Keycloak Admin API reports `admin_ready=false`.
2. `/api/auth/me` reports an active `break_glass` principal.

If Keycloak is unavailable during a normal OIDC session, the workspace returns
an operational error and does not silently switch stores.

## Verification

Run the focused backend and frontend suites:

```powershell
python -m pytest -q tests/test_keycloak_admin_runtime.py tests/test_identity_user_runtime.py tests/test_console_auth_user_routes.py
Set-Location frontend-react
npm test -- --run src/sentinel/__tests__/access-users-workspace.test.tsx
```

Use a disposable non-admin identity for a live create/update/password/delete
smoke. Do not use the production administrator for destructive verification.
