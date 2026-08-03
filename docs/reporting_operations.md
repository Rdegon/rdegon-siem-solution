# Reporting operations

Rdegon Sentinel reporting uses the existing control-plane store for both report
templates and report runs. The Web API and `siem-report-scheduler.service` call
the same executor, so a scheduled report does not have a second configuration
store or a separate implementation.

## Runtime contract

- Templates contain a bounded period (`12h`, `24h`, `7d`, or `30d`), the
  production tenant scope (`main`), sections, formats, retention, and schedule.
- A manual API request persists a `queued` run before returning `202`.
- The executor records `running` progress after every section and finishes as
  `completed`, `completed_with_warnings`, or `failed`.
- Section loaders query the existing SIEM dashboard, incident, source, asset,
  vulnerability, and platform services. Fixtures and browser-generated data are
  not part of the production path.
- JSON and CSV artifacts are always available after a terminal state. PDF uses
  the pinned ReportLab web dependency and is advertised only when importable.

## Scheduling and idempotency

The systemd timer invokes `python -m services.web.maintenance.report_scheduler`
every five minutes and is persistent across reboot. Each schedule occurrence
uses a deterministic key derived from the template ID and UTC schedule slot.
The persisted run is reused after a process restart, so a slot cannot create a
second job. A stale interrupted run is resumed under the same run ID.

Schedule state returned with every template includes `next_run_ts`,
`last_run_ts`, and `last_run_status`. Enable/disable and schedule edits are
audited as template changes. Queue and completion are separate audit events.

## API and RBAC

- Read: `resources:view`
- Template writes, schedule changes, and manual runs: `resources:write`
- Tenant selection is validated through `X-SIEM-Tenant-Scope`; only scopes
  exposed by the current production tenant model are accepted.
- Manual runs require an 8-160 character idempotency key.

The relevant endpoints are under `/api/reporting`: capabilities, templates,
runs, and run artifacts. Execution errors remain attached to the run and are
shown as structured rows in the UI instead of raw JSON.
