# Contributing

## Branching

Use focused branches:

- `platform/*` for infrastructure and runtime platform changes
- `rules/*` for detection and false-positive calibration
- `repo/*` for repository hygiene, docs, and packaging work
- `refactor/*` for behavior-preserving module decomposition

## Before Commit

Run the checks that match the change:

```powershell
python tools/repo_hygiene_check.py
python -m pytest tests/test_rule_noise_tuning.py
```

For frontend changes:

```powershell
cd frontend-react
npm test
```

## Commit Rules

- Do not commit local `.env` files, credentials, generated archives, screenshots,
  logs, benchmark output, database dumps, or VM/runtime state.
- Keep deploy scripts deterministic and idempotent where possible.
- Update `docs/INDEX.md` when adding or superseding a runbook.
- Keep dated operation records factual: what changed, where, verification, and
  rollback notes.

