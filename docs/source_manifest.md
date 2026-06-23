# Source Manifest

This repository is the clean production source for the SIEM system.

Included:
- `services/web/` backend/API/control-plane runtime modules, routes and templates;
- `services/` ingest, normalizer, filter, writer, stream-correlation and transport workers;
- `correlation_rule_packs/`, SQL seeds and rule publishing scripts;
- `deploy/`, `ops/`, `tools/`, `tests/`;
- `frontend-react/` source, tests and package manifests;
- Windows event agent source.

Excluded:
- local `.env` and credentials;
- screenshots, zips, generated diploma packages and benchmark artifacts;
- logs, caches, build outputs and runtime state;
- local backups and temporary deployment staging folders.

Before push:
- run Python tests for changed subsystems;
- run frontend tests/build when React files changed;
- run secret/artifact scan;
- push only from this clean tree, not from the old development workspace.
