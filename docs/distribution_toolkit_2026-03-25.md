# Distribution Toolkit

## Scope

This toolkit is the customer-facing deployment/export layer for the SIEM platform.

Artifacts:

- clean project export
- local docs export
- operator binary
- topology manifest
- environment templates
- bootstrap helpers
- upgrade plan

## Entry Points

- `python deploy/distribution_toolkit.py --target-root <path> --build-binary`
- `python tools/siem_operator_cli.py distribution export --target-root <path> --build-binary`
- `python tools/siem_operator_cli.py distribution topology`
- `python tools/siem_operator_cli.py distribution upgrade-plan --target-version <version>`

## Output Layout

- `project/`
- `siem_docs/`
- `bin/`
- `distribution/topology.json`
- `distribution/upgrade-plan.json`
- `distribution/env-templates/*.sample`
- `distribution/bootstrap/bootstrap-linux.sh`

## Packaging Rules

- secrets are never embedded in exported templates
- cert paths are documented, not copied
- topology truth is emitted from current repo/runtime assumptions
- upgrade ordering preserves `VM5 -> VM1 -> VM2/VM5 -> VM3 -> VM4 -> post-checks`

## Next Distribution Steps

- add remote bootstrap execution wrappers for Linux targets
- add versioned migration manifests per release
- add customer installer preset generation for common topologies
