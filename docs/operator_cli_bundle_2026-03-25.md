# Operator CLI And Clean Project Bundle

## Purpose

This document describes the machine-local operator tooling exported with the current production-green baseline.

## Deliverables

- `C:\Users\Rdegon\Projects\siem_xfer_2026-03-25\siem_docs`
  - machine-local documentation export
- `C:\Users\Rdegon\Projects\siem_xfer_2026-03-25\siem_project_bundle`
  - clean tracked project copy
  - duplicated operator bundle
  - exported docs
  - optional operator binary output

## Operator CLI

- source: `tools/siem_operator_cli.py`
- binary build script: `deploy/build_siem_operator_binary.py`
- docs export script: `deploy/export_siem_docs.py`
- clean bundle export script: `deploy/export_clean_project_bundle.py`

## Build

```powershell
python .\deploy\build_siem_operator_binary.py --output-dir C:\Users\Rdegon\Projects\siem_xfer_2026-03-25\siem_project_bundle\bin
```

## Bundle Export

```powershell
python .\deploy\export_clean_project_bundle.py --target-root C:\Users\Rdegon\Projects\siem_xfer_2026-03-25\siem_project_bundle --build-binary
```

## Notes

- the clean bundle copies tracked repository files only
- runtime docs can be published separately into the system content plane
- raw secrets are intentionally excluded from the clean bundle outside the approved operator bundle
