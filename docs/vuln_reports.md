# Vulnerability reports

`vuln-siem` uses an `nmap`-based collector to scan configured targets, store XML reports locally, and push summary/finding events into the SIEM through `https://<ingest>:9445/ingest/vulnscanner/json`.

Files:

- `deploy/vuln/rdegon-vuln-reporter.py`
- `deploy/vuln/rdegon-vuln-scan.service`
- `deploy/vuln/rdegon-vuln-scan.timer`

Runtime paths on the scanner host:

- `/opt/rdegon-siem-vuln/targets.txt`
- `/opt/rdegon-siem-vuln/reports/`

Event model:

- summary events:
  - `event.provider = vuln.nmap`
  - `event.category = vulnerability`
  - `event.type = scan_summary`
  - `event.action = summary`
- finding events:
  - `event.provider = vuln.nmap`
  - `event.category = vulnerability`
  - `event.type = open_port`
  - `event.action = finding`

The SIEM web UI exposes these reports in the `Reports` section and allows pivoting to the original events through `event_code`.
