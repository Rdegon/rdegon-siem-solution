# Rules Audit Runbook

1. Build the full local inventory:

```powershell
python tools/full_rule_audit.py --days 30 --output-json artifacts/rule-audit/full_rule_audit.json --output-md artifacts/rule-audit/full_rule_audit.md
```

2. Build inventory with live ClickHouse alert metrics:

```powershell
python tools/full_rule_audit.py --live --days 30 --output-json artifacts/rule-audit/live_full_rule_audit.json --output-md artifacts/rule-audit/live_full_rule_audit.md
```

3. Publish calibrated runtime rules and write before/after reports:

```powershell
python deploy/publish_full_rule_calibration.py --days 30 --output-dir artifacts/rule-audit
```

4. Validate after publish:
- known synthetic attacks still create the expected demo alerts;
- known benchmark and maintenance events do not create new open incidents;
- every rule in the audit has one decision;
- open historical noise is marked `false_positive` or `suppressed`.
