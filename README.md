# STIG Audit Pro

STIG Audit Pro is a Windows-focused, read-only Cisco IOS-XE STIG audit desktop application for an internal team pilot. It preserves the existing sample and live SSH workflows while adding strict check/profile validation, safer evidence, controlled STIG updates, and background multi-device scanning.

## Implemented

- CustomTkinter GUI for targets, checks, guided profiles, results, STIG sources, and TXT/CSV reports
- Sample scans and read-only Netmiko SSH collection with safe-command validation
- Strict Pydantic 2 check-pack schemas, regex/profile/command validation, and inheritance-cycle detection
- IOS-XE parsing for configuration, interfaces, trunks, ACLs, DHCP snooping, ARP inspection, and facts
- Explicit empty-scope handling, insufficient-evidence errors, object counts, and scoped/expiring exceptions
- Semantic VLAN range and trunk `add`/`remove`/`except`/`all` evaluation
- Official, organizational, custom, and example control origins with separate official compliance totals
- UUID ScanRun manifests and isolated atomic, hashed, optionally redacted evidence bundles
- Guided create/clone/rename/delete profile editor with inherited/local values, VLAN notation, topology lists, safe save, and backups
- Versioned STIG source cache, rule diffs, review-required/retired states, and explicit activation records
- Bounded background scan workers with progress, cancellation, timeout, retry, and categorized failures

## Safety boundary

The command planner accepts only `show ...` and `terminal length ...`. There are no configuration commands or remediation features. Credentials are session-only and never written to manifests or evidence. Imported STIG releases never overwrite or regenerate active check logic.

## Install and run

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe -m pytest
.\.venv\Scripts\python.exe app.py
```

See [Windows installation](docs/WINDOWS_INSTALL.md), [architecture](docs/ARCHITECTURE.md), [check authoring](docs/CHECK_AUTHORING.md), [profile management](docs/PROFILE_MANAGEMENT.md), [STIG updates](docs/STIG_UPDATE_WORKFLOW.md), and [evidence/security](docs/EVIDENCE_AND_SECURITY.md).

## Current limits

CKL generation, Excel/JSON reports, CLI/headless operation, signed installers, scheduling, trending, signed packs, and multi-vendor plugins are not implemented. They are intentionally tracked in [the product roadmap](docs/PRODUCT_ROADMAP.md).

## Compatibility notes

Unsafe legacy YAML now fails fast: unknown keys, invalid regex, undeclared commands, automated manual checks, unresolved profile variables, and ambiguous whole-control exceptions are rejected. Automated object checks no longer pass when zero objects match. The example ACL control moved to `data/checks/examples_custom.yaml` and is excluded from official totals.
