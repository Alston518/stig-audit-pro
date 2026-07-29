# STIG Audit Pro Enterprise Roadmap

## Near-Term Polish

- Profile variables editor: edit VLANs, strings, approved servers, banners, and site values without raw YAML.
- Check string editor: expose `strings`, `required_strings`, and `forbidden_strings` as simple list fields.
- Library selector: run L2 only, NDM only, or combined L2+NDM into one report.
- Scan presets: save target scope, profile, command timeout, and report options as reusable jobs.
- Evidence viewer: show command output snippets tied to each finding.

## Reporting

- CKL export with L2-only, NDM-only, and combined output modes.
- Excel workbook report with summary, findings, per-device sheets, and filterable evidence.
- PDF executive report with compliance score, top failing controls, and affected device counts.
- Evidence archive per scan so reports can be reproduced later.

## Operations

- Concurrent multi-device scanning with progress, cancel, retry, and per-device status.
- Encrypted credential storage or integration with an enterprise vault.
- Scheduled scans with Windows Task Scheduler integration.
- Scan history database with trend charts and previous-run comparison.
- Offline mode for importing command output files from restricted environments.

## Governance

- Signed check-pack releases with versioned YAML libraries.
- Approval workflow for check changes and profile changes.
- Audit log for who changed checks, profiles, targets, and reports.
- Role-based access if the app grows into a multi-user service.
- CI tests that validate every check YAML file and sample scan before release.

## Integrations

- Asset inventory import from CSV, NetBox, ServiceNow, or IPAM.
- Git-backed check/profile repository sync.
- STIG update manager that compares imported STIG versions with local check coverage.
- Optional Tenable/Nessus export mapping for teams that already track findings there.
