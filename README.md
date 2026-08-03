# STIG Audit Pro

Core implementation for Milestones 1-4 of a Windows-focused Cisco IOS-XE STIG audit tool.

Implemented now:

- Project skeleton for future GUI, STIG, report, and storage layers.
- Pydantic models for check definitions, site profiles, exceptions, and results.
- YAML loading, inheritance merge, and validation.
- Single-device Netmiko runner and command output cache.
- IOS-XE parsers for running config, interfaces, trunks, ACLs, DHCP snooping, ARP inspection, and basic facts.
- Generic check engine driven by YAML checks.
- Sample IOS-XE command output and unit tests for the first automated policies.
- GUI workflow for targets, checks, profiles, results, STIG metadata, and reports.
- Overview dashboard for library status, scan actions, and last-run findings.
- GUI validation and save actions for check YAML and profile YAML.
- TXT summary and CSV detail report export from scan results.
- L2 CKL template population with one completed checklist per target.
- L2 checklist workflow with optional combined text report and selectable destination.
- Starter manual-review check generation from imported STIG ZIP/XML metadata.
- Cyber.mil lookup for Cisco IOS-XE switch STIG bundles, with direct quarterly package fallback.
- Offline Ed25519 licensing with centralized feature/device enforcement, a
  customer License tab, and a publisher-only administration CLI.

Not implemented yet:

- NDM CKL workflow.
- Excel workbook reports.
- Multi-device concurrent scan orchestration.

## Run Tests

```powershell
python -m pytest
```

## Offline Licensing

Without an installed license, STIG Audit Pro runs in Free mode with a
one-unique-device scan limit. Signed licenses are verified locally; the
customer application contains public keys only and never requires a network
connection or database.

Publisher key generation, license issuance, per-platform customer locations,
public-key registration/rotation, build verification, and the manual acceptance
test are documented in
[`docs/OFFLINE_LICENSING.md`](docs/OFFLINE_LICENSING.md).

The publisher CLI is intentionally outside the customer package:

```powershell
python -m tools.license_admin --help
```

## Add Or Edit Checks

Checks live in `data/checks/*.yaml`. Each check declares metadata, safe show commands, a `check_type`, YAML conditions, result status mapping, and evidence/comment templates.

The engine reads those files at runtime, so changing check logic normally does not require editing Python code.

Most string checks use editable `strings`, `required_strings`, or `forbidden_strings` lists. A blank list leaves the check `Not_Reviewed` until site-specific strings are added.

## Site Profiles

Profiles live in `data/profiles/*.yaml`. A site profile can inherit from a base profile:

```yaml
profile_name: example_site
inherits: base_iosxe_access
unused_vlan: 999
```

The loader reads the base profile first, then overlays the site profile.

## Launch GUI

```powershell
python app.py
```

The GUI supports target management, sample scans, live SSH scans, check/profile YAML editing, STIG metadata viewing, results review, TXT/CSV report export, and an L2 CKL test workflow.

## Target Workbench

The Targets tab keeps a working list of devices in the GUI. You can add one IP, paste many IPs, import CSV/TXT targets, check or uncheck rows, run selected/checked/all rows, and save or load reusable groups from `data/device_groups/*.yaml`.

The application starts with `base_iosxe_access` as the active scan profile. A target set to `Use scan default` uses that active profile without needing a device group. Use groups when you want to save an inventory for later or automatically select a different site profile when that inventory is loaded.

Saved device groups can also carry their default site profile:

```yaml
group_name: building_a_access
profile_name: example_site
targets:
  - ip: 10.50.10.25
    profile_override: null
    checked: true
```

Loading that group switches the scan profile to `example_site`; individual targets can still use `profile_override` when needed.

Example: different buildings can share the same checks while using different profile values:

```yaml
# data/profiles/building_1.yaml
profile_name: building_1
inherits: base_iosxe_access
dhcp_snooping:
  vlans: [110, 120, 130]
arp_inspection:
  vlans: [110, 120, 130]
```

```yaml
# data/device_groups/building_1_access.yaml
group_name: building_1_access
profile_name: building_1
targets:
  - ip: 10.50.11.25
    profile_override: null
    checked: true
```

Building 2 can use the same check library with a different profile, such as VLANs `210, 220, 230`.

## Live SSH Scans

The Targets tab has a scan mode selector:

- `Sample outputs` uses bundled sample command output for demos and tests.
- `Live SSH` uses session-only username/password/enable secret fields and the safe Netmiko runner.

Live SSH runs only planned safe commands from the selected YAML checks. Credentials are not saved by this milestone.

## Reports

After running a sample or live SSH scan, open the Reports tab. The tab shows compliance, Open, NotAFinding, NotApplicable, Error, Skipped, and NotReviewed counts. Use:

- `Save TXT Summary` for a readable scan summary with device totals, open findings, failed objects, errors, and skipped devices.
- `Save CSV Details` for row-level results that can be opened in Excel or filtered by IP, status, STIG family, severity, or Vuln ID.

The Reports tab exports standalone TXT and CSV files. The STIG / CKL tab contains the L2 checklist workflow.

## L2 Checklist Test Workflow

1. On the Targets tab, add one or more IP addresses, check the devices to audit, select `Live SSH`, and enter session credentials.
2. Select the site profile whose VLAN, RADIUS, Root Guard, and other site values match the targets.
3. On the STIG / CKL tab, browse to an IOS-XE L2 `.ckl` template and choose a destination folder.
4. Select `Fill CKL`, `Create text report`, or both, then choose `Run Checked Targets — L2`.
5. Review the scan in the Results tab. The destination receives one completed CKL per successfully scanned target and, when selected, one combined TXT report.

The source CKL is not modified. The completed checklist uses the switch hostname and the IPv4 address configured under the profile-defined management SVI (`management_vlan`, default `300`) for CKL asset fields. If that SVI address is unavailable, the scan target IP is used.

## STIG Sources

The STIG / CKL tab can import STIG ZIP/XML files and cache parsed XCCDF metadata under `data/stigs/cache/`. It includes:

- `Find Selected`, which downloads the latest reachable Cyber.mil package for the selected family.
- `Find L2 + NDM`, which downloads and imports both IOS-XE switch L2 and NDM metadata.
- `Download URL`, which downloads and imports a direct STIG ZIP/XML link copied from the Cyber Exchange page.
- `Import ZIP/XML`, which imports a package that was downloaded manually.

https://www.cyber.mil/stigs/downloads/

The downloader first tries Cyber.mil's current catalog path, then falls back to reachable quarterly packages under `https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/`. The Cisco IOS-XE switch package is a combined bundle; selecting `IOSXE_L2` imports the L2 XCCDF and selecting `IOSXE_NDM` imports the NDM XCCDF.

## Starter Checks From STIGs

After importing the current L2 and/or NDM STIG ZIP/XML files, use `Build Starter Checks` on the STIG / CKL tab. This creates `data/checks/generated_stig_manual.yaml` with one `manual_review` check for each imported STIG rule that does not already have automation.

Starter checks return `Not_Reviewed`, so a full scan can show every imported STIG rule in Results and Reports while we replace manual-review stubs with real automated logic in batches.

## Customer Tailoring

Use profiles for site/customer values such as unused VLAN, DHCP snooping VLANs, ARP inspection VLANs, and additional pruned VLANs. Edit check YAML only when the actual requirement logic differs from the default automated check. The Checks and Profiles tabs can save YAML edits from the GUI.
