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

Not implemented yet:

- GUI.
- CKL writer.
- Excel or text reports.
- Multi-device concurrent scan orchestration.

## Run Tests

```powershell
python -m pytest
```

## Add Or Edit Checks

Checks live in `data/checks/*.yaml`. Each check declares metadata, safe show commands, a `check_type`, YAML conditions, result status mapping, and evidence/comment templates.

The engine reads those files at runtime, so changing check logic normally does not require editing Python code.

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

The GUI currently supports the Milestone 5 shell and sample-audit workflow. CKL writing, Excel/TXT reports, and live multi-device orchestration remain later milestones.

## Target Workbench

The Targets tab keeps a working list of devices in the GUI. You can add one IP, paste many IPs, import CSV/TXT targets, check or uncheck rows, run selected/checked/all rows, and save or load reusable groups from `data/device_groups/*.yaml`.

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

## STIG Sources

The STIG / CKL tab can import STIG ZIP/XML files and cache parsed XCCDF metadata under `data/stigs/cache/`. It includes:

- `Find Latest`, which tries to discover matching ZIP/XML downloads from the official DoD Cyber Exchange STIG downloads page.
- `Download URL`, which downloads and imports a direct STIG ZIP/XML link copied from the Cyber Exchange page.
- `Import ZIP/XML`, which imports a package that was downloaded manually.

https://www.cyber.mil/stigs/downloads/

Cyber Exchange may render the download list with JavaScript instead of exposing ZIP links in the first page response. When that happens, use `Download URL` with the direct package link or use `Import ZIP/XML` after downloading the file.

## Customer Tailoring

Use profiles for site/customer values such as unused VLAN, DHCP snooping VLANs, ARP inspection VLANs, and additional pruned VLANs. Edit check YAML only when the actual requirement logic differs from the default automated check.
