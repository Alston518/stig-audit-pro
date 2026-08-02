# Administrator guide

## Purpose

This guide describes responsibilities and the recommended workflow for authorized personnel operating STIG Audit Pro 0.1.0. The product collects and evaluates evidence. It does not change audited-device configuration and does not make remediation decisions.

## Responsibility model

| Activity | STIG Audit Pro | Administrator / organization |
| --- | --- | --- |
| Select Target Devices | Presents target and device-group controls | Confirms ownership, authorization, scope, and timing |
| Select credentials | Holds entered values for the active process | Provisions and protects an appropriately restricted account |
| Plan collection | Builds commands from licensed, selected checks | Approves the bundled and locally modified command inventory |
| Collect evidence | Runs documented commands and caches returned output | Handles raw output as sensitive device data |
| Evaluate evidence | Applies installed check logic and profile values | Validates logic, profiles, applicability, and accuracy |
| Report results | Produces on-screen, TXT, CSV, and selected CKL artifacts | Reviews, distributes, protects, and retains artifacts |
| Decide remediation | No capability | Determines whether any action is appropriate |
| Make device changes | No capability | Uses separate authorized tools and formal change control |
| Accept risk / certify compliance | No authority | Remains with designated organizational officials |

## Before a live scan

1. Obtain written authorization for the devices, commands, source addresses, time window, and operators. NIST describes pre-established testing constraints and permissions as rules of engagement.
2. Confirm every target is a supported Cisco IOS-XE device and that its address is correct.
3. Confirm a valid signed license enables the required L2, NDM, CKL, multi-device, preset, or advanced-reporting features and permits the intended number of unique devices.
4. Review [Command reference](COMMAND_REFERENCE.md), including every locally installed or edited check pack.
5. Prefer a device account whose command authorization allows only the approved `show` commands and session pagination. Supply an enable secret only when the approved account requires privileged EXEC access.
6. Select and validate the correct site profile. Confirm management VLAN, unused VLAN, DHCP/ARP VLANs, Root Guard upstream neighbors, RADIUS values, topology assumptions, and per-target overrides with the network or security owner.
7. Verify the application version, check files, profile, and source STIG release appropriate for the assessment.
8. Confirm `work/cache/ssh` and the intended report/CKL destination are approved for unredacted device configuration data and protected with suitable access controls, encryption, backup, retention, and monitoring.

## Running a general scan

1. Add targets manually, paste addresses, import a CSV/TXT list, or load an approved device group.
2. Mark the intended targets and verify any profile overrides.
3. Select `Sample outputs` to evaluate local fixtures or `Live SSH` to contact devices.
4. For live SSH, enter the authorized username, password, and optional enable secret. The application does not deliberately save those entered credential fields.
5. Run the selected, checked, or all target scope only after confirming the displayed scope and license limits.
6. Monitor the background worker. Targets are processed sequentially. Cancellation takes effect between device operations; an operation already in progress may finish before the connection closes.
7. Review `Skipped` and `Error` results before interpreting totals. Missing or malformed evidence must not be treated as passing evidence.

## Running an audit and CKL workflow

The STIG/CKL workflow can run L2, NDM, or both families when enabled by the installed license. Before starting:

1. Select the applicable families and all required L2, NDM, and combined CKL templates.
2. Confirm each template contains vulnerability IDs matching its intended family.
3. Choose whether to populate CKLs, create a text report, or both.
4. Select an approved output directory and optional CKL comment behavior.
5. Check the intended targets, select `Live SSH`, and verify the active profile.

The source template is not modified. Completed CKLs are written as new files. Asset values are derived from collected running configuration where possible, with the scan address used as a fallback. Review every completed checklist before submission or distribution.

## Interpreting results

- `NotAFinding` means available evidence satisfied the installed check logic. It does not prove overall security or compliance.
- `Open` means available evidence did not satisfy the installed logic. It is a review trigger, not a remediation instruction.
- `Not_Applicable` means the check established non-applicability for the evaluated scope. Confirm the scope and profile.
- `Not_Reviewed` requires human assessment or additional evidence or organizational context.
- `Error` indicates the application could not make a reliable determination.
- `Skipped` indicates collection did not complete for the device.

For every material result, verify the raw cached evidence, affected objects, active profile, parser behavior, check conditions, STIG family, source requirement, and time of collection. Confirm the device state has not changed since collection.

## Remediation workflow outside the product

STIG Audit Pro never carries out the following steps. They remain entirely within the Administrator's and organization's discretion:

1. Independently reproduce and validate the finding on the device.
2. Confirm the requirement's applicability and current official source language.
3. Analyze mission, availability, interoperability, safety, and security impact.
4. Decide whether to mitigate, accept, avoid, transfer, or otherwise address the risk under organizational policy.
5. Obtain required system-owner, security, change-control, and maintenance approvals.
6. Prepare tested implementation, backup, validation, and rollback plans.
7. Make the change with an authorized configuration-management tool or manual process outside STIG Audit Pro.
8. Validate service health and security controls.
9. Rescan if authorized and retain before/after evidence according to policy.

The presence of an `Open` result does not authorize a change. The absence of an `Open` result does not authorize a system or certify compliance.

## Evidence handling

Live command output is cached below `work/cache/ssh/<device>/`, with one text file per sanitized command name and a `metadata.json` timestamp/command list. The cache is organized per device rather than per scan. A later collection of the same command from the same device can overwrite the earlier cached text.

Version 0.1.0 does not automatically redact cached output, create UUID-isolated run bundles, hash evidence, or enforce retention. `show running-config`, logs, ACLs, SNMP output, version data, and related output may disclose credentials, keys, communities, topology, software exposure, and security controls. Treat the entire cache and all reports/CKLs as sensitive.

Do not place credentials in profiles, check packs, target files, report comments, or CKL comments. Before sharing an artifact, inspect it for IP addresses, hostnames, topology, software versions, access-control entries, authentication material, community strings, keys, and other protected information.

## Licensing data

License verification is offline. The application reads a signed license from the platform-specific application-data path documented in [Offline licensing](OFFLINE_LICENSING.md), or from `STIG_AUDIT_PRO_LICENSE_PATH` when configured. Customer builds contain public verification keys only. Protect issued license files as organizational records and never place publisher private keys in the repository or customer environment.

## Incident and support handling

If a scan produces unexpected device behavior, stop new scans, preserve relevant cached output and reports, record the exact installed check packs and planned command inventory, and notify designated network and security contacts. Investigate account authorization, custom check syntax, device aliases/macros, platform-specific command behavior, and concurrent administrative activity.

For product support, contact [SUPPORT CONTACT]. For security reports, contact [SECURITY CONTACT]. Do not include live credentials or unredacted device output unless an approved secure transfer process specifically requires it.

## External references

- [NIST SP 800-115, Technical Guide to Information Security Testing and Assessment](https://csrc.nist.gov/pubs/sp/800/115/final)
- [NIST Rules of Engagement definition](https://csrc.nist.gov/glossary/term/rules_of_engagement)
- [DoD Cyber Exchange STIG library](https://www.cyber.mil/stigs/downloads/)
