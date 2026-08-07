# Product overview

**Product:** STIG Audit Pro

**Product version:** 0.1.0

**Document status:** Product description for release review

## Official product description

STIG Audit Pro is a Windows-focused desktop application that helps authorized network and security administrators collect, evaluate, review, and report Cisco IOS-XE Security Technical Implementation Guide evidence. It connects to Administrator-selected devices over SSH, optionally enters privileged EXEC mode when an enable secret is supplied, runs a restricted set of read-only operational commands, parses returned text, compares the evidence with YAML check logic and a selected site profile, and produces local findings and audit artifacts.

STIG Audit Pro is deliberately separated from remediation. It does not enter device configuration mode, send configuration commands, save a device configuration, or act on its own findings. The unmodified product and bundled check packs make zero changes to a Target Device's running or startup configuration. Every configuration or operational change considered after a scan is an independent decision and action of authorized organizational personnel.

## What the product does

- Runs sample assessments against bundled fixture output without contacting a device.
- Performs live SSH evidence collection from one or more Administrator-selected Cisco IOS-XE devices. Multiple targets are processed sequentially in a background scan worker.
- Loads L2 and NDM YAML check packs and site profiles at runtime and validates their supported structure.
- Parses running configuration, interface state, switchport negotiation, trunk, CDP neighbor, ACL, DHCP snooping, ARP inspection, SNMP-user, version, and related evidence when required output is available.
- Evaluates automated controls and identifies controls that require manual review.
- Supports site profiles, per-target profile overrides, reusable device groups, and GUI editing of checks and profiles.
- Produces on-screen findings and standalone TXT and CSV reports.
- Populates Administrator-supplied L2, NDM, or combined CKL templates and can create a combined text report.
- Imports and caches STIG ZIP/XML sources and can generate manual-review starter checks for unmapped rules.
- Verifies signed Ed25519 licenses locally and enforces licensed features and device limits without contacting a licensing server.
- Caches collected command output and timestamp metadata on the local workstation.

## What the product does not do

- It does not configure, harden, remediate, patch, reboot, reload, or save configuration on a network device.
- It does not generate or push configuration snippets.
- It does not replace an Administrator, assessor, change-approval process, risk assessment, or authorizing official.
- It does not certify a device, organization, or system as secure, compliant, accredited, or authorized to operate.
- It does not guarantee complete detection or that every automated or manual-review result is correct.
- It does not provide concurrent multi-device command execution, scheduled scans, trend analysis, Excel export, JSON export, or a vendor cloud service in version 0.1.0.
- It does not provide an automatic update service or signed installer in the reviewed repository, although a PyInstaller build specification is present.

## Read-only operational boundary

The GUI constructs a command set from the checks enabled for the selected workflow and license, removes duplicates, adds terminal pagination control, validates each command against the permitted prefixes, and executes collection through Netmiko's single-command method. Across both unmodified bundled check packs, the maximum current collection set contains nine `show` commands. `terminal length 0` is also sent to disable pagination for the active session. If the Administrator supplies an enable secret, Netmiko first performs an `enable` transition into privileged EXEC mode. Neither session operation enters configuration mode or changes the running or startup configuration.

The exact collection inventory, sample-fixture list, and separate full-collection catalog are documented in [Command reference](COMMAND_REFERENCE.md).

## Bundled assessment content

The repository at product version 0.1.0 contains:

- 22 Cisco IOS-XE L2 controls: 21 automated and 1 manual-review; and
- 42 Cisco IOS-XE NDM controls: 37 automated and 5 manual-review.

Across both bundled packs, this is 64 checks: 58 automated and 6 manual-review. These counts describe the bundled implementation and do not represent certified or complete STIG automation.

## Result meanings

| Result | Meaning |
| --- | --- |
| `NotAFinding` | Collected evidence satisfied the implemented check logic. It is not a certification. |
| `Open` | Collected evidence did not satisfy the implemented check logic and requires Administrator review. |
| `Not_Applicable` | The check logic established that the control does not apply to the evaluated scope. |
| `Not_Reviewed` | The control requires human review or lacks the data or organizational context needed for a determination. |
| `Error` | Required evidence, parsing, profile data, or evaluation was insufficient or invalid. |
| `Skipped` | Device collection did not complete, for example because of cancellation, connectivity, or authentication failure. |

An `Open` result is not an instruction to change a device. A `NotAFinding` result is not proof that a device is secure or fully compliant. The Administrator must validate evidence, scope, applicability, profile values, check logic, installed license features, and source STIG version.

## Offline licensing

Without a valid license, the application reports Free mode and applies a one-unique-device scan limit; L2, NDM, CKL, multi-device, preset, and advanced-reporting functions depend on signed feature flags. License verification is local. The customer application contains public verification keys only; publisher private keys and license-issuance tools are outside the customer build. See [Offline licensing](OFFLINE_LICENSING.md).

## Data and network interactions

Live scans connect to the Target Devices selected by the Administrator. Optional STIG-source actions connect to the DoD Cyber Exchange or to a URL selected by the Administrator. Offline license verification does not make a network connection. Version 0.1.0 contains no vendor-operated telemetry, analytics upload, or cloud-processing path.

Command output is cached locally under `work/cache/ssh` without automatic redaction, per-run UUID isolation, or integrity hashes. Reports and CKLs are written to destinations chosen by the Administrator. See [Security and data handling](SECURITY_AND_DATA_HANDLING.md).

## Independence notice

STIG Audit Pro is not an official product of, endorsed by, certified by, or affiliated with the United States Department of Defense, the Defense Information Systems Agency, or Cisco Systems, Inc. All third-party names and marks belong to their respective owners. Official STIG source material should be obtained from the [DoD Cyber Exchange STIG library](https://www.cyber.mil/stigs/downloads/).
