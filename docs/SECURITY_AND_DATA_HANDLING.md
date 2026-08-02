# Security and data handling

## Device safety boundary

The unmodified STIG Audit Pro 0.1.0 product and bundled check packs make zero changes to an audited device's running or startup configuration. Depending on the licensed families and selected workflow, the live-scan path sends a subset of nine bundled `show` commands plus `terminal length 0`. When the Administrator supplies an enable secret, Netmiko also authenticates into privileged EXEC mode with `enable`. Neither session operation enters configuration mode or changes running or startup configuration.

The SSH runner uses Netmiko's single-command execution method. It does not call configuration-set methods, enter configuration mode, save configuration, erase data, reload a device, or apply remediation. See [Command reference](COMMAND_REFERENCE.md) for the exact inventory and custom-pack boundary.

## Local data created by the application

The read-only statement applies to Target Devices. The application writes local operational data, including:

- check packs, site profiles, device groups, and editable YAML;
- imported STIG ZIP/XML sources, extracted XCCDF, metadata, and generated starter checks;
- raw command output and per-device cache metadata below `work/cache/ssh`;
- on-screen results and exported TXT, CSV, and completed CKL files;
- locally installed signed license data in the platform-specific application-data path; and
- application log data produced by the configured logging subsystem.

Most mutable product data in the reviewed source checkout is below the repository `data` and `work` directories. Issued customer licenses use the platform-specific location documented in [Offline licensing](OFFLINE_LICENSING.md), unless `STIG_AUDIT_PRO_LICENSE_PATH` selects an approved alternate file.

## Command-output cache

The live SSH runner caches output per device. Each command is stored as a text file whose name is derived from the command, and `metadata.json` records the device address, sorted command list, and timestamp. The cache is not isolated by scan UUID. Repeating the same command against the same device can overwrite the prior cached text.

Version 0.1.0 does not automatically redact cached command output, calculate evidence hashes, create immutable evidence bundles, or enforce retention. All cached output must therefore be treated as sensitive device data. `show running-config` and other commands may disclose authentication configuration, keys, community strings, access controls, topology, software versions, logging data, or other protected information.

SSH usernames, passwords, and enable secrets are passed to Netmiko from session-entry fields and are not deliberately written to profiles, reports, or the command-output cache. This does not remove the risk that device-returned command output itself contains sensitive values.

## Network connections and telemetry

Version 0.1.0 contains no vendor-operated telemetry, analytics upload, automatic update beacon, cloud-processing service, or licensing-server connection.

The application can initiate these Administrator-directed connections:

- SSH to explicitly selected Target Devices for a live scan;
- HTTPS requests to the DoD Cyber Exchange catalog and download services when STIG discovery is used; and
- HTTP or HTTPS to a URL entered by an Administrator when direct download is used.

Sample scans use local fixture files and make no device connection. Importing a local STIG file requires no external connection. Ed25519 license verification is performed locally with bundled public keys.

## Offline license security

Customer builds contain public verification keys only. Publisher private keys and the publisher license-administration package are intended to remain outside customer builds. A license is accepted only after its schema, timestamps, device limit, feature names, key ID, and Ed25519 signature are validated.

A locally privileged user may still alter application files, replace public keys in an untrusted build, or manipulate the system clock. Code signing, protected installation paths, trusted build distribution, and publisher private-key custody remain essential deployment controls.

## Access and deployment controls

- Use a dedicated device account authorized only for the approved command inventory.
- Restrict write access to application code, `data/checks`, profiles, device groups, public verification keys, and CKL templates.
- Treat custom YAML as trusted administrative content. Prefix validation does not prove that every possible platform-specific `show` variation is side-effect free.
- Permit only reviewed `| include` filters. Do not use output redirection, file or URL destinations, command chaining, aliases, or other side-effecting syntax in custom checks.
- Protect `work/cache/ssh`, report directories, CKL output, license files, and application logs with operating-system access control and encryption appropriate for network configurations.
- Establish organizational retention and secure-deletion procedures; the application does not enforce them.
- Inspect exports before transfer and use an approved encrypted channel.
- Validate the packaged build contains public keys but no publisher tools, issued licenses, or private keys.

## Reporting protections and limits

CSV output applies spreadsheet-formula escaping before writing cells. TXT, CSV, and CKL files may still disclose sensitive network information and must be handled accordingly.

Automated results depend on collected evidence, parser behavior, check logic, profile values, license-selected scope, and source versions. A result is neither a certification nor a substitute for manual assessment, risk analysis, or authorization. All remediation decisions and actions belong to authorized organizational personnel and occur outside the product.
