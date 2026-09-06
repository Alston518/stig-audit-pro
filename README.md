# STIG Audit Pro v0.2.0

STIG Audit Pro is a Windows-focused, read-only Cisco IOS-XE switch auditing
application. It collects approved command evidence over SSH, evaluates
YAML-driven L2 and NDM checks, retains reproducible audit history, and helps
administrators review the effect of new DISA STIG releases.

It never enters configuration mode, applies a fix, saves configuration,
reloads a device, or persists device credentials.

## What v0.2 adds

- First-class audit runs with SQLite history, profile/check snapshots, and
  per-run immutable evidence paths.
- SHA-256 evidence verification. Hashes establish post-collection integrity,
  not who collected the evidence.
- Bounded concurrent scanning (default 5, configurable 1–20), cancellation,
  and GUI-safe per-device progress.
- Strict exact-match command policy shared by YAML validation and Netmiko.
- A versioned local STIG release library, normalized release differences,
  YAML impact analysis, and coverage metrics.
- JSON, XLSX, CKL, and CKLB reporting, plus historical-run comparison.
- Audit History and Evidence GUI views, scan presets, typed profile editing,
  and simple check-string editing alongside advanced YAML editing.

## Quick start

```powershell
python -m pip install -r requirements.txt
python app.py
```

Run the test suite:

```powershell
python -m pytest
```

The default application database and evidence workspace use the platform data
directory. Their resolved locations are reported by the application logs; see
the [database guide](docs/developers/DATABASE_GUIDE.md) for the expected paths.

## Safety boundary

Only commands in the generated [command reference](docs/assurance/COMMAND_REFERENCE.md)
can run. The policy rejects unknown commands, control characters, multiline
input, chaining, configuration, saving, reloading, and remediation commands
before an SSH connection is opened. `terminal length 0` is the sole session
operation and is used only to disable pagination.

See [Security Boundary](docs/assurance/SECURITY_BOUNDARY.md) and
[Evidence Handling](docs/assurance/EVIDENCE_HANDLING.md).

## Documentation

- [Documentation index](docs/INDEX.md)
- [Getting started](docs/operator/GETTING_STARTED.md)
- [Administrator guide](docs/operator/ADMINISTRATOR_GUIDE.md)
- [STIG update and diff workflow](docs/operator/STIG_UPDATE_GUIDE.md)
- [Audit history](docs/operator/AUDIT_HISTORY_GUIDE.md)
- [Architecture](docs/architecture/ARCHITECTURE.md)
- [Check authoring](docs/developers/CHECK_AUTHORING_GUIDE.md)
- [Release changelog](docs/releases/CHANGELOG.md)

## Licensing

The existing offline licensing and free/paid device enforcement remain in
place. Device passwords and enable secrets are session-only and are never put
in audit records, manifests, presets, or normal logs.
