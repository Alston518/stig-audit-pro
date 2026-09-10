# Current Limitations

## What this does

This page defines what STIG Audit Pro 0.2 does not claim to provide.

## When you use it

Review it before procurement, deployment, or an assessment authorization decision.

- Cisco IOS-XE switch L2 and NDM are the supported automation families. NX-OS and other vendors are not supported.
- The product is a Windows-focused, single-user/local desktop application. There is no server, RBAC, SSO, central inventory, or REST API.
- It is strictly read-only toward devices. It does not remediate, enter configuration mode, save configuration, or reload equipment.
- Some STIG requirements remain manual because CLI evidence cannot support a defensible deterministic decision.
- Site-specific values must be tailored in a Site Profile before results are meaningful.
- Automated mappings are not equivalent to verified automation. A mapping is current only after review against the installed rule fingerprint and passing fixture coverage.
- Audit-package export is implemented. Import into the local history database is not yet exposed in the GUI.
- Backups can be created in the GUI. Restore validation exists in the application service, but restore is intentionally not exposed in the GUI during this refinement pass.
- Check-pack content hashing exists through audit snapshots. Signed commercial check-pack distribution is future work.
- Evidence SHA-256 detects changes after capture; it does not prove the identity of the device or operator that produced the evidence.
