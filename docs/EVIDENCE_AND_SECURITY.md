# Evidence and security

Each scan creates a UUID and JSON manifest containing application/check-pack/STIG/profile identity, target list, device facts, collection status, parser versions/warnings, results, exceptions, and report paths. Device output is stored below that UUID, written atomically, and hashed. Runs can be exported as ZIP evidence bundles.

Retention is configurable. Optional redaction removes common password, secret, community, and key lines before persistence. Redaction is defense in depth and must be validated against local configuration conventions. SSH passwords and enable secrets are never serialized.

The application issues only allow-listed read-only commands. It contains no remediation or configuration-command path. CSV output prefixes cells beginning with spreadsheet formula characters.

