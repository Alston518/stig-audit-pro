# Controlled STIG update workflow

Imported sources are retained at `data/stigs/cache/<family>/<benchmark>/<version-release>/` with the original package, extracted XCCDF, SHA-256, import/source provenance, benchmark metadata, and normalized rules.

1. Import a new package without changing the active check pack.
2. Compare it with the previous release.
3. Review added, removed, unchanged, and field-level changed rules.
4. Changed mapped checks become `Review Required`; their logic is blocked unless `allow_unreviewed_logic` is explicitly authorized.
5. New unmapped rules may receive manual-review placeholders. Removed rules become retired and remain in history.
6. An authorized reviewer records activation. No regex or semantic logic is generated from changed prose.

The GUI comparison shows both release identities and changed source content. Approval records source identity; it does not silently edit checks.

