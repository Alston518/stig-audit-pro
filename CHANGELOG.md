# Changelog

## 0.2.0 - 2026-07-11

- Added strict Pydantic 2 check-pack, scope, condition, profile, result, and exception models.
- Eliminated empty-scope and empty-evidence false passes; results now include matched counts and evidence summaries.
- Corrected semantic L2 handling for interface applicability, DTP modes, effective trunk VLAN sets, Vlan1 sections, DHCP snooping, and ARP inspection.
- Isolated example controls from official compliance totals.
- Added object-scoped and expiring exceptions.
- Added UUID ScanRun manifests, atomic evidence, hashing, retention, redaction, and bundle export.
- Added guided profile lifecycle/editing and source-aware safe check editing.
- Added versioned STIG sources, release differences, review states, and explicit activation records.
- Added bounded background scan orchestration, cancellation, retries, progress, and failure categories.
- Added CI, dependency bounds, expanded tests, and pilot documentation.

### Compatibility breaks

- Unsafe manual checks declaring `automated: true`, unknown scope/condition keys, invalid regex, and undeclared condition commands now fail validation.
- Whole-control exceptions must explicitly declare `scope: control`; legacy object exceptions are safely inferred only when both object fields exist.
- Empty automated object scopes default to `Error` unless the check declares `Not_Applicable` or `Not_Reviewed`.
- `EXAMPLE-ACL-LOG-INPUT` moved from the official L2 pack to `examples_custom.yaml` and no longer affects official totals.

