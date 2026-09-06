# Threat Model

## Assets

Protected assets include device credentials in memory, raw configuration evidence, audit findings/history, profile/check snapshots, license verification material, and imported STIG content.

## Primary threats and controls

- **Command injection or configuration change:** exact centralized allowlist; newline/control/chaining rejection; YAML and runtime validation; no remediation component.
- **Credential disclosure:** session-only fields, GUI clearing, model `extra=forbid`, redacted structured logging, and exclusion from database/manifests/presets.
- **Historical evidence tampering:** per-run immutable paths, atomic writes, exact-byte SHA-256, persisted metadata, and on-demand verification.
- **Cross-run overwrite:** UUID roots and no replacement of finalized artifacts.
- **False comparison across changed controls:** normalized STIG fingerprints and `NOT_COMPARABLE` when a materially changed rule prevents a valid comparison.
- **Unsafe or malformed content:** strict Pydantic/YAML schemas, supported versions, corrupt-import errors, and ambiguous-match failures.
- **Worker/GUI concurrency faults:** isolated connections and a queue boundary; only Tk's main thread updates widgets.
- **Database corruption/orphans:** short transactions, schema-version checks, foreign keys, and explicit failure propagation.

## Trust and limitations

The workstation, Python/runtime dependencies, OS file permissions, operator-selected STIG files, and reachable network are trust dependencies. Hashes do not provide signatures or collector identity. The desktop is single-user and does not provide role-based access control, a server database, vault integration, telemetry, or autonomous scheduling in v0.2.

The application displays DISA fix guidance but never executes it. Operators remain responsible for authorization, source validation, findings review, custody, and any remediation performed outside this product.
