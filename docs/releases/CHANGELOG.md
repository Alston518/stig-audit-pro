# Changelog

## 0.2.0 — 2026-09-04

### Architecture and safety

- Introduced application-service, core/domain, and infrastructure boundaries while preserving the CustomTkinter desktop and existing parsers/check engine.
- Replaced broad command-prefix approval with one exact-match, fail-closed `CommandPolicy` used by YAML validation, planning, runtime SSH, tests, and generated documentation.
- Modernized externally editable models to Pydantic 2 validators and strict `extra="forbid"` schemas; versioned bundled check libraries.
- Kept network behavior strictly read-only. No configuration, save, reload, or remediation path was added.

### Audit runs and evidence

- Added UUID-based audit/run-device models and complete lifecycle states.
- Added an embedded SQLAlchemy 2.0 SQLite history database with foreign keys, indexed tables, repositories, and schema versioning.
- Added per-run atomic evidence storage, exact UTF-8 SHA-256 metadata, immutable context snapshots, manifests, integrity verification, and explicit raw-evidence purge.
- Added offline evidence import labeling and session-only credential handling.

### Scanning and operator experience

- Added bounded concurrent multi-device scanning (default five, configurable one–twenty), isolated connections/failures, cancellation, status events, and main-thread GUI consumption.
- Added reusable credential-free scan presets, typed profile editing, simple check-string editing, and retained advanced YAML editing.
- Added per-device audit progress, finding-to-evidence traceability, Evidence and History views, historical report generation, and run-to-run comparison/export.

### STIG lifecycle

- Added versioned coexistence of imported STIG releases with normalized field/rule fingerprints.
- Added stable-identifier release comparison with added/removed/changed/unchanged and field-level changes, including ambiguity handling.
- Added YAML impact recommendations, automation review fingerprints/state, coverage metrics, missing manual starter generation, side-by-side check/fix details, and JSON/CSV/XLSX difference exports.

### Reports

- Preserved TXT, CSV, and CKL behavior.
- Added schema-versioned JSON, professional multi-sheet XLSX, and native STIG Viewer 3-style CKLB import/population/export.
- Centralized report generation behind `ReportService` and evidence references rather than embedding raw configurations by default.

### Engineering

- Added critical unit/fixture coverage for command safety, persistence, evidence, concurrency, STIG differences/impact/repository, run comparison, JSON/XLSX, and CKLB.
- Added generated command and STIG traceability documents, structured documentation, PlantUML sources, and GitHub Actions validation.
- Updated dependency ranges and PyInstaller inputs for the v0.2 modules and resources.

## 0.1.0

Initial development release with CustomTkinter workflows, targets/groups, inherited site profiles, YAML-driven L2/NDM checks, sample and Netmiko scans, licensing, STIG ZIP/XML metadata import, and TXT/CSV reporting.
