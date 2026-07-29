# Architecture

STIG Audit Pro is a read-only desktop application. The GUI coordinates validated profiles and check packs, safe command planning, SSH collection, parsing, evaluation, evidence, reports, and controlled STIG metadata.

The trust boundary is deliberate: YAML is untrusted input and is validated before commands are planned; the command planner permits only show commands and terminal pagination; credentials remain in memory; evidence is stored under an immutable run UUID. Parsers create normalized device views, while evaluators decide status and retain object-level evidence. Source imports never rewrite production logic.

Built-in defaults remain under `data/checks`, `data/profiles`, and `data/templates`. On first GUI launch, missing defaults are seeded into `%LOCALAPPDATA%/STIGAuditPro` without overwriting existing user files. Mutable profiles, check overrides, device groups, imported STIGs, and evidence stay there; `STIG_AUDIT_PRO_DATA_DIR` can select another controlled location.
