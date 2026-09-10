# Site Profiles

## What this does

Stores organization-defined values that DISA requirements expect the assessor to tailor.

## When you use it

Review a profile before the first audit and whenever VLANs, management networks, servers, or policy values change.

Use the typed fields in **Profiles** for common settings. Advanced YAML remains available for administrators. Validation rejects unknown keys and invalid types. Profile inheritance allows a site profile to override a controlled base. The application snapshots and hashes the resolved profile for each Audit Run so later edits never reinterpret history.
