# Windows installation

Install Python 3.11-3.13, clone the repository, then run:

```powershell
py -3.13 -m venv .venv
.\.venv\Scripts\python.exe -m pip install --upgrade pip
.\.venv\Scripts\python.exe -m pip install -e ".[dev]"
.\.venv\Scripts\python.exe -m pytest
.\.venv\Scripts\python.exe app.py
```

Use a standard user account and a user-writable evidence/report folder. Do not place credentials in profiles, device groups, environment files, command history, or evidence. A signed installer is roadmap work; this source installation is appropriate only for a controlled internal pilot.

Mutable application data defaults to `%LOCALAPPDATA%/STIGAuditPro`. Set `STIG_AUDIT_PRO_DATA_DIR` before launch to use an approved alternate location; built-in repository defaults are never overwritten during seeding.
