# Getting Started

## Install and launch

Use Python 3.11 or 3.12 on Windows:

```powershell
python -m pip install -r requirements.txt
python app.py
```

The database and historical evidence locations are shown in application logging and use the platform-specific application-data directory, not the current working directory. Bundled checks, profiles, and sample output remain under `data/` and `tests/sample_outputs/` in a source checkout.

## First audit

1. Open **Audit Run** and select a saved group or enter targets.
2. Select L2, NDM, or both and choose a profile.
3. For a safe demonstration, use sample output. For devices, choose Live SSH and enter session-only credentials.
4. Select concurrency from 1–20 (default 5), then start.
5. Watch per-device status and open **Results** for findings.
6. Use **Evidence**, **Reports**, or **History** after completion.

Passwords and enable secrets are kept only for the operation and are cleared from GUI variables when practical. They are never stored in presets, runs, manifests, or logs.

## Safety expectation

STIG Audit Pro is assessment-only. It does not enter configuration mode, save configuration, reload equipment, or apply fix text. A command not explicitly registered in `CommandPolicy` is rejected before connection.
