# STIG Audit Pro - Codex Handoff

This file is for opening the project from another laptop or a fresh Codex thread.

## Current Project Folder

When cloned with GitHub Desktop, the repo is expected to be named:

```powershell
stig-audit-pro
```

On Jimmy's current PC, the working folder is:

```powershell
C:\Users\Jimmy\Documents\Codex\stig-audit-pro
```

Run the app with:

```powershell
cd "C:\Users\Jimmy\Documents\Codex\stig-audit-pro"
& "C:\Users\Jimmy\AppData\Local\Programs\Python\Python313\python.exe" app.py
```

Run tests with:

```powershell
cd "C:\Users\Jimmy\Documents\Codex\stig-audit-pro"
& "C:\Users\Jimmy\AppData\Local\Programs\Python\Python313\python.exe" -m pytest
```

## Where We Are

- GUI exists and can run sample scans and SSH scans.
- Device groups and site profiles exist.
- Report export exists.
- STIG import/viewing exists.
- L2 check file has 23 checks.
- 17 L2 checks are automated.
- 6 L2 checks are still manual review.
- All automated L2 checks are editable string/pattern checks:
  - `command_pattern_policy`
  - `interface_config_policy`
- NDM checks are loaded as manual-review placeholders.
- CKL generation is not built yet.
- Excel report generation is not built yet.

## Important Files

- `app.py`: app entry point
- `data/checks/iosxe_l2.yaml`: L2 STIG check strings/patterns
- `data/checks/iosxe_ndm.yaml`: NDM STIG placeholder checks
- `data/checks/EDITING.md`: how to edit checks and profile variables
- `data/profiles/*.yaml`: site/building variables and VLAN requirements
- `stig_audit_pro/core/check_engine.py`: YAML-driven check engine
- `stig_audit_pro/gui/main_window.py`: main GUI

## Profile Variable Direction

Profiles are becoming the user-editable variables sheet.

Site-specific values should usually go in `data/profiles/*.yaml`, not directly in check logic. Examples:

- `unused_vlan`
- DHCP snooping VLANs
- ARP inspection VLANs
- extra trunk-pruned VLANs
- future lists like root guard interfaces, uplink interfaces, access-layer switch links

The check YAML can reference profile values with placeholders like:

```yaml
pattern: ^switchport access vlan\s+{{ unused_vlan }}$
```

For profile lists, checks can expand one pattern per profile value using `profile_all` or `profile_forbidden_patterns`.

## Current Scan Behavior

Compliant sample output currently gives:

- 17 `NotAFinding`
- 6 `Not_Reviewed`

Noncompliant sample output currently gives:

- 17 `Open`
- 6 `Not_Reviewed`

Useful object-level findings are already shown for examples like:

- missing DHCP/ARP VLANs
- disabled/notconnect interfaces missing shutdown or unused VLAN
- trunk interfaces allowing VLAN 1
- ACL deny statements missing `log-input`

## Next Recommended Step

Build a Profile Variables GUI:

- Select a profile.
- Edit common variables without opening YAML.
- Save profile changes.
- Show what checks use those variables.

After that, convert more manual L2 checks into automated checks where the profile can provide missing context.

Example: Root Guard can become automated if a profile lists which interfaces connect to access-layer switches, then the check searches those interface blocks for:

```ios
spanning-tree guard root
```

## GitHub Workflow

The GitHub repo is:

```text
https://github.com/Alston518/stig-audit-pro
```

Typical sync steps from GitHub Desktop:

1. Review changed files.
2. Add a short summary.
3. Commit to `main`.
4. Push origin.

On another laptop:

1. Open GitHub Desktop.
2. Fetch origin.
3. Pull origin.
4. Open the project folder in Codex.

## Notes For Future Codex

- The user wants a non-technical GUI and prefers not to edit YAML manually long term.
- Keep site/customer tailoring in profiles/variables where possible.
- Avoid building CKL generation until scan checks and profile editing are more mature.
- The user wants full L2 and NDM coverage eventually, but many entries still need careful manual-to-automated conversion.
