# STIG Audit Pro — Tester Getting Started

This package is the current L2 GUI test build. It runs the validated Cisco
IOS-XE L2 checks, displays results, optionally creates a text report, and fills
one CKL per successfully scanned switch.

## 1. Requirements

- Windows 10 or Windows 11
- Python 3.12
- Network connectivity to the Cisco IOS-XE switches
- An authorized SSH username and password

When installing Python, enable **Add Python to PATH**.

## 2. Extract and install

Extract the complete ZIP to a local folder. Do not run the application from
inside the ZIP.

Open PowerShell in the extracted `Stig_audit_pro` folder and run:

```powershell
python -m pip install -r requirements.txt
```

## 3. Start the GUI

```powershell
python app.py
```

## 4. Select or prepare a profile

Open the **Profiles** tab. The supplied `base_iosxe_access` profile contains the
current test-site values.

A site-specific profile should inherit the base:

```yaml
profile_name: example_building
inherits: base_iosxe_access
```

Add only the values that differ for that site. Profiles can override native,
unused, and management VLANs; DHCP snooping and ARP inspection VLANs; upstream
Root Guard neighbors; and RADIUS group/server values.

## 5. Add targets and credentials

Open the **Targets** tab:

1. Add one IP, paste multiple IPs, or import a CSV/TXT list.
2. Check every target that should be audited.
3. Set **Scan Mode** to `Live SSH`.
4. Enter the SSH username and password.
5. Select a profile override for a target when it differs from the selected
   default profile.

Credentials are kept only for the running GUI session and are not written to
disk.

## 6. Run the L2 checklist audit

Open the **STIG / CKL** tab:

1. Choose `templates\IOSXE_L2_Template.ckl` as the CKL template.
2. Select the destination folder.
3. Select **Fill CKL**, **Create text report**, or both.
4. Choose whether generated comments append to or replace existing CKL
   comments.
5. Click **Run Checked Targets — L2**.

The CKL workflow requires `Live SSH` and will refuse to populate a checklist
from bundled sample output.

## 7. Review the output

The **Results** tab shows each check status and failed object details.

The selected destination receives:

- One `<hostname>_<IP>_IOSXE_L2_completed.ckl` per successfully scanned switch.
- One combined `IOSXE_L2_audit_<timestamp>.txt` when text reporting is selected.

The original CKL template is never overwritten.

The completed CKL receives the switch hostname and the IPv4 address configured
on the profile-defined management SVI (`management_vlan`, default VLAN 300).
If that address cannot be found, the scan target IP is used.

## 8. Expected temporary finding

`V-220651` is intentionally returned as `Open` until the site QoS policy is
implemented and that check is automated.

## Troubleshooting

- If results show `SW-ACCESS-01`, the Targets tab is using sample output instead
  of Live SSH.
- If DHCP snooping or ARP inspection VLANs fail, verify the selected target
  profile.
- If Root Guard fails, verify `root_guard.upstream_switches` contains the core
  or distribution CDP Device ID. Short hostnames match their FQDN form.
- Run the automated suite with:

```powershell
python -m pytest -q
```
