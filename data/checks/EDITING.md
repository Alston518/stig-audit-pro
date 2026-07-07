# Editing Check Strings

The check YAML files are the source of truth for what the app searches for.

## Main Files

- `iosxe_l2.yaml`: L2 STIG checks
- `iosxe_ndm.yaml`: NDM STIG checks

## Where To Edit Search Strings

For string or regex based checks, edit the `pattern` values under `conditions`.

Example:

```yaml
conditions:
  all:
    - command: show running-config
      pattern: ^\s*spanning-tree loopguard default\s*$
      description: spanning-tree loopguard default
```

Change `pattern` when the required text differs for a site. Change `description`
only to make result details easier to read.

For per-interface checks, edit `required_patterns` or `forbidden_patterns`:

```yaml
conditions:
  required_patterns:
    - pattern: ^spanning-tree bpduguard enable$
      description: BPDU Guard enabled
```

## Current Editable L2 String Checks

- `CISC-L2-000030`: VTP operating mode/password patterns
- `CISC-L2-000100`: BPDU Guard interface pattern
- `CISC-L2-000110`: STP Loop Guard global pattern
- `CISC-L2-000120`: Unknown unicast flood blocking pattern
- `CISC-L2-000140`: IP Source Guard interface pattern
- `CISC-L2-000160`: Storm Control interface pattern
- `CISC-L2-000170`: IGMP/MLD snooping forbidden patterns
- `CISC-L2-000180`: Rapid STP/MST acceptable patterns
- `CISC-L2-000200`: Static trunk and DTP forbidden patterns
- `CISC-L2-000240`: Default VLAN management interface pattern

For VLAN lists and site-specific values, edit profile YAML files under
`data/profiles/` instead of changing the check logic.
