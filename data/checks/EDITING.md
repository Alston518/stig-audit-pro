# Editing Check Strings and Site Variables

The check YAML files are the source of truth for what the app searches for. Site profiles are the place for customer or building-specific values.

## Main Files

- `data/checks/iosxe_l2.yaml`: L2 STIG check patterns
- `data/checks/iosxe_ndm.yaml`: NDM STIG entries
- `data/profiles/*.yaml`: site/building variables and VLAN requirements

## Recommended Workflow

1. Pick or create a site profile under `data/profiles/`.
2. Put customer-specific values in that profile, such as unused VLAN, DHCP snooping VLANs, ARP inspection VLANs, and any extra trunk-pruned VLANs.
3. Leave the check YAML alone unless the customer's required config strings are genuinely different.

Profiles can also include a free-form `variables` section. This is the foundation for a future GUI or spreadsheet-style variables editor.

Example:

```yaml
profile_name: example_site
unused_vlan: 999
dhcp_snooping:
  vlans:
    - 10
    - 20
    - 30
arp_inspection:
  vlans:
    - 10
    - 20
    - 30
variables:
  site_label: Example site
  required_user_vlans:
    - 10
    - 20
    - 30
```

## Pattern Variables

Check patterns can reference profile values with double braces:

```yaml
pattern: ^switchport access vlan\s+{{ unused_vlan }}$
```

For profile lists, use `profile_all` or `profile_forbidden_patterns` so the engine expands one search pattern per required value:

```yaml
profile_all:
  - command: show running-config
    profile_key: dhcp_snooping.vlans
    object_type: vlan
    pattern_template: ^\s*ip dhcp snooping vlan\s+.*(?<!\d){{ item }}(?!\d).*$
    description_template: DHCP snooping VLAN {{ item }}
```

## Current Automated L2 Check Style

All automated L2 checks now use editable string/config patterns:

- `command_pattern_policy`: searches command output strings/regexes
- `interface_config_policy`: searches strings/regexes inside matching interface blocks

Manual-review L2 and NDM checks stay manual until we decide a reliable string pattern for each one.
