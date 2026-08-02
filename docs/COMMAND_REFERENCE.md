# Command reference and device-change statement

**Applies to:** STIG Audit Pro 0.1.0

**Platform:** Cisco IOS-XE

## Device-change statement

The unmodified product and bundled check packs make zero changes to an audited device's running configuration or startup configuration.

The live SSH implementation uses Netmiko's `send_command` method for individual collection commands. When an Administrator supplies an enable secret, it also uses Netmiko's `enable` method to enter privileged EXEC mode. Privileged EXEC is not configuration mode and this transition does not change running or startup configuration. The implementation does not call Netmiko configuration-set methods, enter configuration mode, save configuration, erase configuration, reload a device, or execute remediation.

Findings are returned to the Administrator for independent review. Any change made after a scan is performed outside STIG Audit Pro and is entirely at the discretion and responsibility of authorized administrative personnel.

## Commands used by the bundled check packs

The GUI collects commands declared by the checks enabled for the selected workflow and signed license. It removes duplicate commands, adds terminal pagination control, validates command prefixes, and executes the resulting set. A family-specific scan may use only a subset. Across both unmodified version 0.1.0 bundled packs, the maximum collection inventory is:

| Command | Bundled use |
| --- | --- |
| `show running-config` | Global, interface, access-control, management, authentication, service, and other configuration evidence used across L2 and NDM checks. |
| `show running-config | include ssh` | Filtered SSH-related configuration evidence for NDM SSH algorithm checks. |
| `show version` | IOS-XE version evidence for the bundled software-version check. |
| `show vtp status` | VTP mode and operational evidence. |
| `show interfaces status` | Interface state, VLAN, and mode context. |
| `show interfaces switchport | include Negotiation of Trunking` | Filtered Dynamic Trunking Protocol negotiation evidence. |
| `show cdp neighbors detail` | Neighbor identity and local-interface evidence for the Root Guard policy. |
| `show ip access-lists` | IPv4 access-list evidence for NDM management-access evaluation. |
| `show snmp user` | SNMPv3 user authentication and privacy evidence. |

The L2 pack declares five unique `show` commands. The NDM pack declares five unique `show` commands. `show running-config` is shared, producing nine unique commands across both packs.

## Session operations

| Command or operation | Effect |
| --- | --- |
| `terminal length 0` | Disables pagination for the active terminal session so complete output can be collected. It does not enter configuration mode, change running or startup configuration, or persist after logout. |
| `enable` | Used only when the Administrator supplies an enable secret. It authenticates into privileged EXEC mode and does not enter configuration mode or change running or startup configuration. |

Manual-review controls declare no device commands. The bundled L2 pack contains one manual-review control and the NDM pack contains five.

## Full-collection catalog defined in code

The core package separately defines the following full-collection catalog. The version 0.1.0 GUI invokes the planner in selected-check mode rather than requesting this entire catalog. It is documented for code review and any future integration that deliberately uses `run_all=True`:

| Command | Intended evidence category |
| --- | --- |
| `show running-config` | Active configuration text |
| `show version` | Software, platform, uptime, and device facts |
| `show inventory` | Hardware inventory |
| `show vtp status` | VTP status |
| `show vlan brief` | VLAN summary |
| `show interfaces status` | Interface state and VLAN/mode summary |
| `show interfaces trunk` | Trunk state and allowed VLANs |
| `show cdp neighbors detail` | CDP neighbor and local-interface details |
| `show ip access-lists` | IPv4 ACL entries |
| `show ip dhcp snooping` | DHCP snooping operational state |
| `show ip arp inspection` | Dynamic ARP inspection operational state |
| `show logging` | Device log buffer and logging state |
| `show clock` | Device time |

`terminal length 0` is also part of that catalog for session pagination.

## Sample-scan behavior

Sample scans read bundled text fixtures and do not open an SSH connection or send a command to a device. Fixture files exist for:

- `show running-config`
- `show vtp status`
- `show interfaces status`
- `show interfaces switchport | include Negotiation of Trunking`
- `show interfaces trunk`
- `show cdp neighbors detail`
- `show ip access-lists`
- `show ip dhcp snooping`
- `show ip arp inspection`
- `show snmp user`
- `show version`

Fixture availability does not imply that every command is sent during every live scan.

## Custom check packs

The application loads all `*.yaml` files in the active `data/checks` directory. Administrators can edit checks through the GUI or add check packs, so the installed command inventory can differ from the bundled inventory.

The current validator accepts normalized commands beginning with `show ` or `terminal length `. This is a prefix safety check, not a complete semantic parser for every Cisco IOS-XE variation. The bundled pipes are limited to read-only `| include` filters. Custom content must not introduce output redirection, file or URL destinations, command chaining, aliases, or other syntax that could create side effects.

Only trusted, reviewed check packs should be installed. For the strongest production control, use a device account authorized for only the approved command inventory, restrict write access to `data/checks`, and review the final planned commands before deployment. Modified builds and unreviewed check packs are outside the bundled read-only representation.

## Explicitly absent device operations

The version 0.1.0 live-scan path has no implementation for:

- entering global, interface, line, or other device configuration modes;
- sending configuration command sets;
- copying, writing, committing, or saving configuration;
- erasing configuration or files;
- rebooting or reloading devices; or
- generating or applying remediation.
