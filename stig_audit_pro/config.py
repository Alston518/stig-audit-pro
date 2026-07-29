"""Application-wide constants for the core audit package."""

from __future__ import annotations

APP_NAME = "stig-audit-pro"
APP_VERSION = "0.2.0"

DEFAULT_SHOW_COMMANDS: tuple[str, ...] = (
    "terminal length 0",
    "show running-config",
    "show version",
    "show inventory",
    "show vtp status",
    "show vlan brief",
    "show interfaces status",
    "show interfaces trunk",
    "show cdp neighbors detail",
    "show ip access-lists",
    "show ip dhcp snooping",
    "show ip arp inspection",
    "show logging",
    "show clock",
)

SAFE_COMMAND_PREFIXES: tuple[str, ...] = (
    "show ",
    "terminal length ",
)

SUPPORTED_CHECK_TYPES: tuple[str, ...] = (
    "command_contains",
    "command_not_contains",
    "command_pattern_policy",
    "command_regex",
    "section_contains",
    "section_not_contains",
    "interface_policy",
    "interface_config_policy",
    "trunk_vlan_policy",
    "acl_deny_logging_policy",
    "dhcp_snooping_policy",
    "arp_inspection_policy",
    "root_guard_neighbor_policy",
    "manual_review",
)

VALID_STATUSES: tuple[str, ...] = (
    "NotAFinding",
    "Open",
    "Not_Applicable",
    "Not_Reviewed",
    "Error",
    "Skipped",
)
