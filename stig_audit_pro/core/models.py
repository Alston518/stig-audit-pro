"""Pydantic models for editable checks and site profiles."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, validator

from stig_audit_pro.config import SUPPORTED_CHECK_TYPES, VALID_STATUSES


StatusLiteral = Literal[
    "NotAFinding",
    "Open",
    "Not_Applicable",
    "Not_Reviewed",
    "Error",
    "Skipped",
]

CheckTypeLiteral = Literal[
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
    "radius_server_policy",
    "root_guard_neighbor_policy",
    "vty_session_limit_policy",
    "manual_review",
]


class StrictModel(BaseModel):
    """Base model with unknown-key rejection for external YAML schemas."""

    class Config:
        extra = "forbid"


class ResultMapping(StrictModel):
    pass_status: StatusLiteral = "NotAFinding"
    fail_status: StatusLiteral = "Open"
    error_status: StatusLiteral = "Error"


class EvidenceConfig(StrictModel):
    include_command_output: bool = False
    include_failed_objects: bool = True
    pass_comment: str = ""
    fail_comment: str = ""
    error_comment: str = ""
    finding_details_template: str = "default"


class CheckDefinition(StrictModel):
    vuln_id: str
    title: str
    looking_for: str = ""
    stig_family: str
    severity: str
    check_type: CheckTypeLiteral
    commands: list[str] = Field(default_factory=list)
    automated: bool = True
    stig_id: str | None = None
    group_id: str | None = None
    rule_id: str | None = None
    source_benchmark: str | None = None
    source_version: str | None = None
    source_release: str | None = None
    parser: dict[str, Any] = Field(default_factory=dict)
    scope: dict[str, Any] = Field(default_factory=dict)
    conditions: dict[str, Any] = Field(default_factory=dict)
    result: ResultMapping = Field(default_factory=ResultMapping)
    evidence: EvidenceConfig = Field(default_factory=EvidenceConfig)

    @validator("vuln_id", "title", "stig_family", "severity")
    def require_non_empty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("value must not be empty")
        return value

    @validator("check_type")
    def validate_supported_check_type(cls, value: str) -> str:
        if value not in SUPPORTED_CHECK_TYPES:
            raise ValueError(f"unsupported check_type: {value}")
        return value

    @validator("commands", always=True)
    def require_commands_for_automated(
        cls, value: list[str], values: dict[str, Any]
    ) -> list[str]:
        automated = values.get("automated", True)
        check_type = values.get("check_type")
        if automated and check_type != "manual_review" and not value:
            raise ValueError("automated checks must declare at least one command")
        return value


class CheckLibrary(StrictModel):
    library_name: str | None = None
    checks: list[CheckDefinition] = Field(default_factory=list)

    @validator("checks")
    def vuln_ids_must_be_unique(cls, checks: list[CheckDefinition]) -> list[CheckDefinition]:
        seen: set[str] = set()
        duplicates: set[str] = set()
        for check in checks:
            if check.vuln_id in seen:
                duplicates.add(check.vuln_id)
            seen.add(check.vuln_id)
        if duplicates:
            raise ValueError(f"duplicate vuln_id values: {', '.join(sorted(duplicates))}")
        return checks


class DisabledPortPolicy(StrictModel):
    require_shutdown: bool = True
    required_access_vlan: int = 999


class TrunkPolicy(StrictModel):
    vlan_1_must_be_pruned: bool = True
    additional_pruned_vlans: list[int] = Field(default_factory=list)


class DhcpSnoopingPolicy(StrictModel):
    enabled: bool = True
    vlans: list[int] = Field(default_factory=list)
    required_global_commands: list[str] = Field(default_factory=lambda: ["ip dhcp snooping"])


class ArpInspectionPolicy(StrictModel):
    enabled: bool = True
    vlans: list[int] = Field(default_factory=list)


class RootGuardPolicy(StrictModel):
    upstream_switches: list[str] = Field(default_factory=list)


class EndpointAuthenticationPolicy(StrictModel):
    radius_group: str = "ISE-RADIUS"
    radius_servers: list[str] = Field(default_factory=list)
    radius_server_addresses: dict[str, str] = Field(default_factory=dict)


class ProfileComments(StrictModel):
    default_open_prefix: str = "Automated STIG validation found noncompliant configuration."
    default_pass_prefix: str = "Automated STIG validation found required configuration present."
    default_error_prefix: str = (
        "Automated STIG validation could not confidently evaluate this requirement."
    )


class SiteProfile(StrictModel):
    profile_name: str
    inherits: str | None = None
    variables: dict[str, Any] = Field(default_factory=dict)
    unused_vlan: int = 999
    native_vlan: int = 333
    management_vlan: int = 300
    disabled_port_policy: DisabledPortPolicy = Field(default_factory=DisabledPortPolicy)
    trunk_policy: TrunkPolicy = Field(default_factory=TrunkPolicy)
    dhcp_snooping: DhcpSnoopingPolicy = Field(default_factory=DhcpSnoopingPolicy)
    arp_inspection: ArpInspectionPolicy = Field(default_factory=ArpInspectionPolicy)
    root_guard: RootGuardPolicy = Field(default_factory=RootGuardPolicy)
    endpoint_authentication: EndpointAuthenticationPolicy = Field(
        default_factory=EndpointAuthenticationPolicy
    )
    comments: ProfileComments = Field(default_factory=ProfileComments)

    @validator("profile_name")
    def profile_name_must_be_present(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("profile_name must not be empty")
        return value

    @validator("unused_vlan", "native_vlan", "management_vlan")
    def vlan_must_be_valid(cls, value: int) -> int:
        if value < 1 or value > 4094:
            raise ValueError("VLAN must be between 1 and 4094")
        return value


def validate_status(value: str) -> str:
    if value not in VALID_STATUSES:
        raise ValueError(f"unsupported result status: {value}")
    return value
