"""Validated external schemas for check packs and site profiles."""

from __future__ import annotations

import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

StatusLiteral = Literal["NotAFinding", "Open", "Not_Applicable", "Not_Reviewed", "Error", "Skipped"]
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
    "manual_review",
]
ControlOrigin = Literal["official", "organizational", "custom", "example"]
OBJECT_CHECK_TYPES = {
    "interface_policy",
    "interface_config_policy",
    "trunk_vlan_policy",
    "acl_deny_logging_policy",
    "dhcp_snooping_policy",
    "arp_inspection_policy",
}
PLACEHOLDER_RE = re.compile(r"{{\s*([^}]+?)\s*}}")


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    def get(self, key: str, default: Any = None) -> Any:
        """Mapping-style compatibility for the existing evaluator."""
        return self.model_dump(by_alias=True).get(key, default)


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


class ParserConfig(StrictModel):
    name: str | None = None
    version: str | None = None


class ValueMatch(StrictModel):
    equals: Any | None = None
    not_equals: Any | None = None
    in_: list[Any] | None = Field(default=None, alias="in")
    not_in: list[Any] | None = None
    regex: str | None = None

    model_config = ConfigDict(extra="forbid", populate_by_name=True)


ScopeValue = str | int | list[str] | list[int] | ValueMatch


class InterfaceMatch(StrictModel):
    admin_state: ScopeValue | None = None
    status: ScopeValue | None = None
    operational_status: ScopeValue | None = None
    switchport_mode: ScopeValue | None = None
    access_vlan: ScopeValue | None = None
    media_type: ScopeValue | None = None
    shutdown: bool | None = None


class InterfaceScopeRule(StrictModel):
    type: Literal["physical", "any"] = "any"
    match: InterfaceMatch = Field(default_factory=InterfaceMatch)


class InterfaceScope(StrictModel):
    include: list[InterfaceScopeRule] = Field(default_factory=lambda: [InterfaceScopeRule()])


class ScopeConfig(StrictModel):
    interfaces: InterfaceScope | None = None


class PatternConfig(StrictModel):
    command: str | None = None
    pattern: str | None = None
    value: str | None = None
    description: str | None = None
    case_sensitive: bool = False
    object_type: str | None = None
    object_name: str | None = None
    profile_key: str | None = None
    pattern_template: str | None = None
    description_template: str | None = None

    @model_validator(mode="after")
    def validate_pattern(self) -> PatternConfig:
        candidate = self.pattern_template or self.pattern or self.value
        if candidate is None and self.profile_key is None:
            raise ValueError("pattern entry requires pattern, value, or pattern_template")
        if candidate is not None:
            rendered = PLACEHOLDER_RE.sub("1", candidate)
            try:
                re.compile(rendered)
            except re.error as exc:
                raise ValueError(f"invalid regex {candidate!r}: {exc}") from exc
        return self


class FieldCondition(StrictModel):
    field: str
    op: Literal[
        "equals_profile_value",
        "includes_profile_list",
        "excludes_profile_list",
        "equals",
        "not_equals",
        "includes",
        "excludes",
        "contains",
        "regex",
    ]
    value: Any | None = None
    profile_key: str | None = None

    @model_validator(mode="after")
    def validate_operands(self) -> FieldCondition:
        if self.op.endswith("profile_value") or self.op.endswith("profile_list"):
            if not self.profile_key:
                raise ValueError(f"{self.op} requires profile_key")
        if self.op == "regex":
            try:
                re.compile(str(self.value))
            except re.error as exc:
                raise ValueError(f"invalid condition regex: {exc}") from exc
        return self


class AclDenySettings(StrictModel):
    include_standard_acls: bool = True
    include_extended_acls: bool = True
    include_ipv6_acls: bool = False
    require_keyword: str = "log-input"


class ConditionsConfig(StrictModel):
    command: str | None = None
    contains: str | None = None
    value: Any | None = None
    pattern: str | None = None
    case_sensitive: bool = False
    section: str | None = None
    all: list[PatternConfig | FieldCondition] = Field(default_factory=list)
    any: list[PatternConfig] = Field(default_factory=list)
    none: list[PatternConfig] = Field(default_factory=list)
    profile_all: list[PatternConfig] = Field(default_factory=list)
    profile_none: list[PatternConfig] = Field(default_factory=list)
    required_patterns: list[PatternConfig] = Field(default_factory=list)
    any_patterns: list[PatternConfig | list[PatternConfig]] = Field(default_factory=list)
    forbidden_patterns: list[PatternConfig] = Field(default_factory=list)
    profile_required_patterns: list[PatternConfig] = Field(default_factory=list)
    profile_forbidden_patterns: list[PatternConfig] = Field(default_factory=list)
    deny_statements: AclDenySettings = Field(default_factory=AclDenySettings)


class CheckDefinition(StrictModel):
    vuln_id: str
    title: str
    stig_family: str
    severity: str
    check_type: CheckTypeLiteral
    commands: list[str] = Field(default_factory=list)
    automated: bool = True
    control_origin: ControlOrigin = "official"
    include_in_official_totals: bool | None = None
    stig_id: str | None = None
    group_id: str | None = None
    rule_id: str | None = None
    custom_check_id: str | None = None
    source_benchmark: str | None = None
    source_version: str | None = None
    source_release: str | None = None
    source_rule_fingerprint: str | None = None
    review_status: Literal["Active", "Review Required", "Retired"] = "Active"
    allow_unreviewed_logic: bool = False
    parser: ParserConfig = Field(default_factory=ParserConfig)
    scope: ScopeConfig = Field(default_factory=ScopeConfig)
    conditions: ConditionsConfig = Field(default_factory=ConditionsConfig)
    empty_scope_status: Literal["Error", "Not_Applicable", "Not_Reviewed"] | None = None
    result: ResultMapping = Field(default_factory=ResultMapping)
    evidence: EvidenceConfig = Field(default_factory=EvidenceConfig)

    @field_validator("vuln_id", "title", "stig_family", "severity")
    @classmethod
    def require_non_empty(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("value must not be empty")
        return value

    @model_validator(mode="after")
    def validate_check(self) -> CheckDefinition:
        if self.check_type == "manual_review":
            if self.automated:
                raise ValueError("manual_review checks must set automated: false")
        elif not self.automated:
            raise ValueError("non-manual checks cannot set automated: false")
        elif not self.commands:
            raise ValueError("automated checks must declare at least one command")
        if self.check_type in OBJECT_CHECK_TYPES and self.empty_scope_status is None:
            self.empty_scope_status = "Error"
        referenced = {self.conditions.command} if self.conditions.command else set()
        for field_name in (
            "all",
            "any",
            "none",
            "profile_all",
            "profile_none",
            "required_patterns",
            "forbidden_patterns",
            "profile_required_patterns",
            "profile_forbidden_patterns",
        ):
            for item in getattr(self.conditions, field_name):
                if isinstance(item, PatternConfig) and item.command:
                    referenced.add(item.command)
        for item in self.conditions.any_patterns:
            for pattern in item if isinstance(item, list) else [item]:
                if pattern.command:
                    referenced.add(pattern.command)
        undeclared = sorted(command for command in referenced if command not in self.commands)
        if undeclared:
            raise ValueError(f"condition references undeclared command(s): {', '.join(undeclared)}")
        direct_pattern = self.conditions.pattern
        if direct_pattern:
            try:
                re.compile(PLACEHOLDER_RE.sub("1", direct_pattern))
            except re.error as exc:
                raise ValueError(f"invalid regex {direct_pattern!r}: {exc}") from exc
        if self.include_in_official_totals is None:
            self.include_in_official_totals = self.control_origin == "official"
        if self.control_origin != "official" and not self.custom_check_id:
            self.custom_check_id = self.vuln_id
        return self

    def profile_keys(self) -> set[str]:
        keys: set[str] = set()
        payload = self.model_dump(mode="python")
        for value in _walk_values(payload):
            if isinstance(value, str):
                keys.update(key for key in PLACEHOLDER_RE.findall(value) if key != "item")
        for name in (
            "profile_all",
            "profile_none",
            "profile_required_patterns",
            "profile_forbidden_patterns",
        ):
            keys.update(
                item.profile_key for item in getattr(self.conditions, name) if item.profile_key
            )
        for item in self.conditions.all:
            if isinstance(item, FieldCondition) and item.profile_key:
                keys.add(item.profile_key)
        return keys


class CheckLibrary(StrictModel):
    library_name: str | None = None
    check_pack_version: str = "1.0.0"
    schema_version: Literal[1] = 1
    minimum_app_version: str = "0.2.0"
    checks: list[CheckDefinition] = Field(default_factory=list)

    @field_validator("checks")
    @classmethod
    def vuln_ids_must_be_unique(cls, checks: list[CheckDefinition]) -> list[CheckDefinition]:
        ids = [check.vuln_id for check in checks]
        duplicates = sorted({item for item in ids if ids.count(item) > 1})
        if duplicates:
            raise ValueError(f"duplicate vuln_id values: {', '.join(duplicates)}")
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


class TopologyPolicy(StrictModel):
    user_facing_interfaces: list[str] = Field(default_factory=list)
    uplinks: list[str] = Field(default_factory=list)
    access_layer_links: list[str] = Field(default_factory=list)
    exempt_interfaces: list[str] = Field(default_factory=list)
    authorized_trunks: list[str] = Field(default_factory=list)


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
    disabled_port_policy: DisabledPortPolicy = Field(default_factory=DisabledPortPolicy)
    trunk_policy: TrunkPolicy = Field(default_factory=TrunkPolicy)
    dhcp_snooping: DhcpSnoopingPolicy = Field(default_factory=DhcpSnoopingPolicy)
    arp_inspection: ArpInspectionPolicy = Field(default_factory=ArpInspectionPolicy)
    topology: TopologyPolicy = Field(default_factory=TopologyPolicy)
    comments: ProfileComments = Field(default_factory=ProfileComments)

    @field_validator("profile_name")
    @classmethod
    def profile_name_must_be_present(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("profile_name must not be empty")
        return value

    @field_validator("unused_vlan")
    @classmethod
    def vlan_must_be_valid(cls, value: int) -> int:
        if not 1 <= value <= 4094:
            raise ValueError("VLAN must be between 1 and 4094")
        return value

    def resolve_key(self, key: str) -> Any:
        current: Any = self
        for part in key.split("."):
            current = (
                current.get(part) if isinstance(current, dict) else getattr(current, part, None)
            )
            if current is None:
                break
        return self.variables.get(key) if current is None else current


def validate_check_for_profile(check: CheckDefinition, profile: SiteProfile) -> None:
    missing = sorted(key for key in check.profile_keys() if profile.resolve_key(key) is None)
    if missing:
        raise ValueError(
            f"{check.vuln_id} has unresolved profile variable(s): {', '.join(missing)}"
        )


def _walk_values(value: Any):
    if isinstance(value, dict):
        for item in value.values():
            yield from _walk_values(item)
    elif isinstance(value, list):
        for item in value:
            yield from _walk_values(item)
    else:
        yield value
