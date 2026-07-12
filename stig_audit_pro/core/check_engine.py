"""Generic YAML-driven check engine."""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any, cast

from stig_audit_pro.core.exceptions import ExceptionRule, apply_exceptions
from stig_audit_pro.core.models import (
    OBJECT_CHECK_TYPES,
    CheckDefinition,
    FieldCondition,
    SiteProfile,
    StatusLiteral,
    ValueMatch,
    validate_check_for_profile,
)
from stig_audit_pro.core.parser_engine import InterfaceView, ParsedDeviceData, parse_outputs
from stig_audit_pro.core.result_model import CheckResult, FindingObject
from stig_audit_pro.parsers.common import is_physical_interface, vlan_set_to_text
from stig_audit_pro.parsers.iosxe_acls import AclStatement


@dataclass(slots=True)
class EvaluationOutcome:
    passed: bool
    failed_objects: list[FindingObject] = field(default_factory=list)
    passed_objects: list[FindingObject] = field(default_factory=list)
    details: list[str] = field(default_factory=list)
    status_override: str | None = None


class CheckEngine:
    """Evaluate check definitions against parsed command output."""

    def __init__(
        self,
        profile: SiteProfile,
        exception_rules: list[ExceptionRule] | None = None,
    ) -> None:
        self.profile = profile
        self.exception_rules = exception_rules or []

    def evaluate_all(
        self,
        checks: list[CheckDefinition],
        outputs: dict[str, str],
        ip: str,
        hostname: str | None = None,
    ) -> list[CheckResult]:
        parsed = parse_outputs(outputs)
        return [
            self.evaluate(check, outputs=outputs, ip=ip, hostname=hostname, parsed=parsed)
            for check in checks
        ]

    def evaluate(
        self,
        check: CheckDefinition,
        outputs: dict[str, str],
        ip: str,
        hostname: str | None = None,
        parsed: ParsedDeviceData | None = None,
    ) -> CheckResult:
        parsed_data = parsed or parse_outputs(outputs)
        result_hostname = hostname or parsed_data.facts.hostname
        if check.review_status == "Retired":
            return self._result(
                check,
                ip,
                result_hostname,
                status="Not_Applicable",
                parsed=parsed_data,
                details=["Control retired by a newer STIG release; audit history retained."],
            )
        if check.review_status == "Review Required" and not check.allow_unreviewed_logic:
            return self._result(
                check,
                ip,
                result_hostname,
                status="Not_Reviewed",
                parsed=parsed_data,
                details=["Source requirement changed; automated logic requires authorized review."],
            )
        try:
            validate_check_for_profile(check, self.profile)
        except ValueError as exc:
            return self._result(
                check,
                ip,
                result_hostname,
                status="Error",
                parsed=parsed_data,
                error_message=str(exc),
            )
        missing = [command for command in check.commands if command not in outputs]
        if missing:
            return self._result(
                check,
                ip,
                result_hostname,
                status=check.result.error_status,
                parsed=parsed_data,
                error_message=f"Missing command output: {', '.join(missing)}",
            )

        insufficient = [
            command
            for command in check.commands
            if self._insufficient_output(outputs.get(command, ""))
        ]
        if insufficient:
            return self._result(
                check,
                ip,
                result_hostname,
                status=check.result.error_status,
                parsed=parsed_data,
                error_message=f"Insufficient command evidence: {', '.join(insufficient)}",
            )
        relevant_warnings = [
            warning
            for warning in parsed_data.parser_warnings
            if any(command in warning for command in check.commands)
        ]
        if relevant_warnings:
            return self._result(
                check,
                ip,
                result_hostname,
                status=check.result.error_status,
                parsed=parsed_data,
                error_message="; ".join(relevant_warnings),
            )

        try:
            outcome = self._evaluate_by_type(check, outputs, parsed_data)
            matched_count = len(outcome.failed_objects) + len(outcome.passed_objects)
            status = outcome.status_override or (
                check.result.pass_status if outcome.passed else check.result.fail_status
            )
            if (
                check.check_type in OBJECT_CHECK_TYPES
                and matched_count == 0
                and outcome.status_override is None
            ):
                status = check.empty_scope_status or "Error"
                outcome.details.append(
                    f"No objects matched scope; using declared empty_scope_status={status}."
                )
            return self._result(
                check,
                ip,
                result_hostname,
                status=status,
                parsed=parsed_data,
                failed_objects=outcome.failed_objects,
                passed_objects=outcome.passed_objects,
                details=outcome.details,
            )
        except Exception as exc:
            return self._result(
                check,
                ip,
                result_hostname,
                status=check.result.error_status,
                parsed=parsed_data,
                error_message=str(exc),
            )

    def _evaluate_by_type(
        self,
        check: CheckDefinition,
        outputs: dict[str, str],
        parsed: ParsedDeviceData,
    ) -> EvaluationOutcome:
        if check.check_type == "manual_review":
            return EvaluationOutcome(passed=False, details=["Manual review required."])
        if check.check_type == "command_contains":
            return self._command_contains(check, outputs, expected=True)
        if check.check_type == "command_not_contains":
            return self._command_contains(check, outputs, expected=False)
        if check.check_type == "command_pattern_policy":
            return self._command_pattern_policy(check, outputs)
        if check.check_type == "command_regex":
            return self._command_regex(check, outputs)
        if check.check_type == "section_contains":
            return self._section_contains(check, parsed, expected=True)
        if check.check_type == "section_not_contains":
            return self._section_contains(check, parsed, expected=False)
        if check.check_type == "interface_policy":
            return self._interface_policy(check, parsed)
        if check.check_type == "interface_config_policy":
            return self._interface_config_policy(check, parsed)
        if check.check_type == "trunk_vlan_policy":
            return self._trunk_vlan_policy(check, parsed)
        if check.check_type == "acl_deny_logging_policy":
            return self._acl_deny_logging_policy(check, parsed)
        if check.check_type == "dhcp_snooping_policy":
            return self._dhcp_snooping_policy(check, parsed)
        if check.check_type == "arp_inspection_policy":
            return self._arp_inspection_policy(check, parsed)
        raise ValueError(f"Unsupported check type: {check.check_type}")

    def _result(
        self,
        check: CheckDefinition,
        ip: str,
        hostname: str,
        status: str,
        parsed: ParsedDeviceData,
        failed_objects: list[FindingObject] | None = None,
        passed_objects: list[FindingObject] | None = None,
        details: list[str] | None = None,
        error_message: str | None = None,
    ) -> CheckResult:
        failed = failed_objects or []
        passed = passed_objects or []
        detail_lines = details or []
        if failed and check.evidence.include_failed_objects:
            detail_lines.extend(
                f"Failed {obj.object_type} {obj.object_name}: {obj.details}" for obj in failed
            )
        if error_message:
            detail_lines.append(error_message)

        comments = self._comment_for_status(check, status)
        result = CheckResult(
            ip=ip,
            hostname=hostname,
            vuln_id=check.vuln_id,
            stig_family=check.stig_family,
            title=check.title,
            severity=check.severity,
            status=cast(StatusLiteral, status),
            official_stig_id=check.stig_id,
            custom_check_id=check.custom_check_id,
            control_origin=check.control_origin,
            include_in_official_totals=bool(check.include_in_official_totals),
            failed_objects=failed,
            passed_objects=passed,
            matched_object_count=len(failed) + len(passed),
            evidence_summary=(
                f"Evidence error: {error_message}"
                if error_message
                else f"Matched {len(failed) + len(passed)} object(s): "
                f"{len(passed)} passed, {len(failed)} failed."
            ),
            finding_details="\n".join(line for line in detail_lines if line),
            comments=comments,
            commands_used=check.commands,
            error_message=error_message,
            parser_warnings=parsed.parser_warnings,
        )
        return apply_exceptions(result, self.exception_rules)

    def _insufficient_output(self, output: str) -> bool:
        text = output.strip()
        if not text:
            return True
        lowered = text.lower()
        meaningful_lines = [line for line in text.splitlines() if line.strip()]
        if len(meaningful_lines) <= 2 and (
            "building configuration" in lowered or "current configuration : 0 bytes" in lowered
        ):
            return True
        return any(
            marker in lowered
            for marker in (
                "% invalid input",
                "% incomplete command",
                "% ambiguous command",
                "authorization failed",
                "command authorization failed",
                "permission denied",
            )
        )

    def _comment_for_status(self, check: CheckDefinition, status: str) -> str:
        if status == check.result.pass_status and check.evidence.pass_comment:
            return self._render_template(check.evidence.pass_comment)
        if status == check.result.fail_status and check.evidence.fail_comment:
            return self._render_template(check.evidence.fail_comment)
        if status == check.result.error_status and check.evidence.error_comment:
            return self._render_template(check.evidence.error_comment)
        if status == "NotAFinding":
            return self.profile.comments.default_pass_prefix
        if status == "Open":
            return self.profile.comments.default_open_prefix
        if status == "Error":
            return self.profile.comments.default_error_prefix
        return ""

    def _render_template(self, template: str, extra_context: dict[str, Any] | None = None) -> str:
        context = {
            "unused_vlan": self.profile.unused_vlan,
            "additional_pruned_vlans": self.profile.trunk_policy.additional_pruned_vlans,
            "dhcp_snooping.vlans": self.profile.dhcp_snooping.vlans,
            "arp_inspection.vlans": self.profile.arp_inspection.vlans,
        }
        if extra_context:
            context.update(extra_context)

        def format_value(value: Any) -> str:
            if value is None:
                return ""
            if isinstance(value, (list, set, tuple)):
                return ",".join(str(item) for item in value)
            return str(value)

        def replace(match: re.Match[str]) -> str:
            key = match.group(1).strip()
            value = context.get(key)
            if value is None:
                value = self._profile_value(key)
            return format_value(value)

        return re.sub(r"{{\s*([^}]+)\s*}}", replace, template)

    def _profile_value(self, key: str) -> Any:
        current: Any = self.profile
        for part in key.split("."):
            if isinstance(current, dict):
                current = current.get(part)
            else:
                current = getattr(current, part, None)
            if current is None:
                break
        if current is not None:
            return current

        if key in self.profile.variables:
            return self.profile.variables[key]

        for parent_name in (
            "disabled_port_policy",
            "trunk_policy",
            "dhcp_snooping",
            "arp_inspection",
            "comments",
        ):
            parent = getattr(self.profile, parent_name)
            if hasattr(parent, key):
                return getattr(parent, key)
        return None

    def _profile_list(self, key: str) -> set[Any]:
        value = self._profile_value(key)
        if value is None:
            return set()
        if isinstance(value, set):
            return value
        if isinstance(value, list):
            return set(value)
        return {value}

    def _condition_passes(
        self, field_value: Any, condition: FieldCondition | dict[str, Any]
    ) -> bool:
        op = condition.get("op")
        expected = condition.get("value")
        if op == "equals_profile_value":
            expected = self._profile_value(str(condition.get("profile_key")))
            return field_value == expected
        if op == "includes_profile_list":
            required = self._profile_list(str(condition.get("profile_key")))
            return required.issubset(set(field_value or []))
        if op == "excludes_profile_list":
            forbidden = self._profile_list(str(condition.get("profile_key")))
            return set(field_value or []).isdisjoint(forbidden)
        if op == "equals":
            return field_value == expected
        if op == "not_equals":
            return field_value != expected
        if op == "includes":
            return expected in set(field_value or [])
        if op == "excludes":
            return expected not in set(field_value or [])
        if op == "contains":
            return str(expected) in str(field_value)
        if op == "regex":
            return bool(re.search(str(expected), str(field_value), flags=re.MULTILINE))
        raise ValueError(f"Unsupported condition op: {op}")

    def _conditions_pass(
        self, field_getter: Any, conditions: Iterable[FieldCondition | dict[str, Any]]
    ) -> bool:
        return all(
            self._condition_passes(field_getter(str(condition.get("field"))), condition)
            for condition in conditions
        )

    def _command_contains(
        self,
        check: CheckDefinition,
        outputs: dict[str, str],
        expected: bool,
    ) -> EvaluationOutcome:
        command = check.conditions.get("command") or check.commands[0]
        needle = check.conditions.get("contains") or check.conditions.get("value")
        if needle is None:
            raise ValueError(
                "command contains checks require conditions.contains or conditions.value"
            )
        haystack = outputs.get(command, "")
        case_sensitive = bool(check.conditions.get("case_sensitive", False))
        left = haystack if case_sensitive else haystack.lower()
        right = str(needle) if case_sensitive else str(needle).lower()
        found = right in left
        passed = found if expected else not found
        return EvaluationOutcome(
            passed=passed,
            details=[
                f"Command {command} {'contains' if found else 'does not contain'} expected text."
            ],
        )

    def _command_regex(self, check: CheckDefinition, outputs: dict[str, str]) -> EvaluationOutcome:
        command = check.conditions.get("command") or check.commands[0]
        pattern = check.conditions.get("pattern") or check.conditions.get("value")
        if pattern is None:
            raise ValueError("command_regex checks require conditions.pattern or conditions.value")
        matched = self._regex_matches(
            str(pattern),
            outputs.get(command, ""),
            case_sensitive=bool(check.conditions.get("case_sensitive", False)),
        )
        return EvaluationOutcome(passed=matched, details=[f"Regex evaluated against {command}."])

    def _regex_matches(self, pattern: str, text: str, case_sensitive: bool = False) -> bool:
        flags = re.MULTILINE
        if not case_sensitive:
            flags |= re.IGNORECASE
        return bool(re.search(pattern, text, flags=flags))

    def _pattern_label(self, pattern_config: dict[str, Any]) -> str:
        label = str(pattern_config.get("description") or pattern_config.get("pattern") or "")
        return self._render_template(label)

    def _pattern_value(self, pattern_config: dict[str, Any]) -> str:
        pattern = pattern_config.get("pattern") or pattern_config.get("value")
        if pattern is None:
            raise ValueError("pattern policies require pattern values")
        return self._render_template(str(pattern))

    def _profile_pattern_configs(
        self, pattern_configs: Iterable[dict[str, Any]]
    ) -> list[dict[str, Any]]:
        expanded: list[dict[str, Any]] = []
        for pattern_config in pattern_configs:
            profile_key = pattern_config.get("profile_key")
            if not profile_key:
                continue
            for item in sorted(self._profile_list(str(profile_key))):
                rendered = {
                    key: value
                    for key, value in pattern_config.items()
                    if key not in {"profile_key", "pattern_template", "description_template"}
                }
                pattern_template = (
                    pattern_config.get("pattern_template")
                    or pattern_config.get("pattern")
                    or pattern_config.get("value")
                )
                if pattern_template is None:
                    raise ValueError("profile pattern policies require pattern_template or pattern")
                rendered["pattern"] = self._render_template(str(pattern_template), {"item": item})
                description_template = (
                    pattern_config.get("description_template")
                    or pattern_config.get("description")
                    or pattern_template
                )
                rendered["description"] = self._render_template(
                    str(description_template), {"item": item}
                )
                rendered["object_type"] = str(pattern_config.get("object_type") or "profile_value")
                rendered["object_name"] = str(item)
                expanded.append(rendered)
        return expanded

    def _command_pattern_match_text(
        self,
        outputs: dict[str, str],
        pattern_config: dict[str, Any],
        default_command: str,
    ) -> str | None:
        command = str(pattern_config.get("command") or default_command)
        pattern = self._pattern_value(pattern_config)
        flags = re.MULTILINE
        if not bool(pattern_config.get("case_sensitive", False)):
            flags |= re.IGNORECASE
        match = re.search(pattern, outputs.get(command, ""), flags=flags)
        return match.group(0).strip() if match else None

    def _command_pattern_matches(
        self,
        outputs: dict[str, str],
        pattern_config: dict[str, Any],
        default_command: str,
    ) -> bool:
        return (
            self._command_pattern_match_text(outputs, pattern_config, default_command) is not None
        )

    def _command_pattern_policy(
        self, check: CheckDefinition, outputs: dict[str, str]
    ) -> EvaluationOutcome:
        default_command = check.conditions.get("command") or (
            check.commands[0] if check.commands else ""
        )
        required = check.conditions.get("all", []) + self._profile_pattern_configs(
            check.conditions.get("profile_all", []),
        )
        alternatives = check.conditions.get("any", [])
        forbidden = check.conditions.get("none", []) + self._profile_pattern_configs(
            check.conditions.get("profile_none", []),
        )

        missing_configs = [
            pattern_config
            for pattern_config in required
            if not self._command_pattern_matches(outputs, pattern_config, default_command)
        ]
        forbidden_matches = [
            (
                pattern_config,
                self._command_pattern_match_text(outputs, pattern_config, default_command),
            )
            for pattern_config in forbidden
        ]
        forbidden_matches = [(config, text) for config, text in forbidden_matches if text]
        missing = [self._pattern_label(pattern_config) for pattern_config in missing_configs]
        forbidden_found = [
            self._pattern_label(pattern_config) for pattern_config, _ in forbidden_matches
        ]
        any_matched = True
        if alternatives:
            any_matched = any(
                self._command_pattern_matches(outputs, pattern_config, default_command)
                for pattern_config in alternatives
            )

        details: list[str] = []
        if missing:
            details.append(f"Missing required pattern(s): {', '.join(missing)}")
        if alternatives and not any_matched:
            details.append(
                "None of the acceptable pattern(s) matched: "
                + ", ".join(self._pattern_label(pattern_config) for pattern_config in alternatives)
            )
        if forbidden_found:
            details.append(f"Forbidden pattern(s) present: {', '.join(forbidden_found)}")
        if not details:
            details.append("Command pattern policy matched.")

        failed_objects = [
            FindingObject(
                object_type=str(pattern_config.get("object_type") or "pattern"),
                object_name=str(
                    pattern_config.get("object_name") or self._pattern_label(pattern_config)
                ),
                details="missing required pattern",
            )
            for pattern_config in missing_configs
        ]
        failed_objects.extend(
            FindingObject(
                object_type=str(pattern_config.get("object_type") or "pattern"),
                object_name=str(
                    pattern_config.get("object_name") or self._pattern_label(pattern_config)
                ),
                details=f"forbidden pattern present: {matched_text}",
            )
            for pattern_config, matched_text in forbidden_matches
        )

        return EvaluationOutcome(
            passed=not missing and any_matched and not forbidden_found,
            failed_objects=failed_objects,
            details=details,
        )

    def _section_contains(
        self,
        check: CheckDefinition,
        parsed: ParsedDeviceData,
        expected: bool,
    ) -> EvaluationOutcome:
        section = check.conditions.get("section")
        needle = check.conditions.get("contains") or check.conditions.get("value")
        if not section or needle is None:
            raise ValueError("section checks require conditions.section and conditions.contains")
        lines = parsed.running_config.sections.get(str(section), [])
        found = str(needle) in "\n".join(lines)
        return EvaluationOutcome(passed=found if expected else not found)

    def _interface_candidates(
        self, check: CheckDefinition, parsed: ParsedDeviceData
    ) -> list[InterfaceView]:
        interfaces_scope = check.scope.get("interfaces", {}) if check.scope else {}
        include_rules = interfaces_scope.get("include", [{}])
        candidates: list[InterfaceView] = []
        for interface in parsed.interfaces.values():
            include = False
            for rule in include_rules:
                if rule.get("type") == "physical" and not is_physical_interface(interface.name):
                    continue
                match = rule.get("match", {})
                admin_state = match.get("admin_state")
                if admin_state == "disabled_or_notconnect":
                    if interface.operational_status not in {"disabled", "notconnect"}:
                        continue
                status = match.get("status") or match.get("operational_status")
                if status is not None and not self._value_matches(
                    interface.operational_status, status
                ):
                    continue
                switchport_mode = match.get("switchport_mode")
                if switchport_mode is not None and not self._value_matches(
                    interface.switchport_mode,
                    switchport_mode,
                ):
                    continue
                access_vlan = match.get("access_vlan")
                if access_vlan is not None and not self._value_matches(
                    interface.access_vlan, access_vlan
                ):
                    continue
                media_type = match.get("media_type")
                if media_type is not None:
                    actual_media = interface.status.media_type if interface.status else None
                    if not self._value_matches(actual_media, media_type):
                        continue
                shutdown = match.get("shutdown")
                if shutdown is not None and interface.shutdown != shutdown:
                    continue
                include = True
            if include:
                candidates.append(interface)
        return candidates

    def _value_matches(self, actual: Any, expected: Any) -> bool:
        if isinstance(expected, ValueMatch):
            expected = expected.model_dump(by_alias=True, exclude_none=True)
        if isinstance(expected, list):
            return actual in expected
        if isinstance(expected, dict):
            if "equals" in expected and actual != expected["equals"]:
                return False
            if "not_equals" in expected and actual == expected["not_equals"]:
                return False
            if "in" in expected and actual not in expected["in"]:
                return False
            if "not_in" in expected and actual in expected["not_in"]:
                return False
            if "regex" in expected and not self._regex_matches(
                str(expected["regex"]), str(actual or "")
            ):
                return False
            return True
        return actual == expected

    def _interface_field(self, interface: InterfaceView, field: str) -> Any:
        if field == "shutdown":
            return interface.shutdown
        if field == "access_vlan":
            return interface.access_vlan
        if field == "status":
            return interface.operational_status
        if field == "switchport_mode":
            return interface.switchport_mode
        raise ValueError(f"Unsupported interface field: {field}")

    def _interface_config_policy(
        self, check: CheckDefinition, parsed: ParsedDeviceData
    ) -> EvaluationOutcome:
        if check.vuln_id == "CISC-L2-000200":
            return self._static_trunk_policy(parsed)
        required = check.conditions.get("required_patterns", []) + self._profile_pattern_configs(
            check.conditions.get("profile_required_patterns", []),
        )
        if (
            check.vuln_id == "CISC-L2-000210"
            and not self.profile.disabled_port_policy.require_shutdown
        ):
            required = [
                pattern
                for pattern in required
                if "shutdown" not in self._pattern_label(pattern).lower()
            ]
        alternatives = check.conditions.get("any_patterns", [])
        forbidden = check.conditions.get("forbidden_patterns", []) + self._profile_pattern_configs(
            check.conditions.get("profile_forbidden_patterns", []),
        )
        failed: list[FindingObject] = []
        passed: list[FindingObject] = []

        for interface in self._interface_candidates(check, parsed):
            raw_lines = interface.config.raw_lines if interface.config else []
            text = "\n".join(raw_lines)
            missing = [
                self._pattern_label(pattern_config)
                for pattern_config in required
                if not self._regex_matches(
                    self._pattern_value(pattern_config),
                    text,
                    case_sensitive=bool(pattern_config.get("case_sensitive", False)),
                )
            ]
            forbidden_found = [
                self._pattern_label(pattern_config)
                for pattern_config in forbidden
                if self._regex_matches(
                    self._pattern_value(pattern_config),
                    text,
                    case_sensitive=bool(pattern_config.get("case_sensitive", False)),
                )
            ]
            any_missing: list[str] = []
            for group_index, pattern_group in enumerate(alternatives, start=1):
                group = pattern_group if isinstance(pattern_group, list) else [pattern_group]
                if not any(
                    self._regex_matches(
                        self._pattern_value(pattern_config),
                        text,
                        case_sensitive=bool(pattern_config.get("case_sensitive", False)),
                    )
                    for pattern_config in group
                ):
                    any_missing.append(
                        " or ".join(self._pattern_label(pattern_config) for pattern_config in group)
                        or f"alternative group {group_index}"
                    )

            detail_parts = []
            if missing:
                detail_parts.append(f"missing: {', '.join(missing)}")
            if any_missing:
                detail_parts.append(f"missing one of: {', '.join(any_missing)}")
            if forbidden_found:
                detail_parts.append(f"forbidden present: {', '.join(forbidden_found)}")
            details = "; ".join(detail_parts) or "required interface config present"
            obj = FindingObject(
                object_type="interface", object_name=interface.name, details=details
            )
            if detail_parts:
                failed.append(obj)
            else:
                passed.append(obj)

        return EvaluationOutcome(passed=not failed, failed_objects=failed, passed_objects=passed)

    def _static_trunk_policy(self, parsed: ParsedDeviceData) -> EvaluationOutcome:
        failed: list[FindingObject] = []
        passed: list[FindingObject] = []
        for interface in parsed.interfaces.values():
            if not is_physical_interface(interface.name):
                continue
            configured_mode = (interface.switchport_mode or "").lower()
            operational_trunk = bool(
                interface.status and interface.status.vlan_text.lower() == "trunk"
            )
            if (
                configured_mode not in {"trunk", "dynamic desirable", "dynamic auto"}
                and not operational_trunk
            ):
                continue
            obj = FindingObject(
                object_type="interface",
                object_name=interface.name,
                details=(
                    f"configured_mode={configured_mode or 'unset'}, "
                    f"operational_trunk={operational_trunk}"
                ),
            )
            (passed if configured_mode == "trunk" else failed).append(obj)
        return EvaluationOutcome(passed=not failed, failed_objects=failed, passed_objects=passed)

    def _interface_policy(
        self, check: CheckDefinition, parsed: ParsedDeviceData
    ) -> EvaluationOutcome:
        conditions = check.conditions.get("all", [])
        failed: list[FindingObject] = []
        passed: list[FindingObject] = []
        for interface in self._interface_candidates(check, parsed):
            ok = self._conditions_pass(
                lambda field, item=interface: self._interface_field(item, field), conditions
            )
            details = (
                f"status={interface.operational_status}, shutdown={interface.shutdown}, "
                f"access_vlan={interface.access_vlan}"
            )
            obj = FindingObject(
                object_type="interface", object_name=interface.name, details=details
            )
            if ok:
                passed.append(obj)
            else:
                failed.append(obj)
        return EvaluationOutcome(passed=not failed, failed_objects=failed, passed_objects=passed)

    def _trunk_field(self, trunk_name: str, parsed: ParsedDeviceData, field: str) -> Any:
        trunk = parsed.trunks[trunk_name]
        if field == "allowed_vlans":
            return trunk.allowed_vlans
        if field == "active_vlans":
            return trunk.active_vlans
        if field == "status":
            return trunk.status
        if field == "mode":
            return trunk.mode
        if field == "native_vlan":
            return trunk.native_vlan
        raise ValueError(f"Unsupported trunk field: {field}")

    def _trunk_vlan_policy(
        self, check: CheckDefinition, parsed: ParsedDeviceData
    ) -> EvaluationOutcome:
        failed: list[FindingObject] = []
        passed: list[FindingObject] = []
        forbidden = set(self.profile.trunk_policy.additional_pruned_vlans)
        if self.profile.trunk_policy.vlan_1_must_be_pruned:
            forbidden.add(1)
        for interface in parsed.interfaces.values():
            configured_mode = (interface.switchport_mode or "").lower()
            operational_trunk = bool(
                interface.status and interface.status.vlan_text.lower() == "trunk"
            )
            if (
                configured_mode not in {"trunk", "dynamic desirable", "dynamic auto"}
                and not operational_trunk
            ):
                continue
            if not interface.config:
                continue
            allowed = interface.config.trunk_allowed_vlans
            effective = set(range(1, 4095)) if allowed is None else set(allowed)
            present = effective & forbidden
            details = (
                f"effective_allowed_vlans={vlan_set_to_text(effective)}; "
                f"forbidden_present={vlan_set_to_text(present)}"
            )
            obj = FindingObject(
                object_type="interface", object_name=interface.name, details=details
            )
            (failed if present else passed).append(obj)
        return EvaluationOutcome(passed=not failed, failed_objects=failed, passed_objects=passed)

    def _acl_in_scope(self, statement: AclStatement, settings: dict[str, Any]) -> bool:
        if statement.acl_type == "standard" and not settings.get("include_standard_acls", True):
            return False
        if statement.acl_type == "extended" and not settings.get("include_extended_acls", True):
            return False
        if statement.acl_type == "ipv6" and not settings.get("include_ipv6_acls", False):
            return False
        return True

    def _acl_deny_logging_policy(
        self, check: CheckDefinition, parsed: ParsedDeviceData
    ) -> EvaluationOutcome:
        settings = check.conditions.get("deny_statements", {})
        required_keyword = str(settings.get("require_keyword", "log-input")).lower()
        failed: list[FindingObject] = []
        passed: list[FindingObject] = []
        for statement in parsed.acls.deny_statements:
            if not self._acl_in_scope(statement, settings):
                continue
            has_required = re.search(
                rf"\b{re.escape(required_keyword)}\b", statement.text, re.IGNORECASE
            )
            sequence = f" {statement.sequence}" if statement.sequence is not None else ""
            name = f"{statement.acl_name}{sequence}"
            obj = FindingObject(
                object_type="acl_statement",
                object_name=name,
                details=statement.text,
            )
            if has_required:
                passed.append(obj)
            else:
                failed.append(obj)
        return EvaluationOutcome(passed=not failed, failed_objects=failed, passed_objects=passed)

    def _dhcp_field(self, parsed: ParsedDeviceData, field: str) -> Any:
        if field == "global_enabled":
            return parsed.dhcp_snooping.global_enabled
        if field == "snooping_vlans":
            return parsed.dhcp_snooping.vlans
        raise ValueError(f"Unsupported DHCP snooping field: {field}")

    def _dhcp_snooping_policy(
        self, check: CheckDefinition, parsed: ParsedDeviceData
    ) -> EvaluationOutcome:
        if not self.profile.dhcp_snooping.enabled:
            return EvaluationOutcome(
                passed=False,
                status_override="Not_Applicable",
                details=["DHCP snooping policy disabled by profile."],
            )
        conditions = check.conditions.get("all", [])
        ok = self._conditions_pass(lambda field: self._dhcp_field(parsed, field), conditions)
        failed: list[FindingObject] = []
        passed: list[FindingObject] = []
        required_vlans = self._profile_list("dhcp_snooping.vlans")
        missing_vlans = required_vlans - parsed.dhcp_snooping.vlans
        if not parsed.dhcp_snooping.global_enabled:
            failed.append(
                FindingObject(
                    object_type="global", object_name="ip dhcp snooping", details="global disabled"
                )
            )
        if missing_vlans:
            failed.append(
                FindingObject(
                    object_type="vlan",
                    object_name=vlan_set_to_text(set(missing_vlans)),
                    details="missing DHCP snooping VLANs",
                )
            )
        if ok and not failed:
            passed.append(
                FindingObject(
                    object_type="global",
                    object_name="dhcp_snooping",
                    details="required VLANs present",
                )
            )
        return EvaluationOutcome(
            passed=ok and not failed, failed_objects=failed, passed_objects=passed
        )

    def _arp_field(self, parsed: ParsedDeviceData, field: str) -> Any:
        if field == "inspection_vlans":
            return parsed.arp_inspection.vlans
        if field == "vlans":
            return parsed.arp_inspection.vlans
        raise ValueError(f"Unsupported ARP inspection field: {field}")

    def _arp_inspection_policy(
        self, check: CheckDefinition, parsed: ParsedDeviceData
    ) -> EvaluationOutcome:
        if not self.profile.arp_inspection.enabled:
            return EvaluationOutcome(
                passed=False,
                status_override="Not_Applicable",
                details=["ARP inspection policy disabled by profile."],
            )
        conditions = check.conditions.get("all", [])
        ok = self._conditions_pass(lambda field: self._arp_field(parsed, field), conditions)
        failed: list[FindingObject] = []
        passed: list[FindingObject] = []
        required_vlans = self._profile_list("arp_inspection.vlans")
        missing_vlans = required_vlans - parsed.arp_inspection.vlans
        if missing_vlans:
            failed.append(
                FindingObject(
                    object_type="vlan",
                    object_name=vlan_set_to_text(set(missing_vlans)),
                    details="missing ARP inspection VLANs",
                )
            )
        if ok and not failed:
            passed.append(
                FindingObject(
                    object_type="global",
                    object_name="arp_inspection",
                    details="required VLANs present",
                )
            )
        return EvaluationOutcome(
            passed=ok and not failed, failed_objects=failed, passed_objects=passed
        )
