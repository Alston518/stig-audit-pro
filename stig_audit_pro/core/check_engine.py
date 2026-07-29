"""Generic YAML-driven check engine."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable

from stig_audit_pro.core.exceptions import ExceptionRule, apply_exceptions
from stig_audit_pro.core.models import CheckDefinition, SiteProfile
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
    status: str | None = None


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

        try:
            outcome = self._evaluate_by_type(check, outputs, parsed_data)
            status = outcome.status or (check.result.pass_status if outcome.passed else check.result.fail_status)
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
        if check.check_type == "radius_server_policy":
            return self._radius_server_policy(check, parsed)
        if check.check_type == "root_guard_neighbor_policy":
            return self._root_guard_neighbor_policy(check, parsed)
        if check.check_type == "vty_session_limit_policy":
            return self._vty_session_limit_policy(check, outputs)
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
            status=status,
            failed_objects=failed,
            passed_objects=passed,
            finding_details="\n".join(line for line in detail_lines if line),
            comments=comments,
            commands_used=check.commands,
            error_message=error_message,
            parser_warnings=parsed.parser_warnings,
        )
        return apply_exceptions(result, self.exception_rules)

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
            "native_vlan": self.profile.native_vlan,
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
            "root_guard",
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

    def _condition_passes(self, field_value: Any, condition: dict[str, Any]) -> bool:
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

    def _conditions_pass(self, field_getter: Any, conditions: Iterable[dict[str, Any]]) -> bool:
        return all(self._condition_passes(field_getter(condition["field"]), condition) for condition in conditions)

    def _command_contains(
        self,
        check: CheckDefinition,
        outputs: dict[str, str],
        expected: bool,
    ) -> EvaluationOutcome:
        command = check.conditions.get("command") or check.commands[0]
        needle = check.conditions.get("contains") or check.conditions.get("value")
        if needle is None:
            raise ValueError("command contains checks require conditions.contains or conditions.value")
        haystack = outputs.get(command, "")
        case_sensitive = bool(check.conditions.get("case_sensitive", False))
        left = haystack if case_sensitive else haystack.lower()
        right = str(needle) if case_sensitive else str(needle).lower()
        found = right in left
        passed = found if expected else not found
        return EvaluationOutcome(
            passed=passed,
            details=[f"Command {command} {'contains' if found else 'does not contain'} expected text."],
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

    def _expand_pattern_configs(self, pattern_configs: Iterable[Any]) -> list[dict[str, Any]]:
        expanded: list[dict[str, Any]] = []
        for pattern_config in pattern_configs:
            if isinstance(pattern_config, str):
                if pattern_config.strip():
                    expanded.append({"string": pattern_config, "description": pattern_config})
                continue
            if not isinstance(pattern_config, dict):
                continue
            strings = pattern_config.get("strings")
            if strings is not None:
                for item in strings:
                    text = str(item).strip()
                    if not text:
                        continue
                    expanded_item = {
                        key: value
                        for key, value in pattern_config.items()
                        if key not in {"strings", "pattern", "value", "description"}
                    }
                    expanded_item["string"] = text
                    expanded_item["description"] = pattern_config.get("description") or text
                    expanded.append(expanded_item)
                continue
            string_value = str(pattern_config.get("string") or "").strip()
            pattern_value = pattern_config.get("pattern") or pattern_config.get("value")
            if string_value or pattern_value:
                expanded.append(pattern_config)
        return expanded

    def _pattern_label(self, pattern_config: dict[str, Any]) -> str:
        label = str(
            pattern_config.get("description")
            or pattern_config.get("string")
            or pattern_config.get("pattern")
            or ""
        )
        return self._render_template(label)

    def _pattern_value(self, pattern_config: dict[str, Any]) -> str:
        string_value = pattern_config.get("string")
        if string_value is not None:
            return re.escape(self._render_template(str(string_value)))
        pattern = pattern_config.get("pattern") or pattern_config.get("value")
        if pattern is None:
            raise ValueError("pattern policies require pattern values")
        return self._render_template(str(pattern))

    def _profile_pattern_configs(self, pattern_configs: Iterable[dict[str, Any]]) -> list[dict[str, Any]]:
        expanded: list[dict[str, Any]] = []
        for pattern_config in pattern_configs:
            profile_key = pattern_config.get("profile_key")
            if not profile_key:
                continue
            for item in sorted(self._profile_list(str(profile_key))):
                pattern_item = (
                    re.escape(str(item))
                    if bool(pattern_config.get("escape_item", False))
                    else item
                )
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
                rendered["pattern"] = self._render_template(
                    str(pattern_template),
                    {"item": pattern_item},
                )
                description_template = (
                    pattern_config.get("description_template")
                    or pattern_config.get("description")
                    or pattern_template
                )
                rendered["description"] = self._render_template(str(description_template), {"item": item})
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
        command = str(pattern_config.get("command") or default_command)
        return self._command_pattern_match_text(outputs, pattern_config, default_command) is not None

    def _command_pattern_policy(self, check: CheckDefinition, outputs: dict[str, str]) -> EvaluationOutcome:
        default_command = check.conditions.get("command") or (check.commands[0] if check.commands else "")
        required = self._expand_pattern_configs(check.conditions.get("all", [])) + self._profile_pattern_configs(
            check.conditions.get("profile_all", []),
        )
        alternatives = self._expand_pattern_configs(
            check.conditions.get("any", [])
        ) + self._profile_pattern_configs(
            check.conditions.get("profile_any", []),
        )
        forbidden = self._expand_pattern_configs(check.conditions.get("none", [])) + self._profile_pattern_configs(
            check.conditions.get("profile_none", []),
        )
        if not required and not alternatives and not forbidden:
            return EvaluationOutcome(
                passed=False,
                status="Not_Reviewed",
                details=["No search strings are configured for this check yet."],
            )

        missing_configs = [
            pattern_config
            for pattern_config in required
            if not self._command_pattern_matches(outputs, pattern_config, default_command)
        ]
        forbidden_matches = [
            (pattern_config, self._command_pattern_match_text(outputs, pattern_config, default_command))
            for pattern_config in forbidden
        ]
        forbidden_matches = [(config, text) for config, text in forbidden_matches if text]
        missing = [self._pattern_label(pattern_config) for pattern_config in missing_configs]
        forbidden_found = [self._pattern_label(pattern_config) for pattern_config, _ in forbidden_matches]
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
                object_name=str(pattern_config.get("object_name") or self._pattern_label(pattern_config)),
                details="missing required pattern",
            )
            for pattern_config in missing_configs
        ]
        failed_objects.extend(
            FindingObject(
                object_type=str(pattern_config.get("object_type") or "pattern"),
                object_name=str(pattern_config.get("object_name") or self._pattern_label(pattern_config)),
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

    def _interface_candidates(self, check: CheckDefinition, parsed: ParsedDeviceData) -> list[InterfaceView]:
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
                if status is not None and not self._value_matches(interface.operational_status, status):
                    continue
                switchport_mode = match.get("switchport_mode")
                if switchport_mode is not None and not self._value_matches(
                    interface.switchport_mode,
                    switchport_mode,
                ):
                    continue
                access_vlan = match.get("access_vlan")
                if access_vlan is not None and not self._value_matches(interface.access_vlan, access_vlan):
                    continue
                media_type = match.get("media_type")
                if media_type is not None:
                    actual_media = interface.status.media_type if interface.status else None
                    if not self._value_matches(actual_media, media_type):
                        continue
                include = True
            if include:
                candidates.append(interface)
        return candidates

    def _value_matches(self, actual: Any, expected: Any) -> bool:
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
            if "regex" in expected and not self._regex_matches(str(expected["regex"]), str(actual or "")):
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

    def _interface_config_policy(self, check: CheckDefinition, parsed: ParsedDeviceData) -> EvaluationOutcome:
        global_required = (
            self._expand_pattern_configs(check.conditions.get("global_required_patterns", []))
            + self._expand_pattern_configs(check.conditions.get("global_required_strings", []))
            + self._profile_pattern_configs(
                check.conditions.get("profile_global_required_patterns", [])
            )
        )
        exempt = (
            self._expand_pattern_configs(check.conditions.get("exempt_patterns", []))
            + self._expand_pattern_configs(check.conditions.get("exempt_strings", []))
        )
        required = (
            self._expand_pattern_configs(check.conditions.get("required_patterns", []))
            + self._expand_pattern_configs(check.conditions.get("required_strings", []))
            + self._profile_pattern_configs(
            check.conditions.get("profile_required_patterns", []),
        )
        )
        alternatives = check.conditions.get("any_patterns", [])
        forbidden = (
            self._expand_pattern_configs(check.conditions.get("forbidden_patterns", []))
            + self._expand_pattern_configs(check.conditions.get("forbidden_strings", []))
            + self._profile_pattern_configs(
            check.conditions.get("profile_forbidden_patterns", []),
        )
        )
        forbidden_field_values = check.conditions.get("forbidden_field_values", [])
        if (
            not global_required
            and not required
            and not alternatives
            and not forbidden
            and not forbidden_field_values
        ):
            return EvaluationOutcome(
                passed=False,
                status="Not_Reviewed",
                details=["No interface search strings are configured for this check yet."],
            )
        running_text = parsed.raw_outputs.get("show running-config", "")
        missing_global = [
            pattern_config
            for pattern_config in global_required
            if not self._regex_matches(
                self._pattern_value(pattern_config),
                running_text,
                case_sensitive=bool(pattern_config.get("case_sensitive", False)),
            )
        ]
        failed: list[FindingObject] = [
            FindingObject(
                object_type=str(pattern_config.get("object_type") or "global_config"),
                object_name=str(
                    pattern_config.get("object_name") or self._pattern_label(pattern_config)
                ),
                details="missing required global configuration",
            )
            for pattern_config in missing_global
        ]
        passed: list[FindingObject] = []

        candidates = self._interface_candidates(check, parsed)
        if check.conditions.get("require_candidates") and not candidates:
            return EvaluationOutcome(
                passed=False,
                status=check.result.error_status,
                details=["No matching interfaces were found in the collected command output."],
            )

        for interface in candidates:
            raw_lines = interface.config.raw_lines if interface.config else []
            text = "\n".join(raw_lines)
            exempt_found = [
                self._pattern_label(pattern_config)
                for pattern_config in exempt
                if self._regex_matches(
                    self._pattern_value(pattern_config),
                    text,
                    case_sensitive=bool(pattern_config.get("case_sensitive", False)),
                )
            ]
            if exempt_found:
                passed.append(
                    FindingObject(
                        object_type="interface",
                        object_name=interface.name,
                        details=f"exempt: {', '.join(exempt_found)}",
                    )
                )
                continue
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
            forbidden_field_matches: list[str] = []
            for field_config in forbidden_field_values:
                field = str(field_config.get("field") or "")
                if not field:
                    raise ValueError("forbidden_field_values entries require field")
                if "profile_key" in field_config:
                    expected = self._profile_value(str(field_config["profile_key"]))
                else:
                    expected = field_config.get("value")
                actual = self._interface_field(interface, field)
                if self._value_matches(actual, expected):
                    description = str(
                        field_config.get("description")
                        or f"{field} must not equal {expected}"
                    )
                    forbidden_field_matches.append(self._render_template(description))
            any_missing: list[str] = []
            for group_index, pattern_group in enumerate(alternatives, start=1):
                group = self._expand_pattern_configs(
                    pattern_group if isinstance(pattern_group, list) else [pattern_group],
                )
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
            if forbidden_field_matches:
                detail_parts.append(
                    f"forbidden value: {', '.join(forbidden_field_matches)}"
                )
            details = "; ".join(detail_parts) or "required interface config present"
            obj = FindingObject(object_type="interface", object_name=interface.name, details=details)
            if detail_parts:
                failed.append(obj)
            else:
                passed.append(obj)

        return EvaluationOutcome(passed=not failed, failed_objects=failed, passed_objects=passed)

    @staticmethod
    def _neighbor_name_variants(value: str) -> set[str]:
        normalized = value.strip().rstrip(".").lower()
        if not normalized:
            return set()
        return {normalized, normalized.split(".", 1)[0]}

    def _radius_server_policy(
        self,
        check: CheckDefinition,
        parsed: ParsedDeviceData,
    ) -> EvaluationOutcome:
        group_profile_key = str(
            check.conditions.get("radius_group_profile_key")
            or "endpoint_authentication.radius_group"
        )
        servers_profile_key = str(
            check.conditions.get("radius_servers_profile_key")
            or "endpoint_authentication.radius_servers"
        )
        addresses_profile_key = str(
            check.conditions.get("radius_addresses_profile_key")
            or "endpoint_authentication.radius_server_addresses"
        )

        group_name = str(self._profile_value(group_profile_key) or "").strip()
        raw_servers = self._profile_value(servers_profile_key)
        raw_addresses = self._profile_value(addresses_profile_key)
        if not group_name:
            raise ValueError(f"profile.{group_profile_key} must define a RADIUS group")
        if not isinstance(raw_servers, list):
            raise ValueError(f"profile.{servers_profile_key} must be a list")
        server_names = [str(value).strip() for value in raw_servers if str(value).strip()]
        normalized_names = {name.casefold() for name in server_names}
        if len(normalized_names) < 2:
            raise ValueError(
                f"profile.{servers_profile_key} must define at least two unique RADIUS servers"
            )
        if len(normalized_names) != len(server_names):
            raise ValueError(f"profile.{servers_profile_key} contains duplicate RADIUS servers")
        if not isinstance(raw_addresses, dict):
            raise ValueError(
                f"profile.{addresses_profile_key} must map RADIUS server names to IPv4 addresses"
            )

        normalized_addresses = {
            str(name).strip().casefold(): str(address).strip()
            for name, address in raw_addresses.items()
            if str(name).strip() and str(address).strip()
        }
        missing_addresses = [
            name for name in server_names if not normalized_addresses.get(name.casefold())
        ]
        if missing_addresses:
            raise ValueError(
                f"profile.{addresses_profile_key} is missing address mappings for: "
                + ", ".join(missing_addresses)
            )

        def positive_port(condition_key: str, default: int) -> int:
            value = check.conditions.get(condition_key, default)
            if isinstance(value, bool):
                raise ValueError(f"{condition_key} must be a valid TCP/UDP port")
            if isinstance(value, int):
                port = value
            elif isinstance(value, str) and value.strip().isdigit():
                port = int(value.strip())
            else:
                raise ValueError(f"{condition_key} must be a valid TCP/UDP port")
            if port < 1 or port > 65535:
                raise ValueError(f"{condition_key} must be between 1 and 65535")
            return port

        auth_port = positive_port("auth_port", 1812)
        acct_port = positive_port("acct_port", 1813)

        radius_sections: dict[str, tuple[str, list[str]]] = {}
        radius_group_sections: dict[str, tuple[str, list[str]]] = {}
        for header, lines in parsed.running_config.sections.items():
            radius_match = re.fullmatch(
                r"radius[ \t]+server[ \t]+(\S+)",
                header,
                flags=re.IGNORECASE,
            )
            if radius_match:
                radius_sections[radius_match.group(1).casefold()] = (header, lines)
                continue
            group_match = re.fullmatch(
                r"aaa[ \t]+group[ \t]+server[ \t]+radius[ \t]+(\S+)",
                header,
                flags=re.IGNORECASE,
            )
            if group_match:
                radius_group_sections[group_match.group(1).casefold()] = (header, lines)

        failed: list[FindingObject] = []
        passed: list[FindingObject] = []
        for server_name in server_names:
            expected_address = normalized_addresses[server_name.casefold()]
            section = radius_sections.get(server_name.casefold())
            failure_reasons: list[str] = []
            if section is None:
                failure_reasons.append("named RADIUS server section is missing")
            else:
                _, lines = section
                address_pattern = re.compile(
                    rf"^address[ \t]+ipv4[ \t]+{re.escape(expected_address)}"
                    rf"[ \t]+auth-port[ \t]+{auth_port}"
                    rf"[ \t]+acct-port[ \t]+{acct_port}[ \t]*$",
                    flags=re.IGNORECASE,
                )
                if not any(address_pattern.fullmatch(line.strip()) for line in lines):
                    failure_reasons.append(
                        f"expected address {expected_address} with auth-port {auth_port} "
                        f"and acct-port {acct_port} is missing"
                    )
                if not any(
                    re.fullmatch(r"key(?:[ \t]+\S+)+", line.strip(), flags=re.IGNORECASE)
                    for line in lines
                ):
                    failure_reasons.append("key command with at least one value is missing")

            server_object = FindingObject(
                object_type="radius_server",
                object_name=server_name,
                details="; ".join(failure_reasons)
                or (
                    f"address {expected_address}, auth-port {auth_port}, acct-port "
                    f"{acct_port}, and key are configured"
                ),
            )
            if failure_reasons:
                failed.append(server_object)
            else:
                passed.append(server_object)

        group_section = radius_group_sections.get(group_name.casefold())
        group_failures: list[str] = []
        if group_section is None:
            group_failures.append("required AAA RADIUS group section is missing")
        else:
            _, group_lines = group_section
            configured_members: set[str] = set()
            for line in group_lines:
                member_match = re.fullmatch(
                    r"server[ \t]+name[ \t]+(\S+)",
                    line.strip(),
                    flags=re.IGNORECASE,
                )
                if member_match:
                    configured_members.add(member_match.group(1).casefold())
            missing_members = [
                name for name in server_names if name.casefold() not in configured_members
            ]
            if missing_members:
                group_failures.append(
                    "missing server name entries: " + ", ".join(missing_members)
                )

        group_object = FindingObject(
            object_type="radius_group",
            object_name=group_name,
            details="; ".join(group_failures)
            or f"contains all {len(server_names)} profile-defined RADIUS servers",
        )
        if group_failures:
            failed.append(group_object)
        else:
            passed.append(group_object)

        return EvaluationOutcome(
            passed=not failed,
            failed_objects=failed,
            passed_objects=passed,
            details=[
                f"Validated {len(server_names)} profile-defined RADIUS servers and "
                f"AAA group {group_name}."
            ],
        )

    def _vty_session_limit_policy(
        self,
        check: CheckDefinition,
        outputs: dict[str, str],
    ) -> EvaluationOutcome:
        command = str(
            check.conditions.get("command")
            or (check.commands[0] if check.commands else "show running-config")
        )
        profile_key = str(
            check.conditions.get("maximum_sessions_profile_key")
            or "max_concurrent_management_sessions"
        )
        raw_maximum = self._profile_value(profile_key)
        if isinstance(raw_maximum, bool):
            raise ValueError(
                f"profile.{profile_key} must be a positive whole number, not a boolean"
            )
        if isinstance(raw_maximum, int):
            maximum = raw_maximum
        elif isinstance(raw_maximum, str) and re.fullmatch(r"\d+", raw_maximum.strip()):
            maximum = int(raw_maximum.strip())
        else:
            raise ValueError(
                f"profile.{profile_key} must be configured as a positive whole number"
            )
        if maximum < 1:
            raise ValueError(f"profile.{profile_key} must be greater than zero")

        vty_block_pattern = re.compile(
            r"^[ \t]*line[ \t]+vty[ \t]+(\d+)(?:[ \t]+(\d+))?[ \t]*\r?\n"
            r"((?:[ \t]+[^\r\n]*(?:\r?\n|$))*)",
            flags=re.IGNORECASE | re.MULTILINE,
        )
        session_limit_pattern = re.compile(
            r"^[ \t]+session-limit(?:[ \t]+([^\r\n]*?))?[ \t]*$",
            flags=re.IGNORECASE | re.MULTILINE,
        )

        blocks: list[tuple[str, int, int, list[str | None]]] = []
        invalid_ranges: list[FindingObject] = []
        for match in vty_block_pattern.finditer(outputs.get(command, "")):
            start = int(match.group(1))
            end = int(match.group(2) or match.group(1))
            name = f"line vty {start}" if start == end else f"line vty {start} {end}"
            if end < start:
                invalid_ranges.append(
                    FindingObject(
                        object_type="vty_section",
                        object_name=name,
                        details="VTY range ends before it starts",
                    )
                )
                continue
            session_limits = [
                limit.strip() if limit is not None else None
                for limit in session_limit_pattern.findall(match.group(3))
            ]
            blocks.append((name, start, end, session_limits))

        uses_session_limit = any(limits for _, _, _, limits in blocks)
        failed = list(invalid_ranges)
        passed: list[FindingObject] = []

        if uses_session_limit:
            for name, _, _, limits in blocks:
                if not limits:
                    failed.append(
                        FindingObject(
                            object_type="vty_section",
                            object_name=name,
                            details=(
                                "session-limit is missing while other VTY sections "
                                "use session-limit"
                            ),
                        )
                    )
                    continue

                section_failed = False
                for limit_text in limits:
                    if limit_text is None or not re.fullmatch(r"\d+", limit_text):
                        failed.append(
                            FindingObject(
                                object_type="vty_section",
                                object_name=name,
                                details="session-limit does not contain a valid whole number",
                            )
                        )
                        section_failed = True
                        continue
                    configured_limit = int(limit_text)
                    if configured_limit > maximum:
                        failed.append(
                            FindingObject(
                                object_type="vty_section",
                                object_name=name,
                                details=(
                                    f"session-limit {configured_limit} exceeds the "
                                    f"organization-defined maximum of {maximum}"
                                ),
                            )
                        )
                        section_failed = True

                if not section_failed:
                    passed.append(
                        FindingObject(
                            object_type="vty_section",
                            object_name=name,
                            details=(
                                "configured session-limit does not exceed the "
                                f"organization-defined maximum of {maximum}"
                            ),
                        )
                    )

            details = [
                "VTY session-limit mode evaluated against organization-defined "
                f"maximum {maximum}."
            ]
            return EvaluationOutcome(
                passed=not failed,
                failed_objects=failed,
                passed_objects=passed,
                details=details,
            )

        configured_vty_lines: set[int] = set()
        for _, start, end, _ in blocks:
            configured_vty_lines.update(range(start, end + 1))
        configured_count = len(configured_vty_lines)

        capacity = FindingObject(
            object_type="vty_capacity",
            object_name=f"{configured_count} configured VTY line(s)",
            details=(
                f"session-limit is not configured; available VTY line count is "
                f"{configured_count}, organization-defined maximum is {maximum}"
            ),
        )
        if configured_count > maximum:
            failed.append(capacity)
        else:
            passed.append(capacity)

        return EvaluationOutcome(
            passed=not failed,
            failed_objects=failed,
            passed_objects=passed,
            details=[
                "No VTY session-limit command was found; counted "
                f"{configured_count} unique VTY line(s) against maximum {maximum}."
            ],
        )

    def _root_guard_neighbor_policy(
        self,
        check: CheckDefinition,
        parsed: ParsedDeviceData,
    ) -> EvaluationOutcome:
        upstream_profile_key = str(
            check.conditions.get("upstream_profile_key") or "root_guard.upstream_switches"
        )
        configured_upstreams = sorted(str(value) for value in self._profile_list(upstream_profile_key))
        required_string = str(
            check.conditions.get("required_string") or "spanning-tree guard root"
        ).strip()
        if not configured_upstreams:
            return EvaluationOutcome(
                passed=False,
                status="Not_Reviewed",
                details=[
                    "No core/distribution CDP hostnames are configured in "
                    f"profile.{upstream_profile_key}."
                ],
            )

        upstream_names: set[str] = set()
        for hostname in configured_upstreams:
            upstream_names.update(self._neighbor_name_variants(hostname))

        if not parsed.cdp_neighbors:
            return EvaluationOutcome(
                passed=False,
                status="Not_Reviewed",
                details=["No CDP neighbor entries were available; topology could not be verified."],
            )

        switch_neighbors = [neighbor for neighbor in parsed.cdp_neighbors if neighbor.is_switch]
        target_neighbors = []
        exempted: list[FindingObject] = []
        unresolved: list[FindingObject] = []

        for neighbor in switch_neighbors:
            neighbor_names = self._neighbor_name_variants(neighbor.device_id)
            if neighbor_names & upstream_names:
                exempted.append(
                    FindingObject(
                        object_type="interface",
                        object_name=neighbor.local_interface or "unknown",
                        details=f"Root Guard exempt: upstream neighbor {neighbor.device_id}",
                    )
                )
            elif not neighbor.local_interface:
                unresolved.append(
                    FindingObject(
                        object_type="cdp_neighbor",
                        object_name=neighbor.device_id,
                        details="CDP entry did not identify the local interface",
                    )
                )
            else:
                target_neighbors.append(neighbor)

        failed: list[FindingObject] = []
        passed: list[FindingObject] = list(exempted)
        for neighbor in target_neighbors:
            local_name = neighbor.local_interface
            local_config = parsed.running_config.interfaces.get(local_name)
            config_names = [local_name]
            configs = [local_config] if local_config else []

            if local_config and local_config.channel_group:
                port_channel_name = f"Port-channel{local_config.channel_group}"
                port_channel_config = parsed.running_config.interfaces.get(port_channel_name)
                config_names.append(port_channel_name)
                if port_channel_config:
                    configs.append(port_channel_config)

            root_guard_present = any(
                any(line.strip().lower() == required_string.lower() for line in config.raw_lines)
                for config in configs
            )
            details = (
                f"neighbor={neighbor.device_id}; checked configuration on {', '.join(config_names)}"
            )
            obj = FindingObject(
                object_type="interface",
                object_name=local_name,
                details=details if root_guard_present else f"missing {required_string}; {details}",
            )
            if root_guard_present:
                passed.append(obj)
            else:
                failed.append(obj)

        if failed:
            return EvaluationOutcome(
                passed=False,
                failed_objects=failed,
                passed_objects=passed,
                details=["Root Guard is missing on one or more access-switch-facing interfaces."],
            )
        if unresolved:
            return EvaluationOutcome(
                passed=False,
                status="Not_Reviewed",
                failed_objects=unresolved,
                passed_objects=passed,
                details=["One or more switch neighbors could not be mapped to a local interface."],
            )
        if not target_neighbors:
            return EvaluationOutcome(
                passed=True,
                passed_objects=passed,
                details=[
                    "Only configured upstream core/distribution switch neighbors were "
                    "identified by CDP; no access-switch-facing interface required Root Guard."
                ],
            )
        return EvaluationOutcome(
            passed=True,
            passed_objects=passed,
            details=["Root Guard is configured on every CDP-identified access-switch-facing interface."],
        )

    def _interface_policy(self, check: CheckDefinition, parsed: ParsedDeviceData) -> EvaluationOutcome:
        conditions = check.conditions.get("all", [])
        failed: list[FindingObject] = []
        passed: list[FindingObject] = []
        for interface in self._interface_candidates(check, parsed):
            ok = self._conditions_pass(lambda field: self._interface_field(interface, field), conditions)
            details = (
                f"status={interface.operational_status}, shutdown={interface.shutdown}, "
                f"access_vlan={interface.access_vlan}"
            )
            obj = FindingObject(object_type="interface", object_name=interface.name, details=details)
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

    def _trunk_vlan_policy(self, check: CheckDefinition, parsed: ParsedDeviceData) -> EvaluationOutcome:
        conditions = check.conditions.get("all", [])
        failed: list[FindingObject] = []
        passed: list[FindingObject] = []
        for trunk_name, trunk in parsed.trunks.items():
            ok = self._conditions_pass(
                lambda field, name=trunk_name: self._trunk_field(name, parsed, field),
                conditions,
            )
            details = (
                f"mode={trunk.mode}, status={trunk.status}, native_vlan={trunk.native_vlan}, "
                f"allowed_vlans={vlan_set_to_text(trunk.allowed_vlans)}"
            )
            obj = FindingObject(object_type="interface", object_name=trunk_name, details=details)
            if ok:
                passed.append(obj)
            else:
                failed.append(obj)
        return EvaluationOutcome(passed=not failed, failed_objects=failed, passed_objects=passed)

    def _acl_in_scope(self, statement: AclStatement, settings: dict[str, Any]) -> bool:
        if statement.acl_type == "standard" and not settings.get("include_standard_acls", True):
            return False
        if statement.acl_type == "extended" and not settings.get("include_extended_acls", True):
            return False
        if statement.acl_type == "ipv6" and not settings.get("include_ipv6_acls", False):
            return False
        return True

    def _acl_deny_logging_policy(self, check: CheckDefinition, parsed: ParsedDeviceData) -> EvaluationOutcome:
        settings = check.conditions.get("deny_statements", {})
        required_keyword = str(settings.get("require_keyword", "log-input")).lower()
        failed: list[FindingObject] = []
        passed: list[FindingObject] = []
        for statement in parsed.acls.deny_statements:
            if not self._acl_in_scope(statement, settings):
                continue
            has_required = re.search(rf"\b{re.escape(required_keyword)}\b", statement.text, re.IGNORECASE)
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

    def _dhcp_snooping_policy(self, check: CheckDefinition, parsed: ParsedDeviceData) -> EvaluationOutcome:
        conditions = check.conditions.get("all", [])
        ok = self._conditions_pass(lambda field: self._dhcp_field(parsed, field), conditions)
        failed: list[FindingObject] = []
        passed: list[FindingObject] = []
        required_vlans = self._profile_list("dhcp_snooping.vlans")
        missing_vlans = required_vlans - parsed.dhcp_snooping.vlans
        if not parsed.dhcp_snooping.global_enabled:
            failed.append(FindingObject(object_type="global", object_name="ip dhcp snooping", details="global disabled"))
        if missing_vlans:
            failed.append(FindingObject(object_type="vlan", object_name=vlan_set_to_text(set(missing_vlans)), details="missing DHCP snooping VLANs"))
        if ok and not failed:
            passed.append(FindingObject(object_type="global", object_name="dhcp_snooping", details="required VLANs present"))
        return EvaluationOutcome(passed=ok and not failed, failed_objects=failed, passed_objects=passed)

    def _arp_field(self, parsed: ParsedDeviceData, field: str) -> Any:
        if field == "inspection_vlans":
            return parsed.arp_inspection.vlans
        if field == "vlans":
            return parsed.arp_inspection.vlans
        raise ValueError(f"Unsupported ARP inspection field: {field}")

    def _arp_inspection_policy(self, check: CheckDefinition, parsed: ParsedDeviceData) -> EvaluationOutcome:
        conditions = check.conditions.get("all", [])
        ok = self._conditions_pass(lambda field: self._arp_field(parsed, field), conditions)
        failed: list[FindingObject] = []
        passed: list[FindingObject] = []
        required_vlans = self._profile_list("arp_inspection.vlans")
        missing_vlans = required_vlans - parsed.arp_inspection.vlans
        if missing_vlans:
            failed.append(FindingObject(object_type="vlan", object_name=vlan_set_to_text(set(missing_vlans)), details="missing ARP inspection VLANs"))
        if ok and not failed:
            passed.append(FindingObject(object_type="global", object_name="arp_inspection", details="required VLANs present"))
        return EvaluationOutcome(passed=ok and not failed, failed_objects=failed, passed_objects=passed)
