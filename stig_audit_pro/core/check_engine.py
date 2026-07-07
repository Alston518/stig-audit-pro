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
            status = check.result.pass_status if outcome.passed else check.result.fail_status
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
            details = ["Manual review required."]
            if check.check_text:
                details.extend(["STIG Check Text:", check.check_text])
            if check.fix_text:
                details.extend(["STIG Fix Text:", check.fix_text])
            return EvaluationOutcome(passed=False, details=details)
        if check.check_type == "command_contains":
            return self._command_contains(check, outputs, expected=True)
        if check.check_type == "command_not_contains":
            return self._command_contains(check, outputs, expected=False)
        if check.check_type == "command_regex":
            return self._command_regex(check, outputs)
        if check.check_type == "section_contains":
            return self._section_contains(check, parsed, expected=True)
        if check.check_type == "section_not_contains":
            return self._section_contains(check, parsed, expected=False)
        if check.check_type == "interface_policy":
            return self._interface_policy(check, parsed)
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

    def _render_template(self, template: str) -> str:
        context = {
            "unused_vlan": self.profile.unused_vlan,
            "additional_pruned_vlans": self.profile.trunk_policy.additional_pruned_vlans,
            "dhcp_snooping.vlans": self.profile.dhcp_snooping.vlans,
            "arp_inspection.vlans": self.profile.arp_inspection.vlans,
        }

        def replace(match: re.Match[str]) -> str:
            key = match.group(1).strip()
            value = context.get(key, self._profile_value(key))
            return str(value)

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
        flags = re.MULTILINE
        if not bool(check.conditions.get("case_sensitive", False)):
            flags |= re.IGNORECASE
        matched = bool(re.search(str(pattern), outputs.get(command, ""), flags=flags))
        return EvaluationOutcome(passed=matched, details=[f"Regex evaluated against {command}."])

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
                include = True
            if include:
                candidates.append(interface)
        return candidates

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
            details = f"allowed_vlans={vlan_set_to_text(trunk.allowed_vlans)}"
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
