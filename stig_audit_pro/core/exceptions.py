"""Validated, object-aware audit exceptions."""

from __future__ import annotations

from datetime import date
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from stig_audit_pro.core.models import StatusLiteral
from stig_audit_pro.core.result_model import AppliedException, CheckResult


class ExceptionRule(BaseModel):
    model_config = ConfigDict(extra="forbid")
    exception_id: str = ""
    vuln_id: str
    reason: str
    scope: Literal["control", "object"] | None = None
    ip: str | None = None
    hostname: str | None = None
    object_type: str | None = None
    object_name: str | None = None
    source: str = ""
    expires: date | None = None
    approver: str = ""
    ticket: str | None = None
    force_status: StatusLiteral = "NotAFinding"

    @field_validator("reason")
    @classmethod
    def reason_required(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("exception reason must not be empty")
        return value

    @model_validator(mode="after")
    def object_scope_requires_selector(self) -> ExceptionRule:
        if self.scope is None:
            if self.object_type and self.object_name:
                self.scope = "object"
            else:
                raise ValueError("whole-control exceptions must explicitly set scope: control")
        if self.scope == "object" and (not self.object_type or not self.object_name):
            raise ValueError("object exception requires object_type and object_name")
        if not self.exception_id:
            suffix = self.object_name or "control"
            self.exception_id = f"{self.vuln_id}:{suffix}"
        return self

    @property
    def expired(self) -> bool:
        return self.expires is not None and self.expires < date.today()


class ExceptionLibrary(BaseModel):
    model_config = ConfigDict(extra="forbid")
    exceptions: list[ExceptionRule] = Field(default_factory=list)


def _record(rule: ExceptionRule) -> AppliedException:
    return AppliedException(
        exception_id=rule.exception_id,
        scope=rule.scope or "control",
        object_type=rule.object_type,
        object_name=rule.object_name,
        reason=rule.reason,
        source=rule.source,
        expires=rule.expires,
        approver=rule.approver,
        ticket=rule.ticket,
        expired=rule.expired,
    )


def apply_exceptions(result: CheckResult, rules: list[ExceptionRule]) -> CheckResult:
    """Apply only active matching exceptions; never clear unrelated object failures."""
    for rule in rules:
        if rule.vuln_id != result.vuln_id:
            continue
        if rule.ip and rule.ip != result.ip:
            continue
        if rule.hostname and rule.hostname != result.hostname:
            continue
        record = _record(rule)
        if rule.expired:
            result.exceptions_applied.append(record)
            result.parser_warnings.append(f"Expired exception {rule.exception_id} was not applied")
            continue
        if rule.scope == "control":
            result.status = rule.force_status
            result.exceptions_applied.append(record)
            result.comments = (
                f"{result.comments}\nException {rule.exception_id}: {rule.reason}".strip()
            )
            continue
        remaining = []
        matched = []
        for finding in result.failed_objects:
            if finding.object_type == rule.object_type and finding.object_name == rule.object_name:
                matched.append(finding)
            else:
                remaining.append(finding)
        if matched:
            result.failed_objects = remaining
            result.excepted_objects.extend(matched)
            result.exceptions_applied.append(record)
    if result.status == "Open" and not result.failed_objects and result.excepted_objects:
        result.status = "NotAFinding"
    result.matched_object_count = (
        len(result.failed_objects) + len(result.passed_objects) + len(result.excepted_objects)
    )
    return result
