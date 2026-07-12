"""Stable result and scan evidence models."""

from __future__ import annotations

from datetime import UTC, date, datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from stig_audit_pro.core.models import StatusLiteral


class FindingObject(BaseModel):
    model_config = ConfigDict(extra="forbid")
    object_type: str
    object_name: str
    details: str = ""


class AppliedException(BaseModel):
    model_config = ConfigDict(extra="forbid")
    exception_id: str
    scope: str
    object_type: str | None = None
    object_name: str | None = None
    reason: str
    source: str = ""
    expires: date | None = None
    approver: str = ""
    ticket: str | None = None
    expired: bool = False


class CheckResult(BaseModel):
    model_config = ConfigDict(extra="forbid")
    ip: str
    hostname: str = ""
    vuln_id: str
    official_stig_id: str | None = None
    custom_check_id: str | None = None
    control_origin: str = "official"
    include_in_official_totals: bool = True
    stig_family: str
    title: str
    severity: str
    status: StatusLiteral
    failed_objects: list[FindingObject] = Field(default_factory=list)
    passed_objects: list[FindingObject] = Field(default_factory=list)
    excepted_objects: list[FindingObject] = Field(default_factory=list)
    matched_object_count: int = 0
    evidence_summary: str = ""
    finding_details: str = ""
    comments: str = ""
    commands_used: list[str] = Field(default_factory=list)
    evidence: dict[str, Any] = Field(default_factory=dict)
    error_message: str | None = None
    parser_warnings: list[str] = Field(default_factory=list)
    exceptions_applied: list[AppliedException] = Field(default_factory=list)
    evaluated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @property
    def timestamp(self) -> datetime:
        """Backward-compatible name used by existing report writers."""
        return self.evaluated_at

    @field_validator("status")
    @classmethod
    def status_is_known(cls, value: str) -> str:
        return value
