"""Standard result objects emitted by the check engine."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal

from pydantic import BaseModel, Field, validator

from stig_audit_pro.config import VALID_STATUSES

StatusLiteral = Literal[
    "NotAFinding",
    "Open",
    "Not_Applicable",
    "Not_Reviewed",
    "Error",
    "Skipped",
]


class FindingObject(BaseModel):
    object_type: str
    object_name: str
    details: str = ""

    class Config:
        extra = "forbid"


class CheckResult(BaseModel):
    ip: str
    hostname: str
    vuln_id: str
    stig_family: str
    title: str
    severity: str
    status: StatusLiteral
    failed_objects: list[FindingObject] = Field(default_factory=list)
    passed_objects: list[FindingObject] = Field(default_factory=list)
    finding_details: str = ""
    comments: str = ""
    commands_used: list[str] = Field(default_factory=list)
    error_message: str | None = None
    parser_warnings: list[str] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    class Config:
        extra = "forbid"

    @validator("status")
    def validate_status(cls, value: str) -> str:
        if value not in VALID_STATUSES:
            raise ValueError(f"unsupported status: {value}")
        return value

    @property
    def passed(self) -> bool:
        return self.status == "NotAFinding"
