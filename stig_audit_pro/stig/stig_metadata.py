"""STIG metadata models extracted from XCCDF sources."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from pydantic import BaseModel, Field


class StigRuleMetadata(BaseModel):
    vuln_id: str
    rule_id: str = ""
    stig_id: str = ""
    group_id: str = ""
    title: str = ""
    severity: str = ""
    check_text: str = ""
    fix_text: str = ""

    class Config:
        extra = "forbid"


class StigBenchmarkMetadata(BaseModel):
    source_path: str = ""
    source_filename: str = ""
    family: str = ""
    benchmark_id: str = ""
    title: str = ""
    version: str = ""
    release_info: str = ""
    release_date: str = ""
    imported_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    rules: list[StigRuleMetadata] = Field(default_factory=list)

    class Config:
        extra = "forbid"

    @property
    def rule_count(self) -> int:
        return len(self.rules)

    def rule_by_vuln(self, vuln_id: str) -> StigRuleMetadata | None:
        for rule in self.rules:
            if rule.vuln_id == vuln_id:
                return rule
        return None

    @property
    def display_name(self) -> str:
        return self.title or self.benchmark_id or Path(self.source_filename).stem
