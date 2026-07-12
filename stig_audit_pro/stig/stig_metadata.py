"""Validated normalized STIG benchmark metadata."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field


class StigRuleMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid")
    vuln_id: str
    rule_id: str = ""
    stig_id: str = ""
    group_id: str = ""
    title: str = ""
    severity: str = ""
    check_text: str = ""
    fix_text: str = ""

    @property
    def fingerprint(self) -> str:
        payload = self.model_dump(mode="json")
        return hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()


class StigBenchmarkMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid")
    source_path: str = ""
    source_filename: str = ""
    source_sha256: str = ""
    source_url: str = ""
    imported_path: str = ""
    family: str = ""
    benchmark_id: str = ""
    title: str = ""
    version: str = ""
    release_info: str = ""
    release_date: str = ""
    imported_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    rules: list[StigRuleMetadata] = Field(default_factory=list)

    @property
    def rule_count(self) -> int:
        return len(self.rules)

    def rule_by_vuln(self, vuln_id: str) -> StigRuleMetadata | None:
        return next((rule for rule in self.rules if rule.vuln_id == vuln_id), None)

    @property
    def display_name(self) -> str:
        return self.title or self.benchmark_id or Path(self.source_filename).stem
