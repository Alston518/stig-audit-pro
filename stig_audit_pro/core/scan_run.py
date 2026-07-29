"""Serializable identity and provenance for a complete scan run."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field

from stig_audit_pro.config import APP_VERSION
from stig_audit_pro.core.result_model import AppliedException, CheckResult


class PackIdentity(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str
    version: str
    schema_version: int
    sha256: str


class StigIdentity(BaseModel):
    model_config = ConfigDict(extra="forbid")
    benchmark_id: str = ""
    version: str = ""
    release: str = ""
    source_sha256: str = ""


class ProfileIdentity(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str
    sha256: str


class ScanRun(BaseModel):
    model_config = ConfigDict(extra="forbid")
    run_id: UUID = Field(default_factory=uuid4)
    started_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    ended_at: datetime | None = None
    application_version: str = APP_VERSION
    check_packs: list[PackIdentity] = Field(default_factory=list)
    stig: StigIdentity = Field(default_factory=StigIdentity)
    profile: ProfileIdentity
    selected_targets: list[str] = Field(default_factory=list)
    device_facts: dict[str, dict[str, Any]] = Field(default_factory=dict)
    command_collection_status: dict[str, dict[str, Any]] = Field(default_factory=dict)
    parser_versions: dict[str, str] = Field(default_factory=dict)
    parser_warnings: dict[str, list[str]] = Field(default_factory=dict)
    results: list[CheckResult] = Field(default_factory=list)
    exceptions_used: list[AppliedException] = Field(default_factory=list)
    report_paths: list[str] = Field(default_factory=list)

    def finish(self) -> None:
        self.ended_at = datetime.now(UTC)
        self.exceptions_used = [
            item for result in self.results for item in result.exceptions_applied
        ]

    def manifest(self) -> dict[str, Any]:
        return self.model_dump(mode="json")


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_json(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()
