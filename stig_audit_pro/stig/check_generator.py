"""Generate starter manual-review checks from imported STIG metadata."""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path

import yaml

from stig_audit_pro.core.models import (
    CheckDefinition,
    CheckLibrary,
    EvidenceConfig,
    ResultMapping,
)
from stig_audit_pro.stig.stig_metadata import StigBenchmarkMetadata, StigRuleMetadata

GENERATED_LIBRARY_NAME = "generated_stig_manual_starters"
SEVERITY_TO_CATEGORY = {
    "high": "cat1",
    "medium": "cat2",
    "low": "cat3",
}


def build_manual_starter_library(
    metadata_items: Iterable[StigBenchmarkMetadata],
    existing_checks: Iterable[CheckDefinition],
) -> CheckLibrary:
    existing_keys = _existing_rule_keys(existing_checks)
    generated: list[CheckDefinition] = []
    seen_generated: set[str] = set()
    for metadata in metadata_items:
        for rule in metadata.rules:
            key = _rule_key(rule)
            if not key or key in existing_keys or key in seen_generated:
                continue
            seen_generated.add(key)
            generated.append(_manual_check_from_rule(metadata, rule, key))
    return CheckLibrary(library_name=GENERATED_LIBRARY_NAME, checks=generated)


def write_manual_starter_library(library: CheckLibrary, path: str | Path) -> Path:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    payload = _model_dump(library)
    destination.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
    return destination


def _manual_check_from_rule(
    metadata: StigBenchmarkMetadata,
    rule: StigRuleMetadata,
    key: str,
) -> CheckDefinition:
    return CheckDefinition(
        vuln_id=key,
        title=rule.title or key,
        stig_family=metadata.family or "UNKNOWN",
        severity=_severity_to_category(rule.severity),
        automated=False,
        check_type="manual_review",
        commands=[],
        stig_id=rule.stig_id or None,
        group_id=rule.group_id or rule.vuln_id or None,
        rule_id=rule.rule_id or None,
        source_benchmark=metadata.title or metadata.benchmark_id or None,
        source_version=metadata.version or None,
        source_release=metadata.release_info or None,
        source_rule_fingerprint=rule.fingerprint,
        result=ResultMapping(fail_status="Not_Reviewed"),
        evidence=EvidenceConfig(
            include_command_output=False,
            include_failed_objects=False,
            pass_comment="Manual review completed and requirement was marked NotAFinding.",
            fail_comment="Manual review required. Review the STIG requirement and customer/site tailoring.",
            error_comment="Manual review check could not be prepared.",
            finding_details_template="manual_review",
        ),
    )


def _existing_rule_keys(checks: Iterable[CheckDefinition]) -> set[str]:
    keys: set[str] = set()
    for check in checks:
        keys.add(check.vuln_id)
        if check.stig_id:
            keys.add(check.stig_id)
        if check.rule_id:
            keys.add(check.rule_id)
    return keys


def _rule_key(rule: StigRuleMetadata) -> str:
    return rule.stig_id or rule.vuln_id or rule.rule_id


def _severity_to_category(severity: str) -> str:
    return SEVERITY_TO_CATEGORY.get(severity.lower().strip(), severity or "unknown")


def _model_dump(value: object) -> object:
    if hasattr(value, "model_dump"):
        return value.model_dump(exclude_none=True)  # type: ignore[attr-defined]
    if hasattr(value, "dict"):
        return value.dict(exclude_none=True)  # type: ignore[attr-defined]
    return value
