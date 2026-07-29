"""Non-destructive release comparison and check review marking."""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

from stig_audit_pro.core.models import CheckDefinition
from stig_audit_pro.stig.stig_metadata import StigBenchmarkMetadata, StigRuleMetadata


class RuleChange(BaseModel):
    model_config = ConfigDict(extra="forbid")
    stable_key: str
    change_types: list[str] = Field(default_factory=list)
    old_rule: StigRuleMetadata | None = None
    new_rule: StigRuleMetadata | None = None


class StigDiff(BaseModel):
    model_config = ConfigDict(extra="forbid")
    old_version: str
    new_version: str
    added: list[RuleChange] = Field(default_factory=list)
    removed: list[RuleChange] = Field(default_factory=list)
    changed: list[RuleChange] = Field(default_factory=list)
    unchanged: list[RuleChange] = Field(default_factory=list)


class StigDiffService:
    FIELDS = {
        "severity": "changed severity",
        "title": "changed title",
        "check_text": "changed check text",
        "fix_text": "changed fix text",
        "rule_id": "changed rule ID",
        "stig_id": "changed STIG ID or group mapping",
        "group_id": "changed STIG ID or group mapping",
    }

    def compare(self, old: StigBenchmarkMetadata, new: StigBenchmarkMetadata) -> StigDiff:
        old_map = {self._key(rule): rule for rule in old.rules}
        new_map = {self._key(rule): rule for rule in new.rules}
        diff = StigDiff(old_version=old.version, new_version=new.version)
        for key in sorted(old_map.keys() | new_map.keys()):
            before, after = old_map.get(key), new_map.get(key)
            if before is None:
                diff.added.append(
                    RuleChange(stable_key=key, change_types=["added"], new_rule=after)
                )
            elif after is None:
                diff.removed.append(
                    RuleChange(stable_key=key, change_types=["removed"], old_rule=before)
                )
            else:
                changes = sorted(
                    {
                        label
                        for field, label in self.FIELDS.items()
                        if getattr(before, field) != getattr(after, field)
                    }
                )
                item = RuleChange(
                    stable_key=key, change_types=changes, old_rule=before, new_rule=after
                )
                (diff.changed if changes else diff.unchanged).append(item)
        return diff

    def mark_checks(self, checks: list[CheckDefinition], diff: StigDiff) -> None:
        changed = {item.stable_key for item in diff.changed}
        removed = {item.stable_key for item in diff.removed}
        for check in checks:
            keys = {value for value in (check.stig_id, check.rule_id, check.group_id) if value}
            if keys & removed:
                check.review_status = "Retired"
            elif keys & changed:
                check.review_status = "Review Required"

    def _key(self, rule: StigRuleMetadata) -> str:
        return rule.vuln_id or rule.stig_id or rule.rule_id
