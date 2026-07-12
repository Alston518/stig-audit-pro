"""Plan safe commands needed for selected checks."""

from __future__ import annotations

from stig_audit_pro.config import DEFAULT_SHOW_COMMANDS, SAFE_COMMAND_PREFIXES
from stig_audit_pro.core.models import CheckDefinition


class UnsafeCommandError(ValueError):
    """Raised when a check or caller asks for a non-read-only command."""


def is_safe_command(command: str) -> bool:
    normalized = command.strip().lower()
    return any(normalized.startswith(prefix) for prefix in SAFE_COMMAND_PREFIXES)


def validate_safe_commands(commands: list[str]) -> None:
    unsafe = [command for command in commands if not is_safe_command(command)]
    if unsafe:
        raise UnsafeCommandError(f"Unsafe command(s) requested: {', '.join(unsafe)}")


def plan_commands(checks: list[CheckDefinition], run_all: bool = False) -> list[str]:
    commands: list[str] = []
    if run_all:
        commands.extend(DEFAULT_SHOW_COMMANDS)
    else:
        commands.append("terminal length 0")
        for check in checks:
            commands.extend(check.commands)

    deduped: list[str] = []
    seen: set[str] = set()
    for command in commands:
        normalized = command.strip()
        if normalized and normalized not in seen:
            seen.add(normalized)
            deduped.append(normalized)
    validate_safe_commands(deduped)
    return deduped
