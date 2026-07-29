"""Bounded, cancellable multi-device scan orchestration."""

from __future__ import annotations

import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Literal

from stig_audit_pro.core.ssh_runner import (
    DeviceCommandRun,
    DeviceCredentials,
    DeviceTarget,
    NetmikoSshRunner,
)

FailureCategory = Literal[
    "none", "cancelled", "connection", "authentication", "command", "parser", "evaluation"
]


@dataclass(slots=True)
class DeviceScanOutcome:
    ip: str
    status: str
    category: FailureCategory = "none"
    outputs: dict[str, str] = field(default_factory=dict)
    error_message: str | None = None
    attempts: int = 1


class ScanOrchestrator:
    def __init__(
        self,
        runner_factory: Callable[[], NetmikoSshRunner],
        concurrency: int = 4,
        retries: int = 1,
    ) -> None:
        self.runner_factory = runner_factory
        self.concurrency = max(1, min(concurrency, 32))
        self.retries = max(0, retries)
        self._cancel = threading.Event()

    def cancel(self) -> None:
        self._cancel.set()

    def run(
        self,
        targets: list[DeviceTarget],
        credentials: DeviceCredentials,
        commands: list[str],
        run_id: str,
        progress: Callable[[int, int, DeviceScanOutcome], None] | None = None,
    ) -> list[DeviceScanOutcome]:
        outcomes: list[DeviceScanOutcome] = []
        total = len(targets)
        with ThreadPoolExecutor(
            max_workers=self.concurrency, thread_name_prefix="stig-scan"
        ) as pool:
            futures = {
                pool.submit(self._scan_one, target, credentials, commands, run_id): target
                for target in targets
            }
            for completed, future in enumerate(as_completed(futures), start=1):
                if self._cancel.is_set():
                    for pending in futures:
                        pending.cancel()
                try:
                    outcome = future.result()
                except Exception as exc:
                    target = futures[future]
                    outcome = DeviceScanOutcome(
                        ip=target.ip, status="failed", category="command", error_message=str(exc)
                    )
                outcomes.append(outcome)
                if progress:
                    progress(completed, total, outcome)
        return sorted(outcomes, key=lambda item: item.ip)

    def _scan_one(
        self,
        target: DeviceTarget,
        credentials: DeviceCredentials,
        commands: list[str],
        run_id: str,
    ) -> DeviceScanOutcome:
        if self._cancel.is_set():
            return DeviceScanOutcome(ip=target.ip, status="cancelled", category="cancelled")
        last: DeviceCommandRun | None = None
        for attempt in range(1, self.retries + 2):
            if self._cancel.is_set():
                return DeviceScanOutcome(
                    ip=target.ip, status="cancelled", category="cancelled", attempts=attempt
                )
            last = self.runner_factory().run_commands(target, credentials, commands, run_id=run_id)
            if last.status == "scanned":
                return DeviceScanOutcome(
                    ip=target.ip, status="scanned", outputs=last.outputs, attempts=attempt
                )
            category = self._categorize(last.error_message or "")
            if category != "connection":
                break
        assert last is not None
        return DeviceScanOutcome(
            ip=target.ip,
            status="failed",
            category=self._categorize(last.error_message or ""),
            outputs=last.outputs,
            error_message=last.error_message,
            attempts=min(self.retries + 1, attempt),
        )

    def _categorize(self, message: str) -> FailureCategory:
        lowered = message.lower()
        if any(word in lowered for word in ("auth", "password", "permission denied")):
            return "authentication"
        if any(
            word in lowered for word in ("timeout", "timed out", "refused", "unreachable", "dns")
        ):
            return "connection"
        return "command"
