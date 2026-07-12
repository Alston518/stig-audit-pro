"""Plain text and CSV audit report writers."""

from __future__ import annotations

import csv
from collections import Counter, defaultdict
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path

from stig_audit_pro.core.result_model import CheckResult, FindingObject

REPORT_STATUSES = ("NotAFinding", "Open", "Error", "Skipped", "Not_Applicable", "Not_Reviewed")


def build_text_report(
    results: list[CheckResult],
    generated_at: datetime | None = None,
    title: str = "STIG Audit Pro Scan Report",
) -> str:
    generated = generated_at or datetime.now(UTC)
    official_results = [result for result in results if result.include_in_official_totals]
    status_counts: Counter[str] = Counter(result.status for result in official_results)
    device_keys = {(result.ip, result.hostname) for result in results}
    scorable = status_counts["NotAFinding"] + status_counts["Open"] + status_counts["Error"]
    compliance = round((status_counts["NotAFinding"] / scorable) * 100) if scorable else 0

    lines = [
        title,
        "=" * len(title),
        f"Generated: {generated.astimezone().strftime('%Y-%m-%d %H:%M:%S %Z')}",
        f"Devices: {len(device_keys)}",
        f"Results: {len(results)}",
        f"Official results: {len(official_results)}",
        f"Automated compliance: {compliance}%",
        "",
        "Status Summary",
        "--------------",
    ]
    for status in REPORT_STATUSES:
        lines.append(f"{status}: {status_counts[status]}")

    lines.extend(["", "Device Summary", "--------------"])
    if results:
        for key, device_results in _group_by_device(results).items():
            device_counts = Counter(result.status for result in device_results)
            ip, hostname = key
            host_text = hostname if hostname and hostname != "unknown" else "unknown"
            lines.append(
                f"{ip} ({host_text}): "
                f"{len(device_results)} results, "
                f"{device_counts['NotAFinding']} NotAFinding, "
                f"{device_counts['Open']} Open, "
                f"{device_counts['Error']} Error, "
                f"{device_counts['Skipped']} Skipped"
            )
    else:
        lines.append("No results.")

    lines.extend(["", "Open Findings", "-------------"])
    open_results = [result for result in results if result.status == "Open"]
    if open_results:
        for result in open_results:
            lines.extend(_finding_block(result))
    else:
        lines.append("None")

    problem_results = [result for result in results if result.status in {"Error", "Skipped"}]
    lines.extend(["", "Errors And Skipped Devices", "--------------------------"])
    if problem_results:
        for result in problem_results:
            lines.extend(_finding_block(result))
    else:
        lines.append("None")

    return "\n".join(lines).rstrip() + "\n"


def write_text_report(results: list[CheckResult], path: str | Path) -> Path:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(build_text_report(results), encoding="utf-8")
    return destination


def write_csv_report(results: list[CheckResult], path: str | Path) -> Path:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "ip",
                "hostname",
                "vuln_id",
                "stig_family",
                "severity",
                "status",
                "title",
                "failed_objects",
                "passed_objects",
                "comments",
                "finding_details",
                "commands_used",
                "timestamp",
            ],
        )
        writer.writeheader()
        for result in results:
            writer.writerow(
                {
                    key: _safe_spreadsheet_value(value)
                    for key, value in {
                        "ip": result.ip,
                        "hostname": result.hostname,
                        "vuln_id": result.vuln_id,
                        "stig_family": result.stig_family,
                        "severity": result.severity,
                        "status": result.status,
                        "title": result.title,
                        "failed_objects": _objects_to_text(result.failed_objects),
                        "passed_objects": _objects_to_text(result.passed_objects),
                        "comments": result.comments,
                        "finding_details": result.finding_details,
                        "commands_used": "; ".join(result.commands_used),
                        "timestamp": result.timestamp.isoformat(),
                    }.items()
                }
            )
    return destination


def _group_by_device(results: list[CheckResult]) -> dict[tuple[str, str], list[CheckResult]]:
    grouped: dict[tuple[str, str], list[CheckResult]] = defaultdict(list)
    for result in results:
        grouped[(result.ip, result.hostname)].append(result)
    return dict(sorted(grouped.items(), key=lambda item: item[0]))


def _finding_block(result: CheckResult) -> list[str]:
    failed_objects = _objects_to_text(result.failed_objects) or "None"
    details = result.finding_details.strip() or result.comments.strip() or "No details captured."
    return [
        "",
        f"{result.ip} {result.hostname} - {result.vuln_id} ({result.status})",
        f"Title: {result.title}",
        f"Severity: {result.severity}",
        f"Failed objects: {failed_objects}",
        f"Details: {details}",
    ]


def _objects_to_text(objects: Iterable[FindingObject]) -> str:
    return "; ".join(
        f"{obj.object_type}:{obj.object_name}" + (f" ({obj.details})" if obj.details else "")
        for obj in objects
    )


def _safe_spreadsheet_value(value: object) -> object:
    """Prevent CSV cells from being interpreted as formulas by spreadsheet apps."""
    if not isinstance(value, str):
        return value
    if value.lstrip().startswith(("=", "+", "-", "@")):
        return "'" + value
    return value
