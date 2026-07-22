"""Overview dashboard for the desktop GUI."""

from __future__ import annotations

from collections import Counter
from typing import Any

import customtkinter as ctk

from stig_audit_pro.core.models import CheckDefinition, SiteProfile
from stig_audit_pro.core.result_model import CheckResult
from stig_audit_pro.gui.widgets import DANGER, DANGER_HOVER, Metric, PageFrame, Panel, PRIMARY, SUCCESS, WARNING


class OverviewTab(PageFrame):
    def __init__(self, master: ctk.CTkBaseClass, app_controller: object) -> None:
        super().__init__(master)
        self.app_controller = app_controller
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        metrics = ctk.CTkFrame(self, fg_color="transparent")
        metrics.grid(row=0, column=0, sticky="ew", padx=12, pady=(12, 6))
        metrics.grid_columnconfigure((0, 1, 2, 3, 4, 5), weight=1)
        self.metrics = {
            "checks": Metric(metrics, "Checks", accent=PRIMARY),
            "automated": Metric(metrics, "Automated", accent=SUCCESS),
            "tailoring": Metric(metrics, "String Slots", accent=WARNING),
            "l2": Metric(metrics, "L2", accent=PRIMARY),
            "ndm": Metric(metrics, "NDM", accent=PRIMARY),
            "profile": Metric(metrics, "Profile", "-", accent=SUCCESS),
        }
        for column, metric in enumerate(self.metrics.values()):
            metric.grid(row=0, column=column, sticky="ew", padx=4)

        body = ctk.CTkFrame(self, fg_color="transparent")
        body.grid(row=1, column=0, sticky="nsew", padx=12, pady=(6, 12))
        body.grid_columnconfigure(0, weight=3)
        body.grid_columnconfigure(1, weight=2)
        body.grid_rowconfigure(0, weight=1)

        run_panel = Panel(body, "Scan Console")
        run_panel.grid(row=0, column=0, sticky="nsew", padx=(0, 6))
        run_panel.grid_columnconfigure((0, 1, 2), weight=1)
        run_panel.grid_rowconfigure(3, weight=1)

        ctk.CTkButton(
            run_panel,
            text="Targets",
            command=lambda: app_controller.show_tab("Targets"),
        ).grid(row=1, column=0, sticky="ew", padx=(12, 6), pady=(10, 8))
        ctk.CTkButton(
            run_panel,
            text="Run Compliant Demo",
            command=lambda: app_controller.run_sample_audit("compliant"),
            fg_color=SUCCESS,
            hover_color="#0f6b30",
        ).grid(row=1, column=1, sticky="ew", padx=6, pady=(10, 8))
        ctk.CTkButton(
            run_panel,
            text="Run Noncompliant Demo",
            command=lambda: app_controller.run_sample_audit("noncompliant"),
            fg_color=DANGER,
            hover_color=DANGER_HOVER,
        ).grid(row=1, column=2, sticky="ew", padx=(6, 12), pady=(10, 8))

        quick_row = ctk.CTkFrame(run_panel, fg_color="transparent")
        quick_row.grid(row=2, column=0, columnspan=3, sticky="ew", padx=12, pady=(0, 10))
        quick_row.grid_columnconfigure((0, 1, 2), weight=1)
        ctk.CTkButton(quick_row, text="Checks", command=lambda: app_controller.show_tab("Checks")).grid(row=0, column=0, sticky="ew", padx=(0, 6))
        ctk.CTkButton(quick_row, text="STIG Sources", command=lambda: app_controller.show_tab("STIG / CKL")).grid(row=0, column=1, sticky="ew", padx=6)
        ctk.CTkButton(quick_row, text="Reports", command=lambda: app_controller.show_tab("Reports")).grid(row=0, column=2, sticky="ew", padx=(6, 0))

        self.run_summary = ctk.CTkTextbox(run_panel, wrap="word", height=260)
        self.run_summary.grid(row=3, column=0, columnspan=3, sticky="nsew", padx=12, pady=(0, 12))
        self._set_run_summary("No scan results loaded.")

        ops_panel = Panel(body, "Library Status")
        ops_panel.grid(row=0, column=1, sticky="nsew", padx=(6, 0))
        ops_panel.grid_columnconfigure(0, weight=1)
        ops_panel.grid_rowconfigure(1, weight=1)
        self.library_status = ctk.CTkTextbox(ops_panel, wrap="word", height=320)
        self.library_status.grid(row=1, column=0, sticky="nsew", padx=12, pady=(10, 12))
        self._set_library_status("Loading check libraries.")

    def refresh_inventory(self, checks: list[CheckDefinition], profile: SiteProfile | None) -> None:
        family_counts = Counter(check.stig_family for check in checks)
        automated = sum(1 for check in checks if check.automated and check.check_type != "manual_review")
        string_slots = sum(self._blank_string_slots(check.conditions) for check in checks)
        self.metrics["checks"].set(len(checks))
        self.metrics["automated"].set(automated)
        self.metrics["tailoring"].set(string_slots)
        self.metrics["l2"].set(family_counts.get("IOSXE_L2", 0))
        self.metrics["ndm"].set(family_counts.get("IOSXE_NDM", 0))
        self.metrics["profile"].set(profile.profile_name if profile else "-")

        lines = [
            f"Loaded checks: {len(checks)}",
            f"Automated checks: {automated}",
            f"Manual or placeholder checks: {len(checks) - automated}",
            f"Editable blank string slots: {string_slots}",
            f"Active profile: {profile.profile_name if profile else '-'}",
            "",
            "Families:",
        ]
        for family, count in sorted(family_counts.items()):
            lines.append(f"- {family}: {count}")
        self._set_library_status("\n".join(lines))

    def refresh_results(self, results: list[CheckResult]) -> None:
        if not results:
            self._set_run_summary("No scan results loaded.")
            return
        counts = Counter(result.status for result in results)
        devices = sorted({result.ip for result in results})
        open_findings = [result for result in results if result.status == "Open"][:12]
        lines = [
            f"Devices scanned: {len(devices)}",
            f"Total results: {len(results)}",
            f"NotAFinding: {counts.get('NotAFinding', 0)}",
            f"Open: {counts.get('Open', 0)}",
            f"NotReviewed: {counts.get('Not_Reviewed', 0)}",
            f"NotApplicable: {counts.get('Not_Applicable', 0)}",
            f"Error: {counts.get('Error', 0)}",
            f"Skipped: {counts.get('Skipped', 0)}",
            "",
            "Open findings:",
        ]
        if open_findings:
            lines.extend(f"- {result.ip} {result.vuln_id}: {result.title}" for result in open_findings)
        else:
            lines.append("None")
        self._set_run_summary("\n".join(lines))

    def _blank_string_slots(self, value: Any) -> int:
        if isinstance(value, dict):
            count = 0
            for key, child in value.items():
                if key in {"strings", "required_strings", "forbidden_strings"} and child == []:
                    count += 1
                else:
                    count += self._blank_string_slots(child)
            return count
        if isinstance(value, list):
            return sum(self._blank_string_slots(item) for item in value)
        return 0

    def _set_run_summary(self, text: str) -> None:
        self.run_summary.configure(state="normal")
        self.run_summary.delete("1.0", "end")
        self.run_summary.insert("1.0", text)
        self.run_summary.configure(state="disabled")

    def _set_library_status(self, text: str) -> None:
        self.library_status.configure(state="normal")
        self.library_status.delete("1.0", "end")
        self.library_status.insert("1.0", text)
        self.library_status.configure(state="disabled")
