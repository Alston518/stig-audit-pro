"""Reports tab shell for later report generation."""

from __future__ import annotations

import customtkinter as ctk

from stig_audit_pro.core.result_model import CheckResult
from stig_audit_pro.gui.widgets import Metric, PageFrame, Panel


class ReportsTab(PageFrame):
    def __init__(self, master: ctk.CTkBaseClass, app_controller: object) -> None:
        super().__init__(master)
        self.app_controller = app_controller
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        metrics = ctk.CTkFrame(self, fg_color="transparent")
        metrics.grid(row=0, column=0, sticky="ew", padx=12, pady=(12, 6))
        metrics.grid_columnconfigure((0, 1, 2, 3), weight=1)
        self.metrics = {
            "compliance": Metric(metrics, "Compliance", "0%"),
            "open": Metric(metrics, "Open"),
            "not_a_finding": Metric(metrics, "NotAFinding"),
            "error": Metric(metrics, "Error"),
        }
        for column, metric in enumerate(self.metrics.values()):
            metric.grid(row=0, column=column, sticky="ew", padx=4)

        panel = Panel(self, "Report Output")
        panel.grid(row=1, column=0, sticky="nsew", padx=12, pady=(6, 12))
        panel.grid_columnconfigure((0, 1), weight=1)
        ctk.CTkButton(panel, text="Generate Excel Summary", state="disabled").grid(row=1, column=0, sticky="ew", padx=(12, 6), pady=(14, 8))
        ctk.CTkButton(panel, text="Generate TXT Summary", state="disabled").grid(row=1, column=1, sticky="ew", padx=(6, 12), pady=(14, 8))
        self.summary = ctk.CTkTextbox(panel, height=260)
        self.summary.grid(row=2, column=0, columnspan=2, sticky="nsew", padx=12, pady=(4, 12))
        panel.grid_rowconfigure(2, weight=1)
        self.summary.insert("1.0", "No audit results loaded.")
        self.summary.configure(state="disabled")

    def refresh(self, results: list[CheckResult]) -> None:
        total = len(results)
        open_count = sum(1 for result in results if result.status == "Open")
        pass_count = sum(1 for result in results if result.status == "NotAFinding")
        error_count = sum(1 for result in results if result.status == "Error")
        compliance = round((pass_count / total) * 100) if total else 0
        self.metrics["compliance"].set(f"{compliance}%")
        self.metrics["open"].set(open_count)
        self.metrics["not_a_finding"].set(pass_count)
        self.metrics["error"].set(error_count)
        lines = [
            f"Total checks: {total}",
            f"NotAFinding: {pass_count}",
            f"Open: {open_count}",
            f"Error: {error_count}",
            "",
            "Open findings:",
        ]
        lines.extend(f"- {result.vuln_id}: {result.title}" for result in results if result.status == "Open")
        if open_count == 0:
            lines.append("None")
        self.summary.configure(state="normal")
        self.summary.delete("1.0", "end")
        self.summary.insert("1.0", "\n".join(lines))
        self.summary.configure(state="disabled")
