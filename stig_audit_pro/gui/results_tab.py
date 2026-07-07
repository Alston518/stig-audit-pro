"""Results tab for check outcomes and finding detail."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk

import customtkinter as ctk

from stig_audit_pro.core.result_model import CheckResult
from stig_audit_pro.gui.widgets import Metric, PageFrame


class ResultsTab(PageFrame):
    def __init__(self, master: ctk.CTkBaseClass, app_controller: object) -> None:
        super().__init__(master)
        self.app_controller = app_controller
        self.results: list[CheckResult] = []
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(2, weight=1)

        actions = ctk.CTkFrame(self, fg_color="transparent")
        actions.grid(row=0, column=0, sticky="ew", padx=12, pady=(12, 6))
        actions.grid_columnconfigure((0, 1, 2, 3, 4), weight=1)
        self.metrics = {
            "total": Metric(actions, "Total"),
            "NotAFinding": Metric(actions, "NotAFinding"),
            "Open": Metric(actions, "Open"),
            "Error": Metric(actions, "Error"),
        }
        for column, metric in enumerate(self.metrics.values()):
            metric.grid(row=0, column=column, sticky="ew", padx=4)

        run_row = ctk.CTkFrame(self, fg_color="transparent")
        run_row.grid(row=1, column=0, sticky="ew", padx=12, pady=(0, 8))
        run_row.grid_columnconfigure((0, 1, 2), weight=1)
        ctk.CTkButton(run_row, text="Run Compliant Sample", command=lambda: app_controller.run_sample_audit("compliant")).grid(row=0, column=0, sticky="ew", padx=(0, 6))
        ctk.CTkButton(run_row, text="Run Noncompliant Sample", command=lambda: app_controller.run_sample_audit("noncompliant"), fg_color="#9f1d1d", hover_color="#7f1d1d").grid(row=0, column=1, sticky="ew", padx=6)
        ctk.CTkButton(run_row, text="Clear", command=self.clear).grid(row=0, column=2, sticky="ew", padx=(6, 0))

        content = ctk.CTkFrame(self, corner_radius=8, border_width=1)
        content.grid(row=2, column=0, sticky="nsew", padx=12, pady=(0, 12))
        content.grid_columnconfigure(0, weight=3)
        content.grid_columnconfigure(1, weight=2)
        content.grid_rowconfigure(0, weight=1)

        columns = ("ip", "vuln", "family", "severity", "status", "failed")
        self.tree = ttk.Treeview(content, columns=columns, show="headings", selectmode="browse")
        headings = {
            "ip": "IP",
            "vuln": "Vuln ID",
            "family": "Family",
            "severity": "Severity",
            "status": "Status",
            "failed": "Failed Objects",
        }
        widths = {"ip": 110, "vuln": 180, "family": 100, "severity": 80, "status": 120, "failed": 260}
        for column in columns:
            self.tree.heading(column, text=headings[column])
            self.tree.column(column, width=widths[column], anchor="w")
        self.tree.grid(row=0, column=0, sticky="nsew", padx=(10, 6), pady=10)
        self.tree.bind("<<TreeviewSelect>>", self._selection_changed)

        self.details = ctk.CTkTextbox(content, wrap="word")
        self.details.grid(row=0, column=1, sticky="nsew", padx=(6, 10), pady=10)
        self.details.insert("1.0", "Run a sample audit to populate results.")
        self.details.configure(state="disabled")

    def refresh(self, results: list[CheckResult]) -> None:
        self.results = results
        for item in self.tree.get_children():
            self.tree.delete(item)
        for index, result in enumerate(results):
            failed = ", ".join(obj.object_name for obj in result.failed_objects)
            self.tree.insert("", "end", iid=str(index), values=(result.ip, result.vuln_id, result.stig_family, result.severity, result.status, failed))
        self._update_metrics()
        if results:
            self.tree.selection_set("0")
            self._show_result(results[0])
        else:
            self._set_details("No results.")

    def clear(self) -> None:
        self.refresh([])
        self.app_controller.update_report_summary([])

    def _update_metrics(self) -> None:
        counts = {"total": len(self.results), "NotAFinding": 0, "Open": 0, "Error": 0}
        for result in self.results:
            if result.status in counts:
                counts[result.status] += 1
        for key, value in counts.items():
            self.metrics[key].set(value)

    def _selection_changed(self, _event: tk.Event[tk.Misc]) -> None:
        selected = self.tree.selection()
        if not selected:
            return
        index = int(selected[0])
        self._show_result(self.results[index])

    def _show_result(self, result: CheckResult) -> None:
        failed = "\n".join(f"- {obj.object_type}: {obj.object_name} ({obj.details})" for obj in result.failed_objects) or "None"
        passed = "\n".join(f"- {obj.object_type}: {obj.object_name}" for obj in result.passed_objects) or "None"
        text = (
            f"{result.vuln_id}\n{result.title}\n\n"
            f"Status: {result.status}\nSeverity: {result.severity}\nDevice: {result.hostname} ({result.ip})\n\n"
            f"Failed Objects:\n{failed}\n\nPassed Objects:\n{passed}\n\n"
            f"Comments:\n{result.comments}\n\nFinding Details:\n{result.finding_details}"
        )
        self._set_details(text)

    def _set_details(self, text: str) -> None:
        self.details.configure(state="normal")
        self.details.delete("1.0", "end")
        self.details.insert("1.0", text)
        self.details.configure(state="disabled")
