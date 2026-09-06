"""Results tab for check outcomes and finding detail."""

from __future__ import annotations

import tkinter as tk
from tkinter import ttk

import customtkinter as ctk

from stig_audit_pro.core.result_model import CheckResult
from stig_audit_pro.gui.widgets import (
    DANGER,
    Metric,
    PageFrame,
    PRIMARY,
    STATUS_COLORS,
    SUCCESS,
    WARNING,
    confirm_action,
)


class ResultsTab(PageFrame):
    def __init__(self, master: ctk.CTkBaseClass, app_controller: object) -> None:
        super().__init__(master)
        self.app_controller = app_controller
        self.results: list[CheckResult] = []
        self.filtered_results: list[CheckResult] = []
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(3, weight=1)

        actions = ctk.CTkFrame(self, fg_color="transparent")
        actions.grid(row=0, column=0, sticky="ew", padx=12, pady=(12, 6))
        actions.grid_columnconfigure((0, 1, 2, 3, 4, 5, 6), weight=1)
        self.metrics = {
            "total": Metric(actions, "Total", accent=PRIMARY),
            "NotAFinding": Metric(actions, "NotAFinding", accent=SUCCESS),
            "Open": Metric(actions, "Open", accent=DANGER),
            "Not_Applicable": Metric(actions, "NotApplicable", accent="#667085"),
            "Error": Metric(actions, "Error", accent="#c2410c"),
            "Skipped": Metric(actions, "Skipped", accent="#667085"),
            "Not_Reviewed": Metric(actions, "NotReviewed", accent=WARNING),
        }
        for column, metric in enumerate(self.metrics.values()):
            metric.grid(row=0, column=column, sticky="ew", padx=4)

        run_row = ctk.CTkFrame(self, fg_color="transparent")
        run_row.grid(row=1, column=0, sticky="ew", padx=12, pady=(0, 8))
        run_row.grid_columnconfigure((0, 1, 2, 3), weight=1)
        ctk.CTkButton(run_row, text="Run Compliant Sample", command=lambda: app_controller.run_sample_audit("compliant")).grid(row=0, column=0, sticky="ew", padx=(0, 6))
        ctk.CTkButton(run_row, text="Run Noncompliant Sample", command=lambda: app_controller.run_sample_audit("noncompliant"), fg_color="#9f1d1d", hover_color="#7f1d1d").grid(row=0, column=1, sticky="ew", padx=6)
        ctk.CTkButton(run_row, text="View Evidence", command=self._view_evidence).grid(row=0, column=2, sticky="ew", padx=6)
        ctk.CTkButton(run_row, text="Clear", command=self.clear).grid(row=0, column=3, sticky="ew", padx=(6, 0))

        filter_row = ctk.CTkFrame(self, fg_color="transparent")
        filter_row.grid(row=2, column=0, sticky="ew", padx=12, pady=(0, 8))
        filter_row.grid_columnconfigure(1, weight=1)
        self.status_filter = ctk.CTkComboBox(
            filter_row,
            values=["All statuses", "Open", "NotAFinding", "Not_Reviewed", "Not_Applicable", "Error", "Skipped"],
            command=lambda _value: self._render_tree(),
            state="readonly",
            width=160,
        )
        self.status_filter.set("All statuses")
        self.status_filter.grid(row=0, column=0, sticky="w", padx=(0, 8))
        self.search = ctk.CTkEntry(filter_row, placeholder_text="Search IP, Vuln ID, family, title")
        self.search.grid(row=0, column=1, sticky="ew")
        self.search.bind("<KeyRelease>", lambda _event: self._render_tree())

        content = ctk.CTkFrame(self, corner_radius=8, border_width=1)
        content.grid(row=3, column=0, sticky="nsew", padx=12, pady=(0, 12))
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
        for status, colors in STATUS_COLORS.items():
            self.tree.tag_configure(status, background=colors[0], foreground=colors[1])
        self.tree.grid(row=0, column=0, sticky="nsew", padx=(10, 6), pady=10)
        self.tree.bind("<<TreeviewSelect>>", self._selection_changed)

        self.details = ctk.CTkTextbox(content, wrap="word")
        self.details.grid(row=0, column=1, sticky="nsew", padx=(6, 10), pady=10)
        self.details.insert("1.0", "Run a sample audit to populate results.")
        self.details.configure(state="disabled")

    def refresh(self, results: list[CheckResult]) -> None:
        self.results = results
        self._update_metrics()
        self._render_tree()

    def _render_tree(self, selected_result: tuple[str, str] | None = None) -> None:
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.filtered_results = self._filtered_results()
        selected_iid: str | None = None
        for index, result in enumerate(self.filtered_results):
            failed = ", ".join(obj.object_name for obj in result.failed_objects)
            iid = str(index)
            self.tree.insert(
                "",
                "end",
                iid=iid,
                values=(result.ip, result.vuln_id, result.stig_family, result.severity, result.status, failed),
                tags=(result.status,),
            )
            if selected_result == (result.ip, result.vuln_id):
                selected_iid = iid
        if self.filtered_results:
            selected_iid = selected_iid or "0"
            self.tree.selection_set(selected_iid)
            self.tree.focus(selected_iid)
            self.tree.see(selected_iid)
            self._show_result(self.filtered_results[int(selected_iid)])
        elif self.results:
            self._set_details("No results match the current filter.")
        else:
            self._set_details("No results.")

    def select_result(self, ip: str, vuln_id: str) -> None:
        """Reveal and select a result, clearing filters that would otherwise hide it."""
        self.status_filter.set("All statuses")
        self.search.delete(0, "end")
        self._render_tree((ip, vuln_id))

    def _filtered_results(self) -> list[CheckResult]:
        status = self.status_filter.get()
        query = self.search.get().strip().lower()
        filtered: list[CheckResult] = []
        for result in self.results:
            if status != "All statuses" and result.status != status:
                continue
            haystack = f"{result.ip} {result.hostname} {result.vuln_id} {result.title} {result.stig_family} {result.severity} {result.status}".lower()
            if query and query not in haystack:
                continue
            filtered.append(result)
        return filtered

    def clear(self) -> None:
        if not self.results:
            return
        if not confirm_action(
            self,
            title="Clear Results",
            message=f"Clear all {len(self.results)} scan results from the current session?",
            confirm_text="Clear Results",
        ):
            return
        self.refresh([])
        self.app_controller.update_report_summary([])

    def _update_metrics(self) -> None:
        counts = {
            "total": len(self.results),
            "NotAFinding": 0,
            "Open": 0,
            "Not_Applicable": 0,
            "Error": 0,
            "Skipped": 0,
            "Not_Reviewed": 0,
        }
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
        self._show_result(self.filtered_results[index])

    def _selected_result(self) -> CheckResult | None:
        selected = self.tree.selection()
        if not selected:
            return None
        index = int(selected[0])
        if index >= len(self.filtered_results):
            return None
        return self.filtered_results[index]

    def _view_evidence(self) -> None:
        result = self._selected_result()
        if result is not None:
            self.app_controller.show_result_evidence(result)

    def _show_result(self, result: CheckResult) -> None:
        failed = "\n".join(f"- {obj.object_type}: {obj.object_name} ({obj.details})" for obj in result.failed_objects) or "None"
        passed = "\n".join(f"- {obj.object_type}: {obj.object_name}" for obj in result.passed_objects) or "None"
        commands = "\n".join(f"- {command}" for command in result.commands_used) or "None"
        warnings = "\n".join(f"- {warning}" for warning in result.parser_warnings) or "None"
        artifacts = ", ".join(str(item) for item in result.evidence_artifact_ids) or "None"
        text = (
            f"{result.vuln_id}\n{result.title}\n\n"
            f"Audit Run: {result.run_id or '-'}\n"
            f"Rule ID: {result.rule_id or '-'}\nSTIG ID: {result.stig_id or '-'}\n"
            f"Check ID / type: {result.check_id or '-'} / {result.check_type or '-'}\n"
            f"Status: {result.status}\nSeverity: {result.severity}\nDevice: {result.hostname} ({result.ip})\n\n"
            f"Evaluation Reason:\n{result.evaluation_reason or '-'}\n\n"
            f"Commands Used:\n{commands}\n\nEvidence Artifact IDs: {artifacts}\n\n"
            f"Parser Warnings:\n{warnings}\n\nProfile Inputs:\n{result.profile_values_used or '{}'}\n\n"
            f"Failed Objects:\n{failed}\n\nPassed Objects:\n{passed}\n\n"
            f"Comments:\n{result.comments}\n\nFinding Details:\n{result.finding_details}"
        )
        self._set_details(text)

    def _set_details(self, text: str) -> None:
        self.details.configure(state="normal")
        self.details.delete("1.0", "end")
        self.details.insert("1.0", text)
        self.details.configure(state="disabled")
