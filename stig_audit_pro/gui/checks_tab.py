"""Checks tab showing YAML-backed check definitions."""

from __future__ import annotations

from pathlib import Path

import customtkinter as ctk
import yaml

from stig_audit_pro.core.models import CheckDefinition
from stig_audit_pro.gui.widgets import PageFrame, Panel
from stig_audit_pro.gui.yaml_editor import YamlEditor


class ChecksTab(PageFrame):
    def __init__(self, master: ctk.CTkBaseClass, app_controller: object) -> None:
        super().__init__(master)
        self.app_controller = app_controller
        self.checks: list[CheckDefinition] = []
        self.sources: dict[str, Path] = {}
        self.selected: CheckDefinition | None = None
        self.grid_columnconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=2)
        self.grid_rowconfigure(0, weight=1)

        list_panel = Panel(self, "Checks")
        list_panel.grid(row=0, column=0, sticky="nsew", padx=(12, 6), pady=12)
        list_panel.grid_columnconfigure(0, weight=1)
        list_panel.grid_rowconfigure(3, weight=1)

        self.search = ctk.CTkEntry(
            list_panel, placeholder_text="Filter by Vuln ID, title, severity"
        )
        self.search.grid(row=1, column=0, sticky="ew", padx=12, pady=(8, 6))
        self.search.bind("<KeyRelease>", lambda _event: self._render_check_rows())

        filter_row = ctk.CTkFrame(list_panel, fg_color="transparent")
        filter_row.grid(row=2, column=0, sticky="ew", padx=12, pady=(2, 8))
        filter_row.grid_columnconfigure((0, 1), weight=1)
        self.family_filter = ctk.CTkComboBox(
            filter_row,
            values=["All families", "IOSXE_L2", "IOSXE_NDM"],
            command=lambda _value: self._render_check_rows(),
            state="readonly",
        )
        self.family_filter.set("All families")
        self.family_filter.grid(row=0, column=0, sticky="ew", padx=(0, 6))
        self.severity_filter = ctk.CTkComboBox(
            filter_row,
            values=["All severities", "cat1", "cat2", "cat3"],
            command=lambda _value: self._render_check_rows(),
            state="readonly",
        )
        self.severity_filter.set("All severities")
        self.severity_filter.grid(row=0, column=1, sticky="ew", padx=(6, 0))

        self.scroll = ctk.CTkScrollableFrame(list_panel)
        self.scroll.grid(row=3, column=0, sticky="nsew", padx=12, pady=(0, 12))
        self.scroll.grid_columnconfigure(0, weight=1)

        editor_panel = ctk.CTkFrame(self, fg_color="transparent")
        editor_panel.grid(row=0, column=1, sticky="nsew", padx=(6, 12), pady=12)
        editor_panel.grid_columnconfigure(0, weight=1)
        editor_panel.grid_rowconfigure(0, weight=1)
        self.editor = YamlEditor(editor_panel, "Check YAML")
        self.editor.grid(row=0, column=0, sticky="nsew")

        actions = ctk.CTkFrame(editor_panel, fg_color="transparent")
        actions.grid(row=1, column=0, sticky="ew", pady=(8, 0))
        actions.grid_columnconfigure((0, 1, 2), weight=1)
        ctk.CTkButton(actions, text="Validate YAML", command=self._validate_yaml).grid(
            row=0, column=0, sticky="ew", padx=(0, 6)
        )
        ctk.CTkButton(actions, text="Save Check", command=self._save).grid(
            row=0, column=1, sticky="ew", padx=6
        )
        ctk.CTkButton(
            actions, text="Reload From Disk", command=app_controller.reload_from_disk
        ).grid(row=0, column=2, sticky="ew", padx=(6, 0))

        tailoring = ctk.CTkLabel(
            editor_panel,
            text="Tailor customer/site differences in profiles first; edit YAML checks here when the actual requirement logic differs.",
            anchor="w",
            justify="left",
            wraplength=560,
            text_color=("#475467", "#d0d5dd"),
        )
        tailoring.grid(row=2, column=0, sticky="ew", pady=(8, 0))

    def refresh(self, checks: list[CheckDefinition], sources: dict[str, Path]) -> None:
        self.checks = checks
        self.sources = sources
        self.selected = None
        self.editor.set_text("# Select a check to view only its structured definition.\n")
        self.editor.set_status(f"{len(checks)} checks loaded")
        self._render_check_rows()

    def _filtered_checks(self) -> list[CheckDefinition]:
        query = self.search.get().strip().lower()
        family = self.family_filter.get()
        severity = self.severity_filter.get()
        filtered: list[CheckDefinition] = []
        for check in self.checks:
            if family != "All families" and check.stig_family != family:
                continue
            if severity != "All severities" and check.severity != severity:
                continue
            haystack = f"{check.vuln_id} {check.title} {check.severity} {check.check_type}".lower()
            if query and query not in haystack:
                continue
            filtered.append(check)
        return filtered

    def _render_check_rows(self) -> None:
        for child in self.scroll.winfo_children():
            child.destroy()
        for row_index, check in enumerate(self._filtered_checks()):
            row = ctk.CTkFrame(self.scroll, corner_radius=8, border_width=1)
            row.grid(row=row_index, column=0, sticky="ew", pady=4)
            row.grid_columnconfigure(0, weight=1)
            ctk.CTkButton(
                row,
                text=check.vuln_id,
                font=ctk.CTkFont(weight="bold"),
                anchor="w",
                fg_color="transparent",
                command=lambda item=check: self._select(item),
            ).grid(row=0, column=0, sticky="ew", padx=6, pady=(4, 0))
            ctk.CTkLabel(row, text=check.title, anchor="w", wraplength=330, justify="left").grid(
                row=1, column=0, sticky="ew", padx=10, pady=(2, 4)
            )
            ctk.CTkLabel(
                row,
                text=f"{check.stig_family}  |  {check.severity}  |  {check.check_type}",
                text_color=("#475467", "#d0d5dd"),
                anchor="w",
            ).grid(row=2, column=0, sticky="ew", padx=10, pady=(0, 8))

    def _validate_yaml(self) -> None:
        ok, message = self.app_controller.validate_single_check_yaml(self.editor.get_text())
        self.editor.set_status(message, ok=ok)

    def _select(self, check: CheckDefinition) -> None:
        if self.editor.is_dirty:
            self.editor.set_status(
                "Save or reload unsaved changes before selecting another check.", ok=False
            )
            return
        self.selected = check
        source = self.sources.get(check.vuln_id)
        payload = check.model_dump(mode="python", by_alias=True, exclude_none=True)
        self.editor.set_text(yaml.safe_dump(payload, sort_keys=False))
        self.editor.set_status(f"Source: {source.name if source else 'unknown'}")

    def _save(self) -> None:
        if not self.selected:
            self.editor.set_status("Select a check first.", ok=False)
            return
        ok, message = self.app_controller.save_single_check_yaml(
            self.selected.vuln_id, self.editor.get_text(), self.sources[self.selected.vuln_id]
        )
        self.editor.set_status(message, ok=ok)
        if ok:
            self.editor.mark_clean()
