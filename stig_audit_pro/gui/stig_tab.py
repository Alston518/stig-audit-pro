"""STIG source, metadata visualization, and CKL output options tab."""

from __future__ import annotations

import tkinter as tk
from pathlib import Path
from tkinter import filedialog, ttk

import customtkinter as ctk

from stig_audit_pro.gui.widgets import PageFrame, Panel
from stig_audit_pro.stig.stig_metadata import StigBenchmarkMetadata, StigRuleMetadata


class StigTab(PageFrame):
    def __init__(self, master: ctk.CTkBaseClass, app_controller: object) -> None:
        super().__init__(master)
        self.app_controller = app_controller
        self.metadata_items: list[StigBenchmarkMetadata] = []
        self.rule_lookup: dict[str, tuple[StigBenchmarkMetadata, StigRuleMetadata]] = {}
        self.selected_ckl_path: Path | None = None
        self.selected_output_dir: Path | None = None
        self.grid_columnconfigure(0, weight=2)
        self.grid_columnconfigure(1, weight=3)
        self.grid_rowconfigure(0, weight=1)

        self._build_source_panel()
        self._build_detail_panel()

    def _build_source_panel(self) -> None:
        source_panel = Panel(self, "STIG Source")
        source_panel.grid(row=0, column=0, sticky="nsew", padx=(12, 6), pady=12)
        source_panel.grid_columnconfigure(0, weight=1)
        source_panel.grid_rowconfigure(10, weight=1)

        ctk.CTkLabel(source_panel, text="Family").grid(row=1, column=0, sticky="w", padx=12, pady=(8, 4))
        self.family_select = ctk.CTkComboBox(source_panel, values=["IOSXE_L2", "IOSXE_NDM"], state="readonly")
        self.family_select.set("IOSXE_L2")
        self.family_select.grid(row=2, column=0, sticky="ew", padx=12, pady=(0, 8))

        button_row = ctk.CTkFrame(source_panel, fg_color="transparent")
        button_row.grid(row=3, column=0, sticky="ew", padx=12, pady=(4, 8))
        button_row.grid_columnconfigure((0, 1, 2), weight=1)
        ctk.CTkButton(button_row, text="Find Selected", command=self._download_latest).grid(row=0, column=0, sticky="ew", padx=(0, 6))
        ctk.CTkButton(button_row, text="Find L2 + NDM", command=self._download_core_stigs).grid(row=0, column=1, sticky="ew", padx=6)
        ctk.CTkButton(button_row, text="Import ZIP/XML", command=self._import_source).grid(row=0, column=2, sticky="ew", padx=(6, 0))

        ctk.CTkLabel(source_panel, text="Direct ZIP/XML URL").grid(row=4, column=0, sticky="w", padx=12, pady=(6, 4))
        url_row = ctk.CTkFrame(source_panel, fg_color="transparent")
        url_row.grid(row=5, column=0, sticky="ew", padx=12, pady=(0, 8))
        url_row.grid_columnconfigure(0, weight=1)
        self.download_url = ctk.CTkEntry(url_row, placeholder_text="Paste Cyber Exchange ZIP/XML link")
        self.download_url.grid(row=0, column=0, sticky="ew", padx=(0, 8))
        self.download_url.bind("<Return>", lambda _event: self._download_url())
        ctk.CTkButton(url_row, text="Download URL", width=120, command=self._download_url).grid(row=0, column=1)

        ctk.CTkButton(source_panel, text="Refresh Cached STIGs", command=self.app_controller.refresh_stig_metadata).grid(row=6, column=0, sticky="ew", padx=12, pady=(0, 8))
        ctk.CTkButton(source_panel, text="Build Starter Checks", command=self._generate_starter_checks).grid(row=7, column=0, sticky="ew", padx=12, pady=(0, 8))

        self.source_status = ctk.CTkLabel(source_panel, text="No STIG metadata loaded.", anchor="w", text_color=("#475467", "#d0d5dd"))
        self.source_status.grid(row=8, column=0, sticky="ew", padx=12, pady=(2, 8))

        columns = ("family", "version", "rules")
        self.benchmark_tree = ttk.Treeview(source_panel, columns=columns, show="tree headings", height=8, selectmode="browse")
        self.benchmark_tree.heading("#0", text="Benchmark / Rule")
        self.benchmark_tree.heading("family", text="Family")
        self.benchmark_tree.heading("version", text="Version")
        self.benchmark_tree.heading("rules", text="Rules")
        self.benchmark_tree.column("#0", width=330, anchor="w")
        self.benchmark_tree.column("family", width=90, anchor="w")
        self.benchmark_tree.column("version", width=80, anchor="w")
        self.benchmark_tree.column("rules", width=60, anchor="e")
        self.benchmark_tree.grid(row=10, column=0, sticky="nsew", padx=12, pady=(4, 12))
        self.benchmark_tree.bind("<<TreeviewSelect>>", self._selection_changed)

    def _build_detail_panel(self) -> None:
        right = ctk.CTkFrame(self, fg_color="transparent")
        right.grid(row=0, column=1, sticky="nsew", padx=(6, 12), pady=12)
        right.grid_columnconfigure(0, weight=1)
        right.grid_rowconfigure(0, weight=1)

        detail_panel = Panel(right, "STIG Metadata")
        detail_panel.grid(row=0, column=0, sticky="nsew")
        detail_panel.grid_columnconfigure(0, weight=1)
        detail_panel.grid_rowconfigure(1, weight=1)
        self.metadata = ctk.CTkTextbox(detail_panel, wrap="word")
        self.metadata.grid(row=1, column=0, sticky="nsew", padx=12, pady=(8, 12))
        self.metadata.insert("1.0", "Download or import a STIG ZIP/XML to view metadata here.")
        self.metadata.configure(state="disabled")

        output_panel = Panel(right, "L2 Checklist Audit (Test)")
        output_panel.grid(row=1, column=0, sticky="ew", pady=(10, 0))
        output_panel.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(output_panel, text="CKL template").grid(row=1, column=0, sticky="w", padx=12, pady=(10, 6))
        self.ckl_template = ctk.CTkEntry(output_panel, placeholder_text="Select the blank or existing L2 .ckl file")
        self.ckl_template.grid(row=1, column=1, sticky="ew", padx=(12, 6), pady=(10, 6))
        ctk.CTkButton(output_panel, text="Browse", width=82, command=self._browse_ckl).grid(
            row=1, column=2, sticky="e", padx=(0, 12), pady=(10, 6)
        )

        ctk.CTkLabel(output_panel, text="Destination").grid(row=2, column=0, sticky="w", padx=12, pady=6)
        self.output_folder = ctk.CTkEntry(output_panel, placeholder_text="Select output folder")
        self.output_folder.grid(row=2, column=1, sticky="ew", padx=(12, 6), pady=6)
        ctk.CTkButton(output_panel, text="Browse", width=82, command=self._browse_output).grid(
            row=2, column=2, sticky="e", padx=(0, 12), pady=6
        )

        ctk.CTkLabel(
            output_panel,
            text="Uses checked targets, Live SSH credentials, and profile from the Targets tab.",
            text_color=("#475467", "#d0d5dd"),
        ).grid(row=3, column=0, columnspan=3, sticky="w", padx=12, pady=(4, 8))

        options = ctk.CTkFrame(output_panel, fg_color="transparent")
        options.grid(row=4, column=1, columnspan=2, sticky="w", padx=12, pady=4)
        self.write_ckl = ctk.CTkCheckBox(options, text="Fill CKL")
        self.write_ckl.select()
        self.write_ckl.grid(row=0, column=0, sticky="w", padx=(0, 18))
        self.write_text = ctk.CTkCheckBox(options, text="Create text report")
        self.write_text.select()
        self.write_text.grid(row=0, column=1, sticky="w")

        ctk.CTkLabel(output_panel, text="Existing comments").grid(row=5, column=0, sticky="w", padx=12, pady=6)
        self.comment_mode = ctk.CTkComboBox(
            output_panel,
            values=["Append generated comments", "Replace comments"],
            state="readonly",
        )
        self.comment_mode.set("Append generated comments")
        self.comment_mode.grid(row=5, column=1, columnspan=2, sticky="ew", padx=12, pady=6)

        ctk.CTkButton(
            output_panel,
            text="Run Checked Targets — L2",
            command=self._run_l2_audit,
        ).grid(row=6, column=0, columnspan=3, sticky="ew", padx=12, pady=(10, 6))
        self.checklist_status = ctk.CTkLabel(
            output_panel,
            text="Select an L2 CKL template and output folder.",
            anchor="w",
            text_color=("#475467", "#d0d5dd"),
        )
        self.checklist_status.grid(row=7, column=0, columnspan=3, sticky="ew", padx=12, pady=(0, 12))

    def refresh_metadata(self, metadata_items: list[StigBenchmarkMetadata]) -> None:
        self.metadata_items = metadata_items
        self.rule_lookup = {}
        for item in self.benchmark_tree.get_children():
            self.benchmark_tree.delete(item)
        for benchmark_index, metadata in enumerate(metadata_items):
            bench_iid = f"benchmark-{benchmark_index}"
            self.benchmark_tree.insert(
                "",
                "end",
                iid=bench_iid,
                text=metadata.display_name,
                values=(metadata.family, metadata.version, metadata.rule_count),
                open=False,
            )
            for rule_index, rule in enumerate(metadata.rules):
                rule_iid = f"rule-{benchmark_index}-{rule_index}"
                self.rule_lookup[rule_iid] = (metadata, rule)
                self.benchmark_tree.insert(
                    bench_iid,
                    "end",
                    iid=rule_iid,
                    text=f"{rule.stig_id or rule.vuln_id} - {rule.title}",
                    values=(metadata.family, rule.severity, ""),
                )
        self.source_status.configure(text=f"{len(metadata_items)} cached STIG source(s) loaded.")
        if metadata_items:
            self._show_benchmark(metadata_items[0])
        else:
            self._set_detail("Download or import a STIG ZIP/XML to view metadata here.")

    def set_status(self, message: str) -> None:
        self.source_status.configure(text=message)

    def set_checklist_status(self, message: str) -> None:
        self.checklist_status.configure(text=message)

    def _download_latest(self) -> None:
        self.app_controller.download_latest_stig(self.family_select.get())

    def _download_core_stigs(self) -> None:
        self.app_controller.download_core_stigs()

    def _download_url(self) -> None:
        self.app_controller.download_stig_from_url(self.download_url.get(), self.family_select.get())

    def _generate_starter_checks(self) -> None:
        self.app_controller.generate_starter_checks_from_stigs()

    def _import_source(self) -> None:
        path = filedialog.askopenfilename(
            title="Import STIG source",
            filetypes=[("STIG source", "*.zip *.xml"), ("All files", "*.*")],
        )
        if path:
            self.app_controller.import_stig_source(Path(path), self.family_select.get())

    def _browse_ckl(self) -> None:
        path = filedialog.askopenfilename(
            title="Select L2 checklist template",
            filetypes=[("DISA checklist", "*.ckl"), ("XML files", "*.xml"), ("All files", "*.*")],
        )
        if path:
            self.selected_ckl_path = Path(path)
            self.ckl_template.delete(0, "end")
            self.ckl_template.insert(0, path)
            if not self.output_folder.get().strip():
                self.selected_output_dir = Path(path).parent
                self.output_folder.insert(0, str(Path(path).parent))
            self.set_checklist_status(
                f"Selected CKL template: {self.selected_ckl_path.name}. Ready to run."
            )

    def _browse_output(self) -> None:
        path = filedialog.askdirectory(title="Select completed-file destination")
        if path:
            self.selected_output_dir = Path(path)
            self.output_folder.delete(0, "end")
            self.output_folder.insert(0, path)
            self.set_checklist_status(
                f"Destination selected: {self.selected_output_dir}. Ready to run."
            )

    def _run_l2_audit(self) -> None:
        ckl_text = self.ckl_template.get().strip()
        output_text = self.output_folder.get().strip()
        self.selected_ckl_path = Path(ckl_text) if ckl_text else None
        self.selected_output_dir = Path(output_text) if output_text else None
        self.set_checklist_status("Validating L2 checklist audit settings...")
        self.app_controller.run_l2_checklist_audit(
            ckl_path=self.selected_ckl_path,
            output_dir=self.selected_output_dir,
            create_ckl=bool(self.write_ckl.get()),
            create_text=bool(self.write_text.get()),
            append_comments=self.comment_mode.get() == "Append generated comments",
        )

    def _selection_changed(self, _event: tk.Event[tk.Misc]) -> None:
        selected = self.benchmark_tree.selection()
        if not selected:
            return
        iid = selected[0]
        if iid in self.rule_lookup:
            metadata, rule = self.rule_lookup[iid]
            self._show_rule(metadata, rule)
            return
        if iid.startswith("benchmark-"):
            index = int(iid.split("-", 1)[1])
            if index < len(self.metadata_items):
                self._show_benchmark(self.metadata_items[index])

    def _show_benchmark(self, metadata: StigBenchmarkMetadata) -> None:
        text = (
            f"{metadata.display_name}\n\n"
            f"Family: {metadata.family}\n"
            f"Benchmark ID: {metadata.benchmark_id}\n"
            f"Version: {metadata.version}\n"
            f"Release: {metadata.release_info}\n"
            f"Release Date: {metadata.release_date}\n"
            f"Rules: {metadata.rule_count}\n"
            f"Source: {metadata.source_filename}\n"
            f"Imported: {metadata.imported_at}\n"
        )
        self._set_detail(text)

    def _show_rule(self, metadata: StigBenchmarkMetadata, rule: StigRuleMetadata) -> None:
        text = (
            f"{rule.stig_id or rule.vuln_id}\n{rule.title}\n\n"
            f"Family: {metadata.family}\n"
            f"Vuln ID: {rule.vuln_id}\n"
            f"Rule ID: {rule.rule_id}\n"
            f"Severity: {rule.severity}\n\n"
            f"Check Text:\n{rule.check_text}\n\n"
            f"Fix Text:\n{rule.fix_text}"
        )
        self._set_detail(text)

    def _set_detail(self, text: str) -> None:
        self.metadata.configure(state="normal")
        self.metadata.delete("1.0", "end")
        self.metadata.insert("1.0", text)
        self.metadata.configure(state="disabled")
