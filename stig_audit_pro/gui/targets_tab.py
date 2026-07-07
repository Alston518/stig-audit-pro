"""Targets tab with a persistent device-list workbench."""

from __future__ import annotations

import csv
import ipaddress
import re
from pathlib import Path
from tkinter import filedialog

import customtkinter as ctk

from stig_audit_pro.gui.widgets import PageFrame, Panel
from stig_audit_pro.storage.device_groups import DeviceTargetRecord

USE_DEFAULT_PROFILE = "Use scan default"
USE_SELECTED_PROFILE = "Use selected profile"


class TargetsTab(PageFrame):
    def __init__(self, master: ctk.CTkBaseClass, app_controller: object) -> None:
        super().__init__(master)
        self.app_controller = app_controller
        self.targets: list[DeviceTargetRecord] = []
        self.selected_index: int | None = None
        self.profile_values = [USE_DEFAULT_PROFILE]
        self.row_checks: dict[int, ctk.CTkCheckBox] = {}
        self.row_profiles: dict[int, ctk.CTkComboBox] = {}

        self.grid_columnconfigure(0, weight=2)
        self.grid_columnconfigure(1, weight=3)
        self.grid_rowconfigure(0, weight=1)

        self._build_input_panel()
        self._build_table_panel()

    def _build_input_panel(self) -> None:
        panel = Panel(self, "Target Workbench")
        panel.grid(row=0, column=0, sticky="nsew", padx=(12, 6), pady=12)
        panel.grid_columnconfigure(0, weight=1)
        panel.grid_rowconfigure(5, weight=1)

        ctk.CTkLabel(panel, text="Single IP").grid(row=1, column=0, sticky="w", padx=12, pady=(8, 4))
        single_row = ctk.CTkFrame(panel, fg_color="transparent")
        single_row.grid(row=2, column=0, sticky="ew", padx=12, pady=(0, 8))
        single_row.grid_columnconfigure(0, weight=1)
        self.single_ip = ctk.CTkEntry(single_row, placeholder_text="10.50.10.25")
        self.single_ip.grid(row=0, column=0, sticky="ew", padx=(0, 8))
        self.single_ip.bind("<Return>", lambda _event: self.add_single_ip())
        ctk.CTkButton(single_row, text="Add", width=86, command=self.add_single_ip).grid(row=0, column=1)

        ctk.CTkLabel(panel, text="Paste IPs").grid(row=3, column=0, sticky="w", padx=12, pady=(6, 4))
        self.ip_list = ctk.CTkTextbox(panel, height=150)
        self.ip_list.grid(row=4, column=0, sticky="nsew", padx=12, pady=(0, 8))

        add_row = ctk.CTkFrame(panel, fg_color="transparent")
        add_row.grid(row=5, column=0, sticky="ew", padx=12, pady=(0, 10))
        add_row.grid_columnconfigure((0, 1), weight=1)
        ctk.CTkButton(add_row, text="Add Pasted", command=self.add_pasted_ips).grid(row=0, column=0, sticky="ew", padx=(0, 6))
        ctk.CTkButton(add_row, text="Import CSV/TXT", command=self.import_targets).grid(row=0, column=1, sticky="ew", padx=(6, 0))

        group_panel = ctk.CTkFrame(panel, corner_radius=8, border_width=1)
        group_panel.grid(row=6, column=0, sticky="ew", padx=12, pady=(4, 12))
        group_panel.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(group_panel, text="Device Groups", font=ctk.CTkFont(size=14, weight="bold")).grid(row=0, column=0, sticky="w", padx=10, pady=(10, 4))
        self.group_select = ctk.CTkComboBox(group_panel, values=["Session targets"], state="readonly")
        self.group_select.set("Session targets")
        self.group_select.grid(row=1, column=0, sticky="ew", padx=10, pady=(0, 8))

        ctk.CTkLabel(group_panel, text="Group site profile").grid(row=2, column=0, sticky="w", padx=10, pady=(0, 4))
        self.group_profile = ctk.CTkComboBox(group_panel, values=[USE_SELECTED_PROFILE], state="readonly")
        self.group_profile.set(USE_SELECTED_PROFILE)
        self.group_profile.grid(row=3, column=0, sticky="ew", padx=10, pady=(0, 8))

        group_buttons = ctk.CTkFrame(group_panel, fg_color="transparent")
        group_buttons.grid(row=4, column=0, sticky="ew", padx=10, pady=(0, 8))
        group_buttons.grid_columnconfigure((0, 1), weight=1)
        ctk.CTkButton(group_buttons, text="Load", command=self.load_selected_group).grid(row=0, column=0, sticky="ew", padx=(0, 5))
        ctk.CTkButton(group_buttons, text="Save", command=self.save_current_group).grid(row=0, column=1, sticky="ew", padx=(5, 0))
        self.group_name = ctk.CTkEntry(group_panel, placeholder_text="Group name")
        self.group_name.grid(row=5, column=0, sticky="ew", padx=10, pady=(0, 10))

        scan_panel = ctk.CTkFrame(panel, corner_radius=8, border_width=1)
        scan_panel.grid(row=7, column=0, sticky="ew", padx=12, pady=(0, 12))
        scan_panel.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(scan_panel, text="Scan Mode", font=ctk.CTkFont(size=14, weight="bold")).grid(row=0, column=0, columnspan=2, sticky="w", padx=10, pady=(10, 4))
        ctk.CTkLabel(scan_panel, text="Mode").grid(row=1, column=0, sticky="w", padx=10, pady=4)
        self.scan_mode = ctk.CTkComboBox(scan_panel, values=["Sample outputs", "Live SSH"], state="readonly")
        self.scan_mode.set("Sample outputs")
        self.scan_mode.grid(row=1, column=1, sticky="ew", padx=10, pady=4)
        ctk.CTkLabel(scan_panel, text="Username").grid(row=2, column=0, sticky="w", padx=10, pady=4)
        self.ssh_username = ctk.CTkEntry(scan_panel, placeholder_text="TACACS or local username")
        self.ssh_username.grid(row=2, column=1, sticky="ew", padx=10, pady=4)
        ctk.CTkLabel(scan_panel, text="Password").grid(row=3, column=0, sticky="w", padx=10, pady=4)
        self.ssh_password = ctk.CTkEntry(scan_panel, show="*")
        self.ssh_password.grid(row=3, column=1, sticky="ew", padx=10, pady=4)
        ctk.CTkLabel(scan_panel, text="Enable Secret").grid(row=4, column=0, sticky="w", padx=10, pady=4)
        self.enable_secret = ctk.CTkEntry(scan_panel, show="*")
        self.enable_secret.grid(row=4, column=1, sticky="ew", padx=10, pady=4)
        ctk.CTkLabel(scan_panel, text="Timeout").grid(row=5, column=0, sticky="w", padx=10, pady=(4, 10))
        self.ssh_timeout = ctk.CTkEntry(scan_panel)
        self.ssh_timeout.insert(0, "30")
        self.ssh_timeout.grid(row=5, column=1, sticky="ew", padx=10, pady=(4, 10))

        self.status = ctk.CTkLabel(panel, text="No targets loaded.", anchor="w", text_color=("#475467", "#d0d5dd"))
        self.status.grid(row=8, column=0, sticky="ew", padx=12, pady=(0, 8))

    def _build_table_panel(self) -> None:
        panel = Panel(self, "Target List")
        panel.grid(row=0, column=1, sticky="nsew", padx=(6, 12), pady=12)
        panel.grid_columnconfigure(0, weight=1)
        panel.grid_rowconfigure(2, weight=1)

        toolbar = ctk.CTkFrame(panel, fg_color="transparent")
        toolbar.grid(row=1, column=0, sticky="ew", padx=12, pady=(8, 6))
        toolbar.grid_columnconfigure((0, 1, 2, 3), weight=1)
        ctk.CTkButton(toolbar, text="Check All", command=self.check_all).grid(row=0, column=0, sticky="ew", padx=(0, 4))
        ctk.CTkButton(toolbar, text="Uncheck All", command=self.uncheck_all).grid(row=0, column=1, sticky="ew", padx=4)
        ctk.CTkButton(toolbar, text="Remove Selected", command=self.remove_selected).grid(row=0, column=2, sticky="ew", padx=4)
        ctk.CTkButton(toolbar, text="Clear", command=self.clear_targets).grid(row=0, column=3, sticky="ew", padx=(4, 0))

        self.table = ctk.CTkScrollableFrame(panel)
        self.table.grid(row=2, column=0, sticky="nsew", padx=12, pady=(0, 8))
        self.table.grid_columnconfigure(1, weight=1)

        run_row = ctk.CTkFrame(panel, fg_color="transparent")
        run_row.grid(row=3, column=0, sticky="ew", padx=12, pady=(4, 12))
        run_row.grid_columnconfigure((0, 1, 2), weight=1)
        ctk.CTkButton(run_row, text="Run Selected", command=lambda: self.app_controller.run_target_scope("selected")).grid(row=0, column=0, sticky="ew", padx=(0, 6))
        ctk.CTkButton(run_row, text="Run Checked", command=lambda: self.app_controller.run_target_scope("checked")).grid(row=0, column=1, sticky="ew", padx=6)
        ctk.CTkButton(run_row, text="Run All", command=lambda: self.app_controller.run_target_scope("all")).grid(row=0, column=2, sticky="ew", padx=(6, 0))

        self._render_rows()

    def refresh_groups(self, group_names: list[str], profile_names: list[str] | None = None) -> None:
        group_values = ["Session targets", *group_names]
        self.group_select.configure(values=group_values)
        if self.group_select.get() not in group_values:
            self.group_select.set("Session targets")

        if profile_names is not None:
            self.profile_values = [USE_DEFAULT_PROFILE, *profile_names]
            group_profile_values = [USE_SELECTED_PROFILE, *profile_names]
            current_group_profile = self.group_profile.get()
            self.group_profile.configure(values=group_profile_values)
            if current_group_profile not in group_profile_values:
                self.group_profile.set(USE_SELECTED_PROFILE)
            self._refresh_row_profile_values()

    def set_targets(
        self,
        targets: list[DeviceTargetRecord],
        group_name: str | None = None,
        group_profile: str | None = None,
    ) -> None:
        self.targets = [target.copy() for target in targets]
        self.selected_index = 0 if self.targets else None
        if group_name:
            self.group_select.set(group_name)
            self.group_name.delete(0, "end")
            self.group_name.insert(0, group_name)
        self.group_profile.set(group_profile or USE_SELECTED_PROFILE)
        self._render_rows(sync=False)
        self._set_status(f"Loaded {len(self.targets)} target(s).")

    def get_targets(self, scope: str = "all") -> list[DeviceTargetRecord]:
        self._sync_row_state()
        if scope == "selected":
            if self.selected_index is None or self.selected_index >= len(self.targets):
                return []
            return [self.targets[self.selected_index]]
        if scope == "checked":
            return [target for target in self.targets if target.checked]
        return list(self.targets)

    def get_scan_settings(self) -> dict[str, object]:
        timeout_text = self.ssh_timeout.get().strip()
        timeout = int(timeout_text) if timeout_text.isdigit() else 30
        return {
            "mode": self.scan_mode.get(),
            "username": self.ssh_username.get().strip(),
            "password": self.ssh_password.get(),
            "secret": self.enable_secret.get() or None,
            "timeout": timeout,
        }

    def add_single_ip(self) -> None:
        text = self.single_ip.get().strip()
        added, skipped = self._add_targets_from_text(text)
        if added:
            self.single_ip.delete(0, "end")
        self._set_add_status(added, skipped)

    def add_pasted_ips(self) -> None:
        text = self.ip_list.get("1.0", "end")
        added, skipped = self._add_targets_from_text(text)
        if added:
            self.ip_list.delete("1.0", "end")
        self._set_add_status(added, skipped)

    def import_targets(self) -> None:
        path = filedialog.askopenfilename(
            title="Import targets",
            filetypes=[("Target files", "*.csv *.txt"), ("All files", "*.*")],
        )
        if not path:
            return
        imported_text = self._read_import_file(Path(path))
        added, skipped = self._add_targets_from_text(imported_text)
        self._set_add_status(added, skipped)

    def save_current_group(self) -> None:
        self._sync_row_state()
        name = self.group_name.get().strip() or self.group_select.get().strip()
        if not name or name == "Session targets":
            name = "session_targets"
        group_profile = self.group_profile.get()
        if group_profile == USE_SELECTED_PROFILE:
            group_profile = None
        self.app_controller.save_device_group(name, self.targets, group_profile)

    def load_selected_group(self) -> None:
        group_name = self.group_select.get()
        if group_name == "Session targets":
            self._set_status("Choose a saved group to load.")
            return
        self.app_controller.load_device_group(group_name)

    def check_all(self) -> None:
        for target in self.targets:
            target.checked = True
        self._render_rows(sync=False)

    def uncheck_all(self) -> None:
        for target in self.targets:
            target.checked = False
        self._render_rows(sync=False)

    def remove_selected(self) -> None:
        if self.selected_index is None or self.selected_index >= len(self.targets):
            self._set_status("Select a target row first.")
            return
        removed = self.targets.pop(self.selected_index)
        if not self.targets:
            self.selected_index = None
        else:
            self.selected_index = min(self.selected_index, len(self.targets) - 1)
        self._render_rows()
        self._set_status(f"Removed {removed.ip}.")

    def clear_targets(self) -> None:
        self.targets = []
        self.selected_index = None
        self._render_rows()
        self._set_status("Cleared target list.")

    def _add_targets_from_text(self, text: str) -> tuple[int, int]:
        ips, skipped = self._extract_ips(text)
        existing = {target.ip for target in self.targets}
        added = 0
        for ip in ips:
            if ip in existing:
                skipped += 1
                continue
            self.targets.append(DeviceTargetRecord(ip=ip, checked=True))
            existing.add(ip)
            added += 1
        if added and self.selected_index is None:
            self.selected_index = 0
        self._render_rows()
        return added, skipped

    def _extract_ips(self, text: str) -> tuple[list[str], int]:
        values: list[str] = []
        skipped = 0
        for token in re.split(r"[\s,;]+", text):
            cleaned = token.strip().strip('"\'')
            if not cleaned or cleaned.lower() in {"ip", "address", "hostname"}:
                continue
            try:
                values.append(str(ipaddress.ip_address(cleaned)))
            except ValueError:
                skipped += 1
        return values, skipped

    def _read_import_file(self, path: Path) -> str:
        if path.suffix.lower() == ".csv":
            values: list[str] = []
            with path.open("r", encoding="utf-8-sig", newline="") as handle:
                reader = csv.reader(handle)
                for row in reader:
                    values.extend(row)
            return "\n".join(values)
        return path.read_text(encoding="utf-8-sig")

    def _render_rows(self, sync: bool = True) -> None:
        if sync:
            self._sync_row_state()
        for child in self.table.winfo_children():
            child.destroy()
        self.row_checks = {}
        self.row_profiles = {}

        headers = ["Use", "IP Address", "Override", "Row"]
        for column, header in enumerate(headers):
            ctk.CTkLabel(self.table, text=header, font=ctk.CTkFont(weight="bold")).grid(row=0, column=column, sticky="w", padx=8, pady=(0, 6))

        if not self.targets:
            ctk.CTkLabel(self.table, text="No targets yet. Add or import switches on the left.", text_color=("#475467", "#d0d5dd")).grid(row=1, column=0, columnspan=4, sticky="ew", padx=8, pady=18)
            return

        for index, target in enumerate(self.targets, start=1):
            actual_index = index - 1
            selected = actual_index == self.selected_index
            row_color = ("#eaf2ff", "#102a43") if selected else "transparent"
            row = ctk.CTkFrame(self.table, fg_color=row_color, corner_radius=6)
            row.grid(row=index, column=0, columnspan=4, sticky="ew", pady=2)
            row.grid_columnconfigure(1, weight=1)

            check = ctk.CTkCheckBox(row, text="", width=28)
            if target.checked:
                check.select()
            else:
                check.deselect()
            check.grid(row=0, column=0, padx=(8, 4), pady=6)
            self.row_checks[actual_index] = check

            ip_button = ctk.CTkButton(row, text=target.ip, anchor="w", fg_color="transparent", text_color=("#101828", "#f2f4f7"), hover_color=("#d0e2ff", "#1f2937"), command=lambda i=actual_index: self._select_row(i))
            ip_button.grid(row=0, column=1, sticky="ew", padx=4, pady=6)

            combo = ctk.CTkComboBox(row, values=self.profile_values, width=150)
            combo.set(target.profile_override or USE_DEFAULT_PROFILE)
            combo.grid(row=0, column=2, sticky="ew", padx=4, pady=6)
            self.row_profiles[actual_index] = combo

            remove_button = ctk.CTkButton(row, text="Remove", width=78, command=lambda i=actual_index: self._remove_row(i))
            remove_button.grid(row=0, column=3, padx=(4, 8), pady=6)

    def _refresh_row_profile_values(self) -> None:
        for combo in self.row_profiles.values():
            current = combo.get()
            combo.configure(values=self.profile_values)
            if current not in self.profile_values:
                combo.set(USE_DEFAULT_PROFILE)

    def _select_row(self, index: int) -> None:
        self._sync_row_state()
        self.selected_index = index
        self._render_rows()
        self._set_status(f"Selected {self.targets[index].ip}.")

    def _remove_row(self, index: int) -> None:
        self._sync_row_state()
        removed = self.targets.pop(index)
        if not self.targets:
            self.selected_index = None
        else:
            self.selected_index = min(index, len(self.targets) - 1)
        self._render_rows()
        self._set_status(f"Removed {removed.ip}.")

    def _sync_row_state(self) -> None:
        for index, target in enumerate(self.targets):
            check = self.row_checks.get(index)
            if check is not None:
                target.checked = bool(check.get())
            combo = self.row_profiles.get(index)
            if combo is not None:
                value = combo.get()
                target.profile_override = None if value == USE_DEFAULT_PROFILE else value

    def _set_add_status(self, added: int, skipped: int) -> None:
        self._set_status(f"Added {added} target(s), skipped {skipped}.")

    def _set_status(self, message: str) -> None:
        self.status.configure(text=message)
        self.app_controller.set_status(message)

