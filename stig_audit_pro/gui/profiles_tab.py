"""Guided profile variables editor with an optional advanced YAML surface."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path
from tkinter import messagebox, simpledialog

import customtkinter as ctk

from stig_audit_pro.core.models import SiteProfile
from stig_audit_pro.gui.widgets import PageFrame, Panel, label_value
from stig_audit_pro.gui.yaml_editor import YamlEditor


class ProfilesTab(PageFrame):
    def __init__(self, master: ctk.CTkBaseClass, app_controller: object) -> None:
        super().__init__(master)
        self.app_controller = app_controller
        self.current_yaml_path: Path | None = None
        self.grid_columnconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=2)
        self.grid_rowconfigure(0, weight=1)

        left = Panel(self, "Effective Profile")
        left.grid(row=0, column=0, sticky="nsew", padx=(12, 6), pady=12)
        left.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(left, text="Site Profile").grid(
            row=1, column=0, sticky="w", padx=12, pady=(8, 4)
        )
        self.profile_select = ctk.CTkComboBox(
            left, values=["example_site"], command=self._profile_selected, state="readonly"
        )
        self.profile_select.grid(row=1, column=1, sticky="ew", padx=12, pady=(8, 4))

        lifecycle = ctk.CTkFrame(left, fg_color="transparent")
        lifecycle.grid(row=2, column=0, columnspan=2, sticky="ew", padx=12, pady=4)
        lifecycle.grid_columnconfigure((0, 1), weight=1)
        for index, (text, command) in enumerate(
            (
                ("Create", self._create),
                ("Clone", self._clone),
                ("Rename", self._rename),
                ("Delete", self._delete),
            )
        ):
            ctk.CTkButton(lifecycle, text=text, command=command).grid(
                row=index // 2, column=index % 2, sticky="ew", padx=3, pady=3
            )

        self.value_labels: dict[str, ctk.CTkLabel] = {}
        labels = [
            ("profile_name", "Name"),
            ("base", "Base profile"),
            ("unused_vlan", "Unused VLAN"),
            ("native_vlan", "Native VLAN"),
            ("management_vlan", "Management VLAN"),
            ("disabled_vlan", "Disabled Port VLAN"),
            ("trunk_prune", "VLAN 1 Pruned"),
            ("dhcp_vlans", "DHCP Snooping VLANs"),
            ("arp_vlans", "ARP Inspection VLANs"),
        ]
        for offset, (key, text) in enumerate(labels, start=4):
            self.value_labels[key] = label_value(left, offset, text, "-")
        self.consumers = ctk.CTkTextbox(left, height=150, wrap="word")
        self.consumers.grid(row=12, column=0, columnspan=2, sticky="nsew", padx=12, pady=8)

        ctk.CTkButton(left, text="Reload Profile", command=app_controller.reload_from_disk).grid(row=12, column=0, columnspan=2, sticky="ew", padx=12, pady=(18, 6))
        ctk.CTkButton(left, text="Validate Profile YAML", command=self._validate_yaml).grid(row=13, column=0, columnspan=2, sticky="ew", padx=12, pady=(0, 6))
        ctk.CTkButton(left, text="Save Profile YAML", command=self._save_yaml).grid(row=14, column=0, columnspan=2, sticky="ew", padx=12, pady=(0, 12))

        right = ctk.CTkFrame(self, fg_color="transparent")
        right.grid(row=0, column=1, sticky="nsew", padx=(6, 12), pady=12)
        right.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(right, text="Local Overrides", font=ctk.CTkFont(size=16, weight="bold")).grid(
            row=0, column=0, columnspan=2, sticky="w", pady=(4, 8)
        )
        self.base_select = self._combo_row(right, 1, "Base profile")
        self.entries: dict[str, ctk.CTkEntry] = {}
        fields = [
            ("unused_vlan", "Unused VLAN"),
            ("disabled_vlan", "Disabled port VLAN"),
            ("dhcp_vlans", "DHCP VLANs (10,20-30)"),
            ("arp_vlans", "ARP VLANs (10,20-30)"),
            ("user_facing_interfaces", "User-facing interfaces"),
            ("uplinks", "Uplinks"),
            ("access_layer_links", "Access-layer links"),
            ("exempt_interfaces", "Exempt interfaces"),
            ("authorized_trunks", "Authorized trunks"),
        ]
        for row, (key, label) in enumerate(fields, start=2):
            ctk.CTkLabel(right, text=label).grid(row=row, column=0, sticky="w", padx=(4, 8), pady=4)
            entry = ctk.CTkEntry(right)
            entry.grid(row=row, column=1, sticky="ew", pady=4)
            entry.bind(
                "<KeyRelease>",
                lambda _event: self.editor.set_status("Unsaved form changes", ok=False),
            )
            self.entries[key] = entry

    def refresh(self, profile: SiteProfile, yaml_path: Path) -> None:
        self.current_yaml_path = yaml_path
        if hasattr(self.app_controller, "available_profile_names"):
            values = self.app_controller.available_profile_names()
            self.profile_select.configure(values=values)
        self.profile_select.set(profile.profile_name)
        self.base_select.configure(
            values=["None", *[name for name in names if name != profile.profile_name]]
        )
        local = local_values or {}
        self.base_select.set(str(local.get("inherits") or "None"))
        self.editor.set_text(yaml_path.read_text(encoding="utf-8"))
        self.editor.set_status("Profile loaded")
        self.value_labels["profile_name"].configure(text=profile.profile_name)
        self.value_labels["unused_vlan"].configure(text=str(profile.unused_vlan))
        self.value_labels["native_vlan"].configure(text=str(profile.native_vlan))
        self.value_labels["management_vlan"].configure(text=str(profile.management_vlan))
        self.value_labels["disabled_vlan"].configure(text=str(profile.disabled_port_policy.required_access_vlan))
        self.value_labels["trunk_prune"].configure(text=str(profile.trunk_policy.vlan_1_must_be_pruned))
        self.value_labels["dhcp_vlans"].configure(text=", ".join(str(vlan) for vlan in profile.dhcp_snooping.vlans))
        self.value_labels["arp_vlans"].configure(text=", ".join(str(vlan) for vlan in profile.arp_inspection.vlans))

    def _payload(self) -> dict[str, object]:
        return {
            "profile_name": self.profile_select.get(),
            "inherits": None if self.base_select.get() == "None" else self.base_select.get(),
            "unused_vlan": int(self.entries["unused_vlan"].get()),
            "disabled_port_policy": {
                "require_shutdown": bool(self.require_shutdown.get()),
                "required_access_vlan": int(self.entries["disabled_vlan"].get()),
            },
            "trunk_policy": {
                "vlan_1_must_be_pruned": bool(self.prune_vlan1.get()),
                "additional_pruned_vlans": [],
            },
            "dhcp_snooping": {
                "enabled": bool(self.dhcp_enabled.get()),
                "vlans": self._vlans(self.entries["dhcp_vlans"].get()),
            },
            "arp_inspection": {
                "enabled": bool(self.arp_enabled.get()),
                "vlans": self._vlans(self.entries["arp_vlans"].get()),
            },
            "topology": {
                key: self._items(self.entries[key].get())
                for key in (
                    "user_facing_interfaces",
                    "uplinks",
                    "access_layer_links",
                    "exempt_interfaces",
                    "authorized_trunks",
                )
            },
        }

    def _validate_form(self) -> None:
        ok, message = self.app_controller.validate_profile_form(self._payload())
        self.editor.set_status(message, ok=ok)

    def _save_form(self) -> None:
        ok, message = self.app_controller.save_profile_form(self._payload())
        self.editor.set_status(message, ok=ok)

    def _validate_yaml(self) -> None:
        ok, message = self.app_controller.validate_profile_yaml(self.editor.get_text())
        self.editor.set_status(message, ok=ok)

    def _save_yaml(self) -> None:
        if self.current_yaml_path is None:
            self.editor.set_status("Choose a profile first", ok=False)
            return
        ok, message = self.app_controller.save_profile_yaml(self.current_yaml_path, self.editor.get_text())
        self.editor.set_status(message, ok=ok)
