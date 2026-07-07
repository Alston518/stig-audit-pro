"""Profiles tab for site profile preview and validation."""

from __future__ import annotations

from pathlib import Path

import customtkinter as ctk

from stig_audit_pro.core.models import SiteProfile
from stig_audit_pro.gui.widgets import PageFrame, Panel, label_value
from stig_audit_pro.gui.yaml_editor import YamlEditor


class ProfilesTab(PageFrame):
    def __init__(self, master: ctk.CTkBaseClass, app_controller: object) -> None:
        super().__init__(master)
        self.app_controller = app_controller
        self.grid_columnconfigure(0, weight=1)
        self.grid_columnconfigure(1, weight=2)
        self.grid_rowconfigure(0, weight=1)

        left = Panel(self, "Effective Profile")
        left.grid(row=0, column=0, sticky="nsew", padx=(12, 6), pady=12)
        left.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(left, text="Site Profile").grid(row=1, column=0, sticky="w", padx=12, pady=(8, 4))
        self.profile_select = ctk.CTkComboBox(left, values=["example_site", "base_iosxe_access"], command=self._profile_selected, state="readonly")
        self.profile_select.set("example_site")
        self.profile_select.grid(row=1, column=1, sticky="ew", padx=12, pady=(8, 4))

        self.value_labels: dict[str, ctk.CTkLabel] = {}
        labels = [
            ("profile_name", "Name"),
            ("unused_vlan", "Unused VLAN"),
            ("disabled_vlan", "Disabled Port VLAN"),
            ("trunk_prune", "VLAN 1 Pruned"),
            ("dhcp_vlans", "DHCP Snooping VLANs"),
            ("arp_vlans", "ARP Inspection VLANs"),
        ]
        for offset, (key, text) in enumerate(labels, start=3):
            self.value_labels[key] = label_value(left, offset, text, "-")

        ctk.CTkButton(left, text="Reload Profile", command=app_controller.reload_from_disk).grid(row=10, column=0, columnspan=2, sticky="ew", padx=12, pady=(18, 6))
        ctk.CTkButton(left, text="Validate Profile YAML", command=self._validate_yaml).grid(row=11, column=0, columnspan=2, sticky="ew", padx=12, pady=(0, 12))

        right = ctk.CTkFrame(self, fg_color="transparent")
        right.grid(row=0, column=1, sticky="nsew", padx=(6, 12), pady=12)
        right.grid_columnconfigure(0, weight=1)
        right.grid_rowconfigure(0, weight=1)
        self.editor = YamlEditor(right, "Profile YAML")
        self.editor.grid(row=0, column=0, sticky="nsew")

    def refresh(self, profile: SiteProfile, yaml_path: Path) -> None:
        self.profile_select.set(profile.profile_name)
        self.editor.set_text(yaml_path.read_text(encoding="utf-8"))
        self.editor.set_status("Profile loaded")
        self.value_labels["profile_name"].configure(text=profile.profile_name)
        self.value_labels["unused_vlan"].configure(text=str(profile.unused_vlan))
        self.value_labels["disabled_vlan"].configure(text=str(profile.disabled_port_policy.required_access_vlan))
        self.value_labels["trunk_prune"].configure(text=str(profile.trunk_policy.vlan_1_must_be_pruned))
        self.value_labels["dhcp_vlans"].configure(text=", ".join(str(vlan) for vlan in profile.dhcp_snooping.vlans))
        self.value_labels["arp_vlans"].configure(text=", ".join(str(vlan) for vlan in profile.arp_inspection.vlans))

    def _profile_selected(self, value: str) -> None:
        self.app_controller.select_profile(value)

    def _validate_yaml(self) -> None:
        ok, message = self.app_controller.validate_profile_yaml(self.editor.get_text())
        self.editor.set_status(message, ok=ok)
