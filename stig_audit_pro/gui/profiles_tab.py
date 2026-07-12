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
        self.current_path: Path | None = None
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
            ("disabled_vlan", "Disabled Port VLAN"),
            ("trunk_prune", "VLAN 1 Pruned"),
            ("dhcp_vlans", "DHCP Snooping VLANs"),
            ("arp_vlans", "ARP Inspection VLANs"),
        ]
        for offset, (key, text) in enumerate(labels, start=4):
            self.value_labels[key] = label_value(left, offset, text, "-")
        self.consumers = ctk.CTkTextbox(left, height=150, wrap="word")
        self.consumers.grid(row=12, column=0, columnspan=2, sticky="nsew", padx=12, pady=8)

        right = ctk.CTkScrollableFrame(self)
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

        flags = ctk.CTkFrame(right, fg_color="transparent")
        flags.grid(row=11, column=0, columnspan=2, sticky="ew", pady=8)
        self.require_shutdown = ctk.CTkCheckBox(flags, text="Require shutdown on disabled ports")
        self.require_shutdown.grid(row=0, column=0, sticky="w", pady=2)
        self.prune_vlan1 = ctk.CTkCheckBox(flags, text="Require VLAN 1 pruning")
        self.prune_vlan1.grid(row=1, column=0, sticky="w", pady=2)
        self.dhcp_enabled = ctk.CTkCheckBox(flags, text="DHCP snooping policy applies")
        self.dhcp_enabled.grid(row=2, column=0, sticky="w", pady=2)
        self.arp_enabled = ctk.CTkCheckBox(flags, text="ARP inspection policy applies")
        self.arp_enabled.grid(row=3, column=0, sticky="w", pady=2)

        buttons = ctk.CTkFrame(right, fg_color="transparent")
        buttons.grid(row=12, column=0, columnspan=2, sticky="ew", pady=8)
        buttons.grid_columnconfigure((0, 1, 2), weight=1)
        ctk.CTkButton(buttons, text="Validate", command=self._validate_form).grid(
            row=0, column=0, sticky="ew", padx=3
        )
        ctk.CTkButton(buttons, text="Save Profile", command=self._save_form).grid(
            row=0, column=1, sticky="ew", padx=3
        )
        ctk.CTkButton(buttons, text="Reload", command=self._reload).grid(
            row=0, column=2, sticky="ew", padx=3
        )

        self.editor = YamlEditor(right, "Advanced YAML (local values only)")
        self.editor.grid(row=13, column=0, columnspan=2, sticky="nsew", pady=(8, 0))
        advanced = ctk.CTkFrame(right, fg_color="transparent")
        advanced.grid(row=14, column=0, columnspan=2, sticky="ew", pady=6)
        advanced.grid_columnconfigure((0, 1), weight=1)
        ctk.CTkButton(advanced, text="Validate YAML", command=self._validate_yaml).grid(
            row=0, column=0, sticky="ew", padx=3
        )
        ctk.CTkButton(advanced, text="Save Advanced YAML", command=self._save_yaml).grid(
            row=0, column=1, sticky="ew", padx=3
        )

    def _combo_row(self, parent: ctk.CTkBaseClass, row: int, label: str) -> ctk.CTkComboBox:
        ctk.CTkLabel(parent, text=label).grid(row=row, column=0, sticky="w", padx=(4, 8), pady=4)
        combo = ctk.CTkComboBox(parent, values=["None"], state="readonly")
        combo.grid(row=row, column=1, sticky="ew", pady=4)
        return combo

    def refresh(
        self,
        profile: SiteProfile,
        yaml_path: Path,
        profile_names: list[str] | None = None,
        local_values: dict[str, object] | None = None,
        consumers: dict[str, list[str]] | None = None,
    ) -> None:
        self.current_path = yaml_path
        names = profile_names or [profile.profile_name]
        self.profile_select.configure(values=names)
        self.profile_select.set(profile.profile_name)
        self.base_select.configure(
            values=["None", *[name for name in names if name != profile.profile_name]]
        )
        local = local_values or {}
        self.base_select.set(str(local.get("inherits") or "None"))
        self.editor.set_text(yaml_path.read_text(encoding="utf-8"))
        self.editor.set_status("Profile loaded")
        effective = profile.model_dump(mode="python")
        values = {
            "profile_name": profile.profile_name,
            "base": local.get("inherits") or "None",
            "unused_vlan": profile.unused_vlan,
            "disabled_vlan": profile.disabled_port_policy.required_access_vlan,
            "trunk_prune": profile.trunk_policy.vlan_1_must_be_pruned,
            "dhcp_vlans": self._join(profile.dhcp_snooping.vlans),
            "arp_vlans": self._join(profile.arp_inspection.vlans),
        }
        for key, value in values.items():
            self.value_labels[key].configure(text=str(value))
        local_effective = SiteProfile.model_validate(effective)
        form_values = {
            "unused_vlan": local_effective.unused_vlan,
            "disabled_vlan": local_effective.disabled_port_policy.required_access_vlan,
            "dhcp_vlans": self._join(local_effective.dhcp_snooping.vlans),
            "arp_vlans": self._join(local_effective.arp_inspection.vlans),
            **{
                key: self._join(getattr(local_effective.topology, key))
                for key in (
                    "user_facing_interfaces",
                    "uplinks",
                    "access_layer_links",
                    "exempt_interfaces",
                    "authorized_trunks",
                )
            },
        }
        for key, value in form_values.items():
            self.entries[key].delete(0, "end")
            self.entries[key].insert(0, str(value))
        self._set_check(self.require_shutdown, profile.disabled_port_policy.require_shutdown)
        self._set_check(self.prune_vlan1, profile.trunk_policy.vlan_1_must_be_pruned)
        self._set_check(self.dhcp_enabled, profile.dhcp_snooping.enabled)
        self._set_check(self.arp_enabled, profile.arp_inspection.enabled)
        self.consumers.delete("1.0", "end")
        for key, checks in (consumers or {}).items():
            self.consumers.insert("end", f"{key}: {', '.join(checks)}\n")

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
        ok, message = self.app_controller.save_profile_yaml(
            self.profile_select.get(), self.editor.get_text()
        )
        self.editor.set_status(message, ok=ok)

    def _reload(self) -> None:
        if self.editor.is_dirty and not messagebox.askyesno(
            "Unsaved changes", "Discard unsaved profile changes?"
        ):
            return
        self.app_controller.select_profile(self.profile_select.get())

    def _profile_selected(self, value: str) -> None:
        if self.editor.is_dirty:
            self.editor.set_status(
                "Reload or save unsaved YAML before changing profiles.", ok=False
            )
            return
        self.app_controller.select_profile(value)

    def _create(self) -> None:
        name = simpledialog.askstring("Create profile", "New profile name:", parent=self)
        if name:
            self.app_controller.create_profile(
                name, None if self.base_select.get() == "None" else self.base_select.get()
            )

    def _clone(self) -> None:
        name = simpledialog.askstring("Clone profile", "New profile name:", parent=self)
        if name:
            self.app_controller.clone_profile(self.profile_select.get(), name)

    def _rename(self) -> None:
        name = simpledialog.askstring("Rename profile", "New profile name:", parent=self)
        if name:
            self.app_controller.rename_profile(self.profile_select.get(), name)

    def _delete(self) -> None:
        name = self.profile_select.get()
        if messagebox.askyesno(
            "Delete profile", f"Delete {name}? A dependent profile blocks deletion."
        ):
            self.app_controller.delete_profile(name)

    def _vlans(self, text: str) -> list[int]:
        values: set[int] = set()
        for token in text.replace(" ", "").split(","):
            if not token:
                continue
            if "-" in token:
                start, end = (int(item) for item in token.split("-", 1))
                values.update(range(start, end + 1))
            else:
                values.add(int(token))
        if any(value < 1 or value > 4094 for value in values):
            raise ValueError("VLANs must be between 1 and 4094")
        return sorted(values)

    def _items(self, text: str) -> list[str]:
        return [item.strip() for item in text.split(",") if item.strip()]

    def _join(self, values: Sequence[object]) -> str:
        return ",".join(str(value) for value in values)

    def _set_check(self, widget: ctk.CTkCheckBox, value: bool) -> None:
        widget.select() if value else widget.deselect()
