"""Main customtkinter window for STIG Audit Pro."""

from __future__ import annotations

import threading
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any, TypeVar

import customtkinter as ctk
import yaml
from pydantic import BaseModel, ValidationError

from stig_audit_pro.config import APP_VERSION
from stig_audit_pro.core.check_engine import CheckEngine
from stig_audit_pro.core.command_planner import plan_commands
from stig_audit_pro.core.output_cache import CommandOutputCache
from stig_audit_pro.core.ssh_runner import DeviceCredentials, DeviceTarget, NetmikoSshRunner
from stig_audit_pro.core.models import CheckDefinition, CheckLibrary, SiteProfile
from stig_audit_pro.core.result_model import CheckResult
from stig_audit_pro.core.yaml_loader import ConfigValidationError, deep_merge, load_check_library, load_profile, load_yaml_file
from stig_audit_pro.gui.checks_tab import ChecksTab
from stig_audit_pro.gui.license_tab import LicenseTab
from stig_audit_pro.gui.overview_tab import OverviewTab
from stig_audit_pro.gui.profiles_tab import ProfilesTab
from stig_audit_pro.gui.reports_tab import ReportsTab
from stig_audit_pro.gui.results_tab import ResultsTab
from stig_audit_pro.gui.stig_tab import StigTab
from stig_audit_pro.gui.targets_tab import TargetsTab
from stig_audit_pro.gui.widgets import configure_treeview_style
from stig_audit_pro.licensing import (
    LicenseImportError,
    LicenseManager,
    LicensePolicyError,
    LicenseStatus,
)
from stig_audit_pro.reports.audit_report import write_csv_report, write_text_report
from stig_audit_pro.storage.device_groups import DeviceGroup, DeviceGroupStore, DeviceTargetRecord
from stig_audit_pro.stig.check_generator import build_manual_starter_library, write_manual_starter_library
from stig_audit_pro.stig.ckl_writer import (
    CklAsset,
    checklist_vuln_ids,
    extract_ckl_asset,
    safe_device_filename,
    write_completed_ckl,
)
from stig_audit_pro.stig.source_manager import StigSourceError, StigSourceManager
from stig_audit_pro.stig.stig_metadata import StigBenchmarkMetadata

ModelT = TypeVar("ModelT", bound=BaseModel)

COMMAND_FILES = {
    "show running-config": "show_running_config.txt",
    "show vtp status": "show_vtp_status.txt",
    "show interfaces status": "show_interfaces_status.txt",
    "show interfaces switchport | include Negotiation of Trunking": "show_interfaces_switchport_negotiation.txt",
    "show interfaces trunk": "show_interfaces_trunk.txt",
    "show cdp neighbors detail": "show_cdp_neighbors_detail.txt",
    "show ip access-lists": "show_ip_access_lists.txt",
    "show ip dhcp snooping": "show_ip_dhcp_snooping.txt",
    "show ip arp inspection": "show_ip_arp_inspection.txt",
    "show snmp user": "show_snmp_user.txt",
    "show version": "show_version.txt",
}


class StigAuditProApp(ctk.CTk):
    def __init__(self) -> None:
        ctk.set_appearance_mode("System")
        ctk.set_default_color_theme("blue")
        super().__init__()
        configure_treeview_style()

        self.root_dir = Path(__file__).resolve().parents[2]
        self.data_dir = self.root_dir / "data"
        self.sample_dir = self.root_dir / "tests" / "sample_outputs"
        self.device_group_store = DeviceGroupStore(self.data_dir / "device_groups")
        self.stig_source_manager = StigSourceManager(self.data_dir / "stigs" / "cache")
        self.check_path = self.data_dir / "checks" / "iosxe_l2.yaml"
        self.ndm_check_path = self.data_dir / "checks" / "iosxe_ndm.yaml"
        self.check_library_paths: list[Path] = []
        self.profile_name = "example_site"
        self.profile_path = self.data_dir / "profiles" / "example_site.yaml"
        self.checks = []
        self.profile: SiteProfile | None = None
        self.results: list[CheckResult] = []
        self.last_artifacts: list[Path] = []
        self.stig_metadata: list[StigBenchmarkMetadata] = []
        self._scan_cancel_event = threading.Event()
        self._scan_thread: threading.Thread | None = None
        self._scan_in_progress = False
        self._license_notice_dismissed = False
        self.license_manager = LicenseManager()
        self.license_manager.load()

        self.title(f"STIG Audit Pro {APP_VERSION}")
        self.geometry("1280x820")
        self.minsize(1100, 720)
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        self._build_header()
        self._build_tabs()
        self._build_status_bar()
        self.reload_from_disk()
        self.refresh_device_groups()
        self.refresh_stig_metadata()
        self.refresh_license_status(announce=False)

    def _build_header(self) -> None:
        header = ctk.CTkFrame(self, corner_radius=0, fg_color=("#eef2f6", "#0f172a"))
        header.grid(row=0, column=0, sticky="ew")
        header.grid_columnconfigure(0, weight=1)
        title = ctk.CTkLabel(header, text="STIG Audit Pro", font=ctk.CTkFont(size=24, weight="bold"))
        title.grid(row=0, column=0, sticky="w", padx=18, pady=(12, 2))
        subtitle = ctk.CTkLabel(header, text="Cisco IOS-XE switch audit workspace", text_color=("#344054", "#d0d5dd"))
        subtitle.grid(row=1, column=0, sticky="w", padx=18, pady=(0, 12))
        self.version_label = ctk.CTkLabel(
            header,
            text=APP_VERSION,
            font=ctk.CTkFont(weight="bold"),
            corner_radius=8,
            fg_color=("#dbeafe", "#1e3a8a"),
            text_color=("#1e3a8a", "#eff6ff"),
            width=64,
            height=28,
        )
        self.version_label.grid(row=0, column=1, rowspan=2, sticky="e", padx=18)
        self.license_badge = ctk.CTkLabel(
            header,
            text="Free",
            font=ctk.CTkFont(weight="bold"),
            corner_radius=8,
            fg_color=("#fef3c7", "#78350f"),
            text_color=("#92400e", "#fef3c7"),
            width=82,
            height=28,
        )
        self.license_badge.grid(row=0, column=2, rowspan=2, sticky="e", padx=(0, 18))

        self.license_notice_frame = ctk.CTkFrame(
            header,
            corner_radius=0,
            fg_color=("#fffaeb", "#451a03"),
            border_width=1,
            border_color=("#f79009", "#b45309"),
        )
        self.license_notice_frame.grid(
            row=2,
            column=0,
            columnspan=3,
            sticky="ew",
        )
        self.license_notice_frame.grid_columnconfigure(0, weight=1)
        self.license_notice_label = ctk.CTkLabel(
            self.license_notice_frame,
            text="",
            anchor="w",
            text_color=("#7a2e0e", "#fef3c7"),
        )
        self.license_notice_label.grid(
            row=0,
            column=0,
            sticky="ew",
            padx=(18, 10),
            pady=7,
        )
        ctk.CTkButton(
            self.license_notice_frame,
            text="Open License",
            width=100,
            height=26,
            command=lambda: self.show_tab("License"),
        ).grid(row=0, column=1, padx=(0, 8), pady=5)
        ctk.CTkButton(
            self.license_notice_frame,
            text="Dismiss",
            width=76,
            height=26,
            fg_color="transparent",
            border_width=1,
            text_color=("#7a2e0e", "#fef3c7"),
            command=self._dismiss_license_notice,
        ).grid(row=0, column=2, padx=(0, 18), pady=5)
        self.license_notice_frame.grid_remove()

    def _build_tabs(self) -> None:
        self.tabs = ctk.CTkTabview(self)
        self.tabs.grid(row=1, column=0, sticky="nsew", padx=8, pady=8)
        tab_overview = self.tabs.add("Overview")
        tab_targets = self.tabs.add("Targets")
        tab_stig = self.tabs.add("STIG / CKL")
        tab_checks = self.tabs.add("Checks")
        tab_profiles = self.tabs.add("Profiles")
        tab_results = self.tabs.add("Results")
        tab_reports = self.tabs.add("Reports")
        tab_license = self.tabs.add("License")
        for tab in (tab_overview, tab_targets, tab_stig, tab_checks, tab_profiles, tab_results, tab_reports, tab_license):
            tab.grid_columnconfigure(0, weight=1)
            tab.grid_rowconfigure(0, weight=1)

        self.overview_tab = OverviewTab(tab_overview, self)
        self.overview_tab.grid(row=0, column=0, sticky="nsew")
        self.targets_tab = TargetsTab(tab_targets, self)
        self.targets_tab.grid(row=0, column=0, sticky="nsew")
        self.stig_tab = StigTab(tab_stig, self)
        self.stig_tab.grid(row=0, column=0, sticky="nsew")
        self.checks_tab = ChecksTab(tab_checks, self)
        self.checks_tab.grid(row=0, column=0, sticky="nsew")
        self.profiles_tab = ProfilesTab(tab_profiles, self)
        self.profiles_tab.grid(row=0, column=0, sticky="nsew")
        self.results_tab = ResultsTab(tab_results, self)
        self.results_tab.grid(row=0, column=0, sticky="nsew")
        self.reports_tab = ReportsTab(tab_reports, self)
        self.reports_tab.grid(row=0, column=0, sticky="nsew")
        self.license_tab = LicenseTab(tab_license, self)
        self.license_tab.grid(row=0, column=0, sticky="nsew")

    def _build_status_bar(self) -> None:
        footer = ctk.CTkFrame(self, corner_radius=0)
        footer.grid(row=2, column=0, sticky="ew")
        footer.grid_columnconfigure(0, weight=1)
        self.status_label = ctk.CTkLabel(footer, text="Ready", anchor="w")
        self.status_label.grid(row=0, column=0, sticky="ew", padx=14, pady=6)

    def set_status(self, message: str) -> None:
        self.status_label.configure(text=message)

    def show_tab(self, tab_name: str) -> None:
        self.tabs.set(tab_name)

    def show_result(self, result: CheckResult) -> None:
        """Open the Results tab with the requested result selected."""
        self.show_tab("Results")
        self.results_tab.select_result(result.ip, result.vuln_id)

    def refresh_license_status(self, announce: bool = True) -> None:
        self.license_manager.reload()
        self.license_tab.refresh(self.license_manager)
        self.license_badge.configure(
            text=self.license_manager.edition,
            fg_color=(
                ("#dcfce7", "#14532d")
                if self.license_manager.is_valid
                else ("#fef3c7", "#78350f")
            ),
            text_color=(
                ("#166534", "#dcfce7")
                if self.license_manager.is_valid
                else ("#92400e", "#fef3c7")
            ),
        )
        self._update_license_notice()
        if announce:
            self.set_status(
                f"License status: {self.license_manager.mode_summary}."
            )

    def _update_license_notice(self) -> None:
        if self.license_manager.is_valid or self._license_notice_dismissed:
            self.license_notice_frame.grid_remove()
            return
        messages = {
            LicenseStatus.INVALID: (
                "The installed license is invalid. STIG Audit Pro is running "
                "in Free mode."
            ),
            LicenseStatus.EXPIRED: (
                "The installed license has expired. STIG Audit Pro is running "
                "in Free mode."
            ),
            LicenseStatus.MISSING: (
                "No license is installed. STIG Audit Pro is running in Free mode."
            ),
            LicenseStatus.FREE: "STIG Audit Pro is running in Free mode.",
        }
        self.license_notice_label.configure(
            text=messages.get(
                self.license_manager.status,
                "STIG Audit Pro is running in Free mode.",
            )
        )
        self.license_notice_frame.grid()

    def _dismiss_license_notice(self) -> None:
        self._license_notice_dismissed = True
        self.license_notice_frame.grid_remove()

    def import_license_file(self, path: Path) -> None:
        try:
            destination = self.license_manager.import_license(path)
            self.refresh_license_status(announce=False)
            self.license_tab.set_message(
                f"License imported and verified. Installed at {destination}."
            )
            self.tabs.set("License")
            self.set_status(
                f"License {self.license_manager.license_id} imported successfully."
            )
        except LicenseImportError as exc:
            self.refresh_license_status(announce=False)
            self.tabs.set("License")
            self.set_status("License import failed; Free mode remains active.")
            self._show_error(str(exc), kind="license")

    def reload_from_disk(self) -> None:
        try:
            self.check_library_paths = self._check_library_paths()
            libraries = [load_check_library(path) for path in self.check_library_paths]
            checks = [check for library in libraries for check in library.checks]
            self._raise_on_duplicate_checks(checks)
            self.checks = checks
            self._set_active_profile(self.profile_name, announce=False)
            self.checks_tab.refresh(self.checks, self.check_library_paths)
            self.overview_tab.refresh_inventory(self.checks, self.profile)
            self.refresh_device_groups()
            self.set_status(f"Loaded {len(self.checks)} checks using profile {self.profile.profile_name if self.profile else self.profile_name}.")
        except ConfigValidationError as exc:
            self.set_status("YAML validation failed.")
            self._show_error(str(exc), kind="validation")
        except ValueError as exc:
            self.set_status("Check library validation failed.")
            self._show_error(str(exc), kind="validation")

    def available_profile_names(self) -> list[str]:
        return sorted(path.stem for path in (self.data_dir / "profiles").glob("*.yaml"))

    def _check_library_paths(self) -> list[Path]:
        return sorted((self.data_dir / "checks").glob("*.yaml"))

    def _raise_on_duplicate_checks(self, checks: list[CheckDefinition]) -> None:
        seen: set[str] = set()
        duplicates: set[str] = set()
        for check in checks:
            if check.vuln_id in seen:
                duplicates.add(check.vuln_id)
            seen.add(check.vuln_id)
        if duplicates:
            raise ValueError(f"Duplicate check IDs across check libraries: {', '.join(sorted(duplicates))}")

    def refresh_device_groups(self) -> None:
        self.targets_tab.refresh_groups(
            self.device_group_store.list_groups(),
            self.available_profile_names(),
        )

    def refresh_stig_metadata(self) -> None:
        self.stig_metadata = self.stig_source_manager.load_cached_metadata()
        self.stig_tab.refresh_metadata(self.stig_metadata)

    def download_latest_stig(self, family: str) -> None:
        try:
            self.set_status(f"Finding latest {family} STIG metadata from Cyber Exchange...")
            self.update_idletasks()
            metadata = self.stig_source_manager.download_latest(family)
            self.refresh_stig_metadata()
            self.stig_tab.set_status(f"Downloaded {metadata.display_name} with {metadata.rule_count} rule(s).")
            self.set_status(f"Downloaded {metadata.display_name}.")
        except Exception as exc:
            self.stig_tab.set_status("Automatic lookup failed. Paste a direct ZIP/XML URL or import the downloaded file.")
            self.set_status("STIG lookup failed.")
            self._show_error(str(exc))

    def download_core_stigs(self) -> None:
        try:
            downloaded: list[StigBenchmarkMetadata] = []
            for family in ("IOSXE_L2", "IOSXE_NDM"):
                self.set_status(f"Finding latest {family} STIG metadata from Cyber Exchange...")
                self.update_idletasks()
                downloaded.append(self.stig_source_manager.download_latest(family))
            self.refresh_stig_metadata()
            summary = ", ".join(f"{item.family} {item.version}" for item in downloaded)
            self.stig_tab.set_status(f"Downloaded {summary}.")
            self.set_status(f"Downloaded {summary}.")
        except Exception as exc:
            self.stig_tab.set_status("Automatic L2/NDM lookup failed. Paste a direct ZIP/XML URL or import the downloaded file.")
            self.set_status("STIG lookup failed.")
            self._show_error(str(exc))

    def download_stig_from_url(self, url: str, family: str) -> None:
        try:
            self.set_status(f"Downloading {family} STIG package from direct URL...")
            self.update_idletasks()
            metadata = self.stig_source_manager.download_from_url(url, family=family)
            self.refresh_stig_metadata()
            self.stig_tab.set_status(f"Downloaded {metadata.display_name} with {metadata.rule_count} rule(s).")
            self.set_status(f"Downloaded {metadata.display_name}.")
        except Exception as exc:
            self.stig_tab.set_status("Direct URL download failed. Import the ZIP/XML file if the link is protected.")
            self.set_status("STIG URL download failed.")
            self._show_error(str(exc))

    def import_stig_source(self, path: Path, family: str) -> None:
        try:
            metadata = self.stig_source_manager.import_source(path, family=family)
            self.refresh_stig_metadata()
            self.stig_tab.set_status(f"Imported {metadata.display_name} with {metadata.rule_count} rule(s).")
            self.set_status(f"Imported {metadata.display_name}.")
        except Exception as exc:
            self.stig_tab.set_status("STIG import failed.")
            self.set_status("STIG import failed.")
            self._show_error(str(exc))

    def generate_starter_checks_from_stigs(self) -> None:
        try:
            self.refresh_stig_metadata()
            if not self.stig_metadata:
                raise ValueError("Import the current L2/NDM STIG ZIP/XML first, then build starter checks.")
            starter_library = build_manual_starter_library(self.stig_metadata, self.checks)
            destination = self.data_dir / "checks" / "generated_stig_manual.yaml"
            write_manual_starter_library(starter_library, destination)
            self.reload_from_disk()
            self.stig_tab.set_status(
                f"Generated {len(starter_library.checks)} starter manual review check(s) in {destination.name}."
            )
            self.set_status(f"Generated {len(starter_library.checks)} starter check(s).")
        except Exception as exc:
            self.stig_tab.set_status("Starter check generation failed.")
            self.set_status("Starter check generation failed.")
            self._show_error(str(exc))

    def load_device_group(self, group_name: str) -> None:
        try:
            group = self.device_group_store.load_group(group_name)
            if group.profile_name:
                self._set_active_profile(group.profile_name, announce=False)
            self.targets_tab.set_targets(group.targets, group.group_name, group.profile_name)
            profile_text = group.profile_name or (self.profile.profile_name if self.profile else self.profile_name)
            self.set_status(
                f"Loaded {group.group_name}: {len(group.targets)} target(s), profile {profile_text}."
            )
        except Exception as exc:
            self.set_status("Could not load device group.")
            self._show_error(str(exc))

    def save_device_group(
        self,
        group_name: str,
        targets: list[DeviceTargetRecord],
        profile_name: str | None = None,
    ) -> None:
        try:
            self.license_manager.require_feature("saved_presets")
            resolved_profile = profile_name or (self.profile.profile_name if self.profile else self.profile_name)
            group = DeviceGroup(
                group_name=group_name,
                profile_name=resolved_profile,
                targets=targets,
            )
            path = self.device_group_store.save_group(group)
            self.refresh_device_groups()
            self.targets_tab.group_select.set(group.group_name)
            self.targets_tab.group_profile.set(group.profile_name or "Use selected profile")
            self.set_status(
                f"Saved {len(targets)} target(s) to {path.name} with profile {resolved_profile}."
            )
        except Exception as exc:
            self.set_status("Could not save device group.")
            self._show_error(str(exc))

    def select_profile(self, profile_name: str) -> None:
        try:
            self._set_active_profile(profile_name)
            self.refresh_device_groups()
        except Exception as exc:
            self.set_status("Could not load profile.")
            self._show_error(str(exc), kind="validation")

    def _begin_scan(self, total: int, message: str) -> bool:
        if self._scan_in_progress:
            self.set_status(
                "A scan is already running. Cancel it or wait for it to finish."
            )
            return False
        self._scan_cancel_event.clear()
        self._scan_in_progress = True
        self.targets_tab.set_scan_state(
            running=True,
            completed=0,
            total=total,
            message=f"0/{total} devices",
        )
        self.stig_tab.set_scan_running(True)
        self.set_status(message)
        return True

    def _queue_scan_progress(
        self,
        completed: int,
        total: int,
        message: str,
        *,
        checklist: bool = False,
    ) -> None:
        self.after(
            0,
            lambda: self._update_scan_progress(
                completed,
                total,
                message,
                checklist=checklist,
            ),
        )

    def _update_scan_progress(
        self,
        completed: int,
        total: int,
        message: str,
        *,
        checklist: bool = False,
    ) -> None:
        self.targets_tab.set_scan_state(
            running=True,
            completed=completed,
            total=total,
        )
        self.set_status(message)
        if checklist:
            self.stig_tab.set_checklist_status(message)

    def _finish_scan_ui(
        self,
        *,
        completed: int,
        total: int,
        message: str,
    ) -> None:
        self._scan_in_progress = False
        self._scan_thread = None
        self.targets_tab.set_scan_state(
            running=False,
            completed=completed,
            total=total,
        )
        self.stig_tab.set_scan_running(False)
        self.set_status(message)

    def cancel_scan(self) -> None:
        if not self._scan_in_progress:
            self.set_status("No scan is currently running.")
            return
        self._scan_cancel_event.set()
        message = (
            "Cancel requested. The current device will finish, then remaining "
            "targets will be skipped."
        )
        self.set_status(message)
        self.stig_tab.set_checklist_status(message)

    def run_target_scope(self, scope: str) -> None:
        targets = self.targets_tab.get_targets(scope)
        if not targets:
            self.set_status(f"No targets available for {scope} run.")
            return
        try:
            targets = self._licensed_targets(targets)
            checks = self._licensed_checks(self.checks)
            settings = self.targets_tab.get_scan_settings()
            if settings.get("mode") == "Live SSH":
                self._run_live_for_targets(targets, settings, scope, checks)
            else:
                self._run_sample_for_targets(targets, scope, checks)
        except LicensePolicyError as exc:
            self.refresh_license_status(announce=False)
            self.set_status("Scan blocked by the current license.")
            self._show_error(str(exc), kind="license")

    def run_sample_audit(self, sample_name: str) -> None:
        ip = "10.50.10.25" if sample_name == "compliant" else "10.50.10.26"
        target = DeviceTargetRecord(ip=ip, checked=True)
        try:
            targets = self._licensed_targets([target])
            checks = self._licensed_checks(self.checks)
            self._run_sample_for_targets(targets, sample_name, checks)
        except LicensePolicyError as exc:
            self.refresh_license_status(announce=False)
            self.set_status("Demo scan blocked by the current license.")
            self._show_error(str(exc), kind="license")

    def update_report_summary(self, results: list[CheckResult]) -> None:
        self.reports_tab.refresh(results)
        self.overview_tab.refresh_results(results)

    def export_text_report(self, path: Path) -> None:
        try:
            self.license_manager.require_feature("advanced_reporting")
            if not self.results:
                raise ValueError("Run a scan before exporting a report.")
            destination = write_text_report(self.results, path)
            self.set_status(f"Saved TXT report to {destination}.")
            self.reports_tab.set_export_status(f"Saved TXT report: {destination}")
        except LicensePolicyError as exc:
            self.set_status("TXT report export blocked by the current license.")
            self._show_error(str(exc), kind="license")
        except ValueError as exc:
            self.set_status("TXT report export needs more information.")
            self._show_error(str(exc), kind="validation")
        except Exception as exc:
            self.set_status("TXT report export failed.")
            self._show_error(str(exc))

    def export_csv_report(self, path: Path) -> None:
        try:
            self.license_manager.require_feature("advanced_reporting")
            if not self.results:
                raise ValueError("Run a scan before exporting a report.")
            destination = write_csv_report(self.results, path)
            self.set_status(f"Saved CSV report to {destination}.")
            self.reports_tab.set_export_status(f"Saved CSV report: {destination}")
        except LicensePolicyError as exc:
            self.set_status("CSV report export blocked by the current license.")
            self._show_error(str(exc), kind="license")
        except ValueError as exc:
            self.set_status("CSV report export needs more information.")
            self._show_error(str(exc), kind="validation")
        except Exception as exc:
            self.set_status("CSV report export failed.")
            self._show_error(str(exc))

    def run_checklist_audit(
        self,
        *,
        families: set[str],
        ckl_paths: dict[str, Path | None],
        output_dir: Path | None,
        create_ckl: bool,
        create_text: bool,
        append_comments: bool,
    ) -> None:
        """Run L2, NDM, or a combined audit and create the selected artifacts."""

        scan_started = False
        try:
            supported_families = {"IOSXE_L2", "IOSXE_NDM"}
            selected_families = families & supported_families
            if not selected_families:
                raise ValueError("Select L2, NDM, or both before starting the audit.")

            self.license_manager.reload()
            if "IOSXE_L2" in selected_families:
                self.license_manager.require_feature("l2_checks", refresh=False)
            if "IOSXE_NDM" in selected_families:
                self.license_manager.require_feature("ndm_checks", refresh=False)
            if create_ckl:
                self.license_manager.require_feature("ckl_export", refresh=False)
            if create_text:
                self.license_manager.require_feature(
                    "advanced_reporting",
                    refresh=False,
                )
            if not create_ckl and not create_text:
                raise ValueError("Select Fill CKL, Create text report, or both.")
            if output_dir is None:
                raise ValueError(
                    "Select a destination folder for the completed files."
                )
            output_dir.mkdir(parents=True, exist_ok=True)

            checks_by_family = {
                family: [
                    check for check in self.checks if check.stig_family == family
                ]
                for family in supported_families
            }
            for family in selected_families:
                if not checks_by_family[family]:
                    raise ValueError(f"No {family} checks are loaded.")

            selected_checks = [
                check
                for check in self.checks
                if check.stig_family in selected_families
            ]
            if selected_families == supported_families:
                scan_label = "L2 + NDM"
                file_label = "IOSXE_L2_NDM"
                selected_template_key = "COMBINED"
            elif selected_families == {"IOSXE_NDM"}:
                scan_label = "NDM"
                file_label = "IOSXE_NDM"
                selected_template_key = "IOSXE_NDM"
            else:
                scan_label = "L2"
                file_label = "IOSXE_L2"
                selected_template_key = "IOSXE_L2"

            selected_template: Path | None = None
            if create_ckl:
                template_labels = {
                    "IOSXE_L2": "L2",
                    "IOSXE_NDM": "NDM",
                    "COMBINED": "combined L2 and NDM",
                }
                missing_templates = [
                    template_labels[key]
                    for key in ("IOSXE_L2", "IOSXE_NDM", "COMBINED")
                    if ckl_paths.get(key) is None
                ]
                if missing_templates:
                    raise ValueError(
                        "Select all three CKL templates before running: "
                        + ", ".join(missing_templates)
                        + "."
                    )

                template_ids = {
                    key: checklist_vuln_ids(path)
                    for key in ("IOSXE_L2", "IOSXE_NDM", "COMBINED")
                    if (path := ckl_paths.get(key)) is not None
                }
                family_ids = {
                    family: {
                        check.vuln_id for check in checks_by_family[family]
                    }
                    for family in supported_families
                }
                if not (template_ids["IOSXE_L2"] & family_ids["IOSXE_L2"]):
                    raise ValueError(
                        "The selected L2 CKL template contains no IOS-XE L2 "
                        "vulnerability IDs."
                    )
                if not (template_ids["IOSXE_NDM"] & family_ids["IOSXE_NDM"]):
                    raise ValueError(
                        "The selected NDM CKL template contains no IOS-XE NDM "
                        "vulnerability IDs."
                    )
                combined_ids = template_ids["COMBINED"]
                if not (
                    combined_ids & family_ids["IOSXE_L2"]
                    and combined_ids & family_ids["IOSXE_NDM"]
                ):
                    raise ValueError(
                        "The combined CKL template must contain both IOS-XE L2 "
                        "and IOS-XE NDM vulnerability IDs."
                    )
                selected_template = ckl_paths[selected_template_key]

            targets = self.targets_tab.get_targets("checked")
            if not targets:
                raise ValueError("Check at least one target on the Targets tab.")
            targets = self._licensed_targets(targets, refresh=False)
            settings = self.targets_tab.get_scan_settings()
            if settings.get("mode") != "Live SSH":
                raise ValueError(
                    "The CKL workflow requires Live SSH. On the Targets tab, "
                    "change Scan Mode from Sample outputs to Live SSH."
                )
            username = str(settings.get("username") or "")
            password = str(settings.get("password") or "")
            if not username or not password:
                raise ValueError(
                    "Live SSH requires a username and password on the Targets tab."
                )
            if not self._begin_scan(
                len(targets),
                f"Starting {scan_label} checklist audit for "
                f"{len(targets)} target(s)...",
            ):
                return
            scan_started = True
            self._scan_thread = threading.Thread(
                target=self._checklist_scan_worker,
                args=(
                    list(targets),
                    dict(settings),
                    list(selected_checks),
                    set(selected_families),
                    scan_label,
                    file_label,
                    selected_template,
                    output_dir,
                    create_ckl,
                    create_text,
                    append_comments,
                ),
                daemon=True,
                name="stig-audit-checklist-scan",
            )
            self._scan_thread.start()
        except LicensePolicyError as exc:
            if scan_started:
                self._finish_scan_ui(
                    completed=0,
                    total=len(targets) if "targets" in locals() else 0,
                    message="Checklist audit could not be started.",
                )
            self.refresh_license_status(announce=False)
            self.stig_tab.set_checklist_status(
                f"Checklist audit blocked by license: {exc}"
            )
            self.set_status("Checklist audit blocked by the current license.")
            self._show_error(str(exc), kind="license")
        except Exception as exc:
            if scan_started:
                self._finish_scan_ui(
                    completed=0,
                    total=len(targets) if "targets" in locals() else 0,
                    message="Checklist audit could not be started.",
                )
            self.stig_tab.set_checklist_status(
                f"Checklist audit failed: {exc}"
            )
            self.set_status("Checklist audit failed.")
            self._show_error(str(exc), kind="validation")

    def _checklist_scan_worker(
        self,
        targets: list[DeviceTargetRecord],
        settings: dict[str, object],
        checks: list[CheckDefinition],
        selected_families: set[str],
        scan_label: str,
        file_label: str,
        selected_template: Path | None,
        output_dir: Path,
        create_ckl: bool,
        create_text: bool,
        append_comments: bool,
    ) -> None:
        progress = {"completed": 0}
        total = len(targets)

        def progress_callback(
            completed: int,
            progress_total: int,
            message: str,
        ) -> None:
            progress["completed"] = completed
            self._queue_scan_progress(
                completed,
                progress_total,
                message,
                checklist=True,
            )

        try:
            results, assets = self._run_l2_targets(
                targets,
                settings,
                checks,
                audit_label=scan_label,
                cancel_event=self._scan_cancel_event,
                progress_callback=progress_callback,
            )

            artifacts: list[Path] = []
            unmatched_count = 0
            if create_ckl and selected_template is not None:
                for target in targets:
                    asset = assets.get(target.ip)
                    device_results = [
                        result
                        for result in results
                        if result.ip == target.ip
                        and result.stig_family in selected_families
                    ]
                    if asset is None or not device_results:
                        continue
                    filename = (
                        f"{safe_device_filename(asset.hostname)}_"
                        f"{safe_device_filename(target.ip)}_"
                        f"{file_label}_completed.ckl"
                    )
                    summary = write_completed_ckl(
                        selected_template,
                        output_dir / filename,
                        device_results,
                        asset,
                        append_comments=append_comments,
                    )
                    artifacts.append(summary.path)
                    unmatched_count += len(summary.unmatched_result_ids)

            if create_text and results:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                report_path = (
                    output_dir / f"{file_label}_audit_{timestamp}.txt"
                )
                artifacts.append(write_text_report(results, report_path))

            cancelled = self._scan_cancel_event.is_set()
            completed = progress["completed"]
            self.after(
                0,
                lambda: self._complete_checklist_scan(
                    results,
                    artifacts,
                    unmatched_count,
                    scan_label,
                    output_dir,
                    completed,
                    total,
                    cancelled,
                ),
            )
        except Exception as exc:
            message = str(exc)
            completed = progress["completed"]
            self.after(
                0,
                lambda: self._handle_background_scan_error(
                    message,
                    completed,
                    total,
                    checklist=True,
                ),
            )

    def _complete_checklist_scan(
        self,
        results: list[CheckResult],
        artifacts: list[Path],
        unmatched_count: int,
        scan_label: str,
        output_dir: Path,
        completed: int,
        total: int,
        cancelled: bool,
    ) -> None:
        self.last_artifacts = artifacts
        self.results = results
        self.results_tab.refresh(results)
        self.update_report_summary(results)
        if results:
            self.tabs.set("Results")
        open_count = sum(result.status == "Open" for result in results)
        pass_count = sum(result.status == "NotAFinding" for result in results)
        prefix = (
            f"{scan_label} audit cancelled after {completed}/{total} target(s)"
            if cancelled
            else f"{scan_label} audit complete for {completed} target(s)"
        )
        message = (
            f"{prefix}: {pass_count} NotAFinding, {open_count} Open; "
            f"created {len(artifacts)} file(s) in {output_dir}."
        )
        if unmatched_count:
            message += (
                f" {unmatched_count} result(s) had no matching CKL "
                "vulnerability."
            )
        self.stig_tab.set_checklist_status(message)
        self._finish_scan_ui(
            completed=completed,
            total=total,
            message=message,
        )

    def run_l2_checklist_audit(
        self,
        *,
        ckl_path: Path | None,
        output_dir: Path | None,
        create_ckl: bool,
        create_text: bool,
        append_comments: bool,
    ) -> None:
        """Run only the IOS-XE L2 library and optionally write CKL/TXT artifacts."""

        try:
            self.license_manager.reload()
            self.license_manager.require_feature("l2_checks", refresh=False)
            if create_ckl:
                self.license_manager.require_feature("ckl_export", refresh=False)
            if create_text:
                self.license_manager.require_feature(
                    "advanced_reporting", refresh=False
                )
            if not create_ckl and not create_text:
                raise ValueError("Select Fill CKL, Create text report, or both.")
            if output_dir is None:
                raise ValueError("Select a destination folder for the completed files.")
            output_dir.mkdir(parents=True, exist_ok=True)
            if create_ckl:
                if ckl_path is None:
                    raise ValueError("Select the L2 CKL template to populate.")
                template_ids = checklist_vuln_ids(ckl_path)
            else:
                template_ids = set()

            checks = [check for check in self.checks if check.stig_family == "IOSXE_L2"]
            if not checks:
                raise ValueError("No IOSXE_L2 checks are loaded.")
            if create_ckl and not (template_ids & {check.vuln_id for check in checks}):
                raise ValueError(
                    "The selected CKL does not contain vulnerability IDs from the IOS-XE L2 library."
                )

            targets = self.targets_tab.get_targets("checked")
            if not targets:
                raise ValueError("Check at least one target on the Targets tab.")
            targets = self._licensed_targets(targets, refresh=False)
            settings = self.targets_tab.get_scan_settings()
            if settings.get("mode") != "Live SSH":
                raise ValueError(
                    "The CKL workflow requires Live SSH. On the Targets tab, "
                    "change Scan Mode from Sample outputs to Live SSH."
                )
            results, assets = self._run_l2_targets(targets, settings, checks)

            artifacts: list[Path] = []
            unmatched_count = 0
            if create_ckl and ckl_path is not None:
                for target in targets:
                    asset = assets.get(target.ip)
                    device_results = [
                        result
                        for result in results
                        if result.ip == target.ip and result.stig_family == "IOSXE_L2"
                    ]
                    if asset is None or not device_results:
                        continue
                    filename = (
                        f"{safe_device_filename(asset.hostname)}_"
                        f"{safe_device_filename(target.ip)}_IOSXE_L2_completed.ckl"
                    )
                    summary = write_completed_ckl(
                        ckl_path,
                        output_dir / filename,
                        device_results,
                        asset,
                        append_comments=append_comments,
                    )
                    artifacts.append(summary.path)
                    unmatched_count += len(summary.unmatched_result_ids)

            if create_text:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                report_path = output_dir / f"IOSXE_L2_audit_{timestamp}.txt"
                artifacts.append(write_text_report(results, report_path))

            self.last_artifacts = artifacts
            self.results = results
            self.results_tab.refresh(results)
            self.update_report_summary(results)
            self.tabs.set("Results")
            open_count = sum(result.status == "Open" for result in results)
            pass_count = sum(result.status == "NotAFinding" for result in results)
            message = (
                f"L2 audit complete for {len(targets)} target(s): "
                f"{pass_count} NotAFinding, {open_count} Open; "
                f"created {len(artifacts)} file(s) in {output_dir}."
            )
            if unmatched_count:
                message += f" {unmatched_count} result(s) had no matching CKL vulnerability."
            self.stig_tab.set_checklist_status(message)
            self.set_status(message)
        except Exception as exc:
            self.stig_tab.set_checklist_status(f"L2 checklist audit failed: {exc}")
            self.set_status("L2 checklist audit failed.")
            kind = (
                "license"
                if isinstance(exc, LicensePolicyError)
                else "validation"
                if isinstance(exc, (ValueError, ConfigValidationError))
                else "generic"
            )
            self._show_error(str(exc), kind=kind)

    def _run_l2_targets(
        self,
        targets: list[DeviceTargetRecord],
        settings: dict[str, object],
        checks: list[CheckDefinition],
        audit_label: str = "L2",
        cancel_event: threading.Event | None = None,
        progress_callback: Callable[[int, int, str], None] | None = None,
    ) -> tuple[list[CheckResult], dict[str, CklAsset]]:
        results: list[CheckResult] = []
        assets: dict[str, CklAsset] = {}
        mode = str(settings.get("mode") or "Sample outputs")
        credentials: DeviceCredentials | None = None
        runner: NetmikoSshRunner | None = None
        commands = plan_commands(checks, run_all=False)

        if mode == "Live SSH":
            username = str(settings.get("username") or "")
            password = str(settings.get("password") or "")
            if not username or not password:
                raise ValueError("Live SSH requires a username and password on the Targets tab.")
            credentials = DeviceCredentials(
                username=username,
                password=password,
                secret=settings.get("secret") if isinstance(settings.get("secret"), str) else None,
            )
            runner = NetmikoSshRunner(
                CommandOutputCache(self.root_dir / "work" / "cache" / "ssh")
            )

        completed = 0
        total = len(targets)
        for index, target in enumerate(targets, start=1):
            if cancel_event is not None and cancel_event.is_set():
                break
            if progress_callback is not None:
                progress_callback(
                    completed,
                    total,
                    f"Running {audit_label} audit on {target.ip} "
                    f"({index}/{total})...",
                )
            if mode == "Live SSH":
                assert runner is not None and credentials is not None
                run = runner.run_commands(
                    DeviceTarget(
                        ip=target.ip,
                        timeout=int(settings.get("timeout") or 30),
                    ),
                    credentials,
                    commands,
                )
                if run.status == "skipped":
                    results.append(
                        self._skipped_result(
                            target.ip,
                            run.error_message or "SSH connection failed",
                            commands,
                        )
                    )
                    completed += 1
                    if progress_callback is not None:
                        progress_callback(
                            completed,
                            total,
                            f"Completed {target.ip} ({completed}/{total}).",
                        )
                    continue
                outputs = run.outputs
            else:
                outputs = self._load_sample_outputs(self._sample_name_for_target(target))

            profile = self._profile_for_target(target)
            asset = extract_ckl_asset(
                outputs,
                target.ip,
                management_vlan=profile.management_vlan,
            )
            assets[target.ip] = asset
            engine = CheckEngine(profile)
            results.extend(
                engine.evaluate_all(
                    checks,
                    outputs=outputs,
                    ip=target.ip,
                    hostname=asset.hostname,
                )
            )
            completed += 1
            if progress_callback is not None:
                progress_callback(
                    completed,
                    total,
                    f"Completed {target.ip} ({completed}/{total}).",
                )
        return results, assets

    def validate_check_yaml(self, text: str) -> tuple[bool, str]:
        try:
            data = yaml.safe_load(text) or {}
            library = self._validate_model(CheckLibrary, data)
            return True, f"{len(library.checks)} checks valid"
        except (ValidationError, yaml.YAMLError, ValueError) as exc:
            return False, self._short_error(exc)

    def save_check_yaml(self, path: Path, text: str) -> tuple[bool, str]:
        try:
            ok, message = self.validate_check_yaml(text)
            if not ok:
                return False, message
            path.write_text(text, encoding="utf-8")
            self.reload_from_disk()
            return True, f"Saved {path.name}"
        except OSError as exc:
            return False, self._short_error(exc)

    def validate_profile_yaml(self, text: str) -> tuple[bool, str]:
        try:
            data = yaml.safe_load(text) or {}
            if not isinstance(data, dict):
                raise ValueError("Profile YAML must be a mapping")
            inherits = data.get("inherits")
            if inherits:
                base_path = self.data_dir / "profiles" / f"{inherits}.yaml"
                data = deep_merge(load_yaml_file(base_path), data)
            profile = self._validate_model(SiteProfile, data)
            return True, f"{profile.profile_name} valid"
        except (ValidationError, yaml.YAMLError, ValueError) as exc:
            return False, self._short_error(exc)

    def save_profile_yaml(self, path: Path, text: str) -> tuple[bool, str]:
        try:
            ok, message = self.validate_profile_yaml(text)
            if not ok:
                return False, message
            path.write_text(text, encoding="utf-8")
            self.profile_name = path.stem
            self.reload_from_disk()
            return True, f"Saved {path.name}"
        except (OSError, yaml.YAMLError) as exc:
            return False, self._short_error(exc)

    def _set_active_profile(self, profile_name: str, announce: bool = True) -> None:
        self.profile_name = profile_name
        self.profile_path = self.data_dir / "profiles" / f"{profile_name}.yaml"
        self.profile = load_profile(self.profile_path)
        self.profiles_tab.refresh(self.profile, self.profile_path)
        if announce:
            self.set_status(f"Selected site profile {self.profile.profile_name}.")

    def _run_sample_for_targets(
        self,
        targets: list[DeviceTargetRecord],
        label: str,
        checks: list[CheckDefinition],
    ) -> None:
        if self.profile is None:
            self.reload_from_disk()
        if self.profile is None:
            return
        try:
            results: list[CheckResult] = []
            for target in targets:
                profile = self._profile_for_target(target)
                engine = CheckEngine(profile)
                sample_name = self._sample_name_for_target(target)
                outputs = self._load_sample_outputs(sample_name)
                results.extend(engine.evaluate_all(checks, outputs=outputs, ip=target.ip))
            self.results = results
            self.results_tab.refresh(self.results)
            self.update_report_summary(self.results)
            open_count = sum(1 for result in self.results if result.status == "Open")
            pass_count = sum(1 for result in self.results if result.status == "NotAFinding")
            self.tabs.set("Results")
            self.set_status(
                f"{label.title()} run complete for {len(targets)} target(s): "
                f"{pass_count} NotAFinding, {open_count} Open."
            )
        except Exception as exc:
            self.set_status("Sample target run failed.")
            self._show_error(str(exc))

    def _run_live_for_targets(
        self,
        targets: list[DeviceTargetRecord],
        settings: dict[str, object],
        label: str,
        checks: list[CheckDefinition],
    ) -> None:
        username = str(settings.get("username") or "")
        password = str(settings.get("password") or "")
        if not username or not password:
            self.set_status("Live SSH requires a username and password.")
            self._show_error(
                "Enter both an SSH username and password on the Targets tab.",
                kind="validation",
            )
            return
        if not self._begin_scan(
            len(targets),
            f"Starting {label} SSH scan for {len(targets)} target(s)...",
        ):
            return

        try:
            timeout = int(settings.get("timeout") or 30)
            credentials = DeviceCredentials(
                username=username,
                password=password,
                secret=settings.get("secret") if isinstance(settings.get("secret"), str) else None,
            )
            commands = plan_commands(checks, run_all=False)
            self._scan_thread = threading.Thread(
                target=self._live_scan_worker,
                args=(
                    list(targets),
                    credentials,
                    timeout,
                    label,
                    list(checks),
                    commands,
                ),
                daemon=True,
                name="stig-audit-live-scan",
            )
            self._scan_thread.start()
        except Exception as exc:
            self._finish_scan_ui(
                completed=0,
                total=len(targets),
                message="Live SSH scan could not be started.",
            )
            self._show_error(str(exc), kind="connection")

    def _live_scan_worker(
        self,
        targets: list[DeviceTargetRecord],
        credentials: DeviceCredentials,
        timeout: int,
        label: str,
        checks: list[CheckDefinition],
        commands: list[str],
    ) -> None:
        runner = NetmikoSshRunner(
            CommandOutputCache(self.root_dir / "work" / "cache" / "ssh")
        )
        results: list[CheckResult] = []
        completed = 0
        total = len(targets)
        try:
            for index, target in enumerate(targets, start=1):
                if self._scan_cancel_event.is_set():
                    break
                self._queue_scan_progress(
                    completed,
                    total,
                    f"Scanning {target.ip} ({index}/{total}) over SSH...",
                )
                run = runner.run_commands(
                    DeviceTarget(ip=target.ip, timeout=timeout),
                    credentials,
                    commands,
                )
                if run.status == "skipped":
                    results.append(
                        self._skipped_result(
                            target.ip,
                            run.error_message or "SSH connection failed",
                            commands,
                        )
                    )
                else:
                    profile = self._profile_for_target(target)
                    engine = CheckEngine(profile)
                    results.extend(
                        engine.evaluate_all(
                            checks,
                            outputs=run.outputs,
                            ip=target.ip,
                        )
                    )
                completed += 1
                self._queue_scan_progress(
                    completed,
                    total,
                    f"Completed {target.ip} ({completed}/{total}).",
                )
            cancelled = self._scan_cancel_event.is_set()
            self.after(
                0,
                lambda: self._complete_live_scan(
                    results,
                    label,
                    completed,
                    total,
                    cancelled,
                ),
            )
        except Exception as exc:
            message = str(exc)
            self.after(
                0,
                lambda: self._handle_background_scan_error(
                    message,
                    completed,
                    total,
                ),
            )

    def _complete_live_scan(
        self,
        results: list[CheckResult],
        label: str,
        completed: int,
        total: int,
        cancelled: bool,
    ) -> None:
        self.results = results
        self.results_tab.refresh(self.results)
        self.update_report_summary(self.results)
        skipped = sum(1 for result in self.results if result.status == "Skipped")
        open_count = sum(1 for result in self.results if result.status == "Open")
        pass_count = sum(1 for result in self.results if result.status == "NotAFinding")
        if results:
            self.tabs.set("Results")
        prefix = (
            f"{label.title()} SSH run cancelled after {completed}/{total} target(s)"
            if cancelled
            else f"{label.title()} SSH run complete for {completed} target(s)"
        )
        message = (
            f"{prefix}: "
            f"{pass_count} NotAFinding, {open_count} Open, {skipped} Skipped."
        )
        self._finish_scan_ui(
            completed=completed,
            total=total,
            message=message,
        )

    def _handle_background_scan_error(
        self,
        message: str,
        completed: int,
        total: int,
        *,
        checklist: bool = False,
    ) -> None:
        status_message = (
            f"Scan failed after {completed}/{total} target(s)."
        )
        if checklist:
            self.stig_tab.set_checklist_status(
                f"Checklist audit failed: {message}"
            )
        self._finish_scan_ui(
            completed=completed,
            total=total,
            message=status_message,
        )
        self._show_error(message, kind="connection")

    def _skipped_result(self, ip: str, reason: str, commands: list[str]) -> CheckResult:
        return CheckResult(
            ip=ip,
            hostname="unknown",
            vuln_id="DEVICE-SCAN",
            stig_family="SCAN",
            title="Device skipped",
            severity="info",
            status="Skipped",
            failed_objects=[],
            passed_objects=[],
            finding_details=reason,
            comments=reason,
            commands_used=commands,
            error_message=reason,
        )

    def _profile_for_target(self, target: DeviceTargetRecord) -> SiteProfile:
        if target.profile_override:
            profile_path = self.data_dir / "profiles" / f"{target.profile_override}.yaml"
            return load_profile(profile_path)
        if self.profile is None:
            raise ValueError("No site profile loaded")
        return self.profile

    def _licensed_targets(
        self,
        targets: list[DeviceTargetRecord],
        *,
        refresh: bool = True,
    ) -> list[DeviceTargetRecord]:
        normalized = self.license_manager.require_scan_targets(
            (target.ip for target in targets),
            refresh=refresh,
        )
        first_by_ip: dict[str, DeviceTargetRecord] = {}
        for target in targets:
            target_ip = self.license_manager.normalize_unique_targets([target.ip])[0]
            if target_ip not in first_by_ip:
                if hasattr(target, "model_copy"):
                    normalized_target = target.model_copy(update={"ip": target_ip})
                else:
                    normalized_target = target.copy(update={"ip": target_ip})
                first_by_ip[target_ip] = normalized_target
        return [first_by_ip[ip] for ip in normalized]

    def _licensed_checks(
        self, checks: list[CheckDefinition]
    ) -> list[CheckDefinition]:
        allowed: list[CheckDefinition] = []
        for check in checks:
            if check.stig_family == "IOSXE_L2":
                if self.license_manager.feature_enabled("l2_checks"):
                    allowed.append(check)
            elif check.stig_family == "IOSXE_NDM":
                if self.license_manager.feature_enabled("ndm_checks"):
                    allowed.append(check)
            else:
                allowed.append(check)
        if not allowed:
            raise LicensePolicyError(
                "The current license does not enable any of the selected L2 or NDM checks."
            )
        return allowed

    def _sample_name_for_target(self, target: DeviceTargetRecord) -> str:
        return "noncompliant" if target.ip.endswith(".26") else "compliant"

    def _load_sample_outputs(self, sample_name: str) -> dict[str, str]:
        base = self.sample_dir / sample_name
        return {
            command: (base / filename).read_text(encoding="utf-8")
            for command, filename in COMMAND_FILES.items()
        }

    def _validate_model(self, model_type: type[ModelT], data: Any) -> ModelT:
        if hasattr(model_type, "model_validate"):
            return model_type.model_validate(data)  # type: ignore[attr-defined]
        return model_type.parse_obj(data)

    def _show_error(
        self,
        message: str,
        title: str | None = None,
        kind: str = "generic",
    ) -> None:
        dialog_titles = {
            "connection": "Connection Failed",
            "license": "License Issue",
            "validation": "Invalid Input",
            "generic": "Error",
        }
        dialog = ctk.CTkToplevel(self)
        dialog.title(title or dialog_titles.get(kind, dialog_titles["generic"]))
        dialog.geometry("620x260")
        dialog.transient(self)
        dialog.grab_set()
        dialog.grid_columnconfigure(0, weight=1)
        dialog.grid_rowconfigure(0, weight=1)
        text = ctk.CTkTextbox(dialog, wrap="word")
        text.grid(row=0, column=0, sticky="nsew", padx=14, pady=(14, 8))
        text.insert("1.0", message)
        text.configure(state="disabled")

        buttons = ctk.CTkFrame(dialog, fg_color="transparent")
        buttons.grid(row=1, column=0, sticky="ew", padx=14, pady=(0, 14))
        buttons.grid_columnconfigure(0, weight=1)

        def copy_details() -> None:
            self.clipboard_clear()
            self.clipboard_append(message)
            self.update_idletasks()
            copy_button.configure(text="Copied")

        copy_button = ctk.CTkButton(
            buttons,
            text="Copy Details",
            width=110,
            fg_color="transparent",
            border_width=1,
            text_color=("gray10", "gray90"),
            command=copy_details,
        )
        copy_button.grid(row=0, column=0, sticky="w")
        ctk.CTkButton(
            buttons,
            text="OK",
            width=90,
            command=dialog.destroy,
        ).grid(row=0, column=1, sticky="e")

    def _short_error(self, exc: Exception) -> str:
        text = str(exc).replace("\n", " ")
        return text[:120] + ("..." if len(text) > 120 else "")


def run_gui() -> None:
    app = StigAuditProApp()
    app.mainloop()
