"""Main customtkinter window for STIG Audit Pro."""

from __future__ import annotations

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
from stig_audit_pro.core.models import CheckLibrary, SiteProfile
from stig_audit_pro.core.result_model import CheckResult
from stig_audit_pro.core.yaml_loader import ConfigValidationError, deep_merge, load_check_library, load_profile, load_yaml_file
from stig_audit_pro.gui.checks_tab import ChecksTab
from stig_audit_pro.gui.profiles_tab import ProfilesTab
from stig_audit_pro.gui.reports_tab import ReportsTab
from stig_audit_pro.gui.results_tab import ResultsTab
from stig_audit_pro.gui.stig_tab import StigTab
from stig_audit_pro.gui.targets_tab import TargetsTab
from stig_audit_pro.storage.device_groups import DeviceGroup, DeviceGroupStore, DeviceTargetRecord
from stig_audit_pro.stig.source_manager import StigSourceError, StigSourceManager
from stig_audit_pro.stig.stig_metadata import StigBenchmarkMetadata

ModelT = TypeVar("ModelT", bound=BaseModel)

COMMAND_FILES = {
    "show running-config": "show_running_config.txt",
    "show interfaces status": "show_interfaces_status.txt",
    "show interfaces trunk": "show_interfaces_trunk.txt",
    "show ip access-lists": "show_ip_access_lists.txt",
    "show ip dhcp snooping": "show_ip_dhcp_snooping.txt",
    "show ip arp inspection": "show_ip_arp_inspection.txt",
}


class StigAuditProApp(ctk.CTk):
    def __init__(self) -> None:
        ctk.set_appearance_mode("System")
        ctk.set_default_color_theme("blue")
        super().__init__()

        self.root_dir = Path(__file__).resolve().parents[2]
        self.data_dir = self.root_dir / "data"
        self.sample_dir = self.root_dir / "tests" / "sample_outputs"
        self.device_group_store = DeviceGroupStore(self.data_dir / "device_groups")
        self.stig_source_manager = StigSourceManager(self.data_dir / "stigs" / "cache")
        self.check_path = self.data_dir / "checks" / "iosxe_l2.yaml"
        self.ndm_check_path = self.data_dir / "checks" / "iosxe_ndm.yaml"
        self.profile_name = "example_site"
        self.profile_path = self.data_dir / "profiles" / "example_site.yaml"
        self.checks = []
        self.profile: SiteProfile | None = None
        self.results: list[CheckResult] = []
        self.stig_metadata: list[StigBenchmarkMetadata] = []

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

    def _build_header(self) -> None:
        header = ctk.CTkFrame(self, corner_radius=0)
        header.grid(row=0, column=0, sticky="ew")
        header.grid_columnconfigure(0, weight=1)
        title = ctk.CTkLabel(header, text="STIG Audit Pro", font=ctk.CTkFont(size=22, weight="bold"))
        title.grid(row=0, column=0, sticky="w", padx=18, pady=(12, 2))
        subtitle = ctk.CTkLabel(header, text="Cisco IOS-XE switch audit workspace", text_color=("#475467", "#d0d5dd"))
        subtitle.grid(row=1, column=0, sticky="w", padx=18, pady=(0, 12))
        self.version_label = ctk.CTkLabel(header, text=APP_VERSION, font=ctk.CTkFont(weight="bold"))
        self.version_label.grid(row=0, column=1, rowspan=2, sticky="e", padx=18)

    def _build_tabs(self) -> None:
        self.tabs = ctk.CTkTabview(self)
        self.tabs.grid(row=1, column=0, sticky="nsew", padx=8, pady=8)
        tab_targets = self.tabs.add("Targets")
        tab_stig = self.tabs.add("STIG / CKL")
        tab_checks = self.tabs.add("Checks")
        tab_profiles = self.tabs.add("Profiles")
        tab_results = self.tabs.add("Results")
        tab_reports = self.tabs.add("Reports")
        for tab in (tab_targets, tab_stig, tab_checks, tab_profiles, tab_results, tab_reports):
            tab.grid_columnconfigure(0, weight=1)
            tab.grid_rowconfigure(0, weight=1)

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

    def _build_status_bar(self) -> None:
        footer = ctk.CTkFrame(self, corner_radius=0)
        footer.grid(row=2, column=0, sticky="ew")
        footer.grid_columnconfigure(0, weight=1)
        self.status_label = ctk.CTkLabel(footer, text="Ready", anchor="w")
        self.status_label.grid(row=0, column=0, sticky="ew", padx=14, pady=6)

    def set_status(self, message: str) -> None:
        self.status_label.configure(text=message)

    def reload_from_disk(self) -> None:
        try:
            l2_library = load_check_library(self.check_path)
            ndm_library = load_check_library(self.ndm_check_path)
            self.checks = [*l2_library.checks, *ndm_library.checks]
            self._set_active_profile(self.profile_name, announce=False)
            self.checks_tab.refresh(self.checks, self.check_path)
            self.refresh_device_groups()
            self.set_status(f"Loaded {len(self.checks)} checks using profile {self.profile.profile_name if self.profile else self.profile_name}.")
        except ConfigValidationError as exc:
            self.set_status("YAML validation failed.")
            self._show_error(str(exc))

    def available_profile_names(self) -> list[str]:
        return sorted(path.stem for path in (self.data_dir / "profiles").glob("*.yaml"))

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
            self._show_error(str(exc))

    def run_target_scope(self, scope: str) -> None:
        targets = self.targets_tab.get_targets(scope)
        if not targets:
            self.set_status(f"No targets available for {scope} run.")
            return
        settings = self.targets_tab.get_scan_settings()
        if settings.get("mode") == "Live SSH":
            self._run_live_for_targets(targets, settings, scope)
        else:
            self._run_sample_for_targets(targets, scope)

    def run_sample_audit(self, sample_name: str) -> None:
        ip = "10.50.10.25" if sample_name == "compliant" else "10.50.10.26"
        target = DeviceTargetRecord(ip=ip, checked=True)
        self._run_sample_for_targets([target], sample_name)

    def update_report_summary(self, results: list[CheckResult]) -> None:
        self.reports_tab.refresh(results)

    def validate_check_yaml(self, text: str) -> tuple[bool, str]:
        try:
            data = yaml.safe_load(text) or {}
            library = self._validate_model(CheckLibrary, data)
            return True, f"{len(library.checks)} checks valid"
        except (ValidationError, yaml.YAMLError, ValueError) as exc:
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

    def _set_active_profile(self, profile_name: str, announce: bool = True) -> None:
        self.profile_name = profile_name
        self.profile_path = self.data_dir / "profiles" / f"{profile_name}.yaml"
        self.profile = load_profile(self.profile_path)
        self.profiles_tab.refresh(self.profile, self.profile_path)
        if announce:
            self.set_status(f"Selected site profile {self.profile.profile_name}.")

    def _run_sample_for_targets(self, targets: list[DeviceTargetRecord], label: str) -> None:
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
                results.extend(engine.evaluate_all(self.checks, outputs=outputs, ip=target.ip))
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
    ) -> None:
        username = str(settings.get("username") or "")
        password = str(settings.get("password") or "")
        if not username or not password:
            self.set_status("Live SSH requires a username and password.")
            return
        timeout = int(settings.get("timeout") or 30)
        credentials = DeviceCredentials(
            username=username,
            password=password,
            secret=settings.get("secret") if isinstance(settings.get("secret"), str) else None,
        )
        commands = plan_commands(self.checks, run_all=False)
        runner = NetmikoSshRunner(CommandOutputCache(self.root_dir / "work" / "cache" / "ssh"))
        results: list[CheckResult] = []
        for index, target in enumerate(targets, start=1):
            self.set_status(f"Scanning {target.ip} ({index}/{len(targets)}) over SSH...")
            self.update_idletasks()
            run = runner.run_commands(
                DeviceTarget(ip=target.ip, timeout=timeout),
                credentials,
                commands,
            )
            if run.status == "skipped":
                results.append(self._skipped_result(target.ip, run.error_message or "SSH connection failed", commands))
                continue
            profile = self._profile_for_target(target)
            engine = CheckEngine(profile)
            results.extend(engine.evaluate_all(self.checks, outputs=run.outputs, ip=target.ip))
        self.results = results
        self.results_tab.refresh(self.results)
        self.update_report_summary(self.results)
        skipped = sum(1 for result in self.results if result.status == "Skipped")
        open_count = sum(1 for result in self.results if result.status == "Open")
        pass_count = sum(1 for result in self.results if result.status == "NotAFinding")
        self.tabs.set("Results")
        self.set_status(
            f"{label.title()} SSH run complete for {len(targets)} target(s): "
            f"{pass_count} NotAFinding, {open_count} Open, {skipped} Skipped."
        )

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

    def _show_error(self, message: str) -> None:
        dialog = ctk.CTkToplevel(self)
        dialog.title("Error")
        dialog.geometry("620x260")
        dialog.transient(self)
        dialog.grab_set()
        dialog.grid_columnconfigure(0, weight=1)
        dialog.grid_rowconfigure(0, weight=1)
        text = ctk.CTkTextbox(dialog, wrap="word")
        text.grid(row=0, column=0, sticky="nsew", padx=14, pady=(14, 8))
        text.insert("1.0", message)
        text.configure(state="disabled")
        ctk.CTkButton(dialog, text="OK", command=dialog.destroy).grid(row=1, column=0, sticky="e", padx=14, pady=(0, 14))

    def _short_error(self, exc: Exception) -> str:
        text = str(exc).replace("\n", " ")
        return text[:120] + ("..." if len(text) > 120 else "")


def run_gui() -> None:
    app = StigAuditProApp()
    app.mainloop()


