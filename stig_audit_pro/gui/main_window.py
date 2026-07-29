"""Main customtkinter window for STIG Audit Pro."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any, TypeVar

import customtkinter as ctk
import yaml
from pydantic import BaseModel, ValidationError

from stig_audit_pro.config import APP_VERSION
from stig_audit_pro.core.check_engine import CheckEngine
from stig_audit_pro.core.command_planner import plan_commands
from stig_audit_pro.core.models import (
    CheckDefinition,
    CheckLibrary,
    SiteProfile,
    validate_check_for_profile,
)
from stig_audit_pro.core.output_cache import CommandOutputCache
from stig_audit_pro.core.parser_engine import parse_outputs
from stig_audit_pro.core.result_model import CheckResult
from stig_audit_pro.core.scan_orchestrator import ScanOrchestrator
from stig_audit_pro.core.scan_run import (
    PackIdentity,
    ProfileIdentity,
    ScanRun,
    sha256_file,
    sha256_json,
)
from stig_audit_pro.core.ssh_runner import DeviceCredentials, DeviceTarget, NetmikoSshRunner
from stig_audit_pro.core.yaml_loader import (
    ConfigValidationError,
    atomic_write_yaml,
    deep_merge,
    load_check_library,
    load_profile,
    load_yaml_file,
)
from stig_audit_pro.gui.checks_tab import ChecksTab
from stig_audit_pro.gui.overview_tab import OverviewTab
from stig_audit_pro.gui.profiles_tab import ProfilesTab
from stig_audit_pro.gui.reports_tab import ReportsTab
from stig_audit_pro.gui.results_tab import ResultsTab
from stig_audit_pro.gui.stig_tab import StigTab
from stig_audit_pro.gui.targets_tab import TargetsTab
from stig_audit_pro.gui.widgets import configure_treeview_style
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
from stig_audit_pro.storage.device_groups import DeviceGroup, DeviceGroupStore, DeviceTargetRecord
from stig_audit_pro.storage.profile_manager import ProfileManager

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
        self.builtin_data_dir = self.root_dir / "data"
        default_user_root = Path(os.environ.get("LOCALAPPDATA", self.root_dir / "work"))
        self.data_dir = Path(
            os.environ.get("STIG_AUDIT_PRO_DATA_DIR", default_user_root / "STIGAuditPro")
        )
        self._seed_user_data()
        self.sample_dir = self.root_dir / "tests" / "sample_outputs"
        self.device_group_store = DeviceGroupStore(self.data_dir / "device_groups")
        self.profile_manager = ProfileManager(self.data_dir / "profiles")
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
        self.scan_orchestrator: ScanOrchestrator | None = None
        self.active_scan_run: ScanRun | None = None
        self.pending_stig_diffs: dict[str, tuple[StigDiff, StigBenchmarkMetadata]] = {}

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

    def _seed_user_data(self) -> None:
        """Copy missing built-in defaults without overwriting mutable user data."""
        for source in self.builtin_data_dir.rglob("*"):
            if not source.is_file() or "stigs" in source.parts:
                continue
            relative = source.relative_to(self.builtin_data_dir)
            destination = self.data_dir / relative
            if destination.exists():
                continue
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, destination)

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
        for tab in (tab_overview, tab_targets, tab_stig, tab_checks, tab_profiles, tab_results, tab_reports):
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

    def reload_from_disk(self) -> None:
        try:
            self.check_library_paths = self._check_library_paths()
            libraries = [load_check_library(path) for path in self.check_library_paths]
            checks = [check for library in libraries for check in library.checks]
            sources = {
                check.vuln_id: path
                for path, library in zip(paths, libraries, strict=True)
                for check in library.checks
            }
            self._raise_on_duplicate_checks(checks)
            self.checks = checks
            self._set_active_profile(self.profile_name, announce=False)
            self.checks_tab.refresh(self.checks, self.check_library_paths)
            self.overview_tab.refresh_inventory(self.checks, self.profile)
            self.refresh_device_groups()
            self.set_status(
                f"Loaded {len(self.checks)} checks using profile {self.profile.profile_name if self.profile else self.profile_name}."
            )
        except ConfigValidationError as exc:
            self.set_status("YAML validation failed.")
            self._show_error(str(exc))
        except ValueError as exc:
            self.set_status("Check library validation failed.")
            self._show_error(str(exc))

    def available_profile_names(self) -> list[str]:
        return self.profile_manager.names()

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
            raise ValueError(
                f"Duplicate check IDs across check libraries: {', '.join(sorted(duplicates))}"
            )

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
            self.stig_tab.set_status(
                f"Downloaded {metadata.display_name} with {metadata.rule_count} rule(s)."
            )
            self.set_status(f"Downloaded {metadata.display_name}.")
        except Exception as exc:
            self.stig_tab.set_status(
                "Automatic lookup failed. Paste a direct ZIP/XML URL or import the downloaded file."
            )
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
            self.stig_tab.set_status(
                f"Downloaded {metadata.display_name} with {metadata.rule_count} rule(s)."
            )
            self.set_status(f"Downloaded {metadata.display_name}.")
        except Exception as exc:
            self.stig_tab.set_status(
                "Direct URL download failed. Import the ZIP/XML file if the link is protected."
            )
            self.set_status("STIG URL download failed.")
            self._show_error(str(exc))

    def import_stig_source(self, path: Path, family: str) -> None:
        try:
            metadata = self.stig_source_manager.import_source(path, family=family)
            self.refresh_stig_metadata()
            self.stig_tab.set_status(
                f"Imported {metadata.display_name} with {metadata.rule_count} rule(s)."
            )
            self.set_status(f"Imported {metadata.display_name}.")
        except Exception as exc:
            self.stig_tab.set_status("STIG import failed.")
            self.set_status("STIG import failed.")
            self._show_error(str(exc))

    def generate_starter_checks_from_stigs(self) -> None:
        try:
            self.refresh_stig_metadata()
            if not self.stig_metadata:
                raise ValueError(
                    "Import the current L2/NDM STIG ZIP/XML first, then build starter checks."
                )
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

    def compare_stig_releases(self, family: str) -> None:
        items = sorted(
            (item for item in self.stig_metadata if item.family == family),
            key=lambda item: item.imported_at,
        )
        if len(items) < 2:
            self._show_error(f"Import at least two {family} releases to compare.")
            return
        old, new = items[-2], items[-1]
        service = StigDiffService()
        diff = service.compare(old, new)
        service.mark_checks(self.checks, diff)
        self.pending_stig_diffs[family] = (diff, new)
        changed_text = "\n\n".join(
            f"{item.stable_key}: {', '.join(item.change_types)}\n"
            f"OLD CHECK: {(item.old_rule.check_text if item.old_rule else '')}\n"
            f"NEW CHECK: {(item.new_rule.check_text if item.new_rule else '')}\n"
            f"OLD FIX: {(item.old_rule.fix_text if item.old_rule else '')}\n"
            f"NEW FIX: {(item.new_rule.fix_text if item.new_rule else '')}"
            for item in diff.changed
        )
        self.stig_tab.show_diff(
            f"{family} controlled release difference\n\n"
            f"Old: {old.version} {old.release_info}\nNew: {new.version} {new.release_info}\n\n"
            f"Added: {len(diff.added)}\nRemoved: {len(diff.removed)}\n"
            f"Changed: {len(diff.changed)}\nUnchanged: {len(diff.unchanged)}\n\n"
            "Changed automated checks are now Review Required; logic is not silently rewritten.\n\n"
            + (changed_text or "No changed source text.")
        )

    def approve_stig_activation(self, family: str) -> None:
        pending = self.pending_stig_diffs.get(family)
        if pending is None:
            self._show_error("Compare releases before approving activation.")
            return
        _, metadata = pending
        path = self.data_dir / "stigs" / "active-releases.yaml"
        data = load_yaml_file(path) if path.exists() else {}
        data[family] = {
            "benchmark_id": metadata.benchmark_id,
            "version": metadata.version,
            "release": metadata.release_info,
            "source_sha256": metadata.source_sha256,
        }
        atomic_write_yaml(path, data, backup=True)
        self.set_status(f"Approved {family} {metadata.version} activation record.")

    def load_device_group(self, group_name: str) -> None:
        try:
            group = self.device_group_store.load_group(group_name)
            if group.profile_name:
                self._set_active_profile(group.profile_name, announce=False)
            self.targets_tab.set_targets(group.targets, group.group_name, group.profile_name)
            profile_text = group.profile_name or (
                self.profile.profile_name if self.profile else self.profile_name
            )
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
            resolved_profile = profile_name or (
                self.profile.profile_name if self.profile else self.profile_name
            )
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
        self.overview_tab.refresh_results(results)

    def export_text_report(self, path: Path) -> None:
        try:
            if not self.results:
                raise ValueError("Run a scan before exporting a report.")
            destination = write_text_report(self.results, path)
            if self.active_scan_run:
                self.active_scan_run.report_paths.append(str(destination))
            self.set_status(f"Saved TXT report to {destination}.")
            self.reports_tab.set_export_status(f"Saved TXT report: {destination}")
        except Exception as exc:
            self.set_status("TXT report export failed.")
            self._show_error(str(exc))

    def export_csv_report(self, path: Path) -> None:
        try:
            if not self.results:
                raise ValueError("Run a scan before exporting a report.")
            destination = write_csv_report(self.results, path)
            if self.active_scan_run:
                self.active_scan_run.report_paths.append(str(destination))
            self.set_status(f"Saved CSV report to {destination}.")
            self.reports_tab.set_export_status(f"Saved CSV report: {destination}")
        except Exception as exc:
            self.set_status("CSV report export failed.")
            self._show_error(str(exc))

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
            self._show_error(str(exc))

    def _run_l2_targets(
        self,
        targets: list[DeviceTargetRecord],
        settings: dict[str, object],
        checks: list[CheckDefinition],
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

        for index, target in enumerate(targets, start=1):
            self.set_status(f"Running L2 audit on {target.ip} ({index}/{len(targets)})...")
            self.stig_tab.set_checklist_status(
                f"Running L2 audit on {target.ip} ({index}/{len(targets)})..."
            )
            self.update_idletasks()
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
        self.profiles_tab.refresh(
            self.profile,
            self.profile_path,
            profile_names=self.available_profile_names(),
            local_values=self.profile_manager.local_values(profile_name),
            consumers=self.profile_manager.consumers(self.checks),
        )
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
        profiles = {target.ip: self._profile_for_target(target) for target in targets}
        try:
            for profile in profiles.values():
                for check in self.checks:
                    validate_check_for_profile(check, profile)
        except ValueError as exc:
            self.set_status(f"Scan validation failed: {exc}")
            return
        cache = CommandOutputCache(self.data_dir / "evidence", retention_days=30, redact=True)
        concurrency = int(settings.get("concurrency") or 4)
        retries = int(settings.get("retries") or 1)
        self.scan_orchestrator = ScanOrchestrator(
            lambda: NetmikoSshRunner(cache), concurrency=concurrency, retries=retries
        )
        profile_payload = self.profile.model_dump(mode="json") if self.profile else {}
        scan_run = ScanRun(
            profile=ProfileIdentity(name=self.profile_name, sha256=sha256_json(profile_payload)),
            selected_targets=[target.ip for target in targets],
            check_packs=[
                PackIdentity(
                    name=path.stem,
                    version=load_check_library(path).check_pack_version,
                    schema_version=load_check_library(path).schema_version,
                    sha256=sha256_file(path),
                )
                for path in self._check_library_paths()
            ],
            parser_versions={"iosxe": "1"},
        )
        self.active_scan_run = scan_run
        device_targets = [DeviceTarget(ip=target.ip, timeout=timeout) for target in targets]
        self.set_status(f"Starting SSH scan for {len(targets)} target(s)...")

        def progress(done: int, total: int, outcome: object) -> None:
            ip = getattr(outcome, "ip", "device")
            self.after(0, lambda: self.set_status(f"Scanned {ip} ({done}/{total})..."))

        def worker() -> None:
            assert self.scan_orchestrator is not None
            outcomes = self.scan_orchestrator.run(
                device_targets, credentials, commands, str(scan_run.run_id), progress=progress
            )
            results: list[CheckResult] = []
            for outcome in outcomes:
                scan_run.command_collection_status[outcome.ip] = {
                    "status": outcome.status,
                    "category": outcome.category,
                    "attempts": outcome.attempts,
                    "error": outcome.error_message,
                }
                if outcome.status != "scanned":
                    results.append(
                        self._skipped_result(
                            outcome.ip,
                            f"{outcome.category}: {outcome.error_message or outcome.status}",
                            commands,
                        )
                    )
                    continue
                engine = CheckEngine(profiles[outcome.ip])
                device_results = engine.evaluate_all(self.checks, outcome.outputs, outcome.ip)
                results.extend(device_results)
                parsed = parse_outputs(outcome.outputs)
                scan_run.device_facts[outcome.ip] = asdict(parsed.facts)
                scan_run.parser_warnings[outcome.ip] = [
                    warning for result in device_results for warning in result.parser_warnings
                ]
            scan_run.results = results
            scan_run.finish()
            cache.write_manifest(scan_run.run_id, scan_run.manifest())
            cache.enforce_retention()
            self.after(0, lambda: self._finish_live_scan(results, targets, label))

        threading.Thread(target=worker, name="stig-scan-controller", daemon=True).start()

    def cancel_scan(self) -> None:
        if self.scan_orchestrator is None:
            self.set_status("No live scan is running.")
            return
        self.scan_orchestrator.cancel()
        self.set_status("Cancellation requested; active device operations will finish safely.")

    def _finish_live_scan(
        self, results: list[CheckResult], targets: list[DeviceTargetRecord], label: str
    ) -> None:
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
        self.scan_orchestrator = None

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
        ctk.CTkButton(dialog, text="OK", command=dialog.destroy).grid(
            row=1, column=0, sticky="e", padx=14, pady=(0, 14)
        )

    def _short_error(self, exc: Exception) -> str:
        text = str(exc).replace("\n", " ")
        return text[:120] + ("..." if len(text) > 120 else "")


def run_gui() -> None:
    app = StigAuditProApp()
    app.mainloop()
