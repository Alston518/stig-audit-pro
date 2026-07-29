from __future__ import annotations

from datetime import date, timedelta

import pytest
import yaml
from pydantic import ValidationError

from stig_audit_pro.core.check_engine import CheckEngine
from stig_audit_pro.core.exceptions import ExceptionRule
from stig_audit_pro.core.models import CheckDefinition
from stig_audit_pro.core.output_cache import CommandOutputCache
from stig_audit_pro.core.result_model import CheckResult, FindingObject
from stig_audit_pro.core.yaml_loader import (
    ConfigValidationError,
    load_check_libraries,
    load_profile,
)
from stig_audit_pro.parsers.iosxe_running_config import parse_running_config
from stig_audit_pro.reports.audit_report import write_csv_report
from stig_audit_pro.stig.source_manager import StigSourceError, StigSourceManager
from stig_audit_pro.stig.stig_diff import StigDiffService
from stig_audit_pro.stig.stig_metadata import StigBenchmarkMetadata, StigRuleMetadata
from tests.conftest import check_by_vuln, load_outputs
from tests.conftest import load_profile as sample_profile


def _outputs(
    running: str, status: str = "Port Name Status Vlan Duplex Speed Type\n"
) -> dict[str, str]:
    return {"show running-config": running, "show interfaces status": status}


def _status(port: str, vlan: str) -> str:
    return (
        "Port      Name               Status       Vlan       Duplex  Speed Type\n"
        f"{port:<10}{'TEST':<19}{'connected':<13}{vlan:<11}{'a-full':<8}{'a-1G':<6}1000BaseSX\n"
    )


def test_zero_matching_trunks_is_not_a_false_pass():
    result = CheckEngine(sample_profile()).evaluate(
        check_by_vuln("CISC-L2-000200"),
        _outputs(
            "hostname SW1\n!\ninterface GigabitEthernet1/0/1\n switchport mode access\n!\n",
            _status("Gi1/0/1", "10"),
        ),
        "192.0.2.1",
    )
    assert result.status == "Not_Applicable"
    assert result.matched_object_count == 0


@pytest.mark.parametrize("outputs", [{"show running-config": ""}, {}])
def test_empty_or_missing_command_output_is_error(outputs):
    check = CheckDefinition(
        vuln_id="TEST",
        title="Test",
        stig_family="TEST",
        severity="cat3",
        check_type="command_contains",
        commands=["show running-config"],
        conditions={"contains": "hostname"},
    )
    result = CheckEngine(sample_profile()).evaluate(check, outputs, "192.0.2.1")
    assert result.status == "Error"
    assert "command" in (result.error_message or "").lower()


def test_malformed_interfaces_status_is_parser_error():
    outputs = load_outputs("compliant")
    outputs["show interfaces status"] = "unexpected output without a table"
    result = CheckEngine(sample_profile()).evaluate(
        check_by_vuln("CISC-L2-000210"), outputs, "192.0.2.1"
    )
    assert result.status == "Error"
    assert "parser" in (result.error_message or "")


def test_unresolved_profile_variable_is_detected_before_evaluation():
    check = CheckDefinition(
        vuln_id="TEST",
        title="Test",
        stig_family="TEST",
        severity="cat3",
        check_type="command_regex",
        commands=["show running-config"],
        conditions={"pattern": "{{ missing_context }}"},
    )
    result = CheckEngine(sample_profile()).evaluate(
        check, {"show running-config": "hostname SW1"}, "192.0.2.1"
    )
    assert result.status == "Error"
    assert "missing_context" in (result.error_message or "")


def test_invalid_regex_and_undeclared_condition_command_are_rejected():
    base = dict(
        vuln_id="TEST",
        title="Test",
        stig_family="TEST",
        severity="cat3",
        check_type="command_regex",
        commands=["show running-config"],
    )
    with pytest.raises(ValidationError, match="invalid regex"):
        CheckDefinition(**base, conditions={"pattern": "["})
    with pytest.raises(ValidationError, match="undeclared command"):
        CheckDefinition(**base, conditions={"command": "show version", "pattern": "ok"})


def test_multilevel_profile_inheritance_and_cycle_detection(tmp_path):
    (tmp_path / "base.yaml").write_text("profile_name: base\nunused_vlan: 900\n", encoding="utf-8")
    (tmp_path / "middle.yaml").write_text(
        "profile_name: middle\ninherits: base\n", encoding="utf-8"
    )
    (tmp_path / "site.yaml").write_text("profile_name: site\ninherits: middle\n", encoding="utf-8")
    assert load_profile(tmp_path / "site.yaml").unused_vlan == 900
    (tmp_path / "base.yaml").write_text("profile_name: base\ninherits: site\n", encoding="utf-8")
    with pytest.raises(ConfigValidationError, match="cycle"):
        load_profile(tmp_path / "site.yaml")


def test_vlan_ranges_and_trunk_operations_are_semantic():
    running = parse_running_config(
        "interface GigabitEthernet1/0/1\n"
        " switchport mode trunk\n"
        " switchport trunk allowed vlan all\n"
        " switchport trunk allowed vlan remove 1,100-110\n"
        " switchport trunk allowed vlan add 105\n!\n"
    )
    allowed = running.interfaces["GigabitEthernet1/0/1"].trunk_allowed_vlans
    assert allowed is not None and 1 not in allowed and 100 not in allowed and 105 in allowed
    excepted = (
        parse_running_config(
            "interface GigabitEthernet1/0/1\n switchport trunk allowed vlan except 20-30\n!\n"
        )
        .interfaces["GigabitEthernet1/0/1"]
        .trunk_allowed_vlans
    )
    assert excepted is not None and 20 not in excepted and 19 in excepted


def test_profile_vlan_inside_configured_range_matches_and_disabled_flag_applies():
    profile = sample_profile().model_copy(deep=True)
    profile.dhcp_snooping.vlans = [20]
    check = check_by_vuln("CISC-L2-000130")
    output = "ip dhcp snooping vlan 10-30\nip dhcp snooping\n"
    result = CheckEngine(profile).evaluate(check, {"show running-config": output}, "192.0.2.1")
    assert result.status == "NotAFinding"
    profile.dhcp_snooping.enabled = False
    result = CheckEngine(profile).evaluate(check, {"show running-config": output}, "192.0.2.1")
    assert result.status == "Not_Applicable"


def test_duplicate_control_ids_across_libraries_are_rejected(tmp_path):
    payload = {
        "library_name": "one",
        "checks": [
            {
                "vuln_id": "DUP",
                "title": "Duplicate",
                "stig_family": "TEST",
                "severity": "cat3",
                "check_type": "manual_review",
                "automated": False,
            }
        ],
    }
    paths = [tmp_path / "one.yaml", tmp_path / "two.yaml"]
    for path in paths:
        path.write_text(yaml.safe_dump(payload), encoding="utf-8")
    with pytest.raises(ConfigValidationError, match="Duplicate controls"):
        load_check_libraries(paths)


@pytest.mark.parametrize("mode", ["dynamic desirable", "dynamic auto"])
def test_dynamic_trunk_modes_fail_static_trunk_control(mode):
    running = f"interface GigabitEthernet1/0/24\n switchport mode {mode}\n!\n"
    result = CheckEngine(sample_profile()).evaluate(
        check_by_vuln("CISC-L2-000200"),
        _outputs(running, _status("Gi1/0/24", "trunk")),
        "192.0.2.1",
    )
    assert result.status == "Open"


def test_vlan1_section_does_not_scan_into_vlan2():
    check = check_by_vuln("CISC-L2-000240")
    output = "interface Vlan1\n no shutdown\n!\ninterface Vlan2\n ip address 192.0.2.1 255.255.255.0\n!\n"
    result = CheckEngine(sample_profile()).evaluate(
        check, {"show running-config": output}, "192.0.2.1"
    )
    assert result.status == "NotAFinding"


def test_object_exception_keeps_other_failures_and_expired_is_flagged():
    check = check_by_vuln("CISC-L2-000210")
    rules = [
        ExceptionRule(
            exception_id="EX-1",
            vuln_id=check.vuln_id,
            scope="object",
            object_type="interface",
            object_name="GigabitEthernet1/0/2",
            reason="Approved",
            approver="ISSM",
            source="exception register",
            ticket="SEC-1",
        )
    ]
    running = "hostname SW1\n!\n" + "".join(
        f"interface GigabitEthernet1/0/{index}\n switchport mode access\n switchport access vlan 10\n!\n"
        for index in range(1, 4)
    )
    status = "Port      Name               Status       Vlan       Duplex  Speed Type\n" + "".join(
        f"Gi1/0/{index:<3} TEST               disabled     10         auto    auto  10/100/1000BaseTX\n"
        for index in range(1, 4)
    )
    outputs = _outputs(running, status)
    result = CheckEngine(sample_profile(), rules).evaluate(check, outputs, "10.50.10.26")
    assert result.status == "Open"
    assert [item.object_name for item in result.excepted_objects] == ["GigabitEthernet1/0/2"]
    assert {item.object_name for item in result.failed_objects} == {
        "GigabitEthernet1/0/1",
        "GigabitEthernet1/0/3",
    }
    expired = rules[0].model_copy(update={"expires": date.today() - timedelta(days=1)})
    result = CheckEngine(sample_profile(), [expired]).evaluate(check, outputs, "10.50.10.26")
    assert result.status == "Open"
    assert result.exceptions_applied[0].expired is True


def test_stig_diff_added_removed_and_changed_rules():
    old = StigBenchmarkMetadata(
        version="1",
        rules=[
            StigRuleMetadata(vuln_id="V-1", stig_id="A", title="Old"),
            StigRuleMetadata(vuln_id="V-2", stig_id="B", title="Removed"),
        ],
    )
    new = StigBenchmarkMetadata(
        version="2",
        rules=[
            StigRuleMetadata(vuln_id="V-1", stig_id="A", title="New"),
            StigRuleMetadata(vuln_id="V-3", stig_id="C", title="Added"),
        ],
    )
    diff = StigDiffService().compare(old, new)
    assert [item.stable_key for item in diff.added] == ["V-3"]
    assert [item.stable_key for item in diff.removed] == ["V-2"]
    assert diff.changed[0].change_types == ["changed title"]


def test_corrupt_stig_metadata_has_actionable_error(tmp_path):
    path = tmp_path / "cache" / "x" / "metadata.json"
    path.parent.mkdir(parents=True)
    path.write_text("{partial", encoding="utf-8")
    with pytest.raises(StigSourceError, match="Corrupted or partial"):
        StigSourceManager(tmp_path / "cache").load_cached_metadata()


def test_evidence_isolated_by_run_uuid_and_formula_cells_are_safe(tmp_path):
    cache = CommandOutputCache(tmp_path / "evidence")
    first = cache.save_device_outputs("192.0.2.1", {"show version": "one"})
    second = cache.save_device_outputs("192.0.2.1", {"show version": "two"})
    assert first != second
    assert cache.load_output("192.0.2.1", "show version", first) == "one"
    assert cache.load_output("192.0.2.1", "show version", second) == "two"
    result = CheckResult(
        ip="192.0.2.1",
        vuln_id="TEST",
        stig_family="TEST",
        title="=cmd|' /C calc'!A0",
        severity="cat3",
        status="Open",
        failed_objects=[FindingObject(object_type="x", object_name="y")],
    )
    path = write_csv_report([result], tmp_path / "report.csv")
    assert "'=cmd" in path.read_text(encoding="utf-8-sig")
