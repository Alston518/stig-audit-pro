from __future__ import annotations

from tests.conftest import DATA_DIR
from stig_audit_pro.core.yaml_loader import load_check_library, load_exceptions, load_profile


def test_check_library_and_profile_validate():
    library = load_check_library(DATA_DIR / "checks" / "iosxe_l2.yaml")
    ndm_library = load_check_library(DATA_DIR / "checks" / "iosxe_ndm.yaml")
    profile = load_profile(DATA_DIR / "profiles" / "example_site.yaml")
    exceptions = load_exceptions(DATA_DIR / "exceptions" / "exceptions.yaml")

    assert len(library.checks) == 23
    assert len(ndm_library.checks) == 42
    assert any(check.vuln_id == "CISC-L2-000130" for check in library.checks)
    assert any(check.vuln_id == "CISC-ND-001470" for check in ndm_library.checks)
    assert profile.profile_name == "example_site"
    assert profile.unused_vlan == 999
    assert profile.dhcp_snooping.vlans == [10, 20, 30]
    assert exceptions.exceptions[0].force_status == "NotAFinding"


def test_building_profiles_override_site_specific_vlans():
    building_1 = load_profile(DATA_DIR / "profiles" / "building_1.yaml")
    building_2 = load_profile(DATA_DIR / "profiles" / "building_2.yaml")

    assert building_1.profile_name == "building_1"
    assert building_1.dhcp_snooping.vlans == [110, 120, 130]
    assert building_1.arp_inspection.vlans == [110, 120, 130]

    assert building_2.profile_name == "building_2"
    assert building_2.dhcp_snooping.vlans == [210, 220, 230]
    assert building_2.arp_inspection.vlans == [210, 220, 230]

def test_l2_automated_checks_use_editable_string_policies():
    library = load_check_library(DATA_DIR / "checks" / "iosxe_l2.yaml")
    editable_policy_types = {"command_pattern_policy", "interface_config_policy"}

    non_editable = [
        f"{check.vuln_id}: {check.check_type}"
        for check in library.checks
        if check.automated and check.check_type not in editable_policy_types
    ]

    assert non_editable == []
