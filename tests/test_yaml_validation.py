from __future__ import annotations

from tests.conftest import DATA_DIR
from stig_audit_pro.core.yaml_loader import load_check_library, load_exceptions, load_profile


def test_check_library_and_profile_validate():
    library = load_check_library(DATA_DIR / "checks" / "iosxe_l2.yaml")
    profile = load_profile(DATA_DIR / "profiles" / "example_site.yaml")
    exceptions = load_exceptions(DATA_DIR / "exceptions" / "exceptions.yaml")

    assert len(library.checks) == 5
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
