from __future__ import annotations

from collections import Counter
from pathlib import Path

from stig_audit_pro.core.check_engine import CheckEngine
from stig_audit_pro.core.yaml_loader import load_check_library
from tests.conftest import load_l2_checks, load_outputs, load_profile

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _results_by_vuln(kind: str):
    engine = CheckEngine(load_profile())
    results = engine.evaluate_all(
        load_l2_checks(),
        outputs=load_outputs(kind),
        ip="10.50.10.25" if kind == "compliant" else "10.50.10.26",
    )
    return {result.vuln_id: result for result in results}


def test_required_checks_pass_on_compliant_sample_outputs():
    results = _results_by_vuln("compliant")
    counts = Counter(result.status for result in results.values())

    assert counts["NotAFinding"] == 21
    assert counts["Not_Reviewed"] == 0
    assert counts["Not_Applicable"] == 0
    assert counts["Open"] == 1
    assert results["V-220649"].status == "NotAFinding"
    assert results["V-220650"].status == "NotAFinding"
    assert results["V-220651"].status == "Open"
    assert "pending QoS implementation" in results["V-220651"].comments
    assert results["V-220655"].status == "NotAFinding"
    assert results["V-220656"].status == "NotAFinding"
    assert results["V-220657"].status == "NotAFinding"
    assert results["V-220658"].status == "NotAFinding"
    assert results["V-220659"].status == "NotAFinding"
    assert results["V-220660"].status == "NotAFinding"
    assert results["V-220661"].status == "NotAFinding"
    assert results["V-220662"].status == "NotAFinding"
    assert results["V-220664"].status == "NotAFinding"
    assert results["V-220665"].status == "NotAFinding"
    assert results["V-220666"].status == "NotAFinding"
    assert results["V-220667"].status == "NotAFinding"
    assert results["V-220668"].status == "NotAFinding"
    assert results["V-220669"].status == "NotAFinding"
    assert results["V-220671"].status == "NotAFinding"
    assert results["V-220672"].status == "NotAFinding"
    assert results["V-220673"].status == "NotAFinding"


def test_required_checks_fail_on_noncompliant_sample_outputs():
    results = _results_by_vuln("noncompliant")
    counts = Counter(result.status for result in results.values())

    assert counts["Open"] == 20
    assert counts["Not_Reviewed"] == 0
    assert counts["NotAFinding"] == 2
    assert results["V-220649"].status == "Open"
    assert results["V-220650"].status == "Open"
    assert results["V-220651"].status == "Open"
    assert results["V-220655"].status == "Open"
    assert results["V-220655"].failed_objects[0].object_name == "GigabitEthernet1/0/24"
    assert results["V-220656"].status == "Open"
    assert any(
        finding.object_name == "GigabitEthernet1/0/2"
        for finding in results["V-220656"].failed_objects
    )
    assert results["V-220657"].status == "Open"
    assert results["V-220658"].status == "Open"
    assert any(
        finding.object_name == "GigabitEthernet1/0/2"
        for finding in results["V-220658"].failed_objects
    )
    assert results["V-220659"].status == "Open"
    assert results["V-220660"].status == "Open"
    assert any(
        finding.object_name == "GigabitEthernet1/0/2"
        for finding in results["V-220660"].failed_objects
    )
    assert results["V-220661"].status == "Open"
    assert results["V-220662"].status == "Open"
    assert any(
        finding.object_name == "GigabitEthernet1/0/2"
        for finding in results["V-220662"].failed_objects
    )
    assert results["V-220664"].status == "Open"
    assert results["V-220665"].status == "Open"
    assert results["V-220666"].status == "Open"
    assert results["V-220667"].status == "Open"
    assert results["V-220668"].status == "Open"
    assert results["V-220669"].status == "Open"
    assert results["V-220671"].status == "NotAFinding"
    assert results["V-220672"].status == "Open"
    assert results["V-220673"].status == "NotAFinding"
    assert results["V-220669"].failed_objects[0].object_name == "GigabitEthernet1/0/24"
    assert results["V-220659"].failed_objects
    assert results["V-220661"].failed_objects[0].object_name == "30"


def test_vlan1_management_check_allows_no_ip_and_stays_in_interface_block():
    engine = CheckEngine(load_profile())
    check = next(check for check in load_l2_checks() if check.vuln_id == "V-220670")
    outputs = {
        "show running-config": """\
interface Vlan1
 no ip address
 shutdown
!
interface Vlan20
 ip address 192.0.2.1 255.255.255.0
!
"""
    }

    result = engine.evaluate(check, outputs=outputs, ip="10.50.10.25")

    assert result.status == "NotAFinding"


def test_igmp_mld_snooping_check_detects_global_and_vlan_disables():
    engine = CheckEngine(load_profile())
    check = next(check for check in load_l2_checks() if check.vuln_id == "V-220663")

    compliant = engine.evaluate(
        check,
        outputs={"show running-config": "hostname ACCESS-SW01\nip igmp snooping\n"},
        ip="10.50.10.25",
    )
    assert compliant.status == "NotAFinding"

    disabled_commands = (
        "no ip igmp snooping",
        "no ip igmp snooping vlan 11",
        "no ip igmp snooping vlan 11,20,30",
        "no ipv6 mld snooping",
        "no ipv6 mld snooping vlan 11",
    )
    for command in disabled_commands:
        result = engine.evaluate(
            check,
            outputs={"show running-config": f"hostname ACCESS-SW01\n{command}\n"},
            ip="10.50.10.26",
        )
        assert result.status == "Open", command


def test_disabled_port_policy_exempts_dot1x_and_ignores_connected_ports():
    engine = CheckEngine(load_profile())
    original = next(check for check in load_l2_checks() if check.vuln_id == "V-220667")
    scope = {
        "interfaces": {
            "include": [
                {
                    "type": "physical",
                    "match": {
                        "switchport_mode": "access",
                        "admin_state": "disabled_or_notconnect",
                    },
                }
            ]
        }
    }
    conditions = {
        "exempt_strings": [
            {
                "string": "authentication port-control auto",
                "description": "802.1X authentication configured",
            }
        ],
        "required_patterns": original.conditions["required_patterns"],
    }
    check = original.model_copy(update={"scope": scope, "conditions": conditions})
    outputs = {
        "show running-config": """\
interface GigabitEthernet1/0/1
 switchport mode access
 switchport access vlan 10
 authentication port-control auto
!
interface GigabitEthernet1/0/2
 switchport mode access
 switchport access vlan 999
 shutdown
!
interface GigabitEthernet1/0/3
 switchport mode access
 switchport access vlan 10
 shutdown
!
interface GigabitEthernet1/0/4
 switchport mode access
 switchport access vlan 10
!
""",
        "show interfaces status": """\
Port      Name               Status       Vlan       Duplex  Speed Type
Gi1/0/1   DOT1X              notconnect   10         auto    auto  10/100/1000BaseTX
Gi1/0/2   UNUSED             disabled     999        auto    auto  10/100/1000BaseTX
Gi1/0/3   BAD-UNUSED         disabled     10         auto    auto  10/100/1000BaseTX
Gi1/0/4   USER               connected    10         a-full  a-100 10/100/1000BaseTX
""",
    }

    result = engine.evaluate(check, outputs=outputs, ip="10.50.10.25")

    assert result.status == "Open"
    assert [finding.object_name for finding in result.failed_objects] == ["GigabitEthernet1/0/3"]
    passed = {finding.object_name: finding.details for finding in result.passed_objects}
    assert passed["GigabitEthernet1/0/1"] == "exempt: 802.1X authentication configured"
    assert passed["GigabitEthernet1/0/2"] == "required interface config present"
    assert "GigabitEthernet1/0/4" not in passed


def test_user_facing_access_policy_checks_copper_and_ignores_sfp_ports():
    engine = CheckEngine(load_profile())
    original = next(check for check in load_l2_checks() if check.vuln_id == "V-220671")
    scope = {
        "interfaces": {
            "include": [
                {
                    "type": "physical",
                    "match": {"media_type": {"regex": "BaseTX"}},
                }
            ]
        }
    }
    conditions = {"required_strings": ["switchport mode access"]}
    check = original.model_copy(
        update={
            "check_type": "interface_config_policy",
            "commands": ["show running-config", "show interfaces status"],
            "automated": True,
            "scope": scope,
            "conditions": conditions,
            "result": original.result.model_copy(update={"fail_status": "Open"}),
        }
    )
    outputs = {
        "show running-config": """\
interface GigabitEthernet1/0/1
 switchport mode access
!
interface GigabitEthernet1/0/2
 switchport mode trunk
!
interface GigabitEthernet1/0/48
 switchport mode trunk
!
""",
        "show interfaces status": """\
Port      Name               Status       Vlan       Duplex  Speed Type
Gi1/0/1   USER               connected    10         a-full  a-100 10/100/1000BaseTX
Gi1/0/2   BAD-COPPER         connected    trunk      a-full  a-1G  10/100/1000BaseTX
Gi1/0/48  SFP-UPLINK         connected    trunk      a-full  a-1G  1000BaseSX SFP
""",
    }

    result = engine.evaluate(check, outputs=outputs, ip="10.50.10.25")

    assert result.status == "Open"
    assert [finding.object_name for finding in result.failed_objects] == ["GigabitEthernet1/0/2"]
    assert result.passed_objects[0].object_name == "GigabitEthernet1/0/1"


def test_endpoint_authentication_policy_reports_interface_and_radius_failures():
    engine = CheckEngine(load_profile())
    test_check = next(check for check in load_l2_checks() if check.vuln_id == "V-220649")
    outputs = {
        "show running-config": """\
aaa group server radius ISE-RADIUS
 server name ISE1-EDU-01
!
interface GigabitEthernet1/0/1
 switchport mode access
 authentication port-control auto
 dot1x pae authenticator
 mab
!
interface GigabitEthernet1/0/2
 authentication port-control auto
 dot1x pae authenticator
!
""",
        "show interfaces status": """\
Port      Name               Status       Vlan       Duplex  Speed Type
Gi1/0/1   USER1              connected    10         a-full  a-100 10/100/1000BaseTX
Gi1/0/2   USER2              connected    10         a-full  a-100 10/100/1000BaseTX
""",
    }

    result = engine.evaluate(test_check, outputs=outputs, ip="10.50.10.25")

    assert result.status == "Open"
    failures = {(finding.object_type, finding.object_name) for finding in result.failed_objects}
    assert ("interface", "GigabitEthernet1/0/2") in failures
    assert ("radius_server", "ISE2-EDU-02") in failures


def test_endpoint_authentication_policy_passes_complete_configuration():
    engine = CheckEngine(load_profile())
    test_check = next(check for check in load_l2_checks() if check.vuln_id == "V-220649")
    outputs = {
        "show running-config": """\
aaa group server radius ISE-RADIUS
 server name ISE1-EDU-01
 server name ISE2-EDU-02
!
interface GigabitEthernet1/0/1
 switchport mode access
 authentication port-control auto
 dot1x pae authenticator
 mab
!
""",
        "show interfaces status": """\
Port      Name               Status       Vlan       Duplex  Speed Type
Gi1/0/1   USER1              connected    10         a-full  a-100 10/100/1000BaseTX
""",
    }

    result = engine.evaluate(test_check, outputs=outputs, ip="10.50.10.25")

    assert result.status == "NotAFinding"
    assert result.failed_objects == []


def test_native_vlan_assignment_policy_uses_profile_vlan_and_reports_port():
    engine = CheckEngine(load_profile())
    test_check = load_check_library(
        PROJECT_ROOT / "editing" / "check_test.yaml"
    ).checks[0]
    outputs = {
        "show interfaces status": """\
Port      Name               Status       Vlan       Duplex  Speed Type
Gi1/0/1   USER               connected    10         a-full  a-100 10/100/1000BaseTX
Gi1/0/2   BAD-NATIVE         notconnect   333        auto    auto  10/100/1000BaseTX
Gi1/0/24  UPLINK             connected    trunk      a-full  a-1G  1000BaseSX
"""
    }

    result = engine.evaluate(test_check, outputs=outputs, ip="10.50.10.25")

    assert result.status == "Open"
    assert [finding.object_name for finding in result.failed_objects] == [
        "GigabitEthernet1/0/2"
    ]
    assert "access VLAN matches native VLAN 333" in result.failed_objects[0].details


def test_native_vlan_assignment_policy_passes_when_vlan_is_unused():
    engine = CheckEngine(load_profile())
    test_check = load_check_library(
        PROJECT_ROOT / "editing" / "check_test.yaml"
    ).checks[0]
    outputs = {
        "show interfaces status": """\
Port      Name               Status       Vlan       Duplex  Speed Type
Gi1/0/1   USER               connected    10         a-full  a-100 10/100/1000BaseTX
Gi1/0/2   UNUSED             disabled     999        auto    auto  10/100/1000BaseTX
Gi1/0/24  UPLINK             connected    trunk      a-full  a-1G  1000BaseSX
"""
    }

    result = engine.evaluate(test_check, outputs=outputs, ip="10.50.10.25")

    assert result.status == "NotAFinding"
    assert result.failed_objects == []


def test_native_vlan_assignment_policy_errors_when_status_output_is_empty():
    engine = CheckEngine(load_profile())
    test_check = load_check_library(
        PROJECT_ROOT / "editing" / "check_test.yaml"
    ).checks[0]

    result = engine.evaluate(
        test_check,
        outputs={"show interfaces status": ""},
        ip="10.50.10.25",
    )

    assert result.status == "Error"


def test_vlan1_management_check_rejects_configured_ip_address():
    engine = CheckEngine(load_profile())
    check = next(check for check in load_l2_checks() if check.vuln_id == "V-220670")
    outputs = {
        "show running-config": """\
interface Vlan1
 ip address 192.0.2.1 255.255.255.0
 no shutdown
!
"""
    }

    result = engine.evaluate(check, outputs=outputs, ip="10.50.10.26")

    assert result.status == "Open"


def test_root_guard_exempts_upstream_neighbor_but_checks_access_neighbor():
    engine = CheckEngine(load_profile())
    check = next(check for check in load_l2_checks() if check.vuln_id == "V-220655")
    outputs = {
        "show running-config": """\
interface GigabitEthernet1/0/23
 spanning-tree guard root
!
interface GigabitEthernet1/0/24
!\n""",
        "show cdp neighbors detail": """\
Device ID: IDF2-ACCESS01.example.mil
Platform: cisco C9200, Capabilities: Router Switch IGMP
Interface: GigabitEthernet1/0/23, Port ID (outgoing port): GigabitEthernet1/0/48
-------------------------
Device ID: CORE-DIST-01.example.mil
Platform: cisco C9500, Capabilities: Router Switch IGMP
Interface: GigabitEthernet1/0/24, Port ID (outgoing port): TenGigabitEthernet1/0/1
""",
    }

    result = engine.evaluate(check, outputs=outputs, ip="10.50.10.25")

    assert result.status == "NotAFinding"
    assert {obj.object_name for obj in result.passed_objects} == {
        "GigabitEthernet1/0/23",
        "GigabitEthernet1/0/24",
    }


def test_root_guard_only_upstream_neighbors_is_not_a_finding():
    engine = CheckEngine(load_profile())
    check = next(check for check in load_l2_checks() if check.vuln_id == "V-220655")
    outputs = {
        "show running-config": """\
interface GigabitEthernet1/0/24
!
""",
        "show cdp neighbors detail": """\
Device ID: CORE-DIST-01.example.mil
Platform: cisco C9500, Capabilities: Router Switch IGMP
Interface: GigabitEthernet1/0/24, Port ID (outgoing port): TenGigabitEthernet1/0/1
""",
    }

    result = engine.evaluate(check, outputs=outputs, ip="10.50.10.25")

    assert result.status == "NotAFinding"
    assert result.failed_objects == []
    assert result.passed_objects[0].object_name == "GigabitEthernet1/0/24"
    assert "Only configured upstream" in result.finding_details
