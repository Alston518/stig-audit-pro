from __future__ import annotations

from tests.conftest import load_l2_checks, load_outputs, load_profile
from stig_audit_pro.core.check_engine import CheckEngine


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

    assert results["CISC-L2-000210"].status == "NotAFinding"
    assert results["EXAMPLE-TRUNK-VLAN1-PRUNED"].status == "NotAFinding"
    assert results["EXAMPLE-ACL-LOG-INPUT"].status == "NotAFinding"
    assert results["EXAMPLE-DHCP-SNOOPING"].status == "NotAFinding"
    assert results["EXAMPLE-ARP-INSPECTION"].status == "NotAFinding"


def test_required_checks_fail_on_noncompliant_sample_outputs():
    results = _results_by_vuln("noncompliant")

    assert results["CISC-L2-000210"].status == "Open"
    assert results["EXAMPLE-TRUNK-VLAN1-PRUNED"].status == "Open"
    assert results["EXAMPLE-ACL-LOG-INPUT"].status == "Open"
    assert results["EXAMPLE-DHCP-SNOOPING"].status == "Open"
    assert results["EXAMPLE-ARP-INSPECTION"].status == "Open"

    assert results["EXAMPLE-TRUNK-VLAN1-PRUNED"].failed_objects[0].object_name == "GigabitEthernet1/0/24"
    assert results["EXAMPLE-DHCP-SNOOPING"].failed_objects
    assert results["EXAMPLE-ARP-INSPECTION"].failed_objects[0].object_name == "30"
