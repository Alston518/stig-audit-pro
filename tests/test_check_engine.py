from __future__ import annotations

from collections import Counter

from stig_audit_pro.core.check_engine import CheckEngine
from tests.conftest import load_l2_checks, load_outputs, load_profile


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

    assert counts["NotAFinding"] == 16
    assert counts["Not_Reviewed"] == 6
    assert results["CISC-L2-000030"].status == "NotAFinding"
    assert results["CISC-L2-000100"].status == "NotAFinding"
    assert results["CISC-L2-000110"].status == "NotAFinding"
    assert results["CISC-L2-000120"].status == "NotAFinding"
    assert results["CISC-L2-000130"].status == "NotAFinding"
    assert results["CISC-L2-000150"].status == "NotAFinding"
    assert results["CISC-L2-000210"].status == "NotAFinding"
    assert results["CISC-L2-000230"].status == "NotAFinding"


def test_required_checks_fail_on_noncompliant_sample_outputs():
    results = _results_by_vuln("noncompliant")
    counts = Counter(result.status for result in results.values())

    assert counts["Open"] == 15
    assert counts["NotAFinding"] == 1
    assert counts["Not_Reviewed"] == 6
    assert results["CISC-L2-000030"].status == "Open"
    assert results["CISC-L2-000100"].status == "Open"
    assert results["CISC-L2-000110"].status == "Open"
    assert results["CISC-L2-000120"].status == "Open"
    assert results["CISC-L2-000130"].status == "Open"
    assert results["CISC-L2-000150"].status == "Open"
    assert results["CISC-L2-000210"].status == "Open"
    assert results["CISC-L2-000230"].status == "Open"

    assert results["CISC-L2-000230"].failed_objects[0].object_name == "GigabitEthernet1/0/24"
    assert results["CISC-L2-000130"].failed_objects
    assert results["CISC-L2-000150"].failed_objects[0].object_name == "30"
