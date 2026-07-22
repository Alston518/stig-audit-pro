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
    assert counts["Not_Reviewed"] == 5
    assert counts["Not_Applicable"] == 1
    assert results["V-220650"].status == "NotAFinding"
    assert results["V-220655"].status == "Not_Applicable"
    assert results["V-220656"].status == "NotAFinding"
    assert results["V-220657"].status == "NotAFinding"
    assert results["V-220658"].status == "NotAFinding"
    assert results["V-220659"].status == "NotAFinding"
    assert results["V-220661"].status == "NotAFinding"
    assert results["V-220667"].status == "NotAFinding"
    assert results["V-220669"].status == "NotAFinding"


def test_required_checks_fail_on_noncompliant_sample_outputs():
    results = _results_by_vuln("noncompliant")
    counts = Counter(result.status for result in results.values())

    assert counts["Open"] == 17
    assert counts["Not_Reviewed"] == 5
    assert results["V-220650"].status == "Open"
    assert results["V-220655"].status == "Open"
    assert results["V-220655"].failed_objects[0].object_name == "GigabitEthernet1/0/24"
    assert results["V-220656"].status == "Open"
    assert results["V-220657"].status == "Open"
    assert results["V-220658"].status == "Open"
    assert results["V-220659"].status == "Open"
    assert results["V-220661"].status == "Open"
    assert results["V-220667"].status == "Open"
    assert results["V-220669"].status == "Open"
    assert results["V-220669"].failed_objects[0].object_name == "GigabitEthernet1/0/24"
    assert results["V-220659"].failed_objects
    assert results["V-220661"].failed_objects[0].object_name == "30"


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
