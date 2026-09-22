from __future__ import annotations

import json
import shutil

from scripts import generate_stig_traceability


def test_render_is_identical_with_absent_or_conflicting_local_cache(
    tmp_path,
    monkeypatch,
):
    source_checks = generate_stig_traceability.ROOT / "data" / "checks"
    test_checks = tmp_path / "data" / "checks"
    shutil.copytree(source_checks, test_checks)
    monkeypatch.setattr(generate_stig_traceability, "ROOT", tmp_path)

    without_cache = generate_stig_traceability.render()

    cache_file = tmp_path / "data" / "stigs" / "cache" / "IOSXE_L2" / "metadata.json"
    cache_file.parent.mkdir(parents=True)
    cache_file.write_text(
        json.dumps(
            {
                "family": "IOSXE_L2",
                "version": "CONFLICTING-VERSION",
                "release_info": "CONFLICTING-RELEASE",
                "rules": [
                    {
                        "vuln_id": "V-220649",
                        "rule_id": "CONFLICTING-RULE-ID",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    with_conflicting_cache = generate_stig_traceability.render()

    assert with_conflicting_cache == without_cache
    assert "| IOSXE_L2 | V-220649 | SV-220649r863283_rule |" in without_cache
    assert "| IOSXE_NDM | V-220518 | SV-220518r960735_rule |" in without_cache
