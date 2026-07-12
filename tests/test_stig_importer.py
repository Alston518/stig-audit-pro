from __future__ import annotations

import zipfile

import pytest

from stig_audit_pro.stig.source_manager import StigSourceError, StigSourceManager
from stig_audit_pro.stig.xccdf_importer import parse_xccdf_file
from tests.conftest import PROJECT_ROOT


def test_parse_xccdf_metadata():
    metadata = parse_xccdf_file(
        PROJECT_ROOT / "tests" / "fixtures" / "sample_xccdf.xml", family="IOSXE_L2"
    )

    assert metadata.family == "IOSXE_L2"
    assert metadata.title.startswith("Cisco IOS-XE Switch L2S")
    assert metadata.version == "V1R1"
    assert metadata.release_date == "2026-07-04"
    assert metadata.rule_count == 1
    rule = metadata.rules[0]
    assert rule.vuln_id == "V-123456"
    assert rule.rule_id == "SV-123456r1_rule"
    assert rule.stig_id == "CISC-L2-000210"
    assert rule.severity == "medium"
    assert "Review disabled" in rule.check_text


def test_stig_source_manager_imports_zip_and_caches_metadata(tmp_path):
    xml_path = PROJECT_ROOT / "tests" / "fixtures" / "sample_xccdf.xml"
    zip_path = tmp_path / "U_Cisco_IOSXE_L2_STIG.zip"
    with zipfile.ZipFile(zip_path, "w") as archive:
        archive.write(xml_path, "U_SAMPLE-xccdf.xml")

    manager = StigSourceManager(tmp_path / "cache")
    metadata = manager.import_source(zip_path, family="IOSXE_L2")
    cached = manager.load_cached_metadata()

    assert metadata.rule_count == 1
    assert metadata.source_filename == zip_path.name
    assert len(cached) == 1
    assert cached[0].rules[0].stig_id == "CISC-L2-000210"


def test_stig_source_manager_download_from_local_path(tmp_path):
    xml_path = PROJECT_ROOT / "tests" / "fixtures" / "sample_xccdf.xml"
    zip_path = tmp_path / "U_Cisco_IOSXE_L2_STIG.zip"
    with zipfile.ZipFile(zip_path, "w") as archive:
        archive.write(xml_path, "U_SAMPLE-xccdf.xml")

    manager = StigSourceManager(tmp_path / "cache")
    metadata = manager.download_from_url(str(zip_path), family="IOSXE_L2")

    assert metadata.rule_count == 1
    assert metadata.source_filename == zip_path.name


def test_dynamic_cyber_exchange_shell_gets_actionable_error(tmp_path):
    manager = StigSourceManager(tmp_path / "cache")
    manager._read_url_text = lambda _url: "<html><title>Welcome to LWC Communities!</title></html>"  # type: ignore[method-assign]

    with pytest.raises(StigSourceError, match="direct ZIP/XML"):
        manager.discover_downloads(["cisco", "ios", "xe"])
