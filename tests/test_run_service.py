from datetime import datetime, timezone

from stig_audit_pro.application.run_service import OfflineEvidenceDevice, RunService
from stig_audit_pro.core.models import CheckDefinition, SiteProfile
from stig_audit_pro.infrastructure.evidence import EvidenceStore
from stig_audit_pro.infrastructure.persistence import AuditRunRepository, Database


def test_offline_import_creates_reproducible_run_and_history(tmp_path):
    database = Database(tmp_path / "history.sqlite3")
    repository = AuditRunRepository(database)
    store = EvidenceStore(tmp_path / "runs", repository)
    service = RunService(database, repository=repository, evidence_store=store)
    profile = SiteProfile(profile_name="offline-test")
    check = CheckDefinition(
        vuln_id="V-1",
        rule_id="SV-1",
        stig_id="TEST-1",
        title="Hostname is present",
        stig_family="IOSXE_L2",
        severity="cat2",
        check_type="command_contains",
        commands=["show running-config"],
        conditions={"contains": "hostname SW01"},
    )
    collected_at = datetime(2026, 1, 2, 3, 4, tzinfo=timezone.utc)
    imported = OfflineEvidenceDevice(
        target_ip="192.0.2.20",
        hostname="SW01",
        source="authorized collector bundle 42",
        collected_at=collected_at,
        outputs={"show running-config": "hostname SW01\n"},
    )
    try:
        context, result = service.import_offline(
            devices=[imported],
            checks=[check],
            profile_provider=lambda _target: profile,
            profile_snapshot=profile,
            stig_families=["IOSXE_L2"],
            concurrency=1,
        )
        assert result.results[0].status == "NotAFinding"
        assert result.results[0].run_id == context.run_id
        assert len(result.results[0].evidence_artifact_ids) == 1
        run = repository.get_run(context.run_id)
        assert run is not None
        assert run.collection_mode == "OFFLINE_IMPORTED"
        assert run.status == "COMPLETE"
        artifact = repository.list_evidence_artifacts(context.run_id)[0]
        assert artifact.collected_at.replace(tzinfo=timezone.utc) == collected_at
        assert service.evidence_store.load_manifest(context.run_id)["collection_mode"] == "OFFLINE_IMPORTED"
        historical = service.load_results(context.run_id)
        assert historical[0].evidence_artifact_ids == result.results[0].evidence_artifact_ids
        assert service.list_history()[0].pass_count == 1
    finally:
        database.dispose()
