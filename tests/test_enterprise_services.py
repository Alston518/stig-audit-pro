import json
import zipfile
from pathlib import Path

from sqlalchemy import inspect, text

from stig_audit_pro.application.audit_package_service import AuditPackageService
from stig_audit_pro.application.backup_service import BackupService, BackupSource
from stig_audit_pro.application.support_bundle_service import SupportBundleService
from stig_audit_pro.infrastructure.persistence import Database
from stig_audit_pro.infrastructure.persistence.db_models import ActivityLog
from stig_audit_pro.infrastructure.persistence.repositories import ActivityLogRepository


def test_activity_log_redacts_secret_fields(tmp_path):
    database = Database(tmp_path / "audit.sqlite3")
    item = ActivityLogRepository(database).record("AUDIT_STARTED", "audit", "one", details={"password": "do-not-store", "nested": {"token": "abc"}, "message": "password=hunter2"})
    assert item.details == {"password": "[REDACTED]", "nested": {"token": "[REDACTED]"}, "message": "password=[REDACTED]"}


def test_v1_database_is_backed_up_and_migrated(tmp_path):
    path = tmp_path / "audit.sqlite3"
    database = Database(path)
    with database.engine.begin() as connection:
        connection.execute(text("DROP TABLE activity_log"))
        connection.execute(text("UPDATE schema_version SET version = 1 WHERE id = 1"))
    database.dispose()
    migrated = Database(path)
    assert "activity_log" in inspect(migrated.engine).get_table_names()
    assert list(tmp_path.glob("audit.sqlite3.pre-v2-*.bak"))


def test_support_bundle_excludes_and_redacts_secrets(tmp_path):
    database = Database(tmp_path / "audit.sqlite3")
    log = tmp_path / "app.log"
    log.write_text("password=hunter2\nnormal diagnostic\n", encoding="utf-8")
    target = SupportBundleService(database, log_paths=[log]).create(tmp_path / "support.zip")
    with zipfile.ZipFile(target) as archive:
        names = archive.namelist()
        content = "\n".join(archive.read(name).decode("utf-8") for name in names)
    assert "hunter2" not in content
    assert "[REDACTED]" in content
    assert not any("evidence" in name.lower() for name in names)


def test_backup_and_restore_validate_product_archive(tmp_path):
    database = Database(tmp_path / "source.sqlite3")
    data = tmp_path / "profiles"
    data.mkdir()
    (data / "site.yaml").write_text("profile_name: site\n", encoding="utf-8")
    backup = BackupService(database_path=database.path, sources=[BackupSource("profiles", data)])
    archive = backup.create(tmp_path / "backup.zip")
    restore_root = tmp_path / "restored"
    backup.restore(archive, destination_root=restore_root)
    assert (restore_root / "database/stig-audit-pro.sqlite3").is_file()
    assert (restore_root / "data/profiles/site.yaml").is_file()


def test_audit_package_detects_modified_entry(tmp_path):
    run = tmp_path / "run"
    run.mkdir()
    for name, value in (("manifest.json", "{}"), ("checks.snapshot.yaml", "checks: []"), ("profile.snapshot.yaml", "profile_name: site")):
        (run / name).write_text(value, encoding="utf-8")
    service = AuditPackageService()
    package = service.export(run_id="run-1", run_directory=run, destination=tmp_path / "run.zip")
    assert service.verify(package).valid
    with zipfile.ZipFile(package) as archive:
        entries = {name: archive.read(name) for name in archive.namelist()}
    entries["audit/manifest.json"] = b"tampered"
    with zipfile.ZipFile(package, "w") as archive:
        for name, data in entries.items():
            archive.writestr(name, data)
    verification = service.verify(package)
    assert not verification.valid
    assert verification.status == "MODIFIED"
