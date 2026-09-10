"""Portable, integrity-verifiable historical audit packages."""

from __future__ import annotations

import hashlib
import json
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from stig_audit_pro.config import APP_VERSION
from stig_audit_pro.core.archive_safety import MAX_ARCHIVE_BYTES, validate_zip


@dataclass(frozen=True, slots=True)
class AuditPackageVerification:
    valid: bool
    run_id: str | None
    status: str
    problems: tuple[str, ...] = ()


class AuditPackageService:
    def export(self, *, run_id: str, run_directory: str | Path, destination: str | Path, include_evidence: bool = False) -> Path:
        source = Path(run_directory).resolve()
        required = ("manifest.json", "checks.snapshot.yaml", "profile.snapshot.yaml")
        missing = [name for name in required if not (source / name).is_file()]
        if missing:
            raise ValueError(f"Audit run is missing required files: {', '.join(missing)}")
        entries: dict[str, str] = {}
        target = Path(destination)
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary = target.with_suffix(target.suffix + ".tmp")
        with zipfile.ZipFile(temporary, "w", zipfile.ZIP_DEFLATED) as archive:
            candidates = [item for item in source.rglob("*") if item.is_file() and not item.is_symlink()]
            for item in candidates:
                relative = item.relative_to(source).as_posix()
                if not include_evidence and "/evidence/" in f"/{relative}":
                    continue
                data = item.read_bytes()
                entries[relative] = hashlib.sha256(data).hexdigest()
                archive.writestr(f"audit/{relative}", data)
            package_manifest = {"schema_version": 1, "application_version": APP_VERSION, "run_id": run_id, "classification": "IMPORTED_HISTORICAL_AUDIT", "created_at": datetime.now(timezone.utc).isoformat(), "includes_evidence": include_evidence, "entries": entries}
            archive.writestr("package-manifest.json", json.dumps(package_manifest, indent=2) + "\n")
        temporary.replace(target)
        return target

    def verify(self, package_path: str | Path) -> AuditPackageVerification:
        source = Path(package_path)
        if source.stat().st_size > MAX_ARCHIVE_BYTES:
            return AuditPackageVerification(False, None, "INVALID", ("Package exceeds the supported size limit",))
        problems: list[str] = []
        try:
            with zipfile.ZipFile(source) as archive:
                validate_zip(archive)
                payload = json.loads(archive.read("package-manifest.json"))
                if payload.get("schema_version") != 1:
                    problems.append("Unsupported package schema version")
                for name, expected in payload.get("entries", {}).items():
                    try:
                        actual = hashlib.sha256(archive.read(f"audit/{name}")).hexdigest()
                    except KeyError:
                        problems.append(f"Missing: {name}")
                        continue
                    if actual != expected:
                        problems.append(f"Modified: {name}")
                return AuditPackageVerification(not problems, payload.get("run_id"), "VALID" if not problems else "MODIFIED", tuple(problems))
        except Exception as exc:
            return AuditPackageVerification(False, None, "INVALID", (str(exc),))


__all__ = ["AuditPackageService", "AuditPackageVerification"]
