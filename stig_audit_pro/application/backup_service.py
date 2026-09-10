"""Validated local backup and restore for persistent application data."""

from __future__ import annotations

import json
import shutil
import tempfile
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from stig_audit_pro.config import APP_VERSION
from stig_audit_pro.core.archive_safety import MAX_ARCHIVE_BYTES, validate_zip


@dataclass(frozen=True, slots=True)
class BackupSource:
    name: str
    path: Path


class BackupService:
    """Back up only explicitly supplied product-owned files and directories."""

    def __init__(self, *, database_path: str | Path, sources: Iterable[BackupSource], evidence_root: str | Path | None = None) -> None:
        self.database_path = Path(database_path).resolve()
        self.sources = tuple(sources)
        self.evidence_root = Path(evidence_root).resolve() if evidence_root else None

    def create(self, destination: str | Path, *, include_evidence: bool = False) -> Path:
        target = Path(destination)
        target.parent.mkdir(parents=True, exist_ok=True)
        manifest = {"schema_version": 1, "application_version": APP_VERSION, "created_at": datetime.now(timezone.utc).isoformat(), "includes_evidence": include_evidence, "entries": []}
        temporary = target.with_suffix(target.suffix + ".tmp")
        with zipfile.ZipFile(temporary, "w", zipfile.ZIP_DEFLATED) as archive:
            self._add_path(archive, self.database_path, "database/stig-audit-pro.sqlite3", manifest)
            for source in self.sources:
                self._add_path(archive, source.path.resolve(), f"data/{self._safe_name(source.name)}", manifest)
            if include_evidence and self.evidence_root:
                self._add_path(archive, self.evidence_root, "evidence", manifest)
            archive.writestr("backup-manifest.json", json.dumps(manifest, indent=2) + "\n")
        temporary.replace(target)
        return target

    def restore(self, archive_path: str | Path, *, destination_root: str | Path) -> Path:
        source = Path(archive_path)
        if source.stat().st_size > MAX_ARCHIVE_BYTES:
            raise ValueError("Backup archive exceeds the supported size limit")
        root = Path(destination_root).resolve()
        root.mkdir(parents=True, exist_ok=True)
        safety = root.parent / f"{root.name}-before-restore-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
        if root.exists() and any(root.iterdir()):
            shutil.copytree(root, safety)
        with zipfile.ZipFile(source) as archive:
            infos = validate_zip(archive)
            try:
                manifest = json.loads(archive.read("backup-manifest.json"))
            except (KeyError, json.JSONDecodeError) as exc:
                raise ValueError("Not a valid STIG Audit Pro backup") from exc
            if manifest.get("schema_version") != 1:
                raise ValueError("Unsupported backup schema version")
            with tempfile.TemporaryDirectory(dir=root.parent) as temp_dir:
                staging = Path(temp_dir)
                for info in infos:
                    if info.is_dir():
                        continue
                    destination = (staging / info.filename).resolve()
                    destination.relative_to(staging.resolve())
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    with archive.open(info) as input_stream, destination.open("xb") as output_stream:
                        shutil.copyfileobj(input_stream, output_stream)
                restored = staging / "restored"
                restored.mkdir()
                for item in staging.iterdir():
                    if item.name != "restored":
                        shutil.move(str(item), restored / item.name)
                for item in restored.iterdir():
                    destination = root / item.name
                    if destination.exists():
                        if destination.is_dir():
                            shutil.rmtree(destination)
                        else:
                            destination.unlink()
                    shutil.move(str(item), destination)
        return safety

    @staticmethod
    def _safe_name(value: str) -> str:
        cleaned = "".join(character if character.isalnum() or character in "._-" else "-" for character in value).strip(".-")
        if not cleaned:
            raise ValueError("Backup source requires a safe name")
        return cleaned

    @classmethod
    def _add_path(cls, archive: zipfile.ZipFile, source: Path, prefix: str, manifest: dict) -> None:
        if not source.exists() or source.is_symlink():
            return
        files = [source] if source.is_file() else [item for item in source.rglob("*") if item.is_file() and not item.is_symlink()]
        for item in files:
            relative = Path(prefix) if source.is_file() else Path(prefix) / item.relative_to(source)
            archive.write(item, relative.as_posix())
            manifest["entries"].append(relative.as_posix())


__all__ = ["BackupService", "BackupSource"]
