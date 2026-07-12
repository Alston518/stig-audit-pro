"""UUID-isolated, atomic command evidence storage."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import tempfile
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import UUID, uuid4


def _safe_name(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "_", value).strip("_") or "value"


SENSITIVE_LINE_PATTERNS = (
    re.compile(
        r"^\s*(?:enable\s+secret|username\s+\S+\s+(?:password|secret)|snmp-server\s+community)\b.*$",
        re.I,
    ),
    re.compile(r"^\s*(?:password|key-string|pre-shared-key)\b.*$", re.I),
)


class CommandOutputCache:
    def __init__(self, root: str | Path, retention_days: int = 30, redact: bool = False) -> None:
        self.root = Path(root)
        self.retention_days = max(0, retention_days)
        self.redact = redact
        self.root.mkdir(parents=True, exist_ok=True)

    def new_run_id(self) -> str:
        return str(uuid4())

    def run_dir(self, run_id: str | UUID) -> Path:
        canonical = str(UUID(str(run_id)))
        path = self.root / canonical
        path.mkdir(parents=True, exist_ok=True)
        return path

    def device_dir(self, ip: str, run_id: str | UUID | None = None) -> Path:
        # Legacy callers get a fresh immutable run instead of overwriting by IP.
        actual_run_id = run_id or self.new_run_id()
        path = self.run_dir(actual_run_id) / "devices" / _safe_name(ip)
        path.mkdir(parents=True, exist_ok=True)
        return path

    def command_path(self, ip: str, command: str, run_id: str | UUID) -> Path:
        return self.device_dir(ip, run_id) / f"{_safe_name(command)}.txt"

    def metadata_path(self, ip: str, run_id: str | UUID) -> Path:
        return self.device_dir(ip, run_id) / "metadata.json"

    def save_output(self, ip: str, command: str, output: str, run_id: str | UUID) -> Path:
        path = self.command_path(ip, command, run_id)
        self._atomic_write_text(path, self._redact(output) if self.redact else output)
        return path

    def load_output(self, ip: str, command: str, run_id: str | UUID) -> str | None:
        path = self.command_path(ip, command, run_id)
        return path.read_text(encoding="utf-8") if path.exists() else None

    def save_device_outputs(
        self, ip: str, outputs: dict[str, str], run_id: str | UUID | None = None
    ) -> str:
        actual_run_id = str(run_id or self.new_run_id())
        hashes: dict[str, str] = {}
        for command, output in outputs.items():
            stored = self._redact(output) if self.redact else output
            self.save_output(ip, command, output, actual_run_id)
            hashes[command] = hashlib.sha256(stored.encode("utf-8")).hexdigest()
        metadata = {
            "run_id": actual_run_id,
            "ip": ip,
            "commands": sorted(outputs),
            "output_hashes": hashes,
            "redacted": self.redact,
            "timestamp": datetime.now(UTC).isoformat(),
        }
        self._atomic_write_text(
            self.metadata_path(ip, actual_run_id), json.dumps(metadata, indent=2, sort_keys=True)
        )
        return actual_run_id

    def load_device_outputs(
        self, ip: str, commands: list[str], run_id: str | UUID
    ) -> dict[str, str]:
        return {
            command: output
            for command in commands
            if (output := self.load_output(ip, command, run_id)) is not None
        }

    def write_manifest(self, run_id: str | UUID, payload: dict[str, object]) -> Path:
        path = self.run_dir(run_id) / "run-manifest.json"
        self._atomic_write_text(path, json.dumps(payload, indent=2, sort_keys=True, default=str))
        return path

    def export_bundle(self, run_id: str | UUID, destination: str | Path) -> Path:
        source = self.run_dir(run_id)
        target = Path(destination)
        target.parent.mkdir(parents=True, exist_ok=True)
        temp = target.with_suffix(target.suffix + ".tmp")
        with zipfile.ZipFile(temp, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for path in sorted(source.rglob("*")):
                if path.is_file():
                    archive.write(path, path.relative_to(source))
        os.replace(temp, target)
        return target

    def enforce_retention(self, now: datetime | None = None) -> list[Path]:
        cutoff = (now or datetime.now(UTC)) - timedelta(days=self.retention_days)
        removed: list[Path] = []
        for path in self.root.iterdir():
            if not path.is_dir():
                continue
            modified = datetime.fromtimestamp(path.stat().st_mtime, UTC)
            if modified < cutoff:
                shutil.rmtree(path)
                removed.append(path)
        return removed

    def _redact(self, output: str) -> str:
        lines = []
        for line in output.splitlines():
            if any(pattern.match(line) for pattern in SENSITIVE_LINE_PATTERNS):
                lines.append("[REDACTED SENSITIVE CONFIGURATION LINE]")
            else:
                lines.append(line)
        return "\n".join(lines) + ("\n" if output.endswith("\n") else "")

    def _atomic_write_text(self, path: Path, text: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
                handle.write(text)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_name, path)
        finally:
            if os.path.exists(temp_name):
                os.unlink(temp_name)
