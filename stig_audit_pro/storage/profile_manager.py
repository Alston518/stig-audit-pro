"""Safe profile lifecycle and atomic persistence services."""

from __future__ import annotations

import os
import re
import shutil
import tempfile
from datetime import datetime
from pathlib import Path

import yaml

from stig_audit_pro.core.models import CheckDefinition, SiteProfile
from stig_audit_pro.core.yaml_loader import ConfigValidationError, load_profile, load_yaml_file

PROFILE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")


class ProfileManager:
    def __init__(self, profiles_dir: str | Path) -> None:
        self.profiles_dir = Path(profiles_dir)
        self.profiles_dir.mkdir(parents=True, exist_ok=True)

    def names(self) -> list[str]:
        return sorted(path.stem for path in self.profiles_dir.glob("*.yaml"))

    def path(self, name: str) -> Path:
        self._validate_name(name)
        return self.profiles_dir / f"{name}.yaml"

    def load(self, name: str) -> SiteProfile:
        return load_profile(self.path(name), self.profiles_dir)

    def local_values(self, name: str) -> dict[str, object]:
        return load_yaml_file(self.path(name))

    def create(self, name: str, base: str | None = None) -> Path:
        destination = self.path(name)
        if destination.exists():
            raise ConfigValidationError(f"Profile already exists: {name}")
        payload: dict[str, object] = {"profile_name": name, "inherits": base}
        self.save(name, payload, replacing=False)
        return destination

    def clone(self, source: str, new_name: str) -> Path:
        payload = self.local_values(source)
        payload["profile_name"] = new_name
        payload["inherits"] = source
        for key in list(payload):
            if key not in {"profile_name", "inherits"}:
                del payload[key]
        self.save(new_name, payload, replacing=False)
        return self.path(new_name)

    def rename(self, old_name: str, new_name: str) -> Path:
        old_path, new_path = self.path(old_name), self.path(new_name)
        if new_path.exists():
            raise ConfigValidationError(f"Profile already exists: {new_name}")
        payload = self.local_values(old_name)
        payload["profile_name"] = new_name
        self.save(new_name, payload, replacing=False)
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        shutil.copy2(old_path, old_path.with_suffix(f".yaml.{stamp}.renamed.bak"))
        old_path.unlink()
        for path in self.profiles_dir.glob("*.yaml"):
            data = load_yaml_file(path)
            if data.get("inherits") == old_name:
                data["inherits"] = new_name
                self._write_atomic(path, data, backup=True)
        return new_path

    def delete(self, name: str) -> None:
        if len(self.names()) <= 1:
            raise ConfigValidationError("At least one profile must remain")
        dependents = [
            path.stem
            for path in self.profiles_dir.glob("*.yaml")
            if path.stem != name and load_yaml_file(path).get("inherits") == name
        ]
        if dependents:
            raise ConfigValidationError(
                f"Cannot delete {name}; inherited by: {', '.join(sorted(dependents))}"
            )
        path = self.path(name)
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        shutil.copy2(path, path.with_suffix(f".yaml.{stamp}.deleted.bak"))
        path.unlink()

    def save(self, name: str, payload: dict[str, object], replacing: bool = True) -> Path:
        destination = self.path(name)
        if not replacing and destination.exists():
            raise ConfigValidationError(f"Profile already exists: {name}")
        payload = dict(payload)
        payload["profile_name"] = name
        # Validate the exact saved profile, including all inheritance levels.
        fd, temp_name = tempfile.mkstemp(suffix=".yaml", dir=self.profiles_dir)
        os.close(fd)
        temp = Path(temp_name)
        try:
            temp.write_text(yaml.safe_dump(payload, sort_keys=False), encoding="utf-8")
            load_profile(temp, self.profiles_dir)
        finally:
            temp.unlink(missing_ok=True)
        self._write_atomic(destination, payload, backup=replacing and destination.exists())
        return destination

    def consumers(self, checks: list[CheckDefinition]) -> dict[str, list[str]]:
        result: dict[str, list[str]] = {}
        for check in checks:
            for key in check.profile_keys():
                result.setdefault(key, []).append(check.vuln_id)
        return {key: sorted(values) for key, values in sorted(result.items())}

    def _write_atomic(self, path: Path, payload: dict[str, object], backup: bool) -> None:
        if backup and path.exists():
            stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
            shutil.copy2(path, path.with_suffix(f".yaml.{stamp}.bak"))
        fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
                yaml.safe_dump(payload, handle, sort_keys=False)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_name, path)
        finally:
            if os.path.exists(temp_name):
                os.unlink(temp_name)

    def _validate_name(self, name: str) -> None:
        if not PROFILE_NAME_RE.fullmatch(name):
            raise ConfigValidationError(
                "Profile name may contain letters, numbers, dot, underscore, and hyphen"
            )
