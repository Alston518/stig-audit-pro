"""YAML loading, validation, and profile inheritance support."""

from __future__ import annotations

import os
import shutil
import tempfile
from copy import deepcopy
from datetime import datetime
from pathlib import Path
from typing import Any, TypeVar

import yaml
from packaging.version import InvalidVersion, Version
from pydantic import BaseModel, ValidationError

from stig_audit_pro.config import APP_VERSION
from stig_audit_pro.core.exceptions import ExceptionLibrary
from stig_audit_pro.core.models import CheckLibrary, SiteProfile

ModelT = TypeVar("ModelT", bound=BaseModel)


class ConfigValidationError(ValueError):
    """Raised when external YAML cannot be loaded or validated."""


def _model_validate(model_type: type[ModelT], data: Any) -> ModelT:
    try:
        if hasattr(model_type, "model_validate"):
            return model_type.model_validate(data)  # type: ignore[attr-defined]
        return model_type.parse_obj(data)
    except ValidationError as exc:
        raise ConfigValidationError(str(exc)) from exc


def load_yaml_file(path: str | Path) -> dict[str, Any]:
    yaml_path = Path(path)
    try:
        with yaml_path.open("r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle) or {}
    except OSError as exc:
        raise ConfigValidationError(f"Could not read YAML file {yaml_path}: {exc}") from exc

    if not isinstance(data, dict):
        raise ConfigValidationError(f"YAML file {yaml_path} must contain a mapping at top level")
    return data


def deep_merge(base: dict[str, Any], overlay: dict[str, Any]) -> dict[str, Any]:
    merged = deepcopy(base)
    for key, value in overlay.items():
        if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
            merged[key] = deep_merge(merged[key], value)
        else:
            merged[key] = deepcopy(value)
    return merged


def load_check_library(path: str | Path) -> CheckLibrary:
    library = _model_validate(CheckLibrary, load_yaml_file(path))
    try:
        if Version(library.minimum_app_version) > Version(APP_VERSION):
            raise ConfigValidationError(
                f"Check pack {library.library_name or path} requires application "
                f"{library.minimum_app_version} or newer; running {APP_VERSION}"
            )
    except InvalidVersion as exc:
        raise ConfigValidationError(f"Invalid application compatibility version: {exc}") from exc
    return library


def load_check_libraries(paths: list[str | Path]) -> list[CheckLibrary]:
    libraries = [load_check_library(path) for path in paths]
    seen: dict[str, str] = {}
    duplicates: list[str] = []
    for path, library in zip(paths, libraries, strict=True):
        for check in library.checks:
            if check.vuln_id in seen:
                duplicates.append(f"{check.vuln_id} ({seen[check.vuln_id]}, {path})")
            else:
                seen[check.vuln_id] = str(path)
    if duplicates:
        raise ConfigValidationError(
            "Duplicate controls across check libraries: " + ", ".join(sorted(duplicates))
        )
    return libraries


def _resolve_profile_path(profile_name: str, profiles_dir: Path) -> Path:
    candidate = Path(profile_name)
    if candidate.suffix:
        if candidate.is_absolute():
            return candidate
        return profiles_dir / candidate
    return profiles_dir / f"{profile_name}.yaml"


def load_profile(path: str | Path, profiles_dir: str | Path | None = None) -> SiteProfile:
    profile_path = Path(path)
    profile_dir = Path(profiles_dir) if profiles_dir is not None else profile_path.parent
    data = _load_profile_chain(profile_path, profile_dir, [])
    return _model_validate(SiteProfile, data)


def _load_profile_chain(path: Path, profiles_dir: Path, stack: list[Path]) -> dict[str, Any]:
    resolved = path.resolve()
    if resolved in stack:
        cycle = " -> ".join(item.stem for item in [*stack, resolved])
        raise ConfigValidationError(f"Profile inheritance cycle detected: {cycle}")
    data = load_yaml_file(resolved)
    inherits = data.get("inherits")
    if not inherits:
        return data
    base_path = _resolve_profile_path(str(inherits), profiles_dir)
    if not base_path.exists():
        raise ConfigValidationError(f"Inherited profile does not exist: {base_path}")
    base_data = _load_profile_chain(base_path, profiles_dir, [*stack, resolved])
    return deep_merge(base_data, data)


def load_exceptions(path: str | Path) -> ExceptionLibrary:
    return _model_validate(ExceptionLibrary, load_yaml_file(path))


def atomic_write_yaml(path: str | Path, data: dict[str, Any], backup: bool = True) -> Path:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if backup and destination.exists():
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        shutil.copy2(destination, destination.with_suffix(f"{destination.suffix}.{stamp}.bak"))
    fd, temporary = tempfile.mkstemp(prefix=f".{destination.name}.", dir=destination.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            yaml.safe_dump(data, handle, sort_keys=False)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, destination)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return destination
