"""YAML loading, validation, and profile inheritance support."""

from __future__ import annotations

from copy import deepcopy
from pathlib import Path
from typing import Any, TypeVar

import yaml
from pydantic import BaseModel, ValidationError

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
    return _model_validate(CheckLibrary, load_yaml_file(path))


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
    data = load_yaml_file(profile_path)
    inherits = data.get("inherits")
    if inherits:
        base_path = _resolve_profile_path(str(inherits), profile_dir)
        base_data = load_yaml_file(base_path)
        data = deep_merge(base_data, data)
    return _model_validate(SiteProfile, data)


def load_exceptions(path: str | Path) -> ExceptionLibrary:
    return _model_validate(ExceptionLibrary, load_yaml_file(path))
