"""CI entry point for all built-in YAML/check-pack validation."""

from pathlib import Path

from stig_audit_pro.core.models import validate_check_for_profile
from stig_audit_pro.core.yaml_loader import load_check_libraries, load_profile

root = Path(__file__).resolve().parents[1]
libraries = load_check_libraries(sorted((root / "data" / "checks").glob("*.yaml")))
checks = [check for library in libraries for check in library.checks]
for path in sorted((root / "data" / "profiles").glob("*.yaml")):
    profile = load_profile(path)
    for check in checks:
        validate_check_for_profile(check, profile)
print(f"Validated {len(libraries)} check packs, {len(checks)} checks, and all profiles.")
