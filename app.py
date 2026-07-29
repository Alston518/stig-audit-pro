"""Desktop entry point for STIG Audit Pro."""

from __future__ import annotations


def main() -> None:
    from stig_audit_pro.logging_config import configure_logging

    configure_logging()
    try:
        from stig_audit_pro.gui import run_gui
    except ImportError as exc:
        missing = exc.name or "a GUI dependency"
        print(f"Could not start the GUI because {missing} is not installed.")
        print("Install dependencies with: python -m pip install -r requirements.txt")
        raise SystemExit(1) from exc
    run_gui()


if __name__ == "__main__":
    main()
