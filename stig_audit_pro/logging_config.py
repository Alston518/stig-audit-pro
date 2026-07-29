"""Application logging configured for customer-safe diagnostics."""

from __future__ import annotations

import logging
from pathlib import Path

from stig_audit_pro.licensing.paths import log_directory


def configure_logging() -> Path | None:
    """Configure a rotating-free first-version log without failing app startup."""

    root_logger = logging.getLogger()
    if root_logger.handlers:
        return None
    formatter = logging.Formatter(
        "%(asctime)s %(levelname)s %(name)s: %(message)s"
    )
    stream = logging.StreamHandler()
    stream.setFormatter(formatter)
    root_logger.addHandler(stream)
    root_logger.setLevel(logging.INFO)
    try:
        directory = log_directory()
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / "stig-audit-pro.log"
        file_handler = logging.FileHandler(path, encoding="utf-8")
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)
        return path
    except OSError:
        logging.getLogger(__name__).warning(
            "Could not create the application log file; continuing with console logging"
        )
        return None
