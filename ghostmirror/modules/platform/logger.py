"""Logging wrapper for audit logs and channelized platform message distribution."""

from __future__ import annotations

import getpass
import os
from datetime import datetime, timezone

from ghostmirror.core.logger import get_logger

logger = get_logger()


def get_current_user() -> str:
    """Retrieve the current logged-in user name safely."""
    try:
        return getpass.getuser()
    except Exception:
        # Fallback if getuser() is unavailable (e.g. running in custom containers)
        return os.environ.get("USER", os.environ.get("USERNAME", "unknown"))


def log_audit(
    event: str,
    project: str,
    scanner: str,
    result: str,
    user: str | None = None,
    timestamp: str | None = None,
) -> None:
    """Log an audit event directly to the audit channel.

    Saves structured data in key=value format for security tracing.
    """
    if user is None:
        user = get_current_user()
    if timestamp is None:
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

    # Route using channel extra property
    audit_logger = logger.bind(channel="audit")
    audit_logger.info(
        "event={!r} user={!r} project={!r} scanner={!r} result={!r} timestamp={!r}",
        event,
        user,
        project,
        scanner,
        result,
        timestamp,
    )
