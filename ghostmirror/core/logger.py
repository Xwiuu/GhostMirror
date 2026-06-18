"""Central logging configuration built on Loguru.

Log records use the format ``[DATE] [LEVEL] EVENT``. The full event stream is
written to ``logs/ghostmirror.log`` while the console only surfaces warnings and
errors, keeping the interactive CLI clean.
"""

from __future__ import annotations

import sys
from pathlib import Path

from loguru import logger

_CONSOLE_FORMAT = (
    "<green>[{time:YYYY-MM-DD HH:mm:ss}]</green> "
    "<level>[{level}]</level> {message}"
)

#: Guards against re-adding sinks when the CLI is invoked multiple times.
_configured = False

# Drop Loguru's default stderr handler at import time so no events leak in the
# default format before :func:`setup_logger` installs the real sinks.
logger.remove()


def _extra_fields(record) -> str:
    """Build a space-separated string of enriched context fields from extra."""
    parts = []
    for key in ("run_id", "module", "status", "duration", "findings"):
        val = record["extra"].get(key)
        if val is not None:
            if key == "duration":
                parts.append(f"duration={val}s")
            elif key == "findings":
                parts.append(f"findings={val}")
            else:
                parts.append(f"{key}={val}")
    return " ".join(parts)


def _file_format(record):
    extra_str = _extra_fields(record)
    base = "[{time:YYYY-MM-DD HH:mm:ss}] [{level}]"
    if extra_str:
        return f"{base} [{extra_str}] {{message}}\n"
    return f"{base} {{message}}\n"


def is_scanner_log(record) -> bool:
    """Helper to detect if the log originates from a scanner or tool integration module."""
    if record["extra"].get("channel") == "scanner":
        return True
    name = record["name"]
    return (
        "ghostmirror.modules.headers" in name
        or "ghostmirror.modules.ssl" in name
        or "ghostmirror.modules.nmap" in name
        or "ghostmirror.modules.fingerprint" in name
        or "ghostmirror.modules.nuclei" in name
        or "ghostmirror.integrations" in name
    )


def setup_logger(
    log_dir: Path,
    *,
    file_level: str = "INFO",
    console_level: str = "WARNING",
) -> "logger.__class__":
    """Configure the global logger.

    Parameters
    ----------
    log_dir:
        Directory in which log files are created.
    file_level:
        Minimum level written to the log file.
    console_level:
        Minimum level echoed to ``stderr`` (kept high so the menu stays tidy).
    """

    global _configured

    logger.remove()

    log_dir.mkdir(parents=True, exist_ok=True)

    # 1. execution.log (receives everything except audit channel logs)
    logger.add(
        log_dir / "execution.log",
        level=file_level,
        format=_file_format,
        filter=lambda r: r["extra"].get("channel") != "audit",
        rotation="10 MB",
        retention="30 days",
        encoding="utf-8",
        enqueue=True,
        backtrace=False,
        diagnose=False,
    )

    # 2. scanner.log (receives only scanner-channel or scanner module logs)
    logger.add(
        log_dir / "scanner.log",
        level=file_level,
        format=_file_format,
        filter=lambda r: is_scanner_log(r) and r["extra"].get("channel") != "audit",
        rotation="10 MB",
        retention="30 days",
        encoding="utf-8",
        enqueue=True,
        backtrace=False,
        diagnose=False,
    )

    # 3. audit.log (receives only audit channel logs)
    logger.add(
        log_dir / "audit.log",
        level="INFO",
        format="[{time:YYYY-MM-DD HH:mm:ss}] [AUDIT] {message}",
        filter=lambda r: r["extra"].get("channel") == "audit",
        rotation="10 MB",
        retention="30 days",
        encoding="utf-8",
        enqueue=True,
        backtrace=False,
        diagnose=False,
    )

    # 4. errors.log (receives only ERROR level and above, excluding audit logs)
    logger.add(
        log_dir / "errors.log",
        level="ERROR",
        format=_file_format,
        filter=lambda r: r["extra"].get("channel") != "audit",
        rotation="10 MB",
        retention="30 days",
        encoding="utf-8",
        enqueue=True,
        backtrace=True,
        diagnose=True,
    )

    # 5. Console output (sys.stderr)
    logger.add(
        sys.stderr,
        level=console_level,
        format=_CONSOLE_FORMAT,
        colorize=True,
    )

    _configured = True
    return logger


def get_logger() -> "logger.__class__":
    """Return the shared Loguru logger instance."""

    return logger
