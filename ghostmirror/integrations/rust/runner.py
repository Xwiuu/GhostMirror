"""Python bridge to execute the GhostMirror Rust binary and parse its JSON output."""

from __future__ import annotations

import json
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any

from ghostmirror.core.logger import get_logger
from ghostmirror.core.exceptions import ToolError, ToolNotFoundError
from ghostmirror.integrations.rust.models import (
    RustBannerResult,
    RustFingerprintResult,
    RustPortResult,
)

logger = get_logger()

BINARY_NAME = "ghostmirror-rs"


class RustBridge:
    """Bridge to execute ghostmirror-rs binary and parse JSON output into Pydantic models."""

    def __init__(self, binary_path: str | Path | None = None) -> None:
        self._binary_path: Path | None = None
        if binary_path:
            self._binary_path = Path(binary_path)
        self._discovered = False

    def _find_binary(self) -> Path:
        """Locate the Rust binary: explicit path, project build, or system PATH."""
        if self._binary_path and self._binary_path.exists():
            return self._binary_path

        candidates = [
            Path.cwd() / "ghostmirror-rs" / "target" / "release" / BINARY_NAME,
            Path.cwd() / "ghostmirror-rs" / "target" / "debug" / BINARY_NAME,
        ]

        if not self._discovered:
            for candidate in candidates:
                if candidate.exists() and candidate.is_file():
                    self._binary_path = candidate
                    self._discovered = True
                    logger.info(
                        "RUST_BINARY_FOUND path={}", self._binary_path
                    )
                    return self._binary_path

        if shutil.which(BINARY_NAME):
            self._binary_path = Path(shutil.which(BINARY_NAME))
            self._discovered = True
            return self._binary_path

        raise ToolNotFoundError(
            f"Rust binary '{BINARY_NAME}' not found. "
            f"Build it with: cd ghostmirror-rs && cargo build --release"
        )

    def _exec(self, args: list[str]) -> dict[str, Any]:
        """Execute the Rust binary with given args and parse JSON stdout."""
        binary = self._find_binary()
        command = [str(binary)] + args
        cmd_str = " ".join(command)

        logger.info("RUST_EXECUTION_START command={}", cmd_str)
        start = time.perf_counter()

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
        except subprocess.TimeoutExpired:
            logger.error("RUST_EXECUTION_TIMEOUT command={}", cmd_str)
            raise ToolError(f"Rust binary timed out: {cmd_str}")
        except OSError as exc:
            logger.error("RUST_EXECUTION_FAILED error={}", exc)
            raise ToolError(f"Failed to execute Rust binary: {exc}")

        duration = time.perf_counter() - start

        if result.returncode != 0:
            error_msg = result.stderr.strip() or result.stdout.strip() or "unknown error"
            logger.error(
                "RUST_EXECUTION_ERROR exit_code={} stderr={}",
                result.returncode,
                result.stderr[:500],
            )
            raise ToolError(f"Rust binary error (exit={result.returncode}): {error_msg}")

        logger.info(
            "RUST_EXECUTION_FINISHED command={} duration={:.2f}s",
            cmd_str,
            duration,
        )

        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            logger.error("RUST_JSON_PARSE_ERROR error={} stdout={}", exc, result.stdout[:500])
            raise ToolError(f"Failed to parse Rust JSON output: {exc}")

    # ------------------------------------------------------------------ #
    # Public scan methods
    # ------------------------------------------------------------------ #
    def portscan(self, host: str, ports: str, timeout: int = 3) -> RustPortResult:
        """Execute Rust port scan and return parsed result."""
        raw = self._exec(["portscan", "--host", host, "--ports", ports, "--timeout", str(timeout)])
        return RustPortResult.model_validate(raw)

    def banner(self, host: str, port: int = 80, tls: bool = False) -> RustBannerResult:
        """Execute Rust banner grab and return parsed result."""
        args = ["banner", "--host", host, "--port", str(port)]
        if tls:
            args.append("--tls")
        raw = self._exec(args)
        return RustBannerResult.model_validate(raw)

    def fingerprint(self, url: str) -> RustFingerprintResult:
        """Execute Rust HTTP fingerprint and return parsed result."""
        raw = self._exec(["fingerprint", "--url", url])
        return RustFingerprintResult.model_validate(raw)
