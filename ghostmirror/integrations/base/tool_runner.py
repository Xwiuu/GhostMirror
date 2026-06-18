"""Central utility for executing external command-line security tools safely."""

import shutil
import subprocess
import time
from typing import List, Optional

from ghostmirror.core.logger import get_logger
from ghostmirror.integrations.models.result import ToolExecutionResult

logger = get_logger()


from ghostmirror.core.exceptions import (
    ToolError,
    ToolExecutionError,
    ToolNotFoundError,
    ToolTimeoutError,
)


class ToolRunner:
    """Central manager to execute external security tools safely."""

    @staticmethod
    def is_binary_available(binary_name: str) -> bool:
        """Validate if the binary exists in system PATH."""
        return shutil.which(binary_name) is not None

    def run(
        self,
        tool_name: str,
        args: List[str],
        timeout: Optional[float] = None,
        check_exit_code: bool = False,
    ) -> ToolExecutionResult:
        """Executes an external command, captures stdout/stderr, handles timeout, and logs metrics.

        Parameters
        ----------
        tool_name : str
            Name of the binary to run (e.g. 'nmap').
        args : List[str]
            List of command line arguments.
        timeout : Optional[float]
            Timeout duration in seconds.
        check_exit_code : bool
            If True, raises ToolExecutionError if the exit code is non-zero.

        Returns
        -------
        ToolExecutionResult
            The structured execution output.

        Raises
        ------
        ToolNotFoundError
            If the binary is not found.
        ToolTimeoutError
            If execution times out.
        ToolExecutionError
            If check_exit_code is True and exit code is non-zero.
        ToolError
            For other unexpected errors (e.g. PermissionError).
        """
        if not self.is_binary_available(tool_name):
            logger.error("TOOL_NOT_FOUND binary={}", tool_name)
            raise ToolNotFoundError(
                f"External tool '{tool_name}' is not installed or not available in the system PATH."
            )

        command = [tool_name] + args
        cmd_str = " ".join(command)
        
        logger.info("TOOL_EXECUTION_START tool={} command={}", tool_name, cmd_str)
        start_time = time.perf_counter()

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
            duration = time.perf_counter() - start_time
            exit_code = result.returncode
            stdout = result.stdout or ""
            stderr = result.stderr or ""
            
        except subprocess.TimeoutExpired as exc:
            duration = time.perf_counter() - start_time
            stdout = exc.stdout.decode() if isinstance(exc.stdout, bytes) else (exc.stdout or "")
            stderr = exc.stderr.decode() if isinstance(exc.stderr, bytes) else (exc.stderr or "")
            logger.error("TOOL_EXECUTION_TIMEOUT tool={} duration={:.2f}s", tool_name, duration)
            raise ToolTimeoutError(
                f"Tool '{tool_name}' execution timed out after {timeout} seconds.\n"
                f"Stdout: {stdout[:500]}\nStderr: {stderr[:500]}"
            )
        except PermissionError as exc:
            logger.error("TOOL_PERMISSION_DENIED tool={} command={} error={}", tool_name, cmd_str, exc)
            raise ToolError(f"Permission denied while attempting to execute '{tool_name}': {exc}")
        except Exception as exc:
            logger.error("TOOL_UNEXPECTED_ERROR tool={} command={} error={}", tool_name, cmd_str, exc)
            raise ToolError(f"Unexpected error executing external tool '{tool_name}': {exc}")

        success = exit_code == 0
        logger.info(
            "TOOL_EXECUTION_FINISHED tool={} exit_code={} duration={:.2f}s success={}",
            tool_name,
            exit_code,
            duration,
            success,
        )

        if check_exit_code and not success:
            logger.error("TOOL_EXECUTION_FAILED tool={} exit_code={}", tool_name, exit_code)
            raise ToolExecutionError(
                f"Tool '{tool_name}' failed with non-zero exit code {exit_code}.\n"
                f"Stdout: {stdout[:500]}\nStderr: {stderr[:500]}"
            )

        return ToolExecutionResult(
            tool_name=tool_name,
            command=cmd_str,
            exit_code=exit_code,
            stdout=stdout,
            stderr=stderr,
            duration=duration,
            success=success,
        )
