"""Nuclei execution wrapper implementing ToolRunner from Sprint 4."""

from __future__ import annotations

from pathlib import Path
from typing import List, Optional

from ghostmirror.core.logger import get_logger
from ghostmirror.integrations.base.tool_runner import ToolRunner
from ghostmirror.integrations.models.result import ToolExecutionResult

logger = get_logger()


class NucleiRunner:
    """Wrapper class to execute the Nuclei scanner using the common ToolRunner."""

    BINARY_NAME = "nuclei"

    def __init__(self, tool_runner: Optional[ToolRunner] = None) -> None:
        self.runner = tool_runner or ToolRunner()

    def is_installed(self) -> bool:
        """Checks if nuclei binary is available in the system path."""
        return self.runner.is_binary_available(self.BINARY_NAME)

    def scan(
        self,
        target: str,
        templates: List[str],
        output_jsonl_path: Path | str,
        rate_limit: int = 150,
        concurrency: int = 25,
        timeout: float = 300.0,
    ) -> ToolExecutionResult:
        """Executes nuclei scanning against a target using a list of specified templates.

        Parameters
        ----------
        target : str
            The target URL, domain, or IP.
        templates : List[str]
            List of template paths or categories to run.
        output_jsonl_path : Path | str
            Filepath where the raw JSONL result will be saved.
        rate_limit : int, default 150
            Rate limit (request/s) for nuclei (-rate-limit).
        concurrency : int, default 25
            Concurrency level for nuclei (-concurrency).
        timeout : float, default 300.0
            Process execution timeout in seconds.

        Returns
        -------
        ToolExecutionResult
            Command execution output wrapper.
        """
        output_path = Path(output_jsonl_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Build execution arguments
        args = [
            "-target",
            target,
            "-jsonl",
            "-rate-limit",
            str(rate_limit),
            "-concurrency",
            str(concurrency),
            "-o",
            str(output_path),
        ]

        for template in templates:
            args.extend(["-t", template])

        logger.info(
            "NUCLEI_RUNNER_START target={} templates_count={} rate_limit={} concurrency={}",
            target,
            len(templates),
            rate_limit,
            concurrency,
        )

        return self.runner.run(
            tool_name=self.BINARY_NAME,
            args=args,
            timeout=timeout,
        )
