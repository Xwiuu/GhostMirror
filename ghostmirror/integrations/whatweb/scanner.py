"""WhatWeb tool integration wrapper."""

from __future__ import annotations

from pathlib import Path

from ghostmirror.core.logger import get_logger
from ghostmirror.integrations.base.tool_runner import ToolRunner
from ghostmirror.integrations.models.result import ToolExecutionResult

logger = get_logger()


class WhatWebRunner:
    """Helper to run the WhatWeb binary using ToolRunner."""

    def __init__(self, tool_runner: ToolRunner | None = None) -> None:
        self.runner = tool_runner or ToolRunner()

    def scan(
        self,
        target: str,
        json_output_path: Path | str,
        timeout: float | None = 300.0,
    ) -> ToolExecutionResult:
        """Executes WhatWeb scan on the target, writing the JSON output to json_output_path.

        Parameters
        ----------
        target : str
            Target IP or domain.
        json_output_path : Path | str
            Filepath to save the WhatWeb JSON log.
        timeout : float | None, default 300.0
            Maximum time allowed for scan execution in seconds.

        Returns
        -------
        ToolExecutionResult
            Execution results from ToolRunner.
        """
        json_path = Path(json_output_path)
        json_path.parent.mkdir(parents=True, exist_ok=True)

        args = [
            "--color=never",
            f"--log-json={json_path}",
            target,
        ]

        logger.info("WHATWEB_SCAN_RUNNING target={}", target)

        # ToolRunner handles binary validation, process execution, timeout and metrics
        return self.runner.run(
            tool_name="whatweb",
            args=args,
            timeout=timeout,
        )
