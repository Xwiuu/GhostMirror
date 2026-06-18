"""Nuclei updater helper executing nuclei -update-templates."""

from __future__ import annotations

from typing import Optional

from ghostmirror.core.logger import get_logger
from ghostmirror.integrations.base.tool_runner import ToolRunner
from ghostmirror.integrations.models.result import ToolExecutionResult

logger = get_logger()


class NucleiUpdater:
    """Helper to update Nuclei templates."""

    BINARY_NAME = "nuclei"

    def __init__(self, tool_runner: Optional[ToolRunner] = None) -> None:
        self.runner = tool_runner or ToolRunner()

    def update_templates(self, timeout: float = 300.0) -> ToolExecutionResult:
        """Runs `nuclei -update-templates` to update the local signatures database.

        Parameters
        ----------
        timeout : float, default 300.0
            Process execution timeout in seconds.

        Returns
        -------
        ToolExecutionResult
            Command execution output wrapper.
        """
        logger.info("NUCLEI_TEMPLATES_UPDATE_START")
        return self.runner.run(
            tool_name=self.BINARY_NAME,
            args=["-update-templates"],
            timeout=timeout,
        )
