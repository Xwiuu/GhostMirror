"""Tests for Nuclei scanner SKIPPED behavior when tool is not installed."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from ghostmirror.core.exceptions import ToolNotFoundError
from ghostmirror.modules.nuclei.scanner import NucleiScanner


class TestNucleiSkipped:
    """Verify Nuclei scanner raises ToolNotFoundError when not installed."""

    def test_raises_tool_not_found_when_not_installed(self, tmp_path: Path):
        """When nuclei binary is not available, raise ToolNotFoundError."""
        scanner = NucleiScanner(
            project_path=tmp_path,
            target="https://example.com",
            profile="standard",
        )
        scanner.nuclei_runner = MagicMock()
        scanner.nuclei_runner.is_installed.return_value = False
        scanner.validate_scope = MagicMock()

        with pytest.raises(ToolNotFoundError) as excinfo:
            scanner.run()

        assert "nuclei" in str(excinfo.value).lower()

    def test_does_not_raise_tool_not_found_when_installed(self, tmp_path: Path):
        """When nuclei binary is available, proceed without ToolNotFoundError."""
        scanner = NucleiScanner(
            project_path=tmp_path,
            target="https://example.com",
            profile="standard",
        )
        scanner.nuclei_runner = MagicMock()
        scanner.nuclei_runner.is_installed.return_value = True
        scanner.nuclei_runner.scan.return_value = MagicMock(
            success=True, exit_code=0, stdout="", stderr=""
        )
        scanner.validate_scope = MagicMock()

        with patch(
            "ghostmirror.modules.nuclei.scanner.NucleiParser.parse_file",
            return_value=[],
        ):
            with patch(
                "ghostmirror.modules.nuclei.scanner.NucleiCorrelationEngine.correlate",
                return_value=0,
            ):
                result = scanner.run()
                assert result.status == "completed"

    def test_skipped_propagates_through_orchestrator(self):
        """ToolNotFoundError from nuclei should be catchable as SKIPPED."""
        from ghostmirror.modules.orchestrator.execution_context import (
            ExecutionContext,
            ExecutionStatus,
        )

        context = ExecutionContext("test", "example.com", "standard")
        with context.start_step("nuclei") as tracker:
            try:
                raise ToolNotFoundError("nuclei is not installed")
            except ToolNotFoundError:
                tracker.mark_skipped(reason="Nuclei not installed")

        assert tracker.status == ExecutionStatus.SKIPPED
        steps = context.steps
        assert steps[0]["status"] == "skipped"
