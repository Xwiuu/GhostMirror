"""Tests for pipeline resilience — skipped modules."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from ghostmirror.core.exceptions import ToolNotFoundError
from ghostmirror.modules.orchestrator.execution_context import ExecutionContext, ExecutionStatus


class TestSkippedModules:
    def test_tracker_mark_skipped(self):
        """Tracker can be marked as skipped."""
        context = ExecutionContext("test", "example.com", "quick")
        with context.start_step("headers") as tracker:
            tracker.mark_skipped(reason="Tool not found")

        context.finalize()
        timeline = context.to_dict()
        assert timeline["steps"][0]["status"] == "skipped"
        assert "Tool not found" in timeline["steps"][0]["errors"][0]

    def test_tracker_skipped_preserved_on_exit(self):
        """Skipped status should not be overwritten by __exit__."""
        context = ExecutionContext("test", "example.com", "quick")
        with context.start_step("headers") as tracker:
            tracker.mark_skipped(reason="Not available")
            tracker.findings_count = 0

        context.finalize()
        assert context.steps[0]["status"] == "skipped"

    def test_tracker_skipped_logs_no_exception(self):
        """Skipped steps should not log exceptions."""
        context = ExecutionContext("test", "example.com", "quick")
        with context.start_step("headers") as tracker:
            tracker.mark_skipped(reason="Binary not found")

        assert tracker.status == ExecutionStatus.SKIPPED

    def test_execution_context_get_skipped(self):
        """get_skipped_modules returns only skipped steps."""
        context = ExecutionContext("test", "example.com", "standard")
        with context.start_step("headers") as tracker:
            tracker.mark_skipped(reason="Missing")
        with context.start_step("ssl") as tracker:
            pass
        with context.start_step("nmap") as tracker:
            tracker.mark_skipped(reason="Not installed")

        skipped = context.get_skipped_modules()
        assert len(skipped) == 2
        assert skipped[0]["name"] == "headers"
        assert skipped[1]["name"] == "nmap"

    def test_execution_context_get_executed(self):
        """get_executed_modules returns only completed steps."""
        context = ExecutionContext("test", "example.com", "quick")
        with context.start_step("headers") as tracker:
            pass
        with context.start_step("ssl") as tracker:
            tracker.mark_skipped(reason="Missing")
        with context.start_step("nmap") as tracker:
            pass

        executed = context.get_executed_modules()
        assert len(executed) == 2
        assert executed[0]["name"] == "headers"
        assert executed[1]["name"] == "nmap"

    def test_execution_context_get_failed(self):
        """get_failed_modules returns only failed steps."""
        context = ExecutionContext("test", "example.com", "quick")
        with context.start_step("headers"):
            pass  # success
        with context.start_step("ssl") as tracker:
            tracker.status = ExecutionStatus.FAILED
            tracker.errors.append("Connection error")

        failed = context.get_failed_modules()
        assert len(failed) == 1
        assert failed[0]["name"] == "ssl"

    @patch("ghostmirror.modules.headers.scanner.HeadersScanner.run")
    def test_orchestrator_skips_on_tool_not_found(self, mock_headers, project_manager):
        """When a scanner raises ToolNotFoundError, the step is SKIPPED."""
        from ghostmirror.modules.orchestrator.full_scan import FullScanOrchestrator

        handle = project_manager.create_project(
            client="Acme", name="Test", domain="acme.com"
        )
        scope_path = handle.path / "scope.yaml"
        scope = project_manager.scope_manager.load_scope(scope_path)
        scope.targets.domains = ["acme.com"]
        project_manager.scope_manager.write_scope(scope_path, scope)

        mock_headers.side_effect = ToolNotFoundError("whatweb not found")

        orchestrator = FullScanOrchestrator(handle.path, "acme.com", "quick")
        timeline = orchestrator.run()

        steps = {s["name"]: s for s in timeline["steps"]}
        assert steps["headers"]["status"] == "skipped"

    def test_full_pipeline_continues_after_skip(self, project_manager):
        """The pipeline should continue after a skipped step."""
        from ghostmirror.modules.orchestrator.full_scan import FullScanOrchestrator

        handle = project_manager.create_project(
            client="Acme", name="Test2", domain="test.com"
        )
        scope_path = handle.path / "scope.yaml"
        scope = project_manager.scope_manager.load_scope(scope_path)
        scope.targets.domains = ["test.com"]
        project_manager.scope_manager.write_scope(scope_path, scope)

        orchestrator = FullScanOrchestrator(handle.path, "test.com", "quick")
        timeline = orchestrator.run()

        steps = {s["name"]: s for s in timeline["steps"]}
        assert "headers" in steps
        assert "report" in steps
