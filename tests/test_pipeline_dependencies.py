"""Tests for Pipeline Dependency Graph — cascade SKIPPED status."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from ghostmirror.modules.orchestrator.execution_context import ExecutionStatus
from ghostmirror.modules.orchestrator.full_scan import (
    FullScanOrchestrator,
    STEP_DEPENDENCIES,
)


class TestStepDependencies:
    """Verify step dependency map is defined correctly."""

    def test_tech_intel_depends_on_fingerprint(self):
        """Technology Intelligence depends on Fingerprint."""
        assert "fingerprint" in STEP_DEPENDENCIES["technology_intelligence"]

    def test_cve_intel_depends_on_fingerprint(self):
        """CVE Intelligence depends on Fingerprint."""
        assert "fingerprint" in STEP_DEPENDENCIES["cve_intelligence"]

    def test_nuclei_depends_on_cve_and_tech(self):
        """Nuclei depends on both CVE and Technology Intelligence."""
        assert "cve_intelligence" in STEP_DEPENDENCIES["nuclei"]
        assert "technology_intelligence" in STEP_DEPENDENCIES["nuclei"]


class TestPipelineCascadeSkipped:
    """Verify pipeline cascades SKIPPED through dependencies."""

    def create_mock_project(self, tmp_path: Path):
        """Helper to create a mock project with scope."""
        from ghostmirror.core.scope_manager import ScopeManager

        handle = type("Handle", (), {})()
        handle.path = tmp_path
        scope_path = tmp_path / "scope.yaml"
        import json
        scope_content = {
            "project": {"client": "Acme", "name": "Pentest"},
            "targets": {"domains": ["example.com"], "ips": []},
            "allowed_tests": {"destructive_tests": False},
        }
        scope_path.write_text(json.dumps(scope_content))

        metadata_path = tmp_path / "metadata.json"
        import json
        with open(metadata_path, "w") as f:
            json.dump({"domain": "example.com"}, f)
        return handle

    @patch(
        "ghostmirror.modules.headers.scanner.HeadersScanner.run"
    )
    @patch(
        "ghostmirror.modules.ssl.scanner.SSLScanner.run"
    )
    @patch(
        "ghostmirror.modules.nmap.scanner.NmapScanner.run"
    )
    @patch(
        "ghostmirror.modules.fingerprint.scanner.FingerprintScanner.run"
    )
    @patch(
        "ghostmirror.modules.reporting.generator.ReportGenerator.generate"
    )
    def test_fingerprint_skipped_cascades_to_tech_and_cve(
        self,
        mock_report,
        mock_fingerprint,
        mock_nmap,
        mock_ssl,
        mock_headers,
        tmp_path: Path,
    ):
        """When Fingerprint is SKIPPED, Tech Intel and CVE Intel must also be SKIPPED."""
        handle = self.create_mock_project(tmp_path)

        mock_headers.return_value = MagicMock(findings=[1])
        mock_ssl.return_value = MagicMock(findings=[1])
        mock_nmap.return_value = MagicMock(findings=[])
        mock_fingerprint.side_effect = __import__(
            "ghostmirror.core.exceptions", fromlist=["ToolNotFoundError"]
        ).ToolNotFoundError("whatweb is not installed")

        orchestrator = FullScanOrchestrator(
            handle.path, "example.com", "standard"
        )
        timeline = orchestrator.run()

        steps = {s["name"]: s for s in timeline["steps"]}
        assert steps["fingerprint"]["status"] == "skipped"
        assert steps["technology_intelligence"]["status"] == "skipped"
        assert steps["cve_intelligence"]["status"] == "skipped"

    @patch(
        "ghostmirror.modules.headers.scanner.HeadersScanner.run"
    )
    @patch(
        "ghostmirror.modules.ssl.scanner.SSLScanner.run"
    )
    @patch(
        "ghostmirror.modules.nmap.scanner.NmapScanner.run"
    )
    @patch(
        "ghostmirror.modules.fingerprint.scanner.FingerprintScanner.run"
    )
    @patch(
        "ghostmirror.modules.technology_intelligence.engine.TechnologyIntelligenceEngine.analyze_project"
    )
    @patch(
        "ghostmirror.modules.cve_intelligence.engine.CVEIntelligenceEngine.analyze_project"
    )
    @patch(
        "ghostmirror.modules.reporting.generator.ReportGenerator.generate"
    )
    def test_all_steps_complete_when_no_skips(
        self,
        mock_report,
        mock_cve,
        mock_tech,
        mock_fingerprint,
        mock_nmap,
        mock_ssl,
        mock_headers,
        tmp_path: Path,
    ):
        """When no steps are skipped, all should complete."""
        handle = self.create_mock_project(tmp_path)

        mock_headers.return_value = MagicMock(findings=[])
        mock_ssl.return_value = MagicMock(findings=[])
        mock_nmap.return_value = MagicMock(findings=[])
        mock_fingerprint.return_value = MagicMock(findings=[])
        mock_tech.return_value = {"findings": []}
        mock_cve.return_value = {"findings": []}

        orchestrator = FullScanOrchestrator(
            handle.path, "example.com", "standard"
        )
        timeline = orchestrator.run()

        steps = {s["name"]: s for s in timeline["steps"]}
        assert steps["fingerprint"]["status"] == "completed"
        assert steps["technology_intelligence"]["status"] == "completed"
        assert steps["cve_intelligence"]["status"] == "completed"

    def test_dependency_skip_reason_includes_dep_names(self, tmp_path: Path):
        """Skipped reason should mention which dependencies were skipped."""
        from ghostmirror.modules.orchestrator.execution_context import (
            ExecutionContext,
        )

        context = ExecutionContext("test", "example.com", "standard")
        context.add_step_result(
            "fingerprint", "skipped", __import__("datetime").datetime.now(),
            __import__("datetime").datetime.now(), 0.1, 0,
        )
        context.add_step_result(
            "technology_intelligence", "skipped", __import__("datetime").datetime.now(),
            __import__("datetime").datetime.now(), 0.1, 0,
            ["Dependency skipped: fingerprint"],
        )
        result = context.to_dict()
        steps = {s["name"]: s for s in result["steps"]}
        assert steps["technology_intelligence"]["errors"] == [
            "Dependency skipped: fingerprint"
        ]
