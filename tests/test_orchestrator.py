"""Unit tests for the Full Scan Orchestrator and Pipeline."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from ghostmirror.core.project_manager import ProjectManager
from ghostmirror.modules.base.scanner import OutOfScopeError
from ghostmirror.modules.models.finding import ScanResultModel
from ghostmirror.modules.orchestrator.execution_context import ExecutionContext
from ghostmirror.modules.orchestrator.full_scan import FullScanOrchestrator
from ghostmirror.modules.orchestrator.pipeline import get_pipeline_steps


def test_pipeline_steps_mapping():
    """Verify that get_pipeline_steps returns correct lists and handles errors."""
    lite_steps = get_pipeline_steps("lite")
    assert "headers" in lite_steps
    assert "ssl" in lite_steps
    assert "nuclei" not in lite_steps

    standard_steps = get_pipeline_steps("standard")
    assert "nuclei" in standard_steps
    assert "cve_intelligence" in standard_steps

    with pytest.raises(ValueError, match="Perfil inválido"):
        get_pipeline_steps("invalid_profile")


def test_execution_context_tracking(tmp_path: Path):
    """Test step duration tracking and saving timeline."""
    context = ExecutionContext("test-project", "example.com", "standard")
    
    with context.start_step("headers") as tracker:
        tracker.findings_count = 3

    context.finalize()
    timeline = context.to_dict()

    assert timeline["project"] == "test-project"
    assert timeline["target"] == "example.com"
    assert timeline["profile"] == "standard"
    assert len(timeline["steps"]) == 1
    assert timeline["steps"][0]["name"] == "headers"
    assert timeline["steps"][0]["status"] == "completed"
    assert timeline["steps"][0]["findings"] == 3

    # Save to disk
    timeline_path = context.save_timeline(tmp_path)
    assert timeline_path.exists()
    
    with open(timeline_path, "r", encoding="utf-8") as f:
        loaded = json.load(f)
    assert loaded["project"] == "test-project"


@patch("ghostmirror.modules.headers.scanner.HeadersScanner.run")
@patch("ghostmirror.modules.ssl.scanner.SSLScanner.run")
@patch("ghostmirror.modules.nmap.scanner.NmapScanner.run")
@patch("ghostmirror.modules.fingerprint.scanner.FingerprintScanner.run")
@patch("ghostmirror.modules.technology_intelligence.engine.TechnologyIntelligenceEngine.analyze_project")
@patch("ghostmirror.modules.cve_intelligence.engine.CVEIntelligenceEngine.analyze_project")
@patch("ghostmirror.modules.nuclei.scanner.NucleiScanner.run")
@patch("ghostmirror.modules.owasp.scanner.OWASPScanner.run")
@patch("ghostmirror.modules.reporting.generator.ReportGenerator.generate")
def test_full_scan_orchestrator_success(
    mock_report,
    mock_owasp,
    mock_nuclei,
    mock_cve,
    mock_tech,
    mock_fingerprint,
    mock_nmap,
    mock_ssl,
    mock_headers,
    project_manager: ProjectManager,
):
    """Test successful orchestration of standard profile scan."""
    # 1. Create project
    handle = project_manager.create_project(
        client="Acme", name="Pentest", domain="acme.com"
    )

    # Enable tests on scope
    scope_path = handle.path / "scope.yaml"
    scope = project_manager.scope_manager.load_scope(scope_path)
    scope.targets.domains = ["acme.com"]
    project_manager.scope_manager.write_scope(scope_path, scope)

    # 2. Setup Mocks
    mock_headers.return_value = MagicMock(findings=[1, 2])
    mock_ssl.return_value = MagicMock(findings=[1])
    mock_nmap.return_value = MagicMock(findings=[])
    mock_fingerprint.return_value = MagicMock(findings=[])
    mock_tech.return_value = {"findings": []}
    mock_cve.return_value = {"findings": []}
    mock_nuclei.return_value = MagicMock(findings=[1, 2, 3])
    mock_owasp.return_value = MagicMock(findings=[])

    # 3. Run Orchestrator
    orchestrator = FullScanOrchestrator(handle.path, "acme.com", "standard")
    timeline = orchestrator.run()

    # 4. Verify results
    assert timeline["profile"] == "standard"
    assert len(timeline["steps"]) == 13  # 12 scanners/intelligence + 1 report

    # Assert specific step outputs
    steps = {s["name"]: s for s in timeline["steps"]}
    assert steps["headers"]["status"] == "completed"
    assert steps["headers"]["findings"] == 2
    assert steps["ssl"]["findings"] == 1
    assert steps["nuclei"]["findings"] == 3
    assert steps["owasp"]["status"] == "completed"
    assert steps["report"]["status"] == "completed"

    # Verify timeline file exists
    assert (handle.path / "execution" / "full_scan_timeline.json").exists()


def test_full_scan_orchestrator_out_of_scope(project_manager: ProjectManager):
    """Orchestrator must raise OutOfScopeError if target is not authorized."""
    handle = project_manager.create_project(
        client="Acme", name="Pentest", domain="acme.com"
    )

    orchestrator = FullScanOrchestrator(handle.path, "malicious.com", "lite")
    with pytest.raises(OutOfScopeError):
        orchestrator.run()


@patch("ghostmirror.modules.headers.scanner.HeadersScanner.run")
@patch("ghostmirror.modules.ssl.scanner.SSLScanner.run")
@patch("ghostmirror.modules.nmap.scanner.NmapScanner.run")
@patch("ghostmirror.modules.fingerprint.scanner.FingerprintScanner.run")
@patch("ghostmirror.modules.reporting.generator.ReportGenerator.generate")
def test_full_scan_orchestrator_resilience_to_errors(
    mock_report,
    mock_fingerprint,
    mock_nmap,
    mock_ssl,
    mock_headers,
    project_manager: ProjectManager,
):
    """Orchestrator should capture step exceptions without halting the entire pipeline."""
    handle = project_manager.create_project(
        client="Acme", name="Pentest", domain="acme.com"
    )

    scope_path = handle.path / "scope.yaml"
    scope = project_manager.scope_manager.load_scope(scope_path)
    scope.targets.domains = ["acme.com"]
    project_manager.scope_manager.write_scope(scope_path, scope)

    # Headers fails, but SSL succeeds
    mock_headers.side_effect = RuntimeError("Network error")
    mock_ssl.return_value = MagicMock(findings=[1])
    mock_nmap.return_value = MagicMock(findings=[])
    mock_fingerprint.return_value = MagicMock(findings=[])

    orchestrator = FullScanOrchestrator(handle.path, "acme.com", "lite")
    timeline = orchestrator.run()

    # Pipeline should have executed all steps, headers fails, ssl completes
    steps = {s["name"]: s for s in timeline["steps"]}
    assert steps["headers"]["status"] == "failed"
    assert steps["ssl"]["status"] == "completed"
    assert steps["report"]["status"] == "completed"

