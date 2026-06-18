"""Unit tests for the FindingsManager."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import pytest

from ghostmirror.modules.findings.manager import FindingsManager
from ghostmirror.modules.models.finding import (
    FindingModel,
    FindingSeverity,
    ScanResultModel,
)


def test_findings_manager_save_and_load(tmp_path: Path) -> None:
    # Set up findings manager for mock project path
    project_path = tmp_path / "test-project"
    project_path.mkdir()
    
    manager = FindingsManager(project_path)
    
    # Create mock scan result
    started = datetime.now(timezone.utc)
    finished = datetime.now(timezone.utc)
    result = ScanResultModel(
        scanner_name="headers",
        target="example.com",
        started_at=started,
        finished_at=finished,
        status="completed",
        findings=[
            FindingModel(
                title="Missing CSP",
                description="CSP is absent.",
                severity=FindingSeverity.MEDIUM,
                target="example.com",
                recommendation="Add CSP.",
            )
        ],
        statistics={"total": 1, "medium": 1},
    )
    
    # Save findings
    saved_path = manager.save_findings("headers", result)
    assert saved_path.exists()
    assert saved_path.name == "headers.json"
    
    # Load findings
    loaded = manager.load_findings("headers")
    assert loaded.scanner_name == "headers"
    assert loaded.target == "example.com"
    assert len(loaded.findings) == 1
    assert loaded.findings[0].title == "Missing CSP"
    assert loaded.statistics["total"] == 1


def test_findings_manager_list_and_export(tmp_path: Path) -> None:
    project_path = tmp_path / "test-project"
    project_path.mkdir()
    manager = FindingsManager(project_path)

    # 1. Check list returns empty dict when no findings exist
    assert manager.list_findings() == {}

    # 2. Save mock findings for headers and ssl
    started = datetime.now(timezone.utc)
    res_headers = ScanResultModel(
        scanner_name="headers",
        target="example.com",
        started_at=started,
        finished_at=started,
        status="completed",
        findings=[],
        statistics={"total": 0},
    )
    res_ssl = ScanResultModel(
        scanner_name="ssl",
        target="example.com",
        started_at=started,
        finished_at=started,
        status="completed",
        findings=[],
        statistics={"total": 0},
    )
    
    manager.save_findings("headers", res_headers)
    manager.save_findings("ssl", res_ssl)
    
    # 3. Check listing
    all_findings = manager.list_findings()
    assert "headers" in all_findings
    assert "ssl" in all_findings
    assert all_findings["headers"].scanner_name == "headers"
    assert all_findings["ssl"].scanner_name == "ssl"
    
    # 4. Check exporting
    export_file = tmp_path / "exported_findings.json"
    manager.export_all_findings(export_file)
    assert export_file.exists()
