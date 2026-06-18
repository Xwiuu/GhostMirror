"""Additional unit tests to maximize coverage of the Technology Intelligence Module."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from ghostmirror.models.technology import TechnologyModel
from ghostmirror.modules.base.scanner import OutOfScopeError, ScannerError
from ghostmirror.modules.technology_intelligence.knowledge_base import KnowledgeBase
from ghostmirror.modules.technology_intelligence.profiler import TechnologyProfilerEngine
from ghostmirror.modules.technology_intelligence.scanner import TechnologyIntelligenceScanner


def test_knowledge_base_nonexistent_dir() -> None:
    kb = KnowledgeBase(knowledge_dir=Path("/nonexistent/dir/path/doesnt/exist"))
    assert len(kb.definitions) == 0


def test_knowledge_base_missing_files(tmp_path: Path) -> None:
    kb_dir = tmp_path / "kb"
    kb_dir.mkdir()
    # Write only one file, others missing
    (kb_dir / "servers.json").write_text('{"Nginx": {"category": "WEB SERVER"}}', encoding="utf-8")
    
    kb = KnowledgeBase(knowledge_dir=kb_dir)
    assert "nginx" in kb.definitions
    assert len(kb.definitions) == 1


def test_knowledge_base_invalid_json(tmp_path: Path) -> None:
    kb_dir = tmp_path / "kb"
    kb_dir.mkdir()
    (kb_dir / "servers.json").write_text("invalid json {", encoding="utf-8")
    
    kb = KnowledgeBase(knowledge_dir=kb_dir)
    assert len(kb.definitions) == 0


def test_profiler_engine_unmapped_technologies() -> None:
    techs = [
        TechnologyModel(name="SomeCustomFramework", category="BACKEND FRAMEWORKS", confidence=0.9, source="test")
    ]
    # Default risk score addition for unknown apps: +2
    risk = TechnologyProfilerEngine.calculate_risk("example.com", techs, ["TLS 1.2"])
    assert risk.risk_score == 2
    assert risk.risk_level == "LOW"


def test_profiler_engine_obsolete_protocols() -> None:
    techs = []
    # 0 base + 15 obsolete TLS = 15
    risk = TechnologyProfilerEngine.calculate_risk("example.com", techs, ["SSLv3"])
    assert risk.risk_score == 15
    assert risk.risk_level == "LOW"
    assert any("obsoletos" in obs for obs in risk.observations)


def test_profiler_engine_attack_surface_entry_points_django_tom_joom_mag_ghost() -> None:
    techs = [
        TechnologyModel(name="Django", category="BACKEND FRAMEWORKS", confidence=1.0, source="test"),
        TechnologyModel(name="Tomcat", category="WEB SERVER", confidence=1.0, source="test"),
        TechnologyModel(name="Joomla", category="CMS", confidence=1.0, source="test"),
        TechnologyModel(name="Magento", category="CMS", confidence=1.0, source="test"),
        TechnologyModel(name="Ghost CMS", category="CMS", confidence=1.0, source="test"),
        TechnologyModel(name="FastAPI", category="BACKEND FRAMEWORKS", confidence=1.0, source="test"),
    ]
    surface = TechnologyProfilerEngine.analyze_attack_surface("example.com", techs, 60)
    assert "Django Admin Interface (/admin/)" in surface.potential_entry_points
    assert "Tomcat Manager Application (/manager/)" in surface.potential_entry_points
    assert "Joomla Administrator Console (/administrator/)" in surface.potential_entry_points
    assert "Magento Admin Panel (/admin/)" in surface.potential_entry_points
    assert "Ghost CMS Admin (/ghost/)" in surface.potential_entry_points
    assert "FastAPI Swagger Documentation (/docs)" in surface.potential_entry_points


@patch("ghostmirror.modules.base.scanner.ScopeManager.load_scope")
@patch("ghostmirror.modules.base.scanner.ScopeManager.is_ready_for_testing")
def test_scanner_out_of_scope(
    mock_is_ready: MagicMock,
    mock_load_scope: MagicMock,
    tmp_path: Path
) -> None:
    mock_scope = MagicMock()
    mock_scope.targets.domains = ["allowed.com"]
    mock_load_scope.return_value = mock_scope
    mock_is_ready.return_value = True

    project_dir = tmp_path / "test-project"
    project_dir.mkdir()
    (project_dir / "scope.yaml").write_text("{}", encoding="utf-8")

    scanner = TechnologyIntelligenceScanner(
        project_path=project_dir,
        target="notallowed.com",
    )
    with pytest.raises(OutOfScopeError):
        scanner.run()


@patch("ghostmirror.modules.base.scanner.ScopeManager.load_scope")
@patch("ghostmirror.modules.base.scanner.ScopeManager.is_ready_for_testing")
def test_scanner_missing_profile(
    mock_is_ready: MagicMock,
    mock_load_scope: MagicMock,
    tmp_path: Path
) -> None:
    mock_scope = MagicMock()
    mock_scope.targets.domains = ["example.com"]
    mock_load_scope.return_value = mock_scope
    mock_is_ready.return_value = True

    project_dir = tmp_path / "test-project"
    project_dir.mkdir()
    (project_dir / "scope.yaml").write_text("{}", encoding="utf-8")

    scanner = TechnologyIntelligenceScanner(
        project_path=project_dir,
        target="example.com",
    )
    with pytest.raises(ScannerError, match="Perfil de tecnologia não encontrado"):
        scanner.run()


@patch("ghostmirror.modules.base.scanner.ScopeManager.load_scope")
@patch("ghostmirror.modules.base.scanner.ScopeManager.is_ready_for_testing")
@patch("ghostmirror.modules.technology_intelligence.engine.TechnologyIntelligenceEngine.analyze_project")
def test_scanner_unexpected_error(
    mock_analyze: MagicMock,
    mock_is_ready: MagicMock,
    mock_load_scope: MagicMock,
    tmp_path: Path
) -> None:
    mock_scope = MagicMock()
    mock_scope.targets.domains = ["example.com"]
    mock_load_scope.return_value = mock_scope
    mock_is_ready.return_value = True

    project_dir = tmp_path / "test-project"
    project_dir.mkdir()
    (project_dir / "scope.yaml").write_text("{}", encoding="utf-8")

    mock_analyze.side_effect = Exception("Unexpected server database crash")

    scanner = TechnologyIntelligenceScanner(
        project_path=project_dir,
        target="example.com",
    )
    with pytest.raises(ScannerError, match="Erro ao executar a análise de tecnologia"):
        scanner.run()
