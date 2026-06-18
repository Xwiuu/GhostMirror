"""Unit tests for the Technology Intelligence Module, Risk Profiler, and CLI."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import typer
from typer.testing import CliRunner

from ghostmirror.app.cli import app
from ghostmirror.core.project_manager import ProjectHandle
from ghostmirror.models.project import ProjectModel, ProjectStatus
from ghostmirror.models.fingerprint import FingerprintProfile
from ghostmirror.models.technology import TechnologyModel
from ghostmirror.modules.models.finding import FindingSeverity
from ghostmirror.modules.technology_intelligence.engine import TechnologyIntelligenceEngine
from ghostmirror.modules.technology_intelligence.knowledge_base import KnowledgeBase
from ghostmirror.modules.technology_intelligence.profiler import TechnologyProfilerEngine
from ghostmirror.modules.technology_intelligence.recommendations import RecommendationEngine
from ghostmirror.modules.technology_intelligence.scanner import TechnologyIntelligenceScanner


@pytest.fixture()
def mock_kb(tmp_path: Path) -> KnowledgeBase:
    """Creates a temporary knowledge base with specific test data."""
    kb_dir = tmp_path / "knowledge"
    kb_dir.mkdir()
    
    servers_data = {
        "Apache": {
            "category": "WEB SERVER",
            "risk_level": "MEDIUM",
            "attack_surface": ["web_server"],
            "recommended_scans": ["nuclei_apache", "ssl_scan"],
            "common_exposures": ["directory_listing"]
        }
    }
    cms_data = {
        "WordPress": {
            "category": "CMS",
            "risk_level": "MEDIUM",
            "attack_surface": ["cms", "admin_panel"],
            "recommended_scans": ["wordpress_security_profile", "plugin_enumeration"],
            "common_exposures": ["xmlrpc_enabled"]
        }
    }
    databases_data = {
        "Redis": {
            "category": "DATABASE",
            "risk_level": "HIGH",
            "attack_surface": ["database_service"],
            "recommended_scans": ["redis_exposure_check"],
            "common_exposures": ["no_auth_exposure"]
        }
    }
    
    (kb_dir / "servers.json").write_text(json.dumps(servers_data), encoding="utf-8")
    (kb_dir / "cms.json").write_text(json.dumps(cms_data), encoding="utf-8")
    (kb_dir / "databases.json").write_text(json.dumps(databases_data), encoding="utf-8")
    
    return KnowledgeBase(knowledge_dir=kb_dir)


# --------------------------------------------------------------------------- #
# Knowledge Base Tests
# --------------------------------------------------------------------------- #
def test_knowledge_base_loading(mock_kb: KnowledgeBase) -> None:
    assert len(mock_kb.definitions) == 3
    assert "apache" in mock_kb.definitions
    assert "wordpress" in mock_kb.definitions
    assert "redis" in mock_kb.definitions

    risk = mock_kb.get_technology_risk("WordPress")
    assert risk is not None
    assert risk.technology == "WordPress"
    assert risk.category == "CMS"
    assert risk.risk_level == "MEDIUM"
    assert "xmlrpc_enabled" in risk.common_exposures

    non_existent = mock_kb.get_technology_risk("InvalidTech")
    assert non_existent is None


# --------------------------------------------------------------------------- #
# Profiler Engine Tests
# --------------------------------------------------------------------------- #
def test_profiler_engine_risk_score() -> None:
    techs = [
        TechnologyModel(name="WordPress", category="CMS", confidence=1.0, source="test"),
        TechnologyModel(name="WooCommerce", category="CMS", confidence=1.0, source="test"),
        TechnologyModel(name="Redis", category="DATABASE", confidence=1.0, source="test"),
        TechnologyModel(name="Cloudflare", category="WAF", confidence=1.0, source="test"),
    ]
    
    # 15 (WordPress) + 20 (WooCommerce) + 30 (Redis) - 10 (Cloudflare) - 5 (TLS 1.3) = 50
    risk = TechnologyProfilerEngine.calculate_risk("example.com", techs, ["TLS 1.3", "TLS 1.2"])
    assert risk.risk_score == 50
    assert risk.risk_level == "HIGH"
    
    # 15 (WordPress) + 20 (WooCommerce) + 30 (Redis) - 10 (Cloudflare) + 15 (obsolete TLS) = 70 (capped or verified)
    risk_obsolete = TechnologyProfilerEngine.calculate_risk("example.com", techs, ["TLS 1.0"])
    assert risk_obsolete.risk_score == 70
    assert risk_obsolete.risk_level == "HIGH"


def test_profiler_engine_attack_surface() -> None:
    techs = [
        TechnologyModel(name="WordPress", category="CMS", confidence=1.0, source="test"),
        TechnologyModel(name="Redis", category="DATABASE", confidence=1.0, source="test"),
        TechnologyModel(name="Nginx", category="WEB SERVER", confidence=1.0, source="test"),
        TechnologyModel(name="Stripe", category="PAYMENTS", confidence=1.0, source="test"),
    ]
    
    surface = TechnologyProfilerEngine.analyze_attack_surface("example.com", techs, 45)
    assert surface.target == "example.com"
    assert "Nginx" in surface.web_servers
    assert "WordPress" in surface.cms
    assert "Redis" in surface.databases
    assert "Stripe" in surface.external_services
    assert "WordPress Admin Panel (/wp-admin/)" in surface.potential_entry_points
    assert "Exposed Database Service (Redis)" in surface.potential_entry_points
    assert "Database Service (Redis)" in surface.high_value_assets
    assert "Content Management System (WordPress)" in surface.high_value_assets
    assert "Payment Provider Integration (Stripe)" in surface.high_value_assets
    assert surface.risk_score == 45


# --------------------------------------------------------------------------- #
# Recommendation Engine Tests
# --------------------------------------------------------------------------- #
def test_recommendation_engine(mock_kb: KnowledgeBase) -> None:
    techs = [
        TechnologyModel(name="WordPress", category="CMS", confidence=1.0, source="test"),
        TechnologyModel(name="Redis", category="DATABASE", confidence=1.0, source="test"),
    ]
    
    scans, templates = RecommendationEngine.generate_recommendations(techs, mock_kb)
    assert "wordpress_security_profile" in scans
    assert "redis_exposure_check" in scans
    assert "wordpress" in templates
    assert "redis" in templates


# --------------------------------------------------------------------------- #
# Intelligence Orchestration Engine Tests
# --------------------------------------------------------------------------- #
def test_orchestration_engine_analyze(tmp_path: Path, mock_kb: KnowledgeBase) -> None:
    project_dir = tmp_path / "test-project"
    profiles_dir = project_dir / "profiles"
    profiles_dir.mkdir(parents=True)
    findings_dir = project_dir / "findings"
    findings_dir.mkdir(parents=True)

    techs = [
        TechnologyModel(name="WordPress", category="CMS", confidence=1.0, source="test"),
        TechnologyModel(name="Redis", category="DATABASE", confidence=1.0, source="test"),
    ]
    profile = FingerprintProfile(
        target="example.com",
        cms="WordPress",
        databases=["Redis"],
        technologies=techs
    )
    
    (profiles_dir / "technology_profile.json").write_text(
        json.dumps(profile.model_dump(mode="json")), encoding="utf-8"
    )

    # Pre-populate ssl.json to test TLS version loading
    ssl_data = {
        "scanner_name": "ssl",
        "target": "example.com",
        "started_at": "2026-06-17T00:00:00Z",
        "finished_at": "2026-06-17T00:01:00Z",
        "status": "completed",
        "findings": [],
        "statistics": {},
        "certificate_summary": {
            "issuer": "Let's Encrypt",
            "expires_in_days": 30,
            "expires_at": "2026-07-17",
            "tls_versions": ["TLS 1.3", "TLS 1.2"]
        }
    }
    (findings_dir / "ssl.json").write_text(json.dumps(ssl_data), encoding="utf-8")

    engine = TechnologyIntelligenceEngine(knowledge_dir=mock_kb.knowledge_dir)
    report = engine.analyze_project(project_dir)

    assert report["target"] == "example.com"
    # score calculation: 15 (WordPress) + 30 (Redis) - 5 (TLS 1.3) = 40
    assert report["risk_score"] == 40
    assert report["risk_level"] == "MEDIUM"
    assert "WordPress" in report["technologies"]
    assert "Redis" in report["technologies"]
    
    # Check that output files were created
    assert (profiles_dir / "attack_surface_profile.json").exists()
    assert (profiles_dir / "risk_profile.json").exists()
    assert (findings_dir / "technology_intelligence.json").exists()

    # Verify findings count and details
    findings = report["findings"]
    assert len(findings) > 0
    titles = [f["title"] for f in findings]
    assert "WordPress Attack Surface Identified" in titles
    assert "Redis Exposure Risk" in titles


# --------------------------------------------------------------------------- #
# Scanner Wrapper Tests
# --------------------------------------------------------------------------- #
@patch("ghostmirror.modules.base.scanner.ScopeManager.load_scope")
@patch("ghostmirror.modules.base.scanner.ScopeManager.is_ready_for_testing")
def test_scanner_run(
    mock_is_ready: MagicMock,
    mock_load_scope: MagicMock,
    tmp_path: Path,
    mock_kb: KnowledgeBase
) -> None:
    # Setup mocks for Scope
    mock_scope = MagicMock()
    mock_scope.targets.domains = ["example.com"]
    mock_load_scope.return_value = mock_scope
    mock_is_ready.return_value = True

    project_dir = tmp_path / "test-project"
    profiles_dir = project_dir / "profiles"
    profiles_dir.mkdir(parents=True)
    findings_dir = project_dir / "findings"
    findings_dir.mkdir(parents=True)
    (project_dir / "scope.yaml").write_text("{}", encoding="utf-8")

    techs = [
        TechnologyModel(name="WordPress", category="CMS", confidence=1.0, source="test"),
    ]
    profile = FingerprintProfile(
        target="example.com",
        cms="WordPress",
        technologies=techs
    )
    (profiles_dir / "technology_profile.json").write_text(
        json.dumps(profile.model_dump(mode="json")), encoding="utf-8"
    )

    scanner = TechnologyIntelligenceScanner(
        project_path=project_dir,
        target="example.com",
        knowledge_dir=mock_kb.knowledge_dir
    )
    
    result = scanner.run()
    assert result.status == "completed"
    assert len(result.findings) > 0
    assert (findings_dir / "technology_intelligence.json").exists()


# --------------------------------------------------------------------------- #
# CLI Command Tests
# --------------------------------------------------------------------------- #
@patch("ghostmirror.app.cli.bootstrap")
def test_cli_analyze_technologies(mock_bootstrap: MagicMock, tmp_path: Path, mock_kb: KnowledgeBase) -> None:
    runner = CliRunner()

    project_dir = tmp_path / "test-project"
    profiles_dir = project_dir / "profiles"
    profiles_dir.mkdir(parents=True)
    (project_dir / "scope.yaml").write_text("{}", encoding="utf-8")

    # Create dummy technology profile
    techs = [
        TechnologyModel(name="WordPress", category="CMS", confidence=1.0, source="test"),
        TechnologyModel(name="Redis", category="DATABASE", confidence=1.0, source="test"),
    ]
    profile = FingerprintProfile(
        target="example.com",
        cms="WordPress",
        technologies=techs
    )
    (profiles_dir / "technology_profile.json").write_text(
        json.dumps(profile.model_dump(mode="json")), encoding="utf-8"
    )

    # Mock Project Handle & Metadata
    mock_handle = MagicMock(spec=ProjectHandle)
    mock_handle.slug = "test-project"
    mock_handle.path = project_dir
    mock_metadata = ProjectModel(
        uuid="uuid-1234",
        client="test-client",
        name="test-project",
        status=ProjectStatus.ACTIVE,
        created_at=MagicMock(),
        ghostmirror_version="0.1.0"
    )
    mock_handle.metadata = mock_metadata

    # Mock app context
    mock_ctx = MagicMock()
    mock_ctx.projects.list_projects.return_value = [mock_handle]
    mock_ctx.projects.open_project.return_value = mock_handle
    mock_bootstrap.return_value = mock_ctx

    # Patch the KnowledgeBase constructor inside engine.py to point to mock_kb's path
    with patch("ghostmirror.modules.technology_intelligence.engine.KnowledgeBase", return_value=mock_kb):
        result = runner.invoke(app, ["analyze", "technologies", "-p", "test-project"])
        
    assert result.exit_code == 0
    assert "TECHNOLOGY INTELLIGENCE COMPLETE" in result.stdout
    assert "Target:" in result.stdout
    assert "example.com" in result.stdout
    assert "Risk Score:" in result.stdout
