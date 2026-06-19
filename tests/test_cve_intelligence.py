"""Unit tests for the CVE Intelligence Module, Risk Correlation, and CLI."""

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
from ghostmirror.modules.cve_intelligence.knowledge_base import CVEKnowledgeBase
from ghostmirror.modules.cve_intelligence.normalizer import TechnologyNormalizer
from ghostmirror.modules.cve_intelligence.matcher import (
    parse_version,
    compare_versions,
    check_constraint,
    check_rule,
    is_parseable_version,
    CVEVulnerabilityMatcher,
)
from ghostmirror.modules.cve_intelligence.scoring import VulnerabilityScoringEngine
from ghostmirror.modules.cve_intelligence.recommendations import CVERecommendationEngine
from ghostmirror.modules.cve_intelligence.scanner import CVEIntelligenceScanner
from ghostmirror.modules.cve_intelligence.engine import CVEIntelligenceEngine


@pytest.fixture()
def mock_cve_kb(tmp_path: Path) -> CVEKnowledgeBase:
    """Creates a temporary CVE Knowledge Base with specific test data."""
    kb_dir = tmp_path / "knowledge_cves"
    kb_dir.mkdir()

    cves_data = [
        {
            "cve_id": "CVE-2021-41773",
            "title": "Apache Path Traversal",
            "description": "Apache HTTP Server 2.4.49 traversal flaw.",
            "severity": "HIGH",
            "cvss_score": 7.5,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            "affected_product": "Apache",
            "affected_versions": ["== 2.4.49"],
            "fixed_versions": ["2.4.50"],
            "references": ["https://example.com/ref"],
            "published_at": "2021-10-05T00:00:00Z",
            "updated_at": "2021-12-08T00:00:00Z",
            "exploit_available": True,
            "kev_listed": True,
            "source": "local"
        },
        {
            "cve_id": "CVE-2022-0543",
            "title": "Redis Lua sandbox bypass",
            "description": "Lua escape vulnerability.",
            "severity": "CRITICAL",
            "cvss_score": 10.0,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            "affected_product": "Redis",
            "affected_versions": ["< 6.0.16"],
            "fixed_versions": ["6.0.16"],
            "references": [],
            "published_at": None,
            "updated_at": None,
            "exploit_available": True,
            "kev_listed": False,
            "source": "local"
        }
    ]

    aliases_data = {
        "apache httpd": "Apache",
        "httpd": "Apache",
        "redis-server": "Redis"
    }

    rules_data = {
        "default_operator": "==",
        "operators_supported": ["<", "<=", ">", ">=", "==", "range:"],
        "product_rules": {}
    }

    nuclei_data = {
        "cves": {
            "CVE-2021-41773": "http/cves/2021/CVE-2021-41773.yaml",
            "CVE-2022-0543": "network/redis/CVE-2022-0543.yaml"
        },
        "technologies": {
            "Apache": "http/technologies/apache/",
            "Redis": "network/redis/"
        },
        "exposures": {
            "configs": "http/exposures/configs/",
            "databases": "network/databases/"
        }
    }

    (kb_dir / "known_cves.json").write_text(json.dumps(cves_data), encoding="utf-8")
    (kb_dir / "technology_aliases.json").write_text(json.dumps(aliases_data), encoding="utf-8")
    (kb_dir / "version_rules.json").write_text(json.dumps(rules_data), encoding="utf-8")
    (kb_dir / "nuclei_template_map.json").write_text(json.dumps(nuclei_data), encoding="utf-8")

    return CVEKnowledgeBase(knowledge_dir=kb_dir)


# --------------------------------------------------------------------------- #
# Version Parser / Matcher Tests
# --------------------------------------------------------------------------- #
def test_version_parsing() -> None:
    assert parse_version("1.2.3") == [1, 2, 3]
    assert parse_version("8.5p1") == [8, 5, "p", 1]
    assert parse_version("") == []
    assert parse_version(None) == []


def test_compare_versions() -> None:
    assert compare_versions("1.2.3", "1.2.4") == -1
    assert compare_versions("1.2.4", "1.2.3") == 1
    assert compare_versions("1.2.3", "1.2.3") == 0
    assert compare_versions("8.5p1", "9.8p1") == -1
    assert compare_versions("1.2", "1.2.0") == 0
    assert compare_versions("1.2.3", "1.2") == 1
    assert compare_versions("1.2", "1.2.3") == -1


def test_check_rule_operators() -> None:
    assert check_rule("1.2.3", "== 1.2.3") is True
    assert check_rule("1.2.3", "< 1.2.4") is True
    assert check_rule("1.2.3", "<= 1.2.3") is True
    assert check_rule("1.2.3", "> 1.2.2") is True
    assert check_rule("1.2.3", ">= 1.2.3") is True
    assert check_rule("1.2.3", "1.2.3") is True  # Implicit ==
    assert check_rule("1.5.0", "range: >=1.0.0,<2.0.0") is True
    assert check_rule("2.0.0", "range: >=1.0.0,<2.0.0") is False


def test_is_parseable_version() -> None:
    assert is_parseable_version("1.2.3") is True
    assert is_parseable_version("abc") is False
    assert is_parseable_version("") is False
    assert is_parseable_version(None) is False


# --------------------------------------------------------------------------- #
# Alias Normalizer Tests
# --------------------------------------------------------------------------- #
def test_normalizer(mock_cve_kb: CVEKnowledgeBase) -> None:
    normalizer = TechnologyNormalizer(mock_cve_kb.aliases_path)
    assert normalizer.normalize("apache httpd") == "Apache"
    assert normalizer.normalize("HTTPD") == "Apache"
    assert normalizer.normalize("UnknownTech") == "UnknownTech"


# --------------------------------------------------------------------------- #
# CVE Matcher Tests
# --------------------------------------------------------------------------- #
def test_cve_matcher_confirmed(mock_cve_kb: CVEKnowledgeBase) -> None:
    matcher = CVEVulnerabilityMatcher(mock_cve_kb)

    # Confirmed Vulnerable
    matches = matcher.match_technology("example.com", "Apache", "2.4.49")
    assert len(matches) == 1
    assert matches[0].match_confidence == "CONFIRMED"
    assert matches[0].matched_cve.cve_id == "CVE-2021-41773"

    # Confirmed Range Match
    matches_redis = matcher.match_technology("example.com", "Redis", "5.0.0")
    assert len(matches_redis) == 1
    assert matches_redis[0].match_confidence == "CONFIRMED"
    assert matches_redis[0].matched_cve.cve_id == "CVE-2022-0543"


def test_cve_matcher_potential(mock_cve_kb: CVEKnowledgeBase) -> None:
    matcher = CVEVulnerabilityMatcher(mock_cve_kb)

    # Missing Version -> Potential Exposure
    matches = matcher.match_technology("example.com", "Apache", None)
    assert len(matches) == 1
    assert matches[0].match_confidence == "POTENTIAL"


def test_cve_matcher_unknown(mock_cve_kb: CVEKnowledgeBase) -> None:
    matcher = CVEVulnerabilityMatcher(mock_cve_kb)

    # Non-parseable Version -> Unknown
    matches = matcher.match_technology("example.com", "Apache", "abc")
    assert len(matches) == 1
    assert matches[0].match_confidence == "UNKNOWN"


def test_cve_matcher_fixed(mock_cve_kb: CVEKnowledgeBase) -> None:
    matcher = CVEVulnerabilityMatcher(mock_cve_kb)

    # Fixed version -> Should skip finding
    matches = matcher.match_technology("example.com", "Apache", "2.4.50")
    assert len(matches) == 0


# --------------------------------------------------------------------------- #
# Scoring Engine Tests
# --------------------------------------------------------------------------- #
def test_scoring_engine() -> None:
    from ghostmirror.models.cve import CVEModel
    from ghostmirror.models.cve_match import CVEMatchModel

    cve = CVEModel(
        cve_id="CVE-TEST-1",
        title="Test Title",
        description="Test description",
        severity="HIGH",
        cvss_score=8.5,
        cvss_vector=None,
        affected_product="Apache",
        affected_versions=[],
        fixed_versions=[],
        references=[],
        exploit_available=True,
        kev_listed=True
    )
    match = CVEMatchModel(
        target="example.com",
        technology="Apache",
        detected_version="2.4.49",
        matched_cve=cve,
        match_confidence="CONFIRMED",
        match_reason="Matches",
        risk_level="HIGH",
        priority="HIGH",
        recommended_action="Update",
        recommended_scans=[]
    )

    techs = [
        TechnologyModel(name="Apache", category="WEB SERVER", confidence=1.0, source="test"),
        TechnologyModel(name="Redis", category="DATABASE", confidence=1.0, source="test")
    ]

    # Calculation:
    # Match Severity HIGH: +20
    # Exploit Available: +15
    # KEV Listed: +20
    # Internet-facing: +10
    # Database exposed: +15
    # Total: 20 + 15 + 20 + 10 + 15 = 80
    score, level = VulnerabilityScoringEngine.calculate_risk(
        [match], techs, ["TLS 1.2", "TLS 1.3"]
    )
    # Check that strong TLS subtraction is applied: 80 - 5 = 75
    assert score == 75
    assert level == "CRITICAL"


# --------------------------------------------------------------------------- #
# Recommendations Engine Tests
# --------------------------------------------------------------------------- #
def test_recommendation_engine(mock_cve_kb: CVEKnowledgeBase) -> None:
    from ghostmirror.models.cve import CVEModel
    from ghostmirror.models.cve_match import CVEMatchModel

    cve = CVEModel(
        cve_id="CVE-2021-41773",
        title="Test",
        description="Test",
        severity="HIGH",
        cvss_score=7.5,
        affected_product="Apache",
    )
    match = CVEMatchModel(
        target="example.com",
        technology="Apache",
        matched_cve=cve,
        match_confidence="CONFIRMED",
        match_reason="Matched",
        risk_level="HIGH",
        priority="HIGH",
        recommended_action="Upgrade",
    )

    techs = [TechnologyModel(name="Apache", category="WEB SERVER", confidence=1.0, source="test")]
    recs = CVERecommendationEngine.generate_recommendations([match], techs)
    assert any("Apache" in r for r in recs)

    templates = CVERecommendationEngine.map_nuclei_templates([match], techs, mock_cve_kb.nuclei_map)
    assert "http/cves/2021/CVE-2021-41773.yaml" in templates
    assert "http/technologies/apache/" in templates


# --------------------------------------------------------------------------- #
# Engine and Scanner Tests
# --------------------------------------------------------------------------- #
def test_orchestration_and_scanner(tmp_path: Path, mock_cve_kb: CVEKnowledgeBase) -> None:
    project_dir = tmp_path / "test-project"
    profiles_dir = project_dir / "profiles"
    profiles_dir.mkdir(parents=True)
    findings_dir = project_dir / "findings"
    findings_dir.mkdir(parents=True)

    # Create technology_profile.json
    techs = [
        TechnologyModel(name="Apache", category="WEB SERVER", version="2.4.49", confidence=1.0, source="test")
    ]
    profile = FingerprintProfile(
        target="example.com",
        technologies=techs
    )
    (profiles_dir / "technology_profile.json").write_text(json.dumps(profile.model_dump(mode="json")), encoding="utf-8")

    # Create scope file
    (project_dir / "scope.yaml").write_text(
        json.dumps({
            "project": {"client": "test", "name": "test"},
            "allowed_tests": {"port_scan": True, "ssl_scan": True},
            "targets": {"domains": ["example.com"], "ips": []}
        }),
        encoding="utf-8"
    )

    # Run engine directly
    engine = CVEIntelligenceEngine(knowledge_dir=mock_cve_kb.knowledge_dir)
    report = engine.analyze_project(project_dir)

    assert report["target"] == "example.com"
    assert report["total_cves"] == 1
    assert report["high_count"] == 1

    # Run scanner wrapper
    scanner = CVEIntelligenceScanner(
        project_path=project_dir,
        target="example.com",
        knowledge_dir=mock_cve_kb.knowledge_dir
    )
    result = scanner.run()
    assert result.status == "completed"
    assert len(result.findings) == 1


# --------------------------------------------------------------------------- #
# CLI Command Tests
# --------------------------------------------------------------------------- #
def test_cli_analyze_cves(tmp_path: Path, mock_cve_kb: CVEKnowledgeBase) -> None:
    project_dir = tmp_path / "my-project"
    profiles_dir = project_dir / "profiles"
    profiles_dir.mkdir(parents=True)
    findings_dir = project_dir / "findings"
    findings_dir.mkdir(parents=True)

    # Write profile and scope
    techs = [
        TechnologyModel(name="Apache", category="WEB SERVER", version="2.4.49", confidence=1.0, source="test")
    ]
    profile = FingerprintProfile(
        target="example.com",
        technologies=techs
    )
    (profiles_dir / "technology_profile.json").write_text(json.dumps(profile.model_dump(mode="json")), encoding="utf-8")

    (project_dir / "scope.yaml").write_text(
        json.dumps({
            "project": {"client": "test", "name": "test"},
            "allowed_tests": {"port_scan": True, "ssl_scan": True},
            "targets": {"domains": ["example.com"], "ips": []}
        }),
        encoding="utf-8"
    )

    runner = CliRunner()

    # Stub ProjectManager and ProjectHandle
    from ghostmirror.core.config_manager import ConfigManager
    from ghostmirror.core.project_manager import ProjectManager

    meta = ProjectModel(client="test", name="test")
    handle = ProjectHandle(slug="my-project", path=project_dir, metadata=meta)

    with patch("ghostmirror.app.cli.bootstrap") as mock_bootstrap:
        mock_ctx = MagicMock()
        mock_ctx.projects.list_projects.return_value = [handle]
        mock_ctx.projects.open_project.return_value = handle
        mock_bootstrap.return_value = mock_ctx

        # Patch knowledge path in engine initialization to mock_cve_kb.knowledge_dir
        with patch("ghostmirror.modules.cve_intelligence.engine.CVEKnowledgeBase", return_value=mock_cve_kb):
            result = runner.invoke(app, ["analyze", "cves", "-p", "my-project"])

            assert result.exit_code == 0
            assert "CVE INTELLIGENCE COMPLETE" in result.stdout
            assert "Target:\nexample.com" in result.stdout
            assert "CVE Matches:\n1" in result.stdout


# --------------------------------------------------------------------------- #
# Extra Coverage Tests
# --------------------------------------------------------------------------- #
def test_normalizer_fallback() -> None:
    # Use non-existent path to trigger fallback mapping
    normalizer = TechnologyNormalizer(Path("/nonexistent/aliases.json"))
    assert normalizer.normalize("apache httpd") == "Apache"
    assert normalizer.normalize("httpd") == "Apache"
    assert normalizer.normalize("nginx") == "Nginx"


def test_kb_nonexistent(tmp_path: Path) -> None:
    # Directory empty or nonexistent
    kb = CVEKnowledgeBase(knowledge_dir=tmp_path / "nonexistent")
    assert len(kb.cves) == 0
    assert kb.version_rules == {}
    assert kb.nuclei_map == {}


def test_matcher_exceptions(mock_cve_kb: CVEKnowledgeBase) -> None:
    matcher = CVEVulnerabilityMatcher(mock_cve_kb)
    # Patch check_rule to raise an exception inside match_technology
    with patch("ghostmirror.modules.cve_intelligence.matcher.check_rule", side_effect=Exception("Test Exception")):
        matches = matcher.match_technology("example.com", "Apache", "2.4.49")
        # Match should still be processed, check exceptions are caught gracefully
        assert len(matches) == 0


def test_scoring_variations() -> None:
    # Test scoring logic with different combinations
    # 1. No matches, WAF/CDN present, strong TLS
    techs_waf = [
        TechnologyModel(name="Cloudflare", category="WAF", confidence=1.0, source="test")
    ]
    # score: 0 + 10 (internet) - 10 (WAF) - 5 (strong TLS) = -5 -> bounded to 0
    score, level = VulnerabilityScoringEngine.calculate_risk([], techs_waf, ["TLS 1.3"])
    assert score == 0
    assert level == "LOW"

    # 2. No matches, Database exposed, weak TLS
    techs_db = [
        TechnologyModel(name="MySQL", category="DATABASE", confidence=1.0, source="test")
    ]
    # score: 0 + 10 (internet) + 15 (DB) = 25
    score, level = VulnerabilityScoringEngine.calculate_risk([], techs_db, ["TLS 1.0"])
    assert score == 25
    assert level == "MEDIUM"


def test_scanner_scope_and_errors(tmp_path: Path, mock_cve_kb: CVEKnowledgeBase) -> None:
    project_dir = tmp_path / "scope-project"
    project_dir.mkdir()

    # Missing scope file -> FileNotFoundError
    scanner = CVEIntelligenceScanner(
        project_path=project_dir,
        target="example.com",
        knowledge_dir=mock_cve_kb.knowledge_dir
    )
    with pytest.raises(FileNotFoundError):
        scanner.run()

    # Scope file exists, but target is out of scope -> OutOfScopeError
    (project_dir / "scope.yaml").write_text(
        json.dumps({
            "project": {"client": "test", "name": "test"},
            "allowed_tests": {"port_scan": True, "ssl_scan": True},
            "targets": {"domains": ["different.com"], "ips": []}
        }),
        encoding="utf-8"
    )
    from ghostmirror.modules.base.scanner import OutOfScopeError
    with pytest.raises(OutOfScopeError):
        scanner.run()


def test_scanner_engine_failures(tmp_path: Path, mock_cve_kb: CVEKnowledgeBase) -> None:
    project_dir = tmp_path / "fail-project"
    project_dir.mkdir()
    (project_dir / "scope.yaml").write_text(
        json.dumps({
            "project": {"client": "test", "name": "test"},
            "allowed_tests": {"port_scan": True, "ssl_scan": True},
            "targets": {"domains": ["example.com"], "ips": []}
        }),
        encoding="utf-8"
    )

    # Trigger SKIPPED in engine due to missing technology_profile.json
    scanner = CVEIntelligenceScanner(
        project_path=project_dir,
        target="example.com",
        knowledge_dir=mock_cve_kb.knowledge_dir
    )
    result = scanner.run()
    assert result.status == "completed"
    assert len(result.findings) == 0

    # Trigger generic exception
    from ghostmirror.modules.base.scanner import ScannerError
    with patch("ghostmirror.modules.cve_intelligence.engine.CVEIntelligenceEngine.analyze_project", side_effect=ValueError("Unexpected database error")):
        with pytest.raises(ScannerError) as exc_info:
            scanner.run()
        assert "Unexpected database error" in str(exc_info.value)


def test_engine_ssl_warnings_and_waf(tmp_path: Path, mock_cve_kb: CVEKnowledgeBase) -> None:
    project_dir = tmp_path / "extra-project"
    profiles_dir = project_dir / "profiles"
    profiles_dir.mkdir(parents=True)
    findings_dir = project_dir / "findings"
    findings_dir.mkdir(parents=True)

    techs = [
        TechnologyModel(name="Cloudflare", category="WAF", confidence=1.0, source="test"),
        TechnologyModel(name="Apache", category="WEB SERVER", version="2.4.49", confidence=1.0, source="test")
    ]
    profile = FingerprintProfile(
        target="example.com",
        technologies=techs
    )
    (profiles_dir / "technology_profile.json").write_text(json.dumps(profile.model_dump(mode="json")), encoding="utf-8")

    # Invalid ssl.json contents to trigger warning catch
    (findings_dir / "ssl.json").write_text("invalid json data", encoding="utf-8")

    engine = CVEIntelligenceEngine(knowledge_dir=mock_cve_kb.knowledge_dir)
    report = engine.analyze_project(project_dir)
    assert report["target"] == "example.com"

