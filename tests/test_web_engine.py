from __future__ import annotations

import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from ghostmirror.models.web_endpoint import WebEndpoint, WebForm
from ghostmirror.models.web_indicator import IndicatorType, WebIndicator
from ghostmirror.models.finding_confidence import ConfidenceLevel
from ghostmirror.models.parameter_profile import ParameterProfile, ParameterType
from ghostmirror.models.web_intelligence_report import WebIntelligenceReport, BusinessLogicArea, CorrelationResult, OpportunityScore
from ghostmirror.models.web_attack_surface import WebAttackSurface, IndicatorSummary
from ghostmirror.modules.web_intelligence.engine import WebIntelligenceEngine


class TestWebIntelligenceReport:
    def test_empty_report_defaults(self):
        report = WebIntelligenceReport()
        assert report.target == ""
        assert report.endpoints == []
        assert report.indicators == []
        assert report.overall_score == 0
        assert report.risk_level == "INFO"

    def test_report_with_data(self):
        report = WebIntelligenceReport(
            target="https://example.com",
            endpoints=[WebEndpoint(url="https://example.com/login")],
            indicators=[WebIndicator(
                indicator_type=IndicatorType.XSS,
                title="XSS Test",
                description="",
            )],
            total_endpoints=1,
            total_indicators=1,
            overall_score=50,
            risk_level="MEDIUM",
        )
        assert report.target == "https://example.com"
        assert len(report.endpoints) == 1
        assert len(report.indicators) == 1
        assert report.overall_score == 50


class TestWebAttackSurface:
    def test_defaults(self):
        surface = WebAttackSurface()
        assert surface.total_endpoints == 0
        assert surface.overall_exposure == "LOW"
        assert surface.indicator_summary.sql_injection == 0

    def test_with_data(self):
        summary = IndicatorSummary(sql_injection=3, xss=2)
        surface = WebAttackSurface(
            total_endpoints=10,
            auth_endpoints=3,
            api_endpoints=2,
            param_count=15,
            sensitive_params=5,
            indicator_summary=summary,
            overall_exposure="HIGH",
        )
        assert surface.total_endpoints == 10
        assert surface.indicator_summary.sql_injection == 3
        assert surface.indicator_summary.xss == 2
        assert surface.overall_exposure == "HIGH"


class TestCorrelationResult:
    def test_defaults(self):
        cr = CorrelationResult(title="Test", correlation_type="xss")
        assert cr.score == 0
        assert cr.classification == "LOW"


class TestOpportunityScore:
    def test_defaults(self):
        opp = OpportunityScore(title="Test", score=75, classification="HIGH")
        assert opp.score == 75
        assert opp.classification == "HIGH"


class TestBusinessLogicArea:
    def test_defaults(self):
        area = BusinessLogicArea(area="checkout")
        assert area.risk == "info"
        assert area.endpoints == []


class TestIndicatorTypes:
    def test_enum_values(self):
        assert IndicatorType.SQL_INJECTION.value == "sql_injection"
        assert IndicatorType.XSS.value == "xss"
        assert IndicatorType.SSRF.value == "ssrf"
        assert IndicatorType.IDOR.value == "idor"
        assert IndicatorType.OPEN_REDIRECT.value == "open_redirect"
        assert IndicatorType.PATH_TRAVERSAL.value == "path_traversal"

    def test_confidence_levels(self):
        assert ConfidenceLevel.LOW.value.upper() == "LOW"
        assert ConfidenceLevel.MEDIUM.value.upper() == "MEDIUM"
        assert ConfidenceLevel.HIGH.value.upper() == "HIGH"


class TestWebIndicator:
    def test_defaults(self):
        ind = WebIndicator(indicator_type=IndicatorType.XSS, title="Test", description="Desc")
        assert ind.confidence == ConfidenceLevel.LOW
        assert ind.endpoint == ""
        assert ind.parameter == ""

    def test_with_data(self):
        ind = WebIndicator(
            indicator_type=IndicatorType.SQL_INJECTION,
            title="SQLi Found",
            description="SQL error in response",
            endpoint="https://example.com/page?id=1",
            parameter="id",
            confidence=ConfidenceLevel.HIGH,
            evidence="SQL syntax error",
        )
        assert ind.title == "SQLi Found"
        assert ind.confidence == ConfidenceLevel.HIGH
        assert ind.evidence == "SQL syntax error"


class TestParameterProfile:
    def test_defaults(self):
        pp = ParameterProfile(name="test")
        assert pp.param_type == ParameterType.QUERY
        assert pp.sensitivity.name == "NONE"
        assert pp.locations == []

    def test_with_sensitivity(self):
        pp = ParameterProfile(name="id", sensitivity="high")
        assert pp.sensitivity == "high"

    def test_classify_sensitivity(self):
        assert ParameterProfile.classify_sensitivity("token").value == "critical"
        assert ParameterProfile.classify_sensitivity("unknown").value == "none"


class TestWebEndpoint:
    def test_defaults(self):
        ep = WebEndpoint(url="https://example.com/")
        assert ep.method.value == "GET"
        assert ep.params == []
        assert ep.forms == []
        assert ep.is_api is False

    def test_with_forms(self):
        form = WebForm(action="/login", method="POST", inputs=["user", "pass"])
        ep = WebEndpoint(url="https://example.com/login", forms=[form], is_auth=True)
        assert len(ep.forms) == 1
        assert ep.forms[0].inputs == ["user", "pass"]
        assert ep.is_auth is True


class TestWebForm:
    def test_creation(self):
        form = WebForm(action="/submit", method="POST", inputs=["name", "email"])
        assert form.action == "/submit"
        assert form.method == "POST"
        assert len(form.inputs) == 2


class TestSerialization:
    def test_report_serialization(self):
        report = WebIntelligenceReport(
            target="https://example.com",
            endpoints=[WebEndpoint(url="https://example.com/login")],
            indicators=[WebIndicator(
                indicator_type=IndicatorType.XSS,
                title="XSS",
                description="Reflected XSS",
            )],
            opportunities=[OpportunityScore(title="XSS Opportunity", score=60, classification="HIGH")],
            business_areas=[BusinessLogicArea(area="checkout")],
            auth_profile={"has_login": True},
            js_findings={"scripts_analyzed": 4},
            overall_score=60,
            risk_level="HIGH",
        )
        data = report.model_dump(mode="json")
        assert data["target"] == "https://example.com"
        assert data["overall_score"] == 60
        assert len(data["endpoints"]) == 1
        assert len(data["indicators"]) == 1
        assert len(data["opportunities"]) == 1

    def test_attack_surface_serialization(self):
        as_ = WebAttackSurface(
            total_endpoints=5,
            auth_endpoints=2,
            indicator_summary=IndicatorSummary(xss=1, ssrf=1),
            overall_exposure="MEDIUM",
        )
        data = as_.model_dump(mode="json")
        assert data["total_endpoints"] == 5
        assert data["indicator_summary"]["xss"] == 1
        assert data["overall_exposure"] == "MEDIUM"


class TestWebIntelligenceEngine:
    def test_empty_report(self):
        engine = WebIntelligenceEngine()
        report = engine._empty_report()
        assert report.target == ""
        assert report.overall_score == 0
        assert report.risk_level == "INFO"

    def test_load_json_missing(self):
        engine = WebIntelligenceEngine()
        result = engine._load_json(Path("nonexistent.json"))
        assert result is None

    def test_load_json_invalid(self, tmp_path: Path):
        engine = WebIntelligenceEngine()
        bad = tmp_path / "bad.json"
        bad.write_text("not json")
        result = engine._load_json(bad)
        assert result is None

    def test_load_json_valid(self, tmp_path: Path):
        engine = WebIntelligenceEngine()
        good = tmp_path / "good.json"
        good.write_text('{"key": "value"}')
        result = engine._load_json(good)
        assert result == {"key": "value"}

    def test_save_json(self, tmp_path: Path):
        engine = WebIntelligenceEngine()
        out = tmp_path / "out.json"
        engine._save_json(out, {"a": 1})
        data = json.loads(out.read_text(encoding="utf-8"))
        assert data == {"a": 1}

    def test_save_json_error(self, tmp_path: Path):
        engine = WebIntelligenceEngine()
        out = tmp_path / "nested" / "out.json"
        engine._save_json(out, {"a": 1})
        assert not out.exists()

    def test_extract_headers_none(self):
        engine = WebIntelligenceEngine()
        assert engine._extract_headers(None) == {}

    def test_extract_headers_empty(self):
        engine = WebIntelligenceEngine()
        assert engine._extract_headers({}) == {}

    def test_extract_headers_no_findings(self):
        engine = WebIntelligenceEngine()
        assert engine._extract_headers({"other": 1}) == {}

    def test_extract_headers_with_data(self):
        engine = WebIntelligenceEngine()
        hf = {"findings": [{"title": "Server", "evidence": "nginx"}, {"title": "X-Powered-By", "evidence": "Express"}]}
        result = engine._extract_headers(hf)
        assert result["Server"] == "nginx"
        assert result["X-Powered-By"] == "Express"

    def test_extract_headers_malformed_skipped(self):
        engine = WebIntelligenceEngine()
        hf = {"findings": [{"title": "Server", "evidence": "nginx"}, {"bad": True}]}
        result = engine._extract_headers(hf)
        assert result["Server"] == "nginx"

    def test_build_attack_surface_no_endpoints(self):
        engine = WebIntelligenceEngine()
        surface = engine._build_attack_surface([], [], [], {}, {})
        assert surface.total_endpoints == 0
        assert surface.overall_exposure == "LOW"

    def test_build_attack_surface_critical(self):
        engine = WebIntelligenceEngine()
        inds = [WebIndicator(indicator_type=IndicatorType.XSS, title=f"XSS{i}", description="", confidence=ConfidenceLevel.HIGH) for i in range(10)]
        surface = engine._build_attack_surface(
            [WebEndpoint(url="https://x.com/a")], [], inds, {}, {},
        )
        assert surface.overall_exposure == "CRITICAL"

    def test_build_attack_surface_high(self):
        engine = WebIntelligenceEngine()
        inds = [WebIndicator(indicator_type=IndicatorType.XSS, title=f"XSS{i}", description="", confidence=ConfidenceLevel.HIGH) for i in range(5)]
        surface = engine._build_attack_surface(
            [WebEndpoint(url="https://x.com/a")], [], inds, {}, {},
        )
        assert surface.overall_exposure == "HIGH"

    def test_build_attack_surface_medium(self):
        engine = WebIntelligenceEngine()
        inds = [WebIndicator(indicator_type=IndicatorType.XSS, title=f"XSS{i}", description="") for i in range(2)]
        surface = engine._build_attack_surface(
            [WebEndpoint(url="https://x.com/a")], [], inds, {}, {},
        )
        assert surface.overall_exposure == "MEDIUM"

    def test_build_attack_surface_low_with_endpoints(self):
        engine = WebIntelligenceEngine()
        inds = [WebIndicator(indicator_type=IndicatorType.XSS, title="XSS", description="")]
        surface = engine._build_attack_surface(
            [WebEndpoint(url="https://x.com/a")], [], inds, {}, {},
        )
        assert surface.overall_exposure == "LOW"

    def test_save_artifacts(self, tmp_path: Path):
        engine = WebIntelligenceEngine()
        report = WebIntelligenceReport(
            target="https://x.com",
            endpoints=[WebEndpoint(url="https://x.com/a")],
            parameters=[ParameterProfile(name="id")],
            js_findings={"scripts_analyzed": 2},
            auth_profile={"has_login": True},
            correlations=[CorrelationResult(title="Test", correlation_type="xss")],
            opportunities=[OpportunityScore(title="Opp", score=50, classification="MEDIUM")],
            business_areas=[BusinessLogicArea(area="checkout")],
        )
        engine._save_artifacts(tmp_path, report, [{"priority": "HIGH", "text": "Fix it"}], [], WebAttackSurface())
        assert (tmp_path / "endpoint_inventory.json").exists()
        assert (tmp_path / "parameter_inventory.json").exists()
        assert (tmp_path / "js_intelligence.json").exists()
        assert (tmp_path / "auth_profile.json").exists()
        assert (tmp_path / "web_indicators.json").exists()
        assert (tmp_path / "correlation_results.json").exists()
        assert (tmp_path / "opportunity_scores.json").exists()
        assert (tmp_path / "web_recommendations.json").exists()
        assert (tmp_path / "attack_surface.json").exists()
        assert (tmp_path / "web_intelligence_report.json").exists()

    def test_save_findings(self, tmp_path: Path):
        from ghostmirror.modules.models.finding import FindingModel, FindingSeverity

        engine = WebIntelligenceEngine()
        findings = [
            FindingModel(
                title="[Web] XSS Found",
                description="Reflected XSS",
                severity=FindingSeverity.HIGH,
                target="https://x.com",
                evidence="<script>alert(1)</script>",
                recommendation="Sanitize output",
                source="web_intelligence",
            )
        ]
        engine._save_findings(tmp_path, findings)
        f = tmp_path / "findings" / "web_intelligence.json"
        assert f.exists()
        data = json.loads(f.read_text(encoding="utf-8"))
        assert data[0]["title"] == "[Web] XSS Found"

    def test_save_findings_empty(self, tmp_path: Path):
        engine = WebIntelligenceEngine()
        engine._save_findings(tmp_path, [])
        assert not (tmp_path / "findings" / "web_intelligence.json").exists()

    @patch("ghostmirror.modules.web_intelligence.endpoint_mapper.EndpointMapper.discover")
    @patch("ghostmirror.modules.web_intelligence.parameter_discovery.ParameterDiscovery.discover")
    def test_analyze_project(
        self, mock_param_discover, mock_endpoint_discover, tmp_path: Path,
    ):
        mock_endpoint_discover.return_value = [WebEndpoint(url="https://x.com/")]
        mock_param_discover.return_value = [ParameterProfile(name="id")]

        profile_dir = tmp_path / "profiles"
        profile_dir.mkdir()
        (profile_dir / "technology_profile.json").write_text('{"target": "https://x.com"}')

        engine = WebIntelligenceEngine()
        report = engine.analyze_project(tmp_path)
        assert report.target == "https://x.com"
        assert len(report.endpoints) == 1
        assert len(report.parameters) == 1
        assert (tmp_path / "profiles" / "web_intelligence").exists()

    def test_analyze_project_no_target(self, tmp_path: Path):
        profile_dir = tmp_path / "profiles"
        profile_dir.mkdir()
        (profile_dir / "technology_profile.json").write_text("{}")

        engine = WebIntelligenceEngine()
        report = engine.analyze_project(tmp_path)
        assert report.target == ""
        assert report.overall_score == 0
        assert report.risk_level == "INFO"
