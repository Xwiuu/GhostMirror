from __future__ import annotations

import pytest

from ghostmirror.modules.web_intelligence.injection_indicators import InjectionIndicators
from ghostmirror.modules.web_intelligence.xss_indicators import XSSIndicators
from ghostmirror.modules.web_intelligence.ssti_indicators import SSTIIndicators
from ghostmirror.modules.web_intelligence.ssrf_indicators import SSRFIndicators
from ghostmirror.modules.web_intelligence.idor_indicators import IDORIndicators
from ghostmirror.modules.web_intelligence.redirect_indicators import RedirectIndicators
from ghostmirror.modules.web_intelligence.traversal_indicators import TraversalIndicators
from ghostmirror.modules.web_intelligence.business_logic_indicators import BusinessLogicIndicators
from ghostmirror.modules.web_intelligence.scoring import WebScoringEngine
from ghostmirror.modules.web_intelligence.recommendations import WebRecommendationEngine
from ghostmirror.modules.web_intelligence.findings_mapper import WebFindingsMapper
from ghostmirror.models.web_indicator import IndicatorType, WebIndicator, SeverityLevel
from ghostmirror.models.finding_confidence import ConfidenceLevel
from ghostmirror.models.web_endpoint import WebEndpoint
from ghostmirror.models.parameter_profile import ParameterProfile, ParameterSensitivity
from ghostmirror.models.web_intelligence_report import WebIntelligenceReport, CorrelationResult, OpportunityScore, BusinessLogicArea


class TestInjectionIndicators:
    @pytest.fixture
    def analyzer(self):
        return InjectionIndicators()

    def test_sql_error_detection(self, analyzer):
        endpoints = [WebEndpoint(url="https://example.com/page?id=1", response_body_sample="SQL syntax error near '1' at line 1")]
        params = [ParameterProfile(name="id", sensitivity=ParameterSensitivity.HIGH)]
        indicators = analyzer.analyze(endpoints, params)
        assert any(i.indicator_type == IndicatorType.SQL_INJECTION for i in indicators)
        assert any(i.confidence == ConfidenceLevel.HIGH for i in indicators if i.indicator_type == IndicatorType.SQL_INJECTION)

    def test_stack_trace_detection(self, analyzer):
        endpoints = [WebEndpoint(url="https://example.com/error", response_body_sample="Traceback (most recent call last):\n  File \"app.py\", line 42")]
        indicators = analyzer.analyze(endpoints, [])
        assert any(i.indicator_type == IndicatorType.INFO_LEAK for i in indicators)

    def test_db_error_detection(self, analyzer):
        endpoints = [WebEndpoint(url="https://example.com/db-error", response_body_sample="Database error: SQLSTATE[42000]")]
        indicators = analyzer.analyze(endpoints, [])
        assert any(i.indicator_type == IndicatorType.SQL_INJECTION for i in indicators)

    def test_dynamic_param_indicators(self, analyzer):
        endpoints = [WebEndpoint(url="https://example.com/search")]
        params = [ParameterProfile(name="q"), ParameterProfile(name="category")]
        indicators = analyzer.analyze(endpoints, params)
        assert any(i.indicator_type == IndicatorType.SQL_INJECTION and i.parameter == "q" for i in indicators)

    def test_no_false_positives(self, analyzer):
        endpoints = [WebEndpoint(url="https://example.com/static-page", response_body_sample="<html>Welcome!</html>")]
        indicators = analyzer.analyze(endpoints, [])
        assert len(indicators) == 0


class TestXSSIndicators:
    @pytest.fixture
    def analyzer(self):
        return XSSIndicators()

    def test_unsafe_event_handler(self, analyzer):
        endpoints = [WebEndpoint(url="https://example.com/page", response_body_sample='<button onclick="alert(1)">Click</button>')]
        indicators = analyzer.analyze(endpoints, [])
        assert any(i.indicator_type == IndicatorType.XSS for i in indicators)

    def test_eval_detection(self, analyzer):
        endpoints = [WebEndpoint(url="https://example.com/page", response_body_sample="<script>eval(userInput)</script>")]
        indicators = analyzer.analyze(endpoints, [])
        assert any("Dangerous" in i.title or "eval" in i.title.lower() for i in indicators)

    def test_html_sink_detection(self, analyzer):
        endpoints = [WebEndpoint(url="https://example.com/page", response_body_sample="<script>element.innerHTML = data</script>")]
        indicators = analyzer.analyze(endpoints, [])
        assert any("innerHTML" in i.title or "HTML Sink" in i.title for i in indicators)

    def test_no_false_positives(self, analyzer):
        endpoints = [WebEndpoint(url="https://example.com/clean", response_body_sample="<html><p>Safe content</p></html>")]
        indicators = analyzer.analyze(endpoints, [])
        assert len(indicators) == 0


class TestSSTIIndicators:
    @pytest.fixture
    def analyzer(self):
        return SSTIIndicators()

    def test_tech_profile_detection(self, analyzer):
        endpoints = [WebEndpoint(url="https://example.com/")]
        tech_profile = {"technologies": [{"name": "Flask", "category": "framework"}], "backend_framework": "flask"}
        indicators = analyzer.analyze(endpoints, tech_profile)
        assert any("Jinja2" in i.title or "Jinja2" in i.technology for i in indicators)

    def test_django_detection(self, analyzer):
        endpoints = [WebEndpoint(url="https://example.com/")]
        tech_profile = {"technologies": [{"name": "Django", "category": "framework"}], "backend_framework": "django"}
        indicators = analyzer.analyze(endpoints, tech_profile)
        assert any("Django" in i.technology for i in indicators)

    def test_template_error_detection(self, analyzer):
        endpoints = [WebEndpoint(url="https://example.com/user", response_body_sample="jinja2.exceptions.UndefinedError")]
        indicators = analyzer.analyze(endpoints, None)
        assert any(i.indicator_type == IndicatorType.SSTI for i in indicators)
        assert any(i.confidence == ConfidenceLevel.HIGH for i in indicators)

    def test_no_tech_no_indicators(self, analyzer):
        endpoints = [WebEndpoint(url="https://example.com/", response_body_sample="<html>Static</html>")]
        indicators = analyzer.analyze(endpoints, None)
        assert len(indicators) == 0

    def test_express_handlebars(self, analyzer):
        endpoints = [WebEndpoint(url="https://example.com/")]
        tech_profile = {"technologies": [{"name": "Express", "category": "framework"}], "backend_framework": "express", "backend_language": "node"}
        indicators = analyzer.analyze(endpoints, tech_profile)
        assert any("Handlebars" in i.technology or "Mustache" in i.technology for i in indicators)


class TestSSRFIndicators:
    @pytest.fixture
    def analyzer(self):
        return SSRFIndicators()

    def test_url_parameter(self, analyzer):
        params = [ParameterProfile(name="url", locations=["https://example.com/fetch"])]
        indicators = analyzer.analyze(params)
        assert any(i.indicator_type == IndicatorType.SSRF for i in indicators)

    def test_webhook_param(self, analyzer):
        params = [ParameterProfile(name="webhook")]
        indicators = analyzer.analyze(params)
        assert any(i.indicator_type == IndicatorType.SSRF for i in indicators)

    def test_target_param(self, analyzer):
        params = [ParameterProfile(name="target")]
        indicators = analyzer.analyze(params)
        assert any(i.indicator_type == IndicatorType.SSRF for i in indicators)

    def test_discord_webhook_js(self, analyzer):
        params = []
        js_findings = {"internal_urls": ["https://discord.com/api/webhooks/12345/abcde"]}
        indicators = analyzer.analyze(params, js_findings)
        assert any("discord" in i.title.lower() for i in indicators)

    def test_no_params(self, analyzer):
        indicators = analyzer.analyze([])
        assert len(indicators) == 0


class TestIDORIndicators:
    @pytest.fixture
    def analyzer(self):
        return IDORIndicators()

    def test_numeric_id(self, analyzer):
        endpoints = [WebEndpoint(url="https://example.com/user/123")]
        indicators = analyzer.analyze(endpoints)
        assert any(i.indicator_type == IndicatorType.IDOR for i in indicators)

    def test_uuid_id(self, analyzer):
        endpoints = [WebEndpoint(url="https://example.com/user/550e8400-e29b-41d4-a716-446655440000")]
        indicators = analyzer.analyze(endpoints)
        assert any(i.indicator_type == IndicatorType.IDOR for i in indicators)

    def test_order_id(self, analyzer):
        endpoints = [WebEndpoint(url="https://example.com/order/42")]
        indicators = analyzer.analyze(endpoints)
        assert any(i.indicator_type == IndicatorType.IDOR for i in indicators)

    def test_no_ids(self, analyzer):
        endpoints = [WebEndpoint(url="https://example.com/static-page")]
        indicators = analyzer.analyze(endpoints)
        assert len(indicators) == 0


class TestRedirectIndicators:
    @pytest.fixture
    def analyzer(self):
        return RedirectIndicators()

    def test_redirect_param(self, analyzer):
        params = [ParameterProfile(name="redirect", locations=["https://example.com/auth"])]
        indicators = analyzer.analyze(params)
        assert any(i.indicator_type == IndicatorType.OPEN_REDIRECT for i in indicators)

    def test_next_param(self, analyzer):
        params = [ParameterProfile(name="next")]
        indicators = analyzer.analyze(params)
        assert any(i.indicator_type == IndicatorType.OPEN_REDIRECT for i in indicators)

    def test_return_url(self, analyzer):
        params = [ParameterProfile(name="return_url")]
        indicators = analyzer.analyze(params)
        assert any(i.indicator_type == IndicatorType.OPEN_REDIRECT for i in indicators)

    def test_no_params(self, analyzer):
        indicators = analyzer.analyze([])
        assert len(indicators) == 0


class TestTraversalIndicators:
    @pytest.fixture
    def analyzer(self):
        return TraversalIndicators()

    def test_file_param(self, analyzer):
        params = [ParameterProfile(name="file", locations=["https://example.com/download"])]
        indicators = analyzer.analyze(params)
        assert any(i.indicator_type == IndicatorType.PATH_TRAVERSAL for i in indicators)

    def test_download_param(self, analyzer):
        params = [ParameterProfile(name="download")]
        indicators = analyzer.analyze(params)
        assert any(i.indicator_type == IndicatorType.PATH_TRAVERSAL for i in indicators)

    def test_template_param(self, analyzer):
        params = [ParameterProfile(name="template")]
        indicators = analyzer.analyze(params)
        assert any(i.indicator_type == IndicatorType.PATH_TRAVERSAL for i in indicators)

    def test_no_params(self, analyzer):
        indicators = analyzer.analyze([])
        assert len(indicators) == 0


class TestBusinessLogicIndicators:
    @pytest.fixture
    def analyzer(self):
        return BusinessLogicIndicators()

    def test_checkout_endpoint(self, analyzer):
        endpoints = [WebEndpoint(url="https://example.com/checkout")]
        areas, indicators = analyzer.analyze(endpoints, [])
        assert any(a.area == "checkout" for a in areas)

    def test_coupon_param(self, analyzer):
        endpoints = [WebEndpoint(url="https://example.com/checkout")]
        params = [ParameterProfile(name="coupon")]
        areas, indicators = analyzer.analyze(endpoints, params)
        assert any("coupon" in i.title.lower() for i in indicators)

    def test_wallet_endpoint(self, analyzer):
        endpoints = [WebEndpoint(url="https://example.com/wallet/balance")]
        areas, indicators = analyzer.analyze(endpoints, [])
        assert any("credits" in a.area or "wallet" in a.area for a in areas)

    def test_discount_param(self, analyzer):
        endpoints = [WebEndpoint(url="https://example.com/cart")]
        params = [ParameterProfile(name="discount")]
        areas, indicators = analyzer.analyze(endpoints, params)
        assert any("discount" in i.title.lower() for i in indicators)

    def test_no_business_areas(self, analyzer):
        endpoints = [WebEndpoint(url="https://example.com/about")]
        areas, indicators = analyzer.analyze(endpoints, [])
        assert len(areas) == 0
        assert len(indicators) == 0


class TestWebScoringEngine:
    @pytest.fixture
    def engine(self):
        return WebScoringEngine()

    def test_calculate_opportunities(self, engine):
        correlations = [
            CorrelationResult(title="Open Redirect", correlation_type="open_redirect", score=75, classification="HIGH"),
            CorrelationResult(title="SSRF", correlation_type="ssrf", score=45, classification="MEDIUM"),
        ]
        opportunities = engine.calculate_opportunities(correlations)
        assert len(opportunities) == 2
        assert opportunities[0].score >= opportunities[1].score

    def test_classify(self, engine):
        assert engine._classify(80) == "CRITICAL"
        assert engine._classify(60) == "HIGH"
        assert engine._classify(30) == "MEDIUM"
        assert engine._classify(10) == "LOW"

    def test_empty_correlations(self, engine):
        opportunities = engine.calculate_opportunities([])
        assert opportunities == []

    def test_score_capped_at_100(self, engine):
        cr = CorrelationResult(title="Test", correlation_type="test", score=100, classification="CRITICAL", owasp_category="A01")
        opp = engine.calculate_opportunities([cr])
        assert opp[0].score <= 100


class TestWebRecommendationEngine:
    @pytest.fixture
    def engine(self):
        return WebRecommendationEngine()

    def test_critical_opportunities_generates_recommendations(self, engine):
        report = WebIntelligenceReport(
            opportunities=[OpportunityScore(title="Critical Bug", score=90, classification="CRITICAL")],
            js_findings={},
            auth_profile={},
            total_endpoints=5,
            total_indicators=3,
        )
        recs = engine.generate(report)
        assert any("CRITICAL" in r.get("priority", "") for r in recs)

    def test_secrets_found_recommendation(self, engine):
        report = WebIntelligenceReport(
            opportunities=[],
            js_findings={"secrets_found": ["sk-abc123"]},
            auth_profile={},
            total_endpoints=5,
            total_indicators=0,
        )
        recs = engine.generate(report)
        assert any("secret" in r.get("title", "").lower() for r in recs)

    def test_admin_without_auth_recommendation(self, engine):
        report = WebIntelligenceReport(
            opportunities=[],
            js_findings={},
            auth_profile={"has_admin": True, "has_login": False},
            total_endpoints=5,
            total_indicators=0,
        )
        recs = engine.generate(report)
        assert any("admin" in r.get("title", "").lower() for r in recs)

    def test_empty_report(self, engine):
        report = WebIntelligenceReport()
        recs = engine.generate(report)
        assert len(recs) >= 0


class TestWebFindingsMapper:
    @pytest.fixture
    def mapper(self):
        return WebFindingsMapper()

    def test_map_high_severity(self, mapper):
        indicators = [
            WebIndicator(
                indicator_type=IndicatorType.XSS,
                title="XSS Found",
                description="Reflected XSS detected",
                severity=SeverityLevel.HIGH,
                endpoint="https://example.com/page",
                evidence="<script>alert(1)</script>",
                recommendation="Apply output encoding",
            )
        ]
        findings = mapper.map_to_findings(indicators, "https://example.com")
        assert len(findings) >= 1
        assert findings[0].severity.value == "HIGH"

    def test_filter_low_info(self, mapper):
        indicators = [
            WebIndicator(
                indicator_type=IndicatorType.XSS,
                title="Low XSS",
                description="",
                severity=SeverityLevel.LOW,
            ),
            WebIndicator(
                indicator_type=IndicatorType.IDOR,
                title="Info IDOR",
                description="",
                severity=SeverityLevel.INFO,
            ),
        ]
        findings = mapper.map_to_findings(indicators, "https://example.com")
        assert len(findings) == 0

    def test_empty_indicators(self, mapper):
        findings = mapper.map_to_findings([], "https://example.com")
        assert findings == []
