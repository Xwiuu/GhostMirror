from __future__ import annotations

import pytest

from ghostmirror.modules.web_intelligence.correlation import CorrelationEngine
from ghostmirror.models.web_indicator import IndicatorType, WebIndicator
from ghostmirror.models.finding_confidence import ConfidenceLevel
from ghostmirror.models.web_endpoint import WebEndpoint


class TestCorrelationEngine:
    @pytest.fixture
    def engine(self):
        return CorrelationEngine()

    def test_correlate_no_indicators(self, engine):
        results = engine.correlate(endpoints=[], indicators=[])
        assert results == []

    def test_correlate_with_open_redirect(self, engine):
        indicators = [
            WebIndicator(
                indicator_type=IndicatorType.OPEN_REDIRECT,
                title="Open Redirect",
                description="",
                parameter="redirect",
                confidence=ConfidenceLevel.MEDIUM,
            )
        ]
        endpoints = [WebEndpoint(url="https://example.com/auth/callback")]
        tech_profile = {"technologies": [{"name": "Auth0", "category": "authentication"}], "backend_framework": "nextjs"}
        results = engine.correlate(
            endpoints=endpoints,
            indicators=indicators,
            tech_profile=tech_profile,
        )
        assert len(results) > 0
        assert any("Open Redirect" in r.title for r in results)

    def test_correlate_with_ssrf(self, engine):
        indicators = [
            WebIndicator(
                indicator_type=IndicatorType.SSRF,
                title="SSRF",
                description="",
                parameter="url",
                confidence=ConfidenceLevel.MEDIUM,
            )
        ]
        results = engine.correlate(endpoints=[], indicators=indicators)
        assert any("SSRF" in r.title for r in results)

    def test_correlate_with_idor(self, engine):
        indicators = [
            WebIndicator(
                indicator_type=IndicatorType.IDOR,
                title="IDOR",
                description="",
                parameter="id",
                confidence=ConfidenceLevel.MEDIUM,
            )
        ]
        endpoints = [WebEndpoint(url="https://example.com/user/123")]
        results = engine.correlate(endpoints=endpoints, indicators=indicators)
        assert any("IDOR" in r.title for r in results)

    def test_correlate_with_tech_profile(self, engine):
        indicators = [
            WebIndicator(
                indicator_type=IndicatorType.PATH_TRAVERSAL,
                title="Traversal",
                description="",
                parameter="file",
                confidence=ConfidenceLevel.MEDIUM,
            )
        ]
        tech_profile = {"technologies": [{"name": "PHP", "category": "language"}], "backend_language": "php"}
        results = engine.correlate(
            endpoints=[WebEndpoint(url="https://example.com/page.php")],
            indicators=indicators,
            tech_profile=tech_profile,
        )
        assert len(results) > 0

    def test_correlate_with_secrets(self, engine):
        indicators = [
            WebIndicator(
                indicator_type=IndicatorType.EXPOSED_SECRET,
                title="Secret",
                description="",
                confidence=ConfidenceLevel.HIGH,
            )
        ]
        js_findings = {"secrets_found": ["sk-abc123"]}
        results = engine.correlate(
            endpoints=[],
            indicators=indicators,
            js_findings=js_findings,
        )
        assert any("Secret" in r.title or "Exposed" in r.title for r in results)

    def test_correlate_with_auth_profile(self, engine):
        indicators = [
            WebIndicator(
                indicator_type=IndicatorType.OPEN_REDIRECT,
                title="Open Redirect in Auth",
                description="",
                parameter="redirect",
                confidence=ConfidenceLevel.MEDIUM,
            )
        ]
        auth_profile = {"has_login": True, "has_admin": True}
        tech_profile = {"technologies": [{"name": "Auth0", "category": "authentication"}], "backend_framework": "nextjs"}
        results = engine.correlate(
            endpoints=[],
            indicators=indicators,
            tech_profile=tech_profile,
            auth_profile=auth_profile,
        )
        assert len(results) > 0

    def test_classify(self, engine):
        assert engine._classify(85) == "CRITICAL"
        assert engine._classify(60) == "HIGH"
        assert engine._classify(35) == "MEDIUM"
        assert engine._classify(10) == "LOW"

    def test_results_sorted_by_score(self, engine):
        indicators = [
            WebIndicator(indicator_type=IndicatorType.OPEN_REDIRECT, title="A", description="", parameter="redirect", confidence=ConfidenceLevel.MEDIUM),
            WebIndicator(indicator_type=IndicatorType.SSRF, title="B", description="", parameter="url", confidence=ConfidenceLevel.MEDIUM),
        ]
        results = engine.correlate(endpoints=[], indicators=indicators)
        scores = [r.score for r in results]
        assert scores == sorted(scores, reverse=True)
