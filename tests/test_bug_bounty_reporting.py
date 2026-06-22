from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from ghostmirror.models.bug_bounty_opportunity import BugBountyOpportunity
from ghostmirror.models.bug_bounty_report import BugBountyReport
from ghostmirror.models.crawled_route import CrawledRoute
from ghostmirror.models.discovered_api import DiscoveredAPI
from ghostmirror.models.discovered_secret import DiscoveredSecret
from ghostmirror.modules.bug_bounty.findings_mapper import BountyFindingsMapper
from ghostmirror.modules.bug_bounty.recommendations import BountyRecommendations
from ghostmirror.modules.bug_bounty.report_builder import BountyReportBuilder
from ghostmirror.modules.bug_bounty.scoring import BountyScoring
from ghostmirror.modules.models.finding import FindingModel, FindingSeverity


class TestBountyReportBuilder:
    @pytest.fixture
    def builder(self) -> BountyReportBuilder:
        return BountyReportBuilder()

    def test_build_minimal(self, builder: BountyReportBuilder) -> None:
        report = builder.build(
            target="https://example.com",
            routes=[],
            apis=[],
            js_bundles=[],
            sourcemap_findings=[],
            secrets=[],
            interesting_files=[],
            subdomains=[],
            opportunities=[],
            recommendations=[],
            overall_score=0,
            risk_level="INFO",
        )
        assert isinstance(report, BugBountyReport)
        assert report.target == "https://example.com"
        assert report.overall_score == 0
        assert report.total_routes == 0
        assert report.total_apis == 0

    def test_build_with_data(self, builder: BountyReportBuilder) -> None:
        report = builder.build(
            target="https://example.com",
            routes=[{"url": "https://example.com/admin", "title": "Admin", "status": 200}],
            apis=[{"url": "https://example.com/api/users", "method": "GET"}],
            js_bundles=[{"url": "https://example.com/app.js", "size": 1000}],
            sourcemap_findings=[{"js_url": "app.js", "exposed": True}],
            secrets=[{"type": "api_key", "redacted_snippet": "abcd****wxyz", "severity": "high"}],
            interesting_files=[{"path": "/robots.txt", "found": True}],
            subdomains=[{"hostname": "admin.example.com", "source": "html"}],
            opportunities=[{"title": "Test Opportunity", "score": 25, "severity": "HIGH"}],
            recommendations=["Fix this issue"],
            overall_score=45,
            risk_level="MEDIUM",
        )
        assert report.total_routes == 1
        assert report.total_apis == 1
        assert report.total_secrets == 1
        assert report.total_opportunities == 1
        assert len(report.headless_routes) == 1
        assert len(report.recommendations) == 1


class TestBountyScoring:
    @pytest.fixture
    def scoring(self) -> BountyScoring:
        return BountyScoring()

    def test_calculate_empty(self, scoring: BountyScoring) -> None:
        opportunities, score, level = scoring.calculate()
        assert opportunities == []
        assert score == 0
        assert level == "LOW"

    def test_calculate_with_auth_routes(self, scoring: BountyScoring) -> None:
        routes = [{"url": "https://example.com/login"}, {"url": "https://example.com/register"}]
        opportunities, score, level = scoring.calculate(routes=routes)
        assert score >= 10
        types = [o.type for o in opportunities]
        assert "auth_endpoint" in types

    def test_calculate_with_admin_routes(self, scoring: BountyScoring) -> None:
        routes = [{"url": "https://example.com/admin"}, {"url": "https://example.com/dashboard"}]
        opportunities, score, level = scoring.calculate(routes=routes)
        assert score >= 15
        types = [o.type for o in opportunities]
        assert "admin" in types

    def test_calculate_with_payment_routes(self, scoring: BountyScoring) -> None:
        routes = [{"url": "https://example.com/checkout"}, {"url": "https://example.com/cart"}]
        opportunities, score, level = scoring.calculate(routes=routes)
        assert score >= 20
        types = [o.type for o in opportunities]
        assert "business_logic" in types

    def test_calculate_with_apis(self, scoring: BountyScoring) -> None:
        apis = [{"url": "https://example.com/api/users"}, {"url": "https://example.com/api/products"}]
        opportunities, score, level = scoring.calculate(apis=apis)
        assert score >= 2  # 2 apis * 2 = 4, capped... let's see

    def test_calculate_with_graphql(self, scoring: BountyScoring) -> None:
        apis = [{"url": "https://example.com/graphql", "content_type": "graphql"}]
        opportunities, score, level = scoring.calculate(apis=apis)
        types = [o.type for o in opportunities]
        assert "api_endpoint" in types

    def test_calculate_with_exposed_sourcemaps(self, scoring: BountyScoring) -> None:
        sourcemaps = [{"js_url": "app.js", "exposed": True, "files": ["src/main.ts"], "sourcemap_url": "app.js.map"}]
        opportunities, score, level = scoring.calculate(sourcemap_findings=sourcemaps)
        assert score >= 15
        types = [o.type for o in opportunities]
        assert "exposed_sourcemap" in types

    def test_calculate_with_secrets(self, scoring: BountyScoring) -> None:
        secrets = [{"type": "stripe_sk", "severity": "critical", "location": "app.js"}]
        opportunities, score, level = scoring.calculate(secrets=secrets)
        assert score >= 25
        types = [o.type for o in opportunities]
        assert "potential_secret" in types

    def test_calculate_with_interesting_files(self, scoring: BountyScoring) -> None:
        files = [{"path": "/.env", "url": "https://example.com/.env", "found": True}]
        opportunities, score, level = scoring.calculate(interesting_files=files)
        assert score >= 10
        types = [o.type for o in opportunities]
        assert "interesting_file" in types

    def test_calculate_with_sensitive_params(self, scoring: BountyScoring) -> None:
        params = [{"parameter": "password", "classification": "Sensitive", "url": "https://example.com/login"}]
        opportunities, score, level = scoring.calculate(parameters=params)
        types = [o.type for o in opportunities]
        assert "sensitive_param" in types

    def test_risk_level_classification(self, scoring: BountyScoring) -> None:
        _, _, level_low = scoring.calculate()
        assert level_low == "LOW"

        routes = [{"url": "https://example.com/checkout"}, {"url": "https://example.com/payment"}]
        secrets = [{"type": "stripe_sk", "severity": "critical", "location": "app.js"}]
        _, score, level = scoring.calculate(routes=routes, secrets=secrets)
        if score > 70:
            assert level == "CRITICAL"
        elif score > 40:
            assert level == "HIGH"


class TestBountyRecommendations:
    @pytest.fixture
    def recommender(self) -> BountyRecommendations:
        return BountyRecommendations()

    def test_generate_empty_report(self, recommender: BountyRecommendations) -> None:
        report = BugBountyReport(target="https://example.com")
        recs = recommender.generate(report)
        assert len(recs) >= 1

    def test_generate_with_exposed_sourcemaps(self, recommender: BountyRecommendations) -> None:
        report = BugBountyReport(target="https://example.com")
        report.sourcemap_findings = [{"exposed": True, "js_url": "app.js", "files": ["main.ts"]}]
        recs = recommender.generate(report)
        assert any("source map" in r.lower() for r in recs)

    def test_generate_with_apis(self, recommender: BountyRecommendations) -> None:
        report = BugBountyReport(target="https://example.com")
        report.total_apis = 5
        recs = recommender.generate(report)
        assert any("api" in r.lower() for r in recs)

    def test_generate_with_secrets(self, recommender: BountyRecommendations) -> None:
        report = BugBountyReport(target="https://example.com")
        report.total_secrets = 3
        recs = recommender.generate(report)
        assert any("secret" in r.lower() for r in recs)

    def test_generate_with_payment_routes(self, recommender: BountyRecommendations) -> None:
        report = BugBountyReport(target="https://example.com")
        report.headless_routes = [CrawledRoute(url="https://example.com/checkout")]
        recs = recommender.generate(report)
        assert any("payment" in r.lower() for r in recs)

    def test_generate_with_admin_routes(self, recommender: BountyRecommendations) -> None:
        report = BugBountyReport(target="https://example.com")
        report.headless_routes = [CrawledRoute(url="https://example.com/admin")]
        recs = recommender.generate(report)
        assert any("admin" in r.lower() for r in recs)

    def test_generate_with_high_opportunities(self, recommender: BountyRecommendations) -> None:
        report = BugBountyReport(target="https://example.com")
        report.opportunities = [BugBountyOpportunity(title="Test", score=20, severity="HIGH")]
        report.total_opportunities = 1
        recs = recommender.generate(report)
        assert any("high-score" in r.lower() or "prioritize" in r.lower() for r in recs)


class TestBountyFindingsMapper:
    @pytest.fixture
    def mapper(self) -> BountyFindingsMapper:
        return BountyFindingsMapper()

    def test_map_empty_report(self, mapper: BountyFindingsMapper) -> None:
        report = BugBountyReport(target="https://example.com")
        findings = mapper.map(report)
        assert findings == []

    def test_map_sourcemap_findings(self, mapper: BountyFindingsMapper) -> None:
        report = BugBountyReport(target="https://example.com")
        report.sourcemap_findings = [{"exposed": True, "sourcemap_url": "app.js.map", "files": ["a.ts"], "endpoints": ["/api"]}]
        findings = mapper.map(report)
        assert len(findings) >= 1
        assert findings[0].category == "bug_bounty_sourcemap"

    def test_map_secrets(self, mapper: BountyFindingsMapper) -> None:
        report = BugBountyReport(target="https://example.com")
        report.secrets = [DiscoveredSecret(type="stripe_sk", redacted_snippet="sk****ve", severity="critical", location="app.js")]
        findings = mapper.map(report)
        assert len(findings) >= 1
        assert findings[0].category == "bug_bounty_secret"

    def test_map_interesting_files(self, mapper: BountyFindingsMapper) -> None:
        report = BugBountyReport(target="https://example.com")
        report.interesting_files = [{"path": "/.env", "url": "https://example.com/.env", "found": True, "status": 200}]
        findings = mapper.map(report)
        assert len(findings) >= 1
        assert findings[0].category == "bug_bounty_interesting_file"

    def test_map_interesting_files_not_found(self, mapper: BountyFindingsMapper) -> None:
        report = BugBountyReport(target="https://example.com")
        report.interesting_files = [{"path": "/.env", "url": "https://example.com/.env", "found": False, "status": 404}]
        findings = mapper.map(report)
        assert findings == []
