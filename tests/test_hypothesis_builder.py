from __future__ import annotations

import pytest

from ghostmirror.modules.zero_day.hypothesis_builder import HypothesisBuilder


class TestHypothesisBuilder:
    def test_init(self):
        builder = HypothesisBuilder()
        assert builder is not None

    def test_build_empty(self):
        builder = HypothesisBuilder()
        result = builder.build([], [], [], [])
        assert result == []

    def test_build_from_attack_chains(self):
        builder = HypothesisBuilder()
        chains = [{
            "title": "JWT + Admin API Chain",
            "description": "Test chain",
            "confidence": "HIGH",
            "severity": "CRITICAL",
            "score": 85,
            "components": ["JWT", "Admin API"],
            "attack_vector": "Bypass JWT",
            "recommendation": "Test manually",
        }]
        result = builder._build_from_attack_chains(chains)
        assert len(result) == 1
        assert result[0]["confidence"] == "HIGH"

    def test_build_from_attack_chains_empty(self):
        builder = HypothesisBuilder()
        assert builder._build_from_attack_chains([]) == []

    def test_build_from_anomalies_high_severity(self):
        builder = HypothesisBuilder()
        anomalies = [
            {"title": "Anomaly 1", "severity": "HIGH", "signals": [{"signal_type": "rare_endpoint", "source": "test"}]},
            {"title": "Anomaly 2", "severity": "CRITICAL", "signals": [{"signal_type": "sensitive_header", "source": "test"}]},
        ]
        result = builder._build_from_anomalies(anomalies, [])
        assert len(result) >= 1
        assert "Security Control Weakness" in result[0]["title"]

    def test_build_from_anomalies_low_severity(self):
        builder = HypothesisBuilder()
        result = builder._build_from_anomalies(
            [{"title": "Low anomaly", "severity": "LOW", "signals": []}],
            [],
        )
        assert len(result) == 0

    def test_build_from_anomalies_auth_category(self):
        builder = HypothesisBuilder()
        anomalies = [
            {"title": "Rare endpoint", "severity": "LOW", "category": "rare_endpoint",
             "signals": [{"signal_type": "rare_endpoint", "source": "test", "endpoint": "/admin", "method": "GET", "expected": "x", "observed": "y", "severity": "LOW", "description": "test"}]},
        ]
        result = builder._build_from_anomalies(anomalies, [])
        assert any("Information Disclosure" in h["title"] for h in result)

    def test_build_from_opportunities_business_logic(self):
        builder = HypothesisBuilder()
        opportunities = [
            {"title": "Checkout Logic", "opportunity_type": "Business Logic Research", "score": 70},
            {"title": "Coupon Logic", "opportunity_type": "Business Logic Research", "score": 65},
        ]
        result = builder._build_from_opportunities(opportunities, [])
        assert len(result) >= 1

    def test_build_from_opportunities_single(self):
        builder = HypothesisBuilder()
        result = builder._build_from_opportunities(
            [{"title": "Single opp", "opportunity_type": "Business Logic Research", "score": 50}],
            [],
        )
        assert len(result) == 0

    def test_build_cross_cutting_high_findings(self):
        builder = HypothesisBuilder()
        result = builder._build_cross_cutting(
            [{"title": "A1", "severity": "HIGH"}, {"title": "A2", "severity": "MEDIUM"}],
            [{"title": "C1", "severity": "HIGH"}],
            [{"title": "O1", "priority": "HIGH"}, {"title": "O2", "priority": "MEDIUM"}],
            [{"signal_type": "rare_endpoint", "source": "test"}],
        )
        assert len(result) >= 1

    def test_build_cross_cutting_low_findings(self):
        builder = HypothesisBuilder()
        result = builder._build_cross_cutting(
            [{"title": "A1", "severity": "LOW"}],
            [],
            [],
            [],
        )
        assert len(result) == 0

    def test_detect_hypothesis_type_jwt(self):
        builder = HypothesisBuilder()
        assert builder._detect_hypothesis_type(["JWT"]) == "jwt"

    def test_detect_hypothesis_type_graphql(self):
        builder = HypothesisBuilder()
        assert builder._detect_hypothesis_type(["GraphQL"]) == "graphql"

    def test_detect_hypothesis_type_admin(self):
        builder = HypothesisBuilder()
        assert builder._detect_hypothesis_type(["Admin API"]) == "authorization"

    def test_detect_hypothesis_type_business(self):
        builder = HypothesisBuilder()
        assert builder._detect_hypothesis_type(["business logic"]) == "business_logic"

    def test_detect_hypothesis_type_financial(self):
        builder = HypothesisBuilder()
        assert builder._detect_hypothesis_type(["financial flow"]) == "financial"

    def test_detect_hypothesis_type_hidden(self):
        builder = HypothesisBuilder()
        assert builder._detect_hypothesis_type(["hidden functionality"]) == "hidden_functionality"

    def test_detect_hypothesis_type_debug(self):
        builder = HypothesisBuilder()
        assert builder._detect_hypothesis_type(["debug route"]) == "hidden_functionality"

    def test_detect_hypothesis_type_default(self):
        builder = HypothesisBuilder()
        assert builder._detect_hypothesis_type(["unknown"]) == "authorization"

    def test_hypothesis_sorting(self):
        builder = HypothesisBuilder()
        result = builder.build(
            [{"title": "Anomaly HIGH", "severity": "HIGH", "signals": [{"signal_type": "rare_endpoint", "source": "test"}]}],
            [{"title": "Chain", "confidence": "HIGH", "severity": "HIGH", "score": 80, "components": ["JWT"]}],
            [{"title": "BL Opp", "opportunity_type": "Business Logic Research", "score": 70}],
            [],
        )
        if len(result) > 1:
            assert result[0]["score"] >= result[1]["score"]
