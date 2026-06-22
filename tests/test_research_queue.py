from __future__ import annotations

import pytest

from ghostmirror.modules.zero_day.research_queue import ResearchQueue
from ghostmirror.modules.zero_day.scoring import ZeroDayScoring


class TestResearchQueue:
    def test_init(self):
        q = ResearchQueue()
        assert q.queue == []

    def test_build_empty(self):
        q = ResearchQueue()
        result = q.build([], [], [])
        assert result == []

    def test_build_with_items(self):
        q = ResearchQueue()
        result = q.build(
            hypotheses=[{"title": "H1", "hypothesis_type": "Auth", "confidence": "HIGH", "impact": "HIGH", "score": 80}],
            opportunities=[{"title": "O1", "opportunity_type": "Business Logic", "confidence": "MEDIUM", "priority": "MEDIUM", "score": 50}],
            attack_chains=[{"title": "C1", "confidence": "HIGH", "severity": "CRITICAL", "score": 90}],
        )
        assert len(result) == 3

    def test_sort_critical_first(self):
        q = ResearchQueue()
        result = q.build(
            hypotheses=[],
            opportunities=[],
            attack_chains=[
                {"title": "Low Chain", "confidence": "LOW", "severity": "LOW", "score": 20},
                {"title": "Critical Chain", "confidence": "HIGH", "severity": "CRITICAL", "score": 90},
            ],
        )
        assert result[0]["title"] == "Critical Chain"

    def test_sort_higher_confidence_first(self):
        q = ResearchQueue()
        result = q.build(
            hypotheses=[],
            opportunities=[],
            attack_chains=[
                {"title": "Medium Confidence", "confidence": "MEDIUM", "severity": "HIGH", "score": 80},
                {"title": "High Confidence", "confidence": "HIGH", "severity": "HIGH", "score": 70},
            ],
        )
        assert result[0]["title"] == "High Confidence"

    def test_items_have_required_fields(self):
        q = ResearchQueue()
        result = q.build(
            hypotheses=[{"title": "H1", "hypothesis_type": "Auth", "confidence": "HIGH", "impact": "HIGH", "score": 80}],
            opportunities=[{"title": "O1", "opportunity_type": "Business Logic", "confidence": "MEDIUM", "priority": "MEDIUM", "score": 50}],
            attack_chains=[{"title": "C1", "confidence": "LOW", "severity": "MEDIUM", "score": 30}],
        )
        for item in result:
            assert "title" in item
            assert "type" in item
            assert "priority" in item
            assert "confidence" in item
            assert "score" in item

    def test_mixed_types(self):
        q = ResearchQueue()
        result = q.build(
            hypotheses=[{"title": "H1", "hypothesis_type": "Auth Research", "confidence": "HIGH", "impact": "HIGH", "score": 85}],
            opportunities=[],
            attack_chains=[],
        )
        assert result[0]["type"] == "Hypothesis"


class TestZeroDayScoring:
    def test_init(self):
        s = ZeroDayScoring()
        assert s.overall_score == 0
        assert s.risk_level == "LOW"

    def test_calculate_overall_score(self):
        s = ZeroDayScoring()
        score, level = s.calculate_overall_score(
            anomalies=[{"score": 60}],
            attack_chains=[{"score": 50}],
            hypotheses=[{"score": 40}],
            opportunities=[{"score": 30}],
        )
        assert 0 < score <= 100
        assert level in ("LOW", "MEDIUM", "HIGH", "CRITICAL")

    def test_calculate_overall_score_empty(self):
        s = ZeroDayScoring()
        score, level = s.calculate_overall_score([], [], [], [])
        assert score == 0
        assert level == "LOW"

    def test_calculate_anomaly_score_empty(self):
        assert ZeroDayScoring()._calculate_anomaly_score([]) == 0

    def test_calculate_attack_chain_score_empty(self):
        assert ZeroDayScoring()._calculate_attack_chain_score([]) == 0

    def test_calculate_business_logic_score_empty(self):
        assert ZeroDayScoring()._calculate_business_logic_score([]) == 0

    def test_calculate_hypothesis_score_empty(self):
        assert ZeroDayScoring()._calculate_hypothesis_score([]) == 0

    def test_classify_score_low(self):
        assert ZeroDayScoring.classify_score(10) == "LOW"

    def test_classify_score_medium(self):
        assert ZeroDayScoring.classify_score(30) == "MEDIUM"

    def test_classify_score_high(self):
        assert ZeroDayScoring.classify_score(60) == "HIGH"

    def test_classify_score_critical(self):
        assert ZeroDayScoring.classify_score(80) == "CRITICAL"

    def test_classify_priority(self):
        assert ZeroDayScoring.classify_priority(10) == "LOW"
        assert ZeroDayScoring.classify_priority(30) == "MEDIUM"
        assert ZeroDayScoring.classify_priority(60) == "HIGH"
        assert ZeroDayScoring.classify_priority(80) == "CRITICAL"

    def test_full_scoring_pipeline(self):
        s = ZeroDayScoring()
        score, level = s.calculate_overall_score(
            anomalies=[{"score": 80}, {"score": 60}],
            attack_chains=[{"score": 90}, {"score": 70}],
            hypotheses=[{"score": 75}],
            opportunities=[
                {"opportunity_type": "Business Logic Research", "score": 85},
                {"opportunity_type": "Business Logic Research", "score": 65},
                {"opportunity_type": "Other", "score": 40},
            ],
            exposure_score=50,
            api_score=60,
            web_score=40,
        )
        assert 0 < score <= 100

    def test_anomaly_score_no_score_field(self):
        s = ZeroDayScoring()
        assert s._calculate_anomaly_score([{}, {}]) == 0

    def test_attack_chain_score_no_score_field(self):
        s = ZeroDayScoring()
        assert s._calculate_attack_chain_score([{}, {}]) == 0

    def test_business_logic_score_no_bl_opps(self):
        s = ZeroDayScoring()
        assert s._calculate_business_logic_score(
            [{"opportunity_type": "Other", "score": 50}]
        ) == 0
