from __future__ import annotations

import pytest

from ghostmirror.models.attack_chain_path import AttackChainPath
from ghostmirror.models.attack_chain_signal import AttackChainSignal, SignalType
from ghostmirror.modules.attack_chain.chain_scoring import ChainScoringEngine


class TestChainScoring:
    @pytest.fixture
    def scoring(self) -> ChainScoringEngine:
        return ChainScoringEngine()

    def test_severity_score_critical(self, scoring: ChainScoringEngine):
        signals = [
            AttackChainSignal(id="s1", signal_type=SignalType.EXPOSED_ADMIN,
                              severity="critical", confidence=0.9, asset="a"),
        ]
        assert scoring._severity_score(signals) == 1.0

    def test_severity_score_info(self, scoring: ChainScoringEngine):
        signals = [
            AttackChainSignal(id="s1", signal_type=SignalType.EXPOSED_ADMIN,
                              severity="info", confidence=0.5, asset="a"),
        ]
        assert scoring._severity_score(signals) == 0.0

    def test_confidence_score(self, scoring: ChainScoringEngine):
        signals = [
            AttackChainSignal(id="s1", signal_type=SignalType.JWT_DETECTED,
                              severity="medium", confidence=0.8, asset="a"),
            AttackChainSignal(id="s2", signal_type=SignalType.EXPOSED_ADMIN,
                              severity="high", confidence=0.6, asset="a"),
        ]
        assert scoring._confidence_score(signals) == 0.7

    def test_signal_count_score(self, scoring: ChainScoringEngine):
        assert scoring._signal_count_score(0) == 0.0
        assert scoring._signal_count_score(5) == 0.5
        assert scoring._signal_count_score(10) == 1.0

    def test_exploitability_score_kev(self, scoring: ChainScoringEngine):
        signals = [
            AttackChainSignal(id="s1", signal_type=SignalType.CVE_KNOWN_EXPLOITED,
                              severity="critical", confidence=0.9, asset="a"),
        ]
        assert scoring._exploitability_score(signals) > 0

    def test_exposure_score(self, scoring: ChainScoringEngine):
        signals = [
            AttackChainSignal(id="s1", signal_type=SignalType.EXPOSED_ADMIN,
                              severity="high", confidence=0.7, asset="a"),
            AttackChainSignal(id="s2", signal_type=SignalType.SECRET_EXPOSED,
                              severity="critical", confidence=0.9, asset="a"),
        ]
        assert scoring._exposure_score(signals) > 0

    def test_business_impact_score(self, scoring: ChainScoringEngine):
        signals = [
            AttackChainSignal(id="s1", signal_type=SignalType.BUSINESS_LOGIC_SURFACE,
                              severity="medium", confidence=0.5, asset="a"),
        ]
        assert scoring._business_impact_score(signals) > 0

    def test_known_exploitation_score(self, scoring: ChainScoringEngine):
        signals = [
            AttackChainSignal(id="s1", signal_type=SignalType.CVE_KNOWN_EXPLOITED,
                              severity="critical", confidence=0.9, asset="a"),
            AttackChainSignal(id="s2", signal_type=SignalType.PUBLIC_EXPLOIT_AVAILABLE,
                              severity="high", confidence=0.8, asset="a"),
        ]
        assert scoring._known_exploitation_score(signals) > 0

    def test_sensitive_object_score(self, scoring: ChainScoringEngine):
        signals = [
            AttackChainSignal(id="s1", signal_type=SignalType.SENSITIVE_OBJECT,
                              severity="high", confidence=0.6, asset="a"),
        ]
        assert scoring._sensitive_object_score(signals) > 0

    def test_auth_context_score(self, scoring: ChainScoringEngine):
        signals = [
            AttackChainSignal(id="s1", signal_type=SignalType.JWT_DETECTED,
                              severity="medium", confidence=0.7, asset="a"),
            AttackChainSignal(id="s2", signal_type=SignalType.AUTH_SURFACE,
                              severity="high", confidence=0.6, asset="a"),
        ]
        assert scoring._auth_context_score(signals) > 0

    def test_calculate_score(self, scoring: ChainScoringEngine):
        signals = [
            AttackChainSignal(id="s1", signal_type=SignalType.CVE_KNOWN_EXPLOITED,
                              severity="critical", confidence=0.9, asset="server",
                              technology="apache"),
            AttackChainSignal(id="s2", signal_type=SignalType.EXPOSED_ADMIN,
                              severity="high", confidence=0.8, asset="server",
                              endpoint="/admin"),
            AttackChainSignal(id="s3", signal_type=SignalType.SENSITIVE_OBJECT,
                              severity="high", confidence=0.7, asset="server"),
        ]
        chain = AttackChainPath(id="test", title="Test", chain_type="test")
        score = scoring.calculate(chain, signals)
        assert 0 <= score <= 100
        assert chain.score == score
        assert chain.confidence > 0

    def test_classify_score(self, scoring: ChainScoringEngine):
        assert scoring.classify_score(85) == "critical"
        assert scoring.classify_score(70) == "high"
        assert scoring.classify_score(50) == "medium"
        assert scoring.classify_score(20) == "low"

    def test_calculate_likelihood(self, scoring: ChainScoringEngine):
        signals = [
            AttackChainSignal(id="s1", signal_type=SignalType.CVE_KNOWN_EXPLOITED,
                              severity="critical", confidence=0.9, asset="a"),
        ]
        likelihood = scoring._calculate_likelihood(signals)
        assert 0 <= likelihood <= 1

    def test_empty_signals_score_zero(self, scoring: ChainScoringEngine):
        chain = AttackChainPath(id="test", title="Test")
        score = scoring.calculate(chain, [])
        assert score == 0.0
