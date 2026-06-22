from __future__ import annotations

import pytest

from ghostmirror.models.attack_chain_signal import AttackChainSignal, SignalType
from ghostmirror.modules.attack_chain.business_impact import BusinessImpactAnalyzer


class TestBusinessImpactAnalyzer:
    @pytest.fixture
    def analyzer(self) -> BusinessImpactAnalyzer:
        return BusinessImpactAnalyzer()

    def test_analyze_empty(self, analyzer: BusinessImpactAnalyzer):
        impacts = analyzer.analyze([])
        assert len(impacts) == 0

    def test_analyze_exposed_admin(self, analyzer: BusinessImpactAnalyzer):
        signals = [
            AttackChainSignal(id="s1", signal_type=SignalType.EXPOSED_ADMIN,
                              severity="high", confidence=0.7, asset="a"),
        ]
        impacts = analyzer.analyze(signals)
        assert "Admin function abuse" in impacts
        assert "Unauthorized data access" in impacts

    def test_analyze_jwt(self, analyzer: BusinessImpactAnalyzer):
        signals = [
            AttackChainSignal(id="s1", signal_type=SignalType.JWT_DETECTED,
                              severity="medium", confidence=0.8, asset="a"),
        ]
        impacts = analyzer.analyze(signals)
        assert "Account takeover risk" in impacts

    def test_analyze_sensitive_object(self, analyzer: BusinessImpactAnalyzer):
        signals = [
            AttackChainSignal(id="s1", signal_type=SignalType.SENSITIVE_OBJECT,
                              severity="high", confidence=0.6, asset="a"),
        ]
        impacts = analyzer.analyze(signals)
        assert "Customer data exposure" in impacts
        assert "Regulatory exposure" in impacts

    def test_analyze_business_logic(self, analyzer: BusinessImpactAnalyzer):
        signals = [
            AttackChainSignal(id="s1", signal_type=SignalType.BUSINESS_LOGIC_SURFACE,
                              severity="medium", confidence=0.5, asset="a"),
        ]
        impacts = analyzer.analyze(signals)
        assert "Payment manipulation" in impacts

    def test_analyze_no_duplicates(self, analyzer: BusinessImpactAnalyzer):
        signals = [
            AttackChainSignal(id="s1", signal_type=SignalType.EXPOSED_ADMIN,
                              severity="high", confidence=0.7, asset="a"),
            AttackChainSignal(id="s2", signal_type=SignalType.EXPOSED_API,
                              severity="high", confidence=0.7, asset="a"),
        ]
        impacts = analyzer.analyze(signals)
        assert impacts.count("Unauthorized data access") == 1

    def test_analyze_secret_exposed(self, analyzer: BusinessImpactAnalyzer):
        signals = [
            AttackChainSignal(id="s1", signal_type=SignalType.SECRET_EXPOSED,
                              severity="critical", confidence=0.9, asset="a"),
        ]
        impacts = analyzer.analyze(signals)
        assert "Account takeover risk" in impacts

    def test_analyze_cve_known_exploited(self, analyzer: BusinessImpactAnalyzer):
        signals = [
            AttackChainSignal(id="s1", signal_type=SignalType.CVE_KNOWN_EXPLOITED,
                              severity="critical", confidence=0.9, asset="a"),
        ]
        impacts = analyzer.analyze(signals)
        assert "Brand/reputation impact" in impacts
