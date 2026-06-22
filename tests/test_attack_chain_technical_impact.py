from __future__ import annotations

from ghostmirror.models.attack_chain_signal import AttackChainSignal, SignalType
from ghostmirror.modules.attack_chain.technical_impact import TechnicalImpactAnalyzer


class TestTechnicalImpact:
    def test_analyze_empty(self):
        analyzer = TechnicalImpactAnalyzer()
        result = analyzer.analyze([])
        assert result == []

    def test_analyze_jwt(self):
        analyzer = TechnicalImpactAnalyzer()
        signals = [AttackChainSignal(
            id="s1", signal_type=SignalType.JWT_DETECTED,
            severity="medium", confidence=0.8, asset="a",
        )]
        result = analyzer.analyze(signals)
        assert "potential authorization bypass surface" in result

    def test_analyze_exposed_admin(self):
        analyzer = TechnicalImpactAnalyzer()
        signals = [AttackChainSignal(
            id="s1", signal_type=SignalType.EXPOSED_ADMIN,
            severity="high", confidence=0.7, asset="a",
        )]
        result = analyzer.analyze(signals)
        assert "exposed administrative functionality" in result

    def test_analyze_sensitive_object(self):
        analyzer = TechnicalImpactAnalyzer()
        signals = [AttackChainSignal(
            id="s1", signal_type=SignalType.SENSITIVE_OBJECT,
            severity="high", confidence=0.6, asset="a",
        )]
        result = analyzer.analyze(signals)
        assert "possible sensitive object access" in result

    def test_analyze_no_duplicates(self):
        analyzer = TechnicalImpactAnalyzer()
        signals = [
            AttackChainSignal(id="s1", signal_type=SignalType.BOLA_INDICATOR,
                              severity="high", confidence=0.7, asset="a"),
            AttackChainSignal(id="s2", signal_type=SignalType.BFLA_INDICATOR,
                              severity="high", confidence=0.7, asset="a"),
        ]
        result = analyzer.analyze(signals)
        assert result.count("potential authorization bypass surface") == 1

    def test_analyze_missing_header(self):
        analyzer = TechnicalImpactAnalyzer()
        signals = [AttackChainSignal(
            id="s1", signal_type=SignalType.MISSING_HEADER,
            severity="low", confidence=0.9, asset="a",
        )]
        result = analyzer.analyze(signals)
        assert "increased XSS attack surface" in result
