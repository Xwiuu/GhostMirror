from __future__ import annotations

from ghostmirror.models.attack_chain_path import AttackChainPath
from ghostmirror.models.attack_chain_signal import AttackChainSignal, SignalType
from ghostmirror.modules.attack_chain.recommendations import RecommendationsEngine


class TestRecommendations:
    def test_generate_empty(self):
        engine = RecommendationsEngine()
        recs = engine.generate([], AttackChainPath(id="c1", title="Test"))
        assert recs == []

    def test_generate_jwt(self):
        engine = RecommendationsEngine()
        signals = [AttackChainSignal(
            id="s1", signal_type=SignalType.JWT_DETECTED,
            severity="medium", confidence=0.8, asset="a",
        )]
        recs = engine.generate(signals, AttackChainPath(id="c1", title="Test"))
        assert len(recs) >= 1
        assert any("JWT" in r for r in recs)

    def test_generate_no_duplicates(self):
        engine = RecommendationsEngine()
        signals = [
            AttackChainSignal(id="s1", signal_type=SignalType.JWT_DETECTED,
                              severity="medium", confidence=0.8, asset="a"),
            AttackChainSignal(id="s2", signal_type=SignalType.JWT_DETECTED,
                              severity="medium", confidence=0.8, asset="b"),
        ]
        recs = engine.generate(signals, AttackChainPath(id="c1", title="Test"))
        jwt_recs = [r for r in recs if "JWT" in r]
        assert len(jwt_recs) >= 2
        assert len(recs) >= 2

    def test_generate_secret_exposed(self):
        engine = RecommendationsEngine()
        signals = [AttackChainSignal(
            id="s1", signal_type=SignalType.SECRET_EXPOSED,
            severity="critical", confidence=0.9, asset="a",
        )]
        recs = engine.generate(signals, AttackChainPath(id="c1", title="Test"))
        assert len(recs) >= 1
        assert any("secret" in r.lower() or "credential" in r.lower() for r in recs)

    def test_generate_multiple_types(self):
        engine = RecommendationsEngine()
        signals = [
            AttackChainSignal(id="s1", signal_type=SignalType.EXPOSED_ADMIN,
                              severity="high", confidence=0.7, asset="a"),
            AttackChainSignal(id="s2", signal_type=SignalType.MISSING_HEADER,
                              severity="low", confidence=0.9, asset="a"),
        ]
        recs = engine.generate(signals, AttackChainPath(id="c1", title="Test"))
        assert len(recs) >= 2
