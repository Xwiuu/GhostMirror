from __future__ import annotations

import pytest

from ghostmirror.models.attack_chain_path import AttackChainPath
from ghostmirror.modules.attack_chain.chain_prioritizer import ChainPrioritizer


class TestChainPrioritizer:
    @pytest.fixture
    def prioritizer(self) -> ChainPrioritizer:
        return ChainPrioritizer()

    def test_prioritize_empty(self, prioritizer: ChainPrioritizer):
        result = prioritizer.prioritize([])
        assert len(result) == 0

    def test_prioritize_single(self, prioritizer: ChainPrioritizer):
        chains = [
            AttackChainPath(id="c1", title="Test Chain", score=75, confidence=0.8),
        ]
        result = prioritizer.prioritize(chains)
        assert len(result) == 1
        assert result[0].rank == 1

    def test_prioritize_order_by_score(self, prioritizer: ChainPrioritizer):
        chains = [
            AttackChainPath(id="c1", title="Low", score=30, confidence=0.5),
            AttackChainPath(id="c2", title="High", score=85, confidence=0.9),
            AttackChainPath(id="c3", title="Medium", score=55, confidence=0.6),
        ]
        result = prioritizer.prioritize(chains)
        assert result[0].title == "High"
        assert result[1].title == "Medium"
        assert result[2].title == "Low"
        assert result[0].rank == 1
        assert result[1].rank == 2
        assert result[2].rank == 3

    def test_priority_critical(self, prioritizer: ChainPrioritizer):
        chain = AttackChainPath(id="c1", title="Critical", score=85, confidence=0.95)
        assert prioritizer._determine_priority(chain) == "critical"

    def test_priority_high(self, prioritizer: ChainPrioritizer):
        chain = AttackChainPath(id="c1", title="High", score=65, confidence=0.7)
        assert prioritizer._determine_priority(chain) == "high"

    def test_priority_medium(self, prioritizer: ChainPrioritizer):
        chain = AttackChainPath(id="c1", title="Medium", score=45, confidence=0.5)
        assert prioritizer._determine_priority(chain) == "medium"

    def test_priority_low(self, prioritizer: ChainPrioritizer):
        chain = AttackChainPath(id="c1", title="Low", score=20, confidence=0.3)
        assert prioritizer._determine_priority(chain) == "low"

    def test_priority_order(self, prioritizer: ChainPrioritizer):
        assert prioritizer._priority_order("critical") == 4
        assert prioritizer._priority_order("high") == 3
        assert prioritizer._priority_order("medium") == 2
        assert prioritizer._priority_order("low") == 1
        assert prioritizer._priority_order("unknown") == 0

    def test_business_impact_ordering(self, prioritizer: ChainPrioritizer):
        chains = [
            AttackChainPath(id="c1", title="A", score=70, confidence=0.8,
                            business_impact=["Impact1"]),
            AttackChainPath(id="c2", title="B", score=70, confidence=0.8,
                            business_impact=["Impact1", "Impact2", "Impact3"]),
        ]
        result = prioritizer.prioritize(chains)
        assert result[0].title == "B"

    def test_priority_assigns_rank(self, prioritizer: ChainPrioritizer):
        chains = [
            AttackChainPath(id="c1", title="A", score=50, confidence=0.5),
            AttackChainPath(id="c2", title="B", score=60, confidence=0.6),
            AttackChainPath(id="c3", title="C", score=70, confidence=0.7),
        ]
        result = prioritizer.prioritize(chains)
        for p in result:
            assert p.rank >= 1
