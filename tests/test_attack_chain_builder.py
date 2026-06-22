from __future__ import annotations

import pytest

from ghostmirror.models.attack_chain_edge import AttackChainEdge, EdgeType
from ghostmirror.models.attack_chain_node import AttackChainNode, NodeType
from ghostmirror.models.attack_chain_signal import AttackChainSignal, SignalType
from ghostmirror.modules.attack_chain.chain_builder import ChainBuilder


class TestChainBuilder:
    @pytest.fixture
    def builder(self) -> ChainBuilder:
        return ChainBuilder()

    def test_build_chains_no_signals(self, builder: ChainBuilder):
        chains = builder.build_chains([], [], [])
        assert len(chains) == 0

    def test_build_chains_jwt_admin_sensitive(self, builder: ChainBuilder):
        signals = [
            AttackChainSignal(id="jwt1", signal_type=SignalType.JWT_DETECTED,
                              asset="app.com", severity="medium", confidence=0.8),
            AttackChainSignal(id="adm1", signal_type=SignalType.EXPOSED_ADMIN,
                              asset="app.com", endpoint="/admin",
                              severity="high", confidence=0.7),
            AttackChainSignal(id="so1", signal_type=SignalType.SENSITIVE_OBJECT,
                              asset="app.com", severity="high", confidence=0.6),
        ]
        nodes = [
            AttackChainNode(id="asset_app.com", label="app.com", node_type=NodeType.ASSET),
            AttackChainNode(id="ep_/admin", label="/admin", node_type=NodeType.ENDPOINT),
        ]
        edges = [
            AttackChainEdge(source_id="asset_app.com", target_id="ep_/admin",
                            edge_type=EdgeType.EXPOSES),
        ]
        chains = builder.build_chains(signals, nodes, edges)
        assert len(chains) >= 1
        jwt_chain = [c for c in chains if "JWT" in c.title]
        assert len(jwt_chain) >= 1

    def test_build_chains_single_unmatched(self, builder: ChainBuilder):
        signals = [
            AttackChainSignal(id="s1", signal_type=SignalType.GRAPHQL_SURFACE,
                              asset="app.com", severity="medium", confidence=0.5),
        ]
        chains = builder.build_chains(signals, [], [])
        assert len(chains) >= 1
        single_chains = [c for c in chains if c.chain_type == "single_signal"]
        assert len(single_chains) >= 1

    def test_build_chain_has_validation_steps(self, builder: ChainBuilder):
        signals = [
            AttackChainSignal(id="s1", signal_type=SignalType.EXPOSED_ADMIN,
                              asset="app.com", endpoint="/admin",
                              severity="high", confidence=0.7),
        ]
        chains = builder.build_chains(signals, [], [])
        for c in chains:
            if c.chain_type != "single_signal":
                continue
            assert len(c.manual_validation_steps) >= 1
            break

    def test_build_chain_has_recommendations(self, builder: ChainBuilder):
        signals = [
            AttackChainSignal(id="s1", signal_type=SignalType.SECRET_EXPOSED,
                              asset="app.com", endpoint="/.env",
                              severity="critical", confidence=0.9),
        ]
        chains = builder.build_chains(signals, [], [])
        for c in chains:
            if c.chain_type != "single_signal":
                continue
            assert len(c.defensive_recommendations) >= 1
            break

    def test_build_chain_has_evidence_summary(self, builder: ChainBuilder):
        signals = [
            AttackChainSignal(id="s1", signal_type=SignalType.JWT_DETECTED,
                              asset="app.com", severity="medium", confidence=0.8),
        ]
        chains = builder.build_chains(signals, [], [])
        for c in chains:
            assert c.evidence_summary

    def test_build_chain_has_business_impact(self, builder: ChainBuilder):
        signals = [
            AttackChainSignal(id="s1", signal_type=SignalType.EXPOSED_API,
                              asset="app.com", endpoint="/api",
                              severity="high", confidence=0.7),
        ]
        chains = builder.build_chains(signals, [], [])
        for c in chains:
            if c.chain_type != "single_signal":
                continue
            assert len(c.business_impact) >= 1
            break

    def test_build_chain_has_technical_impact(self, builder: ChainBuilder):
        signals = [
            AttackChainSignal(id="s1", signal_type=SignalType.EXPOSED_ADMIN,
                              asset="app.com", endpoint="/admin",
                              severity="high", confidence=0.7),
        ]
        chains = builder.build_chains(signals, [], [])
        for c in chains:
            if c.chain_type != "single_signal":
                continue
            assert len(c.technical_impact) >= 1
            break
