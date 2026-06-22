from __future__ import annotations

from pathlib import Path

import pytest

from ghostmirror.models.attack_chain_edge import AttackChainEdge, EdgeType
from ghostmirror.models.attack_chain_node import AttackChainNode, NodeType
from ghostmirror.models.attack_chain_signal import AttackChainSignal, SignalType
from ghostmirror.modules.attack_chain.graph_builder import GraphBuilder


class TestGraphBuilder:
    @pytest.fixture
    def builder(self) -> GraphBuilder:
        return GraphBuilder()

    def test_build_empty(self, builder: GraphBuilder):
        nodes, edges = builder.build([])
        assert len(nodes) == 0
        assert len(edges) == 0

    def test_build_single_signal(self, builder: GraphBuilder):
        signals = [
            AttackChainSignal(
                id="sig1", signal_type=SignalType.EXPOSED_API,
                asset="example.com", endpoint="/api/test",
                severity="high", confidence=0.8,
            ),
        ]
        nodes, edges = builder.build(signals)
        assert len(nodes) >= 2
        assert len(edges) >= 1

    def test_build_jwt_signal_creates_auth_node(self, builder: GraphBuilder):
        signals = [
            AttackChainSignal(
                id="jwt1", signal_type=SignalType.JWT_DETECTED,
                asset="example.com", severity="medium", confidence=0.7,
            ),
        ]
        nodes, edges = builder.build(signals)
        auth_nodes = [n for n in nodes if n.node_type == NodeType.AUTH]
        assert len(auth_nodes) >= 1
        assert auth_nodes[0].label == "Authentication System"

    def test_build_sensitive_object_creates_object_node(self, builder: GraphBuilder):
        signals = [
            AttackChainSignal(
                id="so1", signal_type=SignalType.SENSITIVE_OBJECT,
                asset="users", severity="high", confidence=0.6,
            ),
        ]
        nodes, edges = builder.build(signals)
        obj_nodes = [n for n in nodes if n.node_type == NodeType.OBJECT]
        assert len(obj_nodes) >= 1

    def test_build_cve_signal_creates_vulnerability_node(self, builder: GraphBuilder):
        signals = [
            AttackChainSignal(
                id="cve1", signal_type=SignalType.CVE_KNOWN_EXPLOITED,
                asset="server", technology="apache",
                severity="critical", confidence=0.9,
            ),
        ]
        nodes, edges = builder.build(signals)
        vuln_nodes = [n for n in nodes if n.node_type == NodeType.VULNERABILITY]
        assert len(vuln_nodes) >= 1

    def test_build_business_logic_creates_biz_node(self, builder: GraphBuilder):
        signals = [
            AttackChainSignal(
                id="bl1", signal_type=SignalType.BUSINESS_LOGIC_SURFACE,
                asset="shop", severity="medium", confidence=0.5,
            ),
        ]
        nodes, edges = builder.build(signals)
        biz_nodes = [n for n in nodes if n.node_type == NodeType.BUSINESS_FUNCTION]
        assert len(biz_nodes) >= 1

    def test_build_zero_day_creates_hypothesis_node(self, builder: GraphBuilder):
        signals = [
            AttackChainSignal(
                id="zd1", signal_type=SignalType.ZERO_DAY_HYPOTHESIS,
                asset="app", severity="high", confidence=0.4,
            ),
        ]
        nodes, edges = builder.build(signals)
        hyp_nodes = [n for n in nodes if n.node_type == NodeType.HYPOTHESIS]
        assert len(hyp_nodes) >= 1

    def test_to_dict(self, builder: GraphBuilder):
        nodes = [AttackChainNode(id="n1", label="Node1", node_type=NodeType.ASSET)]
        edges = [AttackChainEdge(source_id="n1", target_id="n2", edge_type=EdgeType.EXPOSES)]
        result = builder.to_dict(nodes, edges)
        assert "nodes" in result
        assert "edges" in result
        assert len(result["nodes"]) == 1
        assert len(result["edges"]) == 1

    def test_save_graph(self, builder: GraphBuilder, tmp_path: Path):
        import json
        nodes = [AttackChainNode(id="n1", label="Node1", node_type=NodeType.ASSET)]
        edges = [AttackChainEdge(source_id="n1", target_id="n2", edge_type=EdgeType.EXPOSES)]
        path = tmp_path / "attack_graph.json"
        builder.save_graph(path, nodes, edges)
        assert path.exists()
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert "nodes" in data
        assert len(data["nodes"]) == 1

    def test_multiple_signals_shared_asset(self, builder: GraphBuilder):
        signals = [
            AttackChainSignal(id="s1", signal_type=SignalType.EXPOSED_API,
                              asset="example.com", endpoint="/api/v1",
                              severity="high", confidence=0.7),
            AttackChainSignal(id="s2", signal_type=SignalType.JWT_DETECTED,
                              asset="example.com",
                              severity="medium", confidence=0.6),
        ]
        nodes, edges = builder.build(signals)
        assert len(nodes) >= 3
