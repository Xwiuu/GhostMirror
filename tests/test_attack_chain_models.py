from __future__ import annotations

from ghostmirror.models.attack_chain_edge import AttackChainEdge, EdgeType
from ghostmirror.models.attack_chain_node import AttackChainNode, NodeType
from ghostmirror.models.attack_chain_path import AttackChainPath
from ghostmirror.models.attack_chain_priority import AttackChainPriority
from ghostmirror.models.attack_chain_report import AttackChainReport
from ghostmirror.models.attack_chain_signal import AttackChainSignal, SignalType


class TestAttackChainModels:
    def test_signal_defaults(self):
        s = AttackChainSignal(id="s1", signal_type=SignalType.EXPOSED_ADMIN)
        assert s.severity == "info"
        assert s.confidence == 0.5
        assert s.created_at is not None

    def test_node_defaults(self):
        n = AttackChainNode(id="n1", label="Node", node_type=NodeType.ASSET)
        assert n.risk_score == 0.0
        assert n.tags == []

    def test_edge_defaults(self):
        e = AttackChainEdge(source_id="a", target_id="b", edge_type=EdgeType.EXPOSES)
        assert e.weight == 1.0

    def test_path_defaults(self):
        p = AttackChainPath(id="c1", title="Chain")
        assert p.priority == "medium"
        assert p.score == 0.0
        assert p.nodes == []
        assert p.edges == []

    def test_priority_defaults(self):
        p = AttackChainPriority(chain_id="c1", title="Chain")
        assert p.priority == "medium"
        assert p.rank == 0

    def test_report_defaults(self):
        r = AttackChainReport()
        assert r.overall_score == 0.0
        assert r.risk_level == "info"
        assert r.total_signals == 0

    def test_signal_type_values(self):
        assert SignalType.EXPOSED_ADMIN.value == "exposed_admin"
        assert SignalType.BFLA_INDICATOR.value == "bfla_indicator"
        assert SignalType.RATE_LIMIT_UNKNOWN.value == "rate_limit_unknown"

    def test_node_type_values(self):
        assert NodeType.ASSET.value == "Asset"
        assert NodeType.BUSINESS_FUNCTION.value == "Business Function"

    def test_edge_type_values(self):
        assert EdgeType.EXPOSES.value == "exposes"
        assert EdgeType.INCREASES_RISK_OF.value == "increases_risk_of"
        assert EdgeType.AUTHENTICATES_WITH.value == "authenticates_with"
