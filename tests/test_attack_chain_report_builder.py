from __future__ import annotations

from ghostmirror.models.attack_chain_edge import AttackChainEdge, EdgeType
from ghostmirror.models.attack_chain_node import AttackChainNode, NodeType
from ghostmirror.models.attack_chain_path import AttackChainPath
from ghostmirror.models.attack_chain_priority import AttackChainPriority
from ghostmirror.models.attack_chain_report import AttackChainReport
from ghostmirror.models.attack_chain_signal import AttackChainSignal, SignalType
from ghostmirror.modules.attack_chain.report_builder import AttackChainReportBuilder


class TestAttackChainReportBuilder:
    def test_build_empty(self):
        builder = AttackChainReportBuilder()
        report = builder.build(
            target="test.com", project="test",
            signals=[], nodes=[], edges=[], chains=[], priorities=[],
            linked_evidence=[],
        )
        assert isinstance(report, AttackChainReport)
        assert report.total_signals == 0
        assert report.total_chains == 0
        assert report.overall_score == 0.0

    def test_build_with_data(self):
        builder = AttackChainReportBuilder()
        signals = [
            AttackChainSignal(id="s1", signal_type=SignalType.JWT_DETECTED,
                              asset="test.com", severity="high", confidence=0.8),
        ]
        nodes = [AttackChainNode(id="n1", label="test.com", node_type=NodeType.ASSET)]
        edges = [AttackChainEdge(source_id="n1", target_id="n2", edge_type=EdgeType.EXPOSES)]
        chains = [
            AttackChainPath(id="c1", title="Test Chain", score=75, confidence=0.8,
                            business_impact=["Test Impact"], technical_impact=["Tech Impact"]),
        ]
        priorities = [AttackChainPriority(chain_id="c1", title="Test Chain", score=75, rank=1)]
        report = builder.build(
            target="test.com", project="test",
            signals=signals, nodes=nodes, edges=edges,
            chains=chains, priorities=priorities,
            linked_evidence=[],
        )
        assert report.total_signals == 1
        assert report.total_nodes == 1
        assert report.total_edges == 1
        assert report.total_chains == 1
        assert report.overall_score == 75.0

    def test_top_chains(self):
        builder = AttackChainReportBuilder()
        priorities = [
            AttackChainPriority(chain_id="c1", title="Chain 1", score=90, rank=1,
                                priority="critical"),
            AttackChainPriority(chain_id="c2", title="Chain 2", score=80, rank=2,
                                priority="high"),
        ]
        report = builder.build(
            target="t", project="p",
            signals=[], nodes=[], edges=[], chains=[],
            priorities=priorities, linked_evidence=[],
        )
        assert len(report.top_chains) == 2

    def test_priority_matrix(self):
        builder = AttackChainReportBuilder()
        priorities = [
            AttackChainPriority(chain_id="c1", title="Chain 1", score=85, rank=1,
                                priority="critical", confidence=0.9, impact=85, exploitability=0.8),
        ]
        report = builder.build(
            target="t", project="p",
            signals=[], nodes=[], edges=[], chains=[],
            priorities=priorities, linked_evidence=[],
        )
        assert len(report.priority_matrix) == 1
        assert report.priority_matrix[0]["rank"] == 1
        assert report.priority_matrix[0]["score"] == 85

    def test_business_impact_summary(self):
        builder = AttackChainReportBuilder()
        chains = [
            AttackChainPath(id="c1", title="Chain 1", score=50,
                            business_impact=["Impact A", "Impact B"]),
            AttackChainPath(id="c2", title="Chain 2", score=50,
                            business_impact=["Impact A"]),
        ]
        report = builder.build(
            target="t", project="p",
            signals=[], nodes=[], edges=[], chains=chains,
            priorities=[], linked_evidence=[],
        )
        assert len(report.business_impact_summary) == 2
        impact_a = [i for i in report.business_impact_summary if i["impact"] == "Impact A"]
        assert impact_a[0]["count"] == 2

    def test_technical_impact_summary(self):
        builder = AttackChainReportBuilder()
        chains = [
            AttackChainPath(id="c1", title="Chain", score=50,
                            technical_impact=["Tech A", "Tech B"]),
        ]
        report = builder.build(
            target="t", project="p",
            signals=[], nodes=[], edges=[], chains=chains,
            priorities=[], linked_evidence=[],
        )
        assert "Tech A" in report.technical_impact_summary
        assert "Tech B" in report.technical_impact_summary

    def test_attack_graph_summary(self):
        builder = AttackChainReportBuilder()
        nodes = [
            AttackChainNode(id="n1", label="A", node_type=NodeType.ASSET),
            AttackChainNode(id="n2", label="B", node_type=NodeType.ENDPOINT),
        ]
        edges = [
            AttackChainEdge(source_id="n1", target_id="n2", edge_type=EdgeType.EXPOSES),
        ]
        report = builder.build(
            target="t", project="p",
            signals=[], nodes=nodes, edges=edges,
            chains=[], priorities=[], linked_evidence=[],
        )
        gs = report.attack_graph_summary
        assert gs["total_nodes"] == 2
        assert gs["total_edges"] == 1
        assert "Asset" in gs["node_types"]
        assert "Endpoint" in gs["node_types"]

    def test_overall_classify(self):
        builder = AttackChainReportBuilder()
        assert builder._classify_overall(85) == "critical"
        assert builder._classify_overall(70) == "high"
        assert builder._classify_overall(50) == "medium"
        assert builder._classify_overall(20) == "low"
