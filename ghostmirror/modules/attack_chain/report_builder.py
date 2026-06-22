from __future__ import annotations

from typing import Any

from ghostmirror.core.logger import get_logger
from ghostmirror.models.attack_chain_node import AttackChainNode
from ghostmirror.models.attack_chain_edge import AttackChainEdge
from ghostmirror.models.attack_chain_path import AttackChainPath
from ghostmirror.models.attack_chain_priority import AttackChainPriority
from ghostmirror.models.attack_chain_report import AttackChainReport
from ghostmirror.models.attack_chain_signal import AttackChainSignal

logger = get_logger()


class AttackChainReportBuilder:
    def build(
        self,
        target: str,
        project: str,
        signals: list[AttackChainSignal],
        nodes: list[AttackChainNode],
        edges: list[AttackChainEdge],
        chains: list[AttackChainPath],
        priorities: list[AttackChainPriority],
        linked_evidence: list[dict[str, Any]],
    ) -> AttackChainReport:
        top_chains = [p.model_dump(mode="json") for p in priorities[:5]]
        priority_matrix = [
            {"rank": p.rank, "chain_id": p.chain_id, "title": p.title,
             "score": p.score, "priority": p.priority, "confidence": p.confidence,
             "impact": p.impact, "exploitability": p.exploitability}
            for p in priorities
        ]
        business_impacts = self._aggregate_business_impacts(chains)
        technical_impacts = self._aggregate_technical_impacts(chains)

        overall_score = self._calculate_overall(chains)
        risk_level = self._classify_overall(overall_score)

        attack_graph_summary = {
            "total_nodes": len(nodes),
            "total_edges": len(edges),
            "node_types": self._count_node_types(nodes),
            "edge_types": self._count_edge_types(edges),
        }

        report = AttackChainReport(
            target=target,
            project=project,
            total_signals=len(signals),
            total_nodes=len(nodes),
            total_edges=len(edges),
            total_chains=len(chains),
            signals=[s.model_dump(mode="json") for s in signals],
            graph={"nodes": [n.model_dump(mode="json") for n in nodes],
                   "edges": [e.model_dump(mode="json") for e in edges]},
            chains=[c.model_dump(mode="json") for c in chains],
            priorities=[p.model_dump(mode="json") for p in priorities],
            top_chains=top_chains,
            priority_matrix=priority_matrix,
            business_impact_summary=business_impacts,
            technical_impact_summary=technical_impacts,
            attack_graph_summary=attack_graph_summary,
            overall_score=overall_score,
            risk_level=risk_level,
        )

        logger.info(
            "ATTACK_CHAIN_REPORT target={} chains={} score={} risk={}",
            target, len(chains), overall_score, risk_level,
        )
        return report

    def _aggregate_business_impacts(
        self, chains: list[AttackChainPath],
    ) -> list[dict[str, Any]]:
        impact_counts: dict[str, dict[str, Any]] = {}
        for c in chains:
            for bi in c.business_impact:
                if bi not in impact_counts:
                    impact_counts[bi] = {"impact": bi, "count": 0, "chains": []}
                impact_counts[bi]["count"] += 1
                impact_counts[bi]["chains"].append(c.title)
        return sorted(impact_counts.values(), key=lambda x: x["count"], reverse=True)

    def _aggregate_technical_impacts(
        self, chains: list[AttackChainPath],
    ) -> list[str]:
        seen: set[str] = set()
        impacts: list[str] = []
        for c in chains:
            for ti in c.technical_impact:
                if ti not in seen:
                    seen.add(ti)
                    impacts.append(ti)
        return impacts

    def _calculate_overall(self, chains: list[AttackChainPath]) -> float:
        if not chains:
            return 0.0
        return round(sum(c.score for c in chains) / len(chains), 2)

    def _classify_overall(self, score: float) -> str:
        if score >= 80:
            return "critical"
        if score >= 60:
            return "high"
        if score >= 40:
            return "medium"
        return "low"

    def _count_node_types(self, nodes: list[AttackChainNode]) -> dict[str, int]:
        counts: dict[str, int] = {}
        for n in nodes:
            key = n.node_type.value
            counts[key] = counts.get(key, 0) + 1
        return counts

    def _count_edge_types(self, edges: list[AttackChainEdge]) -> dict[str, int]:
        counts: dict[str, int] = {}
        for e in edges:
            key = e.edge_type.value
            counts[key] = counts.get(key, 0) + 1
        return counts
