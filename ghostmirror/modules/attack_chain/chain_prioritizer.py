from __future__ import annotations

from typing import Any

from ghostmirror.models.attack_chain_path import AttackChainPath
from ghostmirror.models.attack_chain_priority import AttackChainPriority


class ChainPrioritizer:
    def prioritize(
        self, chains: list[AttackChainPath],
    ) -> list[AttackChainPriority]:
        scored = []
        for chain in chains:
            priority = self._determine_priority(chain)
            scored.append(AttackChainPriority(
                chain_id=chain.id,
                title=chain.title,
                score=chain.score,
                confidence=chain.confidence,
                likelihood=chain.likelihood,
                impact=chain.impact,
                exploitability=chain.exploitability,
                business_impact=chain.business_impact,
                priority=priority,
                rank=0,
            ))

        scored.sort(
            key=lambda p: (
                self._priority_order(p.priority),
                p.score,
                p.confidence,
                len(p.business_impact),
                p.exploitability,
            ),
            reverse=True,
        )

        for i, p in enumerate(scored):
            p.rank = i + 1

        return scored

    def _determine_priority(self, chain: AttackChainPath) -> str:
        if chain.score >= 80 or chain.confidence >= 0.9:
            return "critical"
        if chain.score >= 60 or chain.confidence >= 0.7:
            return "high"
        if chain.score >= 40 or chain.confidence >= 0.5:
            return "medium"
        return "low"

    def _priority_order(self, priority: str) -> int:
        return {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(priority, 0)
