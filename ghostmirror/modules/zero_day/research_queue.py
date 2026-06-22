from __future__ import annotations

from typing import Any

from ghostmirror.core.logger import get_logger
from ghostmirror.modules.zero_day.scoring import ZeroDayScoring

logger = get_logger()

PRIORITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
CONFIDENCE_ORDER = {"VERY_HIGH": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


class ResearchQueue:
    def __init__(self) -> None:
        self.queue: list[dict[str, Any]] = []
        self.scoring = ZeroDayScoring()

    def build(
        self,
        hypotheses: list[dict[str, Any]],
        opportunities: list[dict[str, Any]],
        attack_chains: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        logger.info("RESEARCH_QUEUE_BUILD")
        self.queue = []

        items: list[dict[str, Any]] = []

        for h in hypotheses:
            items.append({
                "title": h.get("title", "Unknown"),
                "type": "Hypothesis",
                "subtype": h.get("hypothesis_type", ""),
                "confidence": h.get("confidence", "LOW"),
                "priority": h.get("impact", "LOW"),
                "score": h.get("score", 0),
                "source": "hypothesis_builder",
                "summary": h.get("reasoning", "")[:200],
            })

        for o in opportunities:
            items.append({
                "title": o.get("title", "Unknown"),
                "type": "Opportunity",
                "subtype": o.get("opportunity_type", ""),
                "confidence": o.get("confidence", "LOW"),
                "priority": o.get("priority", "LOW"),
                "score": o.get("score", 0),
                "source": "opportunity_engine",
                "summary": o.get("description", "")[:200],
            })

        for ac in attack_chains:
            items.append({
                "title": ac.get("title", "Unknown"),
                "type": "Attack Chain",
                "subtype": "Attack Chain",
                "confidence": ac.get("confidence", "LOW"),
                "priority": ac.get("severity", "LOW"),
                "score": ac.get("score", 0),
                "source": "attack_chain_engine",
                "summary": ac.get("description", "")[:200],
            })

        self.queue = self._sort_queue(items)

        logger.info("RESEARCH_QUEUE_DONE items={}", len(self.queue))
        return self.queue

    def _sort_queue(self, items: list[dict[str, Any]]) -> list[dict[str, Any]]:
        def sort_key(item: dict[str, Any]) -> tuple:
            prio = PRIORITY_ORDER.get(item.get("priority", "LOW"), 99)
            conf = CONFIDENCE_ORDER.get(item.get("confidence", "LOW"), 99)
            score = -item.get("score", 0)
            return (prio, conf, score)

        items.sort(key=sort_key)
        return items
