from __future__ import annotations

from typing import Any

from ghostmirror.core.logger import get_logger
from ghostmirror.models.finding_confidence import ConfidenceLevel
from ghostmirror.models.web_indicator import SeverityLevel
from ghostmirror.models.web_intelligence_report import CorrelationResult, OpportunityScore

logger = get_logger()


class WebScoringEngine:
    def calculate_opportunities(
        self,
        correlations: list[CorrelationResult],
    ) -> list[OpportunityScore]:
        logger.info("WEB_SCORING_START correlations={}", len(correlations))
        opportunities: list[OpportunityScore] = []

        for corr in correlations:
            score = self._apply_modifiers(corr)
            opportunities.append(OpportunityScore(
                title=corr.title,
                score=score,
                classification=self._classify(score),
                correlation_ref=corr.correlation_type,
                endpoint=corr.endpoint,
                indicator_type=corr.correlation_type,
                summary=f"{corr.description} (Score: {score}/100)",
            ))

        opportunities.sort(key=lambda o: o.score, reverse=True)
        logger.info("WEB_SCORING_DONE total={}", len(opportunities))
        return opportunities

    def _apply_modifiers(self, corr: CorrelationResult) -> int:
        score = corr.score

        # Boost for OWASP Top 1 categories
        owasp_boost = {
            "A01": 10,
            "A03": 8,
            "A10": 5,
        }
        for code, boost in owasp_boost.items():
            if code in corr.owasp_category:
                score += boost
                break

        # Boost for critical/high classification
        if corr.classification == "CRITICAL":
            score += 10
        elif corr.classification == "HIGH":
            score += 5

        score = max(0, min(100, score))
        return score

    def _classify(self, score: int) -> str:
        if score >= 76:
            return "CRITICAL"
        if score >= 51:
            return "HIGH"
        if score >= 26:
            return "MEDIUM"
        return "LOW"
