from __future__ import annotations

from typing import Any

from ghostmirror.core.logger import get_logger

logger = get_logger()


class ZeroDayScoring:
    def __init__(self) -> None:
        self.overall_score = 0
        self.risk_level = "LOW"

    def calculate_overall_score(
        self,
        anomalies: list[dict[str, Any]],
        attack_chains: list[dict[str, Any]],
        hypotheses: list[dict[str, Any]],
        opportunities: list[dict[str, Any]],
        exposure_score: int = 0,
        api_score: int = 0,
        web_score: int = 0,
    ) -> tuple[int, str]:
        anomaly_score = self._calculate_anomaly_score(anomalies)
        attack_chain_score = self._calculate_attack_chain_score(attack_chains)
        business_logic_score = self._calculate_business_logic_score(opportunities)
        hypothesis_score = self._calculate_hypothesis_score(hypotheses)

        logger.info(
            "ZERO_DAY_SCORING anomaly={} attack_chain={} biz_logic={} hypothesis={} exposure={} api={} web={}",
            anomaly_score, attack_chain_score, business_logic_score,
            hypothesis_score, exposure_score, api_score, web_score,
        )

        self.overall_score = round(
            anomaly_score * 0.25
            + attack_chain_score * 0.25
            + hypothesis_score * 0.20
            + business_logic_score * 0.15
            + exposure_score * 0.10
            + max(api_score, web_score) * 0.05
        )

        self.overall_score = min(self.overall_score, 100)
        self.risk_level = self.classify_score(self.overall_score)

        logger.info("ZERO_DAY_SCORING_DONE score={} risk={}", self.overall_score, self.risk_level)
        return self.overall_score, self.risk_level

    def _calculate_anomaly_score(self, anomalies: list[dict[str, Any]]) -> int:
        if not anomalies:
            return 0
        scores = [a.get("score", 0) for a in anomalies if a.get("score")]
        if not scores:
            return 0
        return round(sum(scores) / len(scores))

    def _calculate_attack_chain_score(self, attack_chains: list[dict[str, Any]]) -> int:
        if not attack_chains:
            return 0
        scores = [c.get("score", 0) for c in attack_chains if c.get("score")]
        if not scores:
            return 0
        return round(sum(scores) / len(scores))

    def _calculate_business_logic_score(self, opportunities: list[dict[str, Any]]) -> int:
        if not opportunities:
            return 0
        bl_opps = [o for o in opportunities if o.get("opportunity_type") == "Business Logic Research"]
        if not bl_opps:
            return 0
        scores = [o.get("score", 0) for o in bl_opps if o.get("score")]
        return round(sum(scores) / len(scores)) if scores else 0

    def _calculate_hypothesis_score(self, hypotheses: list[dict[str, Any]]) -> int:
        if not hypotheses:
            return 0
        scores = [h.get("score", 0) for h in hypotheses if h.get("score")]
        return round(sum(scores) / len(scores)) if scores else 0

    @staticmethod
    def classify_score(score: int) -> str:
        if score >= 76:
            return "CRITICAL"
        if score >= 51:
            return "HIGH"
        if score >= 26:
            return "MEDIUM"
        return "LOW"

    @staticmethod
    def classify_priority(score: int) -> str:
        if score >= 76:
            return "CRITICAL"
        if score >= 51:
            return "HIGH"
        if score >= 26:
            return "MEDIUM"
        return "LOW"
