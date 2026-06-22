from __future__ import annotations

from typing import Any

from ghostmirror.core.logger import get_logger
from ghostmirror.models.hypothesis_report import HypothesisReport

logger = get_logger()


class ZeroDayReportBuilder:
    def build(
        self,
        target: str,
        anomalies: list[dict[str, Any]],
        differential_signals: list[dict[str, Any]],
        hidden_hypotheses: list[dict[str, Any]],
        business_opportunities: list[dict[str, Any]],
        attack_chains: list[dict[str, Any]],
        hypotheses: list[dict[str, Any]],
        opportunities: list[dict[str, Any]],
        research_queue: list[dict[str, Any]],
        recommendations: list[str],
        findings: list[dict[str, Any]],
        overall_score: int,
        risk_level: str,
    ) -> HypothesisReport:
        logger.info("ZERO_DAY_REPORT_BUILDER_START score={}", overall_score)

        return HypothesisReport(
            target=target,
            anomalies=anomalies,
            attack_chains=attack_chains,
            hypotheses=hypotheses,
            opportunities=opportunities,
            research_queue=research_queue,
            overall_score=overall_score,
            risk_level=risk_level,
            total_signals=len(anomalies) + len(differential_signals),
            total_hypotheses=len(hypotheses) + len(hidden_hypotheses),
            total_opportunities=len(opportunities) + len(business_opportunities),
            total_attack_chains=len(attack_chains),
        )
