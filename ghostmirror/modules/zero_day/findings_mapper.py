from __future__ import annotations

from typing import Any

from ghostmirror.core.logger import get_logger

logger = get_logger()


class ZeroDayFindingsMapper:
    def __init__(self) -> None:
        pass

    def map_to_findings(
        self,
        anomalies: list[dict[str, Any]],
        attack_chains: list[dict[str, Any]],
        hypotheses: list[dict[str, Any]],
        opportunities: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []

        for anomaly in anomalies:
            findings.append(self._anomaly_to_finding(anomaly))

        for chain in attack_chains:
            findings.append(self._chain_to_finding(chain))

        for hypothesis in hypotheses:
            findings.append(self._hypothesis_to_finding(hypothesis))

        for opportunity in opportunities:
            findings.append(self._opportunity_to_finding(opportunity))

        findings.sort(key=lambda f: f.get("score", 0), reverse=True)
        logger.info("FINDINGS_MAPPER_DONE total={}", len(findings))
        return findings

    def _anomaly_to_finding(self, anomaly: dict[str, Any]) -> dict[str, Any]:
        return {
            "title": anomaly.get("title", "Anomaly Detected"),
            "description": anomaly.get("description", ""),
            "severity": anomaly.get("severity", "LOW"),
            "confidence": anomaly.get("confidence", "LOW"),
            "score": anomaly.get("score", 0),
            "category": "zero_day_anomaly",
            "affected_asset": anomaly.get("endpoint", ""),
            "recommendation": "Manual validation required for this anomaly.",
            "source": "zero_day_anomaly_engine",
            "type": "Zero-Day Hypothesis / Anomaly",
        }

    def _chain_to_finding(self, chain: dict[str, Any]) -> dict[str, Any]:
        return {
            "title": chain.get("title", "Attack Chain Detected"),
            "description": chain.get("description", ""),
            "severity": chain.get("severity", "LOW"),
            "confidence": chain.get("confidence", "LOW"),
            "score": chain.get("score", 0),
            "category": "zero_day_attack_chain",
            "affected_asset": "; ".join(chain.get("components", [])),
            "recommendation": chain.get("recommendation", "Manual validation required."),
            "source": "zero_day_attack_chain_engine",
            "type": "Zero-Day Hypothesis / Attack Chain",
        }

    def _hypothesis_to_finding(self, hypothesis: dict[str, Any]) -> dict[str, Any]:
        return {
            "title": hypothesis.get("title", "Zero-Day Hypothesis"),
            "description": hypothesis.get("reasoning", ""),
            "severity": hypothesis.get("impact", "LOW"),
            "confidence": hypothesis.get("confidence", "LOW"),
            "score": hypothesis.get("score", 0),
            "category": "zero_day_hypothesis",
            "affected_asset": "; ".join(hypothesis.get("signals", [])),
            "recommendation": hypothesis.get("recommendation", "Manual validation required."),
            "source": "zero_day_hypothesis_builder",
            "type": "Zero-Day Hypothesis",
        }

    def _opportunity_to_finding(self, opportunity: dict[str, Any]) -> dict[str, Any]:
        return {
            "title": opportunity.get("title", "Research Opportunity"),
            "description": opportunity.get("description", ""),
            "severity": opportunity.get("priority", "LOW"),
            "confidence": opportunity.get("confidence", "LOW"),
            "score": opportunity.get("score", 0),
            "category": "zero_day_opportunity",
            "affected_asset": "; ".join(opportunity.get("signals", [])),
            "recommendation": opportunity.get("recommendation", "Manual validation required."),
            "source": "zero_day_business_logic_engine",
            "type": "Zero-Day Hypothesis / Research Opportunity",
        }
