from __future__ import annotations

from typing import Any

from ghostmirror.core.logger import get_logger

logger = get_logger()


class ZeroDayRecommendations:
    def __init__(self) -> None:
        pass

    def generate(
        self,
        anomalies: list[dict[str, Any]],
        attack_chains: list[dict[str, Any]],
        hypotheses: list[dict[str, Any]],
        opportunities: list[dict[str, Any]],
        overall_score: int,
    ) -> list[str]:
        recommendations: list[str] = []

        if overall_score >= 76:
            recommendations.append(
                "CRITICAL: Immediate manual investigation required. Multiple high-confidence signals indicate significant attack surface."
            )
        elif overall_score >= 51:
            recommendations.append(
                "HIGH: Prioritize manual testing based on the research queue. Focus on high-value attack chains first."
            )

        if anomalies:
            high_anomalies = [a for a in anomalies if a.get("severity") in ("CRITICAL", "HIGH")]
            if high_anomalies:
                recommendations.append(
                    f"Review {len(high_anomalies)} high-severity anomalies for authentication and authorization bypass."
                )

        if attack_chains:
            recommendations.append(
                f"Validate {len(attack_chains)} attack chain(s) starting with the highest confidence items."
            )

        if opportunities:
            bl_opps = [o for o in opportunities if o.get("opportunity_type") == "Business Logic Research"]
            if bl_opps:
                recommendations.append(
                    f"Map and manually test {len(bl_opps)} business logic flow(s) for parameter manipulation and race conditions."
                )

        hidden_hypotheses = [h for h in hypotheses if "Hidden" in h.get("hypothesis_type", "")]
        if hidden_hypotheses:
            recommendations.append(
                f"Investigate {len(hidden_hypotheses)} hidden functionality hypothesis(es) - review client-side code and feature flag activation."
            )

        auth_hypotheses = [h for h in hypotheses if "Authorization" in h.get("hypothesis_type", "")]
        if auth_hypotheses:
            recommendations.append(
                f"Perform comprehensive authorization testing based on {len(auth_hypotheses)} authorization hypothesis(es)."
            )

        if not recommendations:
            recommendations.append(
                "No significant research opportunities identified. Continue with standard security testing."
            )

        return recommendations
