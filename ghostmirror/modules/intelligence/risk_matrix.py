"""Risk matrix generator — Likelihood, Impact, Exploitability, Exposure, Business Risk."""

from __future__ import annotations

from typing import Any

from ghostmirror.core.logger import get_logger
from ghostmirror.models.intelligence_report import RiskMatrix, RiskMatrixEntry

logger = get_logger()


class RiskMatrixGenerator:
    """Generates a 5-dimension risk matrix from scan intelligence."""

    @staticmethod
    def generate(
        attack_surface_score: int,
        critical_findings: int,
        high_findings: int,
        medium_findings: int,
        total_findings: int,
        cve_count: int,
        exploit_available: bool = False,
        kev_count: int = 0,
        open_ports_count: int = 0,
        waf_detected: bool = False,
        cdn_detected: bool = False,
    ) -> RiskMatrix:
        def _level(score: int) -> str:
            if score <= 20:
                return "Low"
            if score <= 40:
                return "Medium"
            if score <= 70:
                return "High"
            return "Critical"

        likelihood_score = 0
        likelihood_score += min(critical_findings * 10, 30)
        likelihood_score += min(high_findings * 5, 20)
        likelihood_score += min(medium_findings * 2, 10)
        likelihood_score += min(open_ports_count * 2, 20)
        likelihood_score += 10 if exploit_available else 0
        likelihood_score = min(likelihood_score, 100)
        likelihood = RiskMatrixEntry(
            category="Likelihood",
            score=likelihood_score,
            level=_level(likelihood_score),
            description=f"Based on {total_findings} findings, {critical_findings} critical, {open_ports_count} open ports",
        )

        impact_score = 0
        impact_score += min(critical_findings * 15, 40)
        impact_score += min(high_findings * 8, 25)
        impact_score += min(kev_count * 10, 20)
        impact_score += 15 if exploit_available else 0
        impact_score = min(impact_score, 100)
        impact = RiskMatrixEntry(
            category="Impact",
            score=impact_score,
            level=_level(impact_score),
            description=f"Based on {cve_count} CVEs, {kev_count} KEV, {critical_findings} critical findings",
        )

        exploitability_score = 0
        exploitability_score += 30 if exploit_available else 0
        exploitability_score += min(kev_count * 15, 30)
        exploitability_score += min(cve_count * 5, 20)
        exploitability_score += min(open_ports_count * 3, 20)
        exploitability_score = min(exploitability_score, 100)
        exploitability = RiskMatrixEntry(
            category="Exploitability",
            score=exploitability_score,
            level=_level(exploitability_score),
            description=f"Exploit available: {exploit_available}, KEV: {kev_count}, CVE count: {cve_count}",
        )

        exposure_score = attack_surface_score
        if waf_detected:
            exposure_score = max(0, exposure_score - 15)
        if cdn_detected:
            exposure_score = max(0, exposure_score - 10)
        exposure = RiskMatrixEntry(
            category="Exposure",
            score=exposure_score,
            level=_level(exposure_score),
            description=f"Attack surface score: {attack_surface_score}",
        )

        business_risk_score = round(
            (likelihood_score * 0.2)
            + (impact_score * 0.3)
            + (exploitability_score * 0.2)
            + (exposure_score * 0.3)
        )
        business_risk = RiskMatrixEntry(
            category="Business Risk",
            score=business_risk_score,
            level=_level(business_risk_score),
            description="Weighted combination of Likelihood, Impact, Exploitability, and Exposure",
        )

        overall_level = _level(business_risk_score)

        logger.info(
            "RISK_MATRIX_GENERATED likelihood={} impact={} exploitability={} exposure={} business={} overall={}",
            likelihood.level,
            impact.level,
            exploitability.level,
            exposure.level,
            business_risk.level,
            overall_level,
        )

        return RiskMatrix(
            likelihood=likelihood,
            impact=impact,
            exploitability=exploitability,
            exposure=exposure,
            business_risk=business_risk,
            overall_level=overall_level,
        )
