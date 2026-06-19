"""Pentest recommendation engine — generates next steps for the assessment."""

from __future__ import annotations

from typing import Any

from ghostmirror.core.logger import get_logger
from ghostmirror.models.intelligence_report import PentestRecommendation

logger = get_logger()


class RecommendationEngine:
    """Generates prioritized pentest recommendations based on intelligence data."""

    @staticmethod
    def generate(
        cms_list: list[str],
        databases: list[str],
        frameworks: list[str],
        open_ports: list[int],
        critical_findings: int,
        high_findings: int,
        medium_findings: int,
        cve_count: int,
        exploit_available: bool,
        waf_detected: bool,
        dns_issues: list[str],
        technologies_count: int,
    ) -> list[PentestRecommendation]:
        recommendations: list[PentestRecommendation] = []
        refs: list[str] = []

        if critical_findings > 0 or high_findings > 3 or (cve_count > 5 and exploit_available):
            refs = []
            if critical_findings > 0:
                refs.append(f"{critical_findings} critical findings")
            if cve_count > 5:
                refs.append(f"{cve_count} CVEs with public exploits")
            recommendations.append(PentestRecommendation(
                assessment_type="Web Application Penetration Test",
                priority="Critical",
                justification=(
                    f"Target has {critical_findings} critical and {high_findings} high findings "
                    f"with {cve_count} correlated CVEs. "
                    "A full-scope web application penetration test is required to validate exploitability."
                ),
                findings_reference=refs,
            ))

        if databases or [p for p in open_ports if p in (3306, 5432, 27017, 6379, 9200)]:
            recommendations.append(PentestRecommendation(
                assessment_type="Database Security Assessment",
                priority="High" if critical_findings > 0 else "Medium",
                justification=(
                    f"Database services detected: {', '.join(databases)}. "
                    "Assess exposure, authentication, and configuration."
                ),
                findings_reference=[f"Ports: {[p for p in open_ports if p in (3306, 5432, 27017, 6379, 9200)]}"],
            ))

        if cms_list:
            recommendations.append(PentestRecommendation(
                assessment_type="CMS Security Review",
                priority="High",
                justification=(
                    f"CMS platforms detected: {', '.join(cms_list)}. "
                    "CMS platforms are frequent targets for automated attacks and plugin vulnerabilities."
                ),
                findings_reference=[f"CMS: {cms_list}"],
            ))

        if not waf_detected:
            recommendations.append(PentestRecommendation(
                assessment_type="WAF Implementation Review",
                priority="Medium",
                justification=(
                    "No Web Application Firewall detected. "
                    "Implementing a WAF provides critical protection against common attack patterns."
                ),
                findings_reference=[],
            ))

        if dns_issues:
            recommendations.append(PentestRecommendation(
                assessment_type="Email Security Assessment",
                priority="Medium",
                justification=(
                    f"DNS configuration issues: {', '.join(dns_issues)}. "
                    "Missing SPF/DMARC/DKIM records expose the domain to email spoofing."
                ),
                findings_reference=dns_issues,
            ))

        recommendations.append(PentestRecommendation(
            assessment_type="Configuration Review",
            priority="Medium",
            justification=(
                f"Target has {technologies_count} technologies and {len(open_ports)} open ports. "
                "A configuration review ensures services are hardened."
            ),
            findings_reference=[f"{technologies_count} technologies, {len(open_ports)} ports"],
        ))

        if not recommendations:
            recommendations.append(PentestRecommendation(
                assessment_type="Baseline Security Assessment",
                priority="Low",
                justification="No critical issues identified. A baseline assessment is recommended.",
                findings_reference=[],
            ))

        logger.info("RECOMMENDATIONS_GENERATED count={}", len(recommendations))
        return recommendations
