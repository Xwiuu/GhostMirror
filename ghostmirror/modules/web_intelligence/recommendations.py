from __future__ import annotations

from typing import Any

from ghostmirror.core.logger import get_logger
from ghostmirror.models.web_intelligence_report import OpportunityScore, WebIntelligenceReport

logger = get_logger()


class WebRecommendationEngine:
    def generate(
        self,
        report: WebIntelligenceReport,
    ) -> list[dict[str, Any]]:
        logger.info("WEB_RECOMMENDATIONS_START")
        recommendations: list[dict[str, Any]] = []

        critical_opps = [o for o in report.opportunities if o.classification == "CRITICAL"]
        high_opps = [o for o in report.opportunities if o.classification == "HIGH"]
        secrets_found = bool(report.js_findings and report.js_findings.get("secrets_found"))
        has_auth = bool(report.auth_profile and report.auth_profile.get("has_login"))
        has_admin = bool(report.auth_profile and report.auth_profile.get("has_admin"))

        if critical_opps:
            recommendations.append({
                "priority": "CRITICAL",
                "type": "web_vulnerability",
                "title": f"{len(critical_opps)} Critical Web Vulnerability Opportunities",
                "description": f"Found {len(critical_opps)} high-priority web vulnerability opportunities requiring immediate manual review.",
                "opportunities": [o.title for o in critical_opps],
            })

        if high_opps:
            recommendations.append({
                "priority": "HIGH",
                "type": "web_vulnerability",
                "title": f"{len(high_opps)} High-Priority Web Opportunities",
                "description": f"Found {len(high_opps)} high-priority web vulnerability opportunities for scheduled testing.",
                "opportunities": [o.title for o in high_opps],
            })

        if secrets_found:
            recommendations.append({
                "priority": "CRITICAL",
                "type": "secret_exposure",
                "title": "Secrets Exposed in Client-Side JavaScript",
                "description": "Potential secrets or API keys were found in JavaScript. Rotate any exposed credentials immediately.",
                "opportunities": report.js_findings.get("secrets_found", [])[:5],
            })

        if report.total_endpoints == 0:
            recommendations.append({
                "priority": "INFO",
                "type": "coverage",
                "title": "No Web Endpoints Discovered",
                "description": "The web crawler did not discover any endpoints. Verify the target URL is correct and accessible.",
                "opportunities": [],
            })

        if report.total_indicators == 0:
            recommendations.append({
                "priority": "INFO",
                "type": "coverage",
                "title": "No Vulnerability Indicators Found",
                "description": "No vulnerability indicators were detected. This may indicate a well-secured application or limited crawl coverage.",
                "opportunities": [],
            })
        elif report.total_indicators > 0:
            recommendations.append({
                "priority": "MEDIUM",
                "type": "manual_review",
                "title": f"{report.total_indicators} Potential Indicators Require Manual Validation",
                "description": "Automated indicators need manual validation to confirm actual exploitability.",
                "opportunities": [],
            })

        if has_admin and not has_auth:
            recommendations.append({
                "priority": "HIGH",
                "type": "auth_bypass",
                "title": "Admin Panel Without Login Endpoint",
                "description": "Admin endpoints were found but no login page was detected. Verify authentication is enforced.",
                "opportunities": [],
            })

        logger.info("WEB_RECOMMENDATIONS_DONE total={}", len(recommendations))
        return recommendations
