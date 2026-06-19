"""Consolidated scoring logic for pentest report risk level."""
from __future__ import annotations
from typing import Any
from ghostmirror.modules.models.finding import FindingModel


class ReportScorer:
    """Calculates a normalized 0-100 risk score and classifies the overall threat level."""

    @staticmethod
    def calculate_score(
        all_findings: list[FindingModel],
        risk_profile: dict[str, Any] | None = None,
        vulnerability_profile: dict[str, Any] | None = None,
        owasp_profile: dict[str, Any] | None = None,
        intelligence_report: dict[str, Any] | None = None,
    ) -> tuple[int, str]:
        findings_score = 0
        for finding in all_findings:
            sev = finding.severity.value.upper()
            if sev == "CRITICAL":
                findings_score += 30
            elif sev == "HIGH":
                findings_score += 20
            elif sev == "MEDIUM":
                findings_score += 10
            elif sev == "LOW":
                findings_score += 5
            elif sev == "INFO":
                findings_score += 1

        findings_part = min(findings_score, 100)

        risk_score = 0.0
        if risk_profile:
            risk_score = float(risk_profile.get("risk_score", 0))

        vuln_score = 0.0
        if vulnerability_profile:
            vuln_score = float(vulnerability_profile.get("overall_vulnerability_score", 0))

        owasp_score = 0.0
        if owasp_profile:
            owasp_score = float(owasp_profile.get("risk_score", 0))

        intel_score = 0.0
        if intelligence_report:
            intel_score = float(intelligence_report.get("overall_security_score", 0))

        has_profiles = (risk_profile is not None) or (vulnerability_profile is not None) or (owasp_score > 0) or (intel_score > 0)
        if has_profiles:
            score = (0.35 * findings_part) + (0.10 * risk_score) + (0.10 * vuln_score) + (0.15 * owasp_score) + (0.30 * intel_score)
        else:
            score = float(findings_part)

        normalized_score = min(max(round(score), 0), 100)

        if normalized_score <= 20:
            level = "LOW"
        elif normalized_score <= 40:
            level = "MEDIUM"
        elif normalized_score <= 70:
            level = "HIGH"
        else:
            level = "CRITICAL"

        return normalized_score, level
