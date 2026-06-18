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
    ) -> tuple[int, str]:
        """Consolidates findings and profile scores, normalizing to 0-100.

        Parameters
        ----------
        all_findings : list[FindingModel]
            Aggregated unique findings from all modules.
        risk_profile : dict[str, Any] | None
            Technology risk profile data if standard/deep scan.
        vulnerability_profile : dict[str, Any] | None
            Vulnerability risk profile data if standard/deep scan.

        Returns
        -------
        tuple[int, str]
            Normalized score (0-100) and risk level classification ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL').
        """
        # 1. Findings severity scoring
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

        # Cap findings component at 100
        findings_part = min(findings_score, 100)

        # 2. Extract profile scores
        risk_score = 0.0
        if risk_profile:
            risk_score = float(risk_profile.get("risk_score", 0))

        vuln_score = 0.0
        if vulnerability_profile:
            vuln_score = float(
                vulnerability_profile.get("overall_vulnerability_score", 0)
            )

        owasp_score = 0.0
        if owasp_profile:
            owasp_score = float(owasp_profile.get("risk_score", 0))

        # 3. Blending components if profiles are present
        has_profiles = (risk_profile is not None) or (
            vulnerability_profile is not None
        ) or (owasp_score > 0)
        if has_profiles:
            # Findings (50%), Risk Profile (15%), Vulnerability Profile (15%), OWASP (20%)
            score = (0.5 * findings_part) + (0.15 * risk_score) + (0.15 * vuln_score) + (0.2 * owasp_score)
        else:
            score = float(findings_part)

        # Normalize to 0-100 range
        normalized_score = min(max(round(score), 0), 100)

        # Classification rules
        if normalized_score <= 20:
            level = "LOW"
        elif normalized_score <= 40:
            level = "MEDIUM"
        elif normalized_score <= 70:
            level = "HIGH"
        else:
            level = "CRITICAL"

        return normalized_score, level
