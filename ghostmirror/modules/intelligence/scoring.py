"""Scoring engine — Attack Surface Score and Risk Score calculations."""

from __future__ import annotations

from typing import Any

from ghostmirror.models.attack_surface_profile import AttackSurfaceProfile


def classify_score(score: int) -> str:
    if score <= 20:
        return "Minimal"
    if score <= 40:
        return "Low"
    if score <= 60:
        return "Medium"
    if score <= 80:
        return "High"
    return "Critical"


class ScoringEngine:
    """Calculates normalized security and attack surface scores."""

    @staticmethod
    def calculate_attack_surface_score(profile: AttackSurfaceProfile) -> tuple[int, str]:
        score = 0

        num_ports = len(profile.open_ports)
        if num_ports <= 3:
            score += 10
        elif num_ports <= 10:
            score += 25
        elif num_ports <= 25:
            score += 45
        else:
            score += 60

        num_services = len(profile.services_exposed)
        if num_services <= 3:
            score += 5
        elif num_services <= 10:
            score += 15
        else:
            score += 30

        if profile.waf.detected:
            score -= 15
        if profile.cdn.detected:
            score -= 10

        tech_count = len(profile.technologies)
        if tech_count >= 10:
            score += 20
        elif tech_count >= 5:
            score += 10

        if profile.cms:
            score += 15
        if profile.databases:
            score += 15
        if profile.frameworks:
            score += 5

        dns_issues = sum([profile.dns.spf_missing, profile.dns.dmarc_missing, profile.dns.dkim_missing])
        score += dns_issues * 5

        if profile.dns.findings:
            score += len(profile.dns.findings) * 3

        final_score = max(0, min(100, score))
        classification = classify_score(final_score)
        return final_score, classification

    @staticmethod
    def calculate_risk_score(
        attack_surface_score: int,
        findings_count: int,
        critical_findings: int,
        high_findings: int,
        medium_findings: int,
        cve_count: int,
        exploit_available: bool = False,
        kev_listed: bool = False,
    ) -> tuple[int, str]:
        score = float(attack_surface_score) * 0.3

        findings_score = 0
        findings_score += critical_findings * 25
        findings_score += high_findings * 15
        findings_score += medium_findings * 8
        findings_score = min(findings_score, 40)
        score += findings_score

        cve_score = min(cve_count * 5, 20)
        score += cve_score

        if exploit_available:
            score += 10
        if kev_listed:
            score += 10

        final_score = max(0, min(100, round(score)))
        classification = classify_score(final_score)
        return final_score, classification

    @staticmethod
    def overall_security_score(
        attack_surface_score: int,
        risk_score: int,
        findings_score: int = 0,
    ) -> tuple[int, str]:
        blended = (attack_surface_score * 0.25) + (risk_score * 0.50) + (findings_score * 0.25)
        final_score = max(0, min(100, round(blended)))
        classification = classify_score(final_score)
        return final_score, classification
