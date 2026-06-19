"""Tests for the Scoring Engine module."""
from __future__ import annotations

import pytest

from ghostmirror.models.attack_surface_profile import (
    AttackSurfaceProfile,
    CDNProfile,
    DNSProfile,
    HostingProfile,
    WAFProfile,
)
from ghostmirror.modules.intelligence.scoring import ScoringEngine, classify_score


class TestClassifyScore:
    def test_minimal(self) -> None:
        assert classify_score(0) == "Minimal"
        assert classify_score(20) == "Minimal"

    def test_low(self) -> None:
        assert classify_score(21) == "Low"
        assert classify_score(40) == "Low"

    def test_medium(self) -> None:
        assert classify_score(41) == "Medium"
        assert classify_score(60) == "Medium"

    def test_high(self) -> None:
        assert classify_score(61) == "High"
        assert classify_score(80) == "High"

    def test_critical(self) -> None:
        assert classify_score(81) == "Critical"
        assert classify_score(100) == "Critical"


class TestCalculateAttackSurfaceScore:
    def test_minimal_ports_no_tech(self) -> None:
        profile = AttackSurfaceProfile(
            target="test.com",
            waf=WAFProfile(detected=True, vendor="Cloudflare"),
            cdn=CDNProfile(detected=True, vendor="Cloudflare"),
            dns=DNSProfile(),
        )
        score, classification = ScoringEngine.calculate_attack_surface_score(profile)
        assert score <= 20
        assert classification == "Minimal"

    def test_high_exposure(self) -> None:
        profile = AttackSurfaceProfile(
            target="test.com",
            open_ports=[22, 80, 443, 3306, 5432, 6379, 8080, 8443, 9200, 27017, 11211, 25],
            services_exposed=["ssh", "http", "https", "mysql", "postgresql"],
            technologies=["nginx", "php", "wordpress", "mysql", "phpmyadmin", "redis"],
            cms=["WordPress"],
            databases=["MySQL", "Redis"],
            dns=DNSProfile(spf_missing=True, dmarc_missing=True, dkim_missing=True),
        )
        score, classification = ScoringEngine.calculate_attack_surface_score(profile)
        assert score > 60
        assert classification in ("High", "Critical")

    def test_waf_cdn_reduces_score(self) -> None:
        with_waf = AttackSurfaceProfile(
            target="test.com",
            open_ports=[80, 443],
            waf=WAFProfile(detected=True, vendor="Cloudflare"),
            cdn=CDNProfile(detected=True, vendor="Cloudflare"),
        )
        without_waf = AttackSurfaceProfile(
            target="test.com",
            open_ports=[80, 443],
        )
        score_with, _ = ScoringEngine.calculate_attack_surface_score(with_waf)
        score_without, _ = ScoringEngine.calculate_attack_surface_score(without_waf)
        assert score_with < score_without

    def test_dns_issues_add_score(self) -> None:
        clean = AttackSurfaceProfile(target="test.com")
        dirty = AttackSurfaceProfile(
            target="test.com",
            dns=DNSProfile(spf_missing=True, dmarc_missing=True),
        )
        score_clean, _ = ScoringEngine.calculate_attack_surface_score(clean)
        score_dirty, _ = ScoringEngine.calculate_attack_surface_score(dirty)
        assert score_dirty > score_clean


class TestCalculateRiskScore:
    def test_low_risk(self) -> None:
        score, level = ScoringEngine.calculate_risk_score(
            attack_surface_score=10,
            findings_count=1,
            critical_findings=0,
            high_findings=0,
            medium_findings=0,
            cve_count=0,
        )
        assert score <= 20
        assert level in ("Minimal", "Low")

    def test_critical_risk(self) -> None:
        score, level = ScoringEngine.calculate_risk_score(
            attack_surface_score=80,
            findings_count=20,
            critical_findings=5,
            high_findings=10,
            medium_findings=5,
            cve_count=15,
            exploit_available=True,
            kev_listed=True,
        )
        assert score > 60

    def test_exploit_available_increases_score(self) -> None:
        base_score, _ = ScoringEngine.calculate_risk_score(
            attack_surface_score=30,
            findings_count=5,
            critical_findings=1,
            high_findings=2,
            medium_findings=2,
            cve_count=5,
            exploit_available=False,
        )
        exploit_score, _ = ScoringEngine.calculate_risk_score(
            attack_surface_score=30,
            findings_count=5,
            critical_findings=1,
            high_findings=2,
            medium_findings=2,
            cve_count=5,
            exploit_available=True,
        )
        assert exploit_score > base_score

    def test_score_bounded(self) -> None:
        score, _ = ScoringEngine.calculate_risk_score(
            attack_surface_score=100,
            findings_count=999,
            critical_findings=999,
            high_findings=999,
            medium_findings=999,
            cve_count=999,
        )
        assert 0 <= score <= 100


class TestOverallSecurityScore:
    def test_blend(self) -> None:
        score, level = ScoringEngine.overall_security_score(
            attack_surface_score=50,
            risk_score=60,
            findings_score=40,
        )
        assert 0 <= score <= 100
        assert level in ("Minimal", "Low", "Medium", "High", "Critical")
