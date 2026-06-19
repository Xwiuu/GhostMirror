"""Tests for the Attack Surface Intelligence module."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from ghostmirror.models.attack_surface_profile import (
    AttackSurfaceProfile,
    CDNProfile,
    DNSFinding,
    DNSProfile,
    HostingProfile,
    WAFProfile,
)
from ghostmirror.models.fingerprint import FingerprintProfile
from ghostmirror.models.technology import TechnologyModel
from ghostmirror.modules.intelligence.attack_surface import AttackSurfaceAnalyzer


class TestAttackSurfaceAnalyzer:
    def test_waf_detection_from_tech_profile(self) -> None:
        tech_profile = FingerprintProfile(
            target="example.com",
            technologies=[
                TechnologyModel(name="Cloudflare", category="WAF", confidence=1.0, source="test"),
            ],
        )
        analyzer = AttackSurfaceAnalyzer()
        result = analyzer._detect_waf(tech_profile, None)
        assert result.detected is True
        assert result.vendor == "Cloudflare"
        assert result.confidence >= 80

    def test_waf_detection_from_waf_field(self) -> None:
        tech_profile = FingerprintProfile(
            target="example.com",
            waf="Cloudflare",
            technologies=[],
        )
        analyzer = AttackSurfaceAnalyzer()
        result = analyzer._detect_waf(tech_profile, None)
        assert result.detected is True
        assert result.vendor == "Cloudflare"

    def test_waf_not_detected(self) -> None:
        tech_profile = FingerprintProfile(
            target="example.com",
            technologies=[
                TechnologyModel(name="Nginx", category="WEB SERVER", confidence=1.0, source="test"),
            ],
        )
        analyzer = AttackSurfaceAnalyzer()
        result = analyzer._detect_waf(tech_profile, None)
        assert result.detected is False

    def test_cdn_detection(self) -> None:
        tech_profile = FingerprintProfile(
            target="example.com",
            technologies=[
                TechnologyModel(name="Cloudflare", category="CDN", confidence=1.0, source="test"),
            ],
        )
        analyzer = AttackSurfaceAnalyzer()
        result = analyzer._detect_cdn(tech_profile, None)
        assert result.detected is True
        assert result.vendor == "Cloudflare"

    def test_cdn_detection_from_cdn_field(self) -> None:
        tech_profile = FingerprintProfile(
            target="example.com",
            cdn="Fastly",
            technologies=[],
        )
        analyzer = AttackSurfaceAnalyzer()
        result = analyzer._detect_cdn(tech_profile, None)
        assert result.detected is True
        assert result.vendor == "Fastly"

    def test_hosting_detection(self) -> None:
        tech_profile = FingerprintProfile(
            target="example.com",
            hosting="AWS",
            technologies=[],
        )
        analyzer = AttackSurfaceAnalyzer()
        result = analyzer._detect_hosting(tech_profile, None)
        assert result.detected is True
        assert result.provider == "AWS"

    def test_analyze_creates_full_profile(self) -> None:
        analyzer = AttackSurfaceAnalyzer()
        result = analyzer.analyze(
            target="example.com",
            technology_profile=FingerprintProfile(
                target="example.com",
                technologies=[
                    TechnologyModel(name="Nginx", category="WEB SERVER", confidence=1.0, source="test"),
                    TechnologyModel(name="WordPress", category="CMS", confidence=1.0, source="test"),
                    TechnologyModel(name="MySQL", category="DATABASE", confidence=1.0, source="test"),
                ],
            ),
            nmap_findings={"open_ports": [80, 443, 3306], "services": ["http", "https", "mysql"]},
        )
        assert result.target == "example.com"
        assert "Nginx" in result.web_servers
        assert "WordPress" in result.cms
        assert "MySQL" in result.databases
        assert 3306 in result.open_ports
        assert "WordPress/admin" in result.potential_entry_points[0]

    def test_dns_finding_model(self) -> None:
        finding = DNSFinding(record_type="SPF", status="MISSING", details="SPF record not found")
        assert finding.record_type == "SPF"
        assert finding.status == "MISSING"

    def test_waf_profile_model(self) -> None:
        waf = WAFProfile(detected=True, vendor="Cloudflare", confidence=95)
        assert waf.detected is True
        assert waf.vendor == "Cloudflare"
        assert waf.confidence == 95

    def test_cdn_profile_model(self) -> None:
        cdn = CDNProfile(detected=True, vendor="Fastly", confidence=88)
        assert cdn.detected is True
        assert cdn.vendor == "Fastly"

    def test_hosting_profile_model(self) -> None:
        hosting = HostingProfile(detected=True, provider="AWS", confidence=90)
        assert hosting.detected is True
        assert hosting.provider == "AWS"

    def test_attack_surface_profile_model(self) -> None:
        profile = AttackSurfaceProfile(
            target="example.com",
            web_servers=["nginx"],
            technologies=["nginx", "php"],
            attack_surface_score=45,
            classification="Medium",
        )
        assert profile.target == "example.com"
        assert profile.attack_surface_score == 45
        assert profile.classification == "Medium"

