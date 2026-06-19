from __future__ import annotations

import pytest

from ghostmirror.models.enriched_cve import EnrichedCVEModel
from ghostmirror.modules.vulnerability_intelligence.attack_correlation import (
    AttackCorrelationEngine,
)


@pytest.fixture()
def enriched_cves() -> list[EnrichedCVEModel]:
    return [
        EnrichedCVEModel(
            cve_id="CVE-2021-41773",
            cvss=7.5, severity="HIGH",
            product="Apache HTTP Server", version="2.4.49",
            attack_vector="NETWORK", complexity="LOW",
            privileges_required="NONE", user_interaction=False,
            impact="HIGH",
        ),
        EnrichedCVEModel(
            cve_id="CVE-2021-44228",
            cvss=10.0, severity="CRITICAL",
            product="Apache Log4j", version="2.14.1",
            attack_vector="NETWORK", complexity="LOW",
            privileges_required="NONE", user_interaction=False,
            impact="HIGH",
        ),
        EnrichedCVEModel(
            cve_id="CVE-LOW-001",
            cvss=4.0, severity="MEDIUM",
            product="Unknown Product", version="1.0",
            attack_vector="LOCAL", complexity="HIGH",
            privileges_required="HIGH", user_interaction=True,
            impact="LOW",
        ),
    ]


class TestAttackCorrelation:
    def test_correlate_basic(self, enriched_cves):
        engine = AttackCorrelationEngine()
        results = engine.correlate(
            enriched_cves=enriched_cves,
            technology_profile=None,
            nuclei_findings=None,
            owasp_profile=None,
            attack_surface_profile=None,
        )
        assert len(results) >= 1
        assert all(r["attack_opportunity_score"] >= 30 for r in results)
        assert results[0]["cve"] in ("CVE-2021-44228", "CVE-2021-41773")

    def test_correlate_with_tech_profile(self, enriched_cves):
        engine = AttackCorrelationEngine()
        tech_profile = {
            "technologies": [
                {"name": "WordPress", "version": "5.8.2", "category": "CMS"},
                {"name": "WooCommerce", "version": "6.0.0", "category": "Plugin"},
                {"name": "MySQL", "version": "8.0", "category": "Database"},
            ]
        }
        enriched_cves.append(
            EnrichedCVEModel(
                cve_id="CVE-WP-001", cvss=8.0, severity="HIGH",
                product="WordPress", version="5.8.2",
                attack_vector="NETWORK", complexity="LOW",
                privileges_required="NONE", user_interaction=False,
                impact="HIGH",
            )
        )
        results = engine.correlate(
            enriched_cves=enriched_cves,
            technology_profile=tech_profile,
            nuclei_findings=None,
            owasp_profile=None,
            attack_surface_profile=None,
        )
        wp_results = [r for r in results if r["technology"] == "WordPress"]
        assert len(wp_results) > 0

    def test_correlate_with_nuclei_confirmation(self, enriched_cves):
        engine = AttackCorrelationEngine()
        nuclei_findings = {
            "findings": [
                {"cve": "CVE-2021-41773"},
            ]
        }
        results = engine.correlate(
            enriched_cves=enriched_cves,
            technology_profile=None,
            nuclei_findings=nuclei_findings,
            owasp_profile=None,
            attack_surface_profile=None,
        )
        cve_result = [r for r in results if r["cve"] == "CVE-2021-41773"]
        if cve_result:
            assert cve_result[0]["nuclei_confirmed"] is True

    def test_correlate_empty_cves(self):
        engine = AttackCorrelationEngine()
        results = engine.correlate(
            enriched_cves=[],
            technology_profile=None,
            nuclei_findings=None,
            owasp_profile=None,
            attack_surface_profile=None,
        )
        assert results == []

    def test_extract_technologies(self):
        tech_profile = {
            "technologies": [
                {"name": "WordPress", "version": "5.8"},
                {"name": "Apache", "version": "2.4.49"},
            ]
        }
        result = AttackCorrelationEngine._extract_technologies(tech_profile)
        assert "wordpress" in result
        assert "apache" in result
        assert result["wordpress"]["version"] == "5.8"

    def test_extract_technologies_none(self):
        assert AttackCorrelationEngine._extract_technologies(None) == {}

    def test_extract_nuclei_cves(self):
        nuclei = {"findings": [{"cve": "CVE-2021-41773"}, {"cve": "CVE-2021-44228"}]}
        result = AttackCorrelationEngine._extract_nuclei_cves(nuclei)
        assert "CVE-2021-41773" in result
        assert "CVE-2021-44228" in result

    def test_extract_nuclei_cves_empty(self):
        assert AttackCorrelationEngine._extract_nuclei_cves(None) == set()

    def test_opportunity_score_critical(self):
        score = AttackCorrelationEngine._calculate_opportunity_score(
            cve_severity="CRITICAL", nuclei_confirmed=True,
            admin_exposed=True, is_cms=True, is_db=False,
            exploit_available=True, internet_exposed=True,
        )
        assert score >= 80

    def test_opportunity_score_low(self):
        score = AttackCorrelationEngine._calculate_opportunity_score(
            cve_severity="LOW", nuclei_confirmed=False,
            admin_exposed=False, is_cms=False, is_db=False,
            exploit_available=False, internet_exposed=False,
        )
        assert score <= 30
