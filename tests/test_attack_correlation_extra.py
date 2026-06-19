"""Additional coverage tests for attack correlation edge cases."""

from ghostmirror.models.enriched_cve import EnrichedCVEModel
from ghostmirror.modules.vulnerability_intelligence.attack_correlation import (
    AttackCorrelationEngine,
)


class TestAttackCorrelationExtra:
    def test_correlate_with_waf_detected(self):
        enriched = [
            EnrichedCVEModel(
                cve_id="CVE-TEST-1", cvss=7.5, severity="HIGH",
                product="WordPress", version="5.8",
                attack_vector="NETWORK", complexity="LOW",
                privileges_required="NONE", user_interaction=False,
                impact="HIGH",
            )
        ]
        engine = AttackCorrelationEngine()
        results = engine.correlate(
            enriched_cves=enriched,
            technology_profile={"technologies": [{"name": "WordPress", "version": "5.8", "category": "CMS"}]},
            nuclei_findings={"findings": [{"cve": "CVE-TEST-1"}]},
            owasp_profile={"categories": [{"id": "A01"}, {"id": "A05"}]},
            attack_surface_profile={"waf": {"detected": True}, "cdn": {"detected": False}},
        )
        assert len(results) >= 1

    def test_extract_owasp_categories_string_format(self):
        result = AttackCorrelationEngine._extract_owasp_categories({
            "categories": ["A01", "A02", "A03"]
        })
        assert "A01" in result
        assert len(result) == 3

    def test_extract_owasp_categories_none(self):
        assert AttackCorrelationEngine._extract_owasp_categories(None) == []

    def test_extract_owasp_categories_empty(self):
        assert AttackCorrelationEngine._extract_owasp_categories({}) == []

    def test_correlate_db_technology(self):
        enriched = [
            EnrichedCVEModel(
                cve_id="CVE-REDIS", cvss=8.0, severity="HIGH",
                product="Redis", version="6.0.0",
                attack_vector="NETWORK", complexity="LOW",
                privileges_required="NONE", user_interaction=False,
                impact="HIGH",
            )
        ]
        engine = AttackCorrelationEngine()
        results = engine.correlate(
            enriched_cves=enriched,
            technology_profile={"technologies": [{"name": "Redis", "version": "6.0.0", "category": "Database"}]},
            nuclei_findings=None,
            owasp_profile=None,
            attack_surface_profile={"waf": {"detected": False}, "cdn": {"detected": False}},
        )
        assert len(results) >= 1
        assert results[0]["is_database"] is True
