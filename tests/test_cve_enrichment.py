from __future__ import annotations

import pytest

from ghostmirror.models.cve import CVEModel
from ghostmirror.models.enriched_cve import EnrichedCVEModel
from ghostmirror.modules.vulnerability_intelligence.cve_enrichment import CVEEnrichmentEngine


class TestCVEEnrichmentEngine:
    def test_enrich_all_empty(self):
        engine = CVEEnrichmentEngine()
        result = engine.enrich_all(None, None)
        assert result == []

    def test_enrich_all_with_findings_key(self):
        engine = CVEEnrichmentEngine()
        data = {
            "findings": [
                {
                    "cve_id": "CVE-2021-41773",
                    "cvss_score": 7.5,
                    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    "severity": "HIGH",
                    "product": "Apache HTTP Server",
                    "description": "test",
                    "references": [],
                }
            ]
        }
        result = engine.enrich_all(None, data)
        assert len(result) == 1
        assert result[0].cve_id == "CVE-2021-41773"

    def test_enrich_all_cache_hit(self):
        engine = CVEEnrichmentEngine()
        data = {
            "matches": [
                {"matched_cve": {"cve_id": "CVE-001", "cvss_score": 5.0, "severity": "MEDIUM"}},
                {"matched_cve": {"cve_id": "CVE-001", "cvss_score": 5.0, "severity": "MEDIUM"}},
            ]
        }
        result = engine.enrich_all(None, data)
        assert len(result) == 2
        assert result[0].cve_id == "CVE-001"

    def test_enrich_all_cvss_none(self):
        engine = CVEEnrichmentEngine()
        data = {
            "matches": [
                {"matched_cve": {"cve_id": "CVE-002", "cvss_score": None, "severity": "LOW"}}
            ]
        }
        result = engine.enrich_all(None, data)
        assert result[0].cvss == 0.0

    def test_enrich_all_no_severity_derives_from_cvss(self):
        engine = CVEEnrichmentEngine()
        data = {
            "matches": [
                {"matched_cve": {"cve_id": "CVE-003", "cvss_score": 9.5}}
            ]
        }
        result = engine.enrich_all(None, data)
        assert result[0].severity == "CRITICAL"

    def test_enrich_from_cve_model(self):
        engine = CVEEnrichmentEngine()
        cve = CVEModel(
            cve_id="CVE-2021-41773",
            title="Test",
            description="Test desc",
            severity="HIGH",
            cvss_score=7.5,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            affected_product="Apache",
            affected_versions=["2.4.49"],
            fixed_versions=["2.4.50"],
            references=["https://example.com"],
            exploit_available=True,
            kev_listed=True,
        )
        result = engine.enrich_from_cve_model(cve, "Apache", "2.4.49")
        assert result.cve_id == "CVE-2021-41773"
        assert result.attack_vector == "NETWORK"
        assert result.complexity == "LOW"
        assert result.privileges_required == "NONE"
        assert result.user_interaction is False
        assert result.impact == "HIGH"

    def test_enrich_from_cve_model_empty_vector(self):
        engine = CVEEnrichmentEngine()
        cve = CVEModel(
            cve_id="CVE-TEST",
            title="T",
            description="D",
            severity="LOW",
            cvss_score=2.0,
            affected_product="P",
            affected_versions=[],
            fixed_versions=[],
            references=[],
            exploit_available=False,
            kev_listed=False,
        )
        result = engine.enrich_from_cve_model(cve, "Product", "")
        assert result.attack_vector == ""
        assert result.complexity == ""
        assert result.privileges_required == ""
        assert result.impact == ""

    def test_build_tech_map_none(self):
        assert CVEEnrichmentEngine._build_tech_map(None) == {}

    def test_build_tech_map_with_data(self):
        result = CVEEnrichmentEngine._build_tech_map({
            "technologies": [
                {"name": "Apache", "version": "2.4.49"},
                {"name": "WordPress", "version": "5.8"},
            ]
        })
        assert result["apache"] == "2.4.49"
        assert result["wordpress"] == "5.8"

    def test_enrich_all_with_tech_profile_version_fallback(self):
        engine = CVEEnrichmentEngine()
        tech_profile = {
            "technologies": [{"name": "Apache", "version": "2.4.49"}]
        }
        data = {
            "matches": [
                {
                    "matched_cve": {
                        "cve_id": "CVE-TECH",
                        "cvss_score": 7.0,
                        "severity": "HIGH",
                    },
                    "technology": "Apache",
                    "detected_version": "2.4.50",
                }
            ]
        }
        result = engine.enrich_all(tech_profile, data)
        assert len(result) == 1
        assert result[0].version == "2.4.50"

    def test_parse_av_adjacent(self):
        assert CVEEnrichmentEngine._parse_av("AV:A") == "ADJACENT"

    def test_parse_av_local(self):
        assert CVEEnrichmentEngine._parse_av("AV:L") == "LOCAL"

    def test_parse_av_physical(self):
        assert CVEEnrichmentEngine._parse_av("AV:P") == "PHYSICAL"

    def test_parse_av_empty(self):
        assert CVEEnrichmentEngine._parse_av("") == ""

    def test_parse_ac_high(self):
        assert CVEEnrichmentEngine._parse_ac("AC:H") == "HIGH"

    def test_parse_ac_empty(self):
        assert CVEEnrichmentEngine._parse_ac("") == ""

    def test_parse_pr_low(self):
        assert CVEEnrichmentEngine._parse_pr("PR:L") == "LOW"

    def test_parse_pr_high(self):
        assert CVEEnrichmentEngine._parse_pr("PR:H") == "HIGH"

    def test_parse_pr_empty(self):
        assert CVEEnrichmentEngine._parse_pr("") == ""

    def test_parse_ui_true(self):
        assert CVEEnrichmentEngine._parse_ui("UI:R") is True

    def test_parse_ui_false(self):
        assert CVEEnrichmentEngine._parse_ui("UI:N") is False

    def test_parse_impact_high(self):
        assert CVEEnrichmentEngine._parse_impact("C:H") == "HIGH"

    def test_parse_impact_low(self):
        assert CVEEnrichmentEngine._parse_impact("C:L") == "LOW"

    def test_parse_impact_empty(self):
        assert CVEEnrichmentEngine._parse_impact("") == ""

    def test_severity_from_cvss_critical(self):
        assert CVEEnrichmentEngine._severity_from_cvss(9.0) == "CRITICAL"

    def test_severity_from_cvss_high(self):
        assert CVEEnrichmentEngine._severity_from_cvss(7.0) == "HIGH"

    def test_severity_from_cvss_medium(self):
        assert CVEEnrichmentEngine._severity_from_cvss(4.0) == "MEDIUM"

    def test_severity_from_cvss_low(self):
        assert CVEEnrichmentEngine._severity_from_cvss(3.9) == "LOW"
