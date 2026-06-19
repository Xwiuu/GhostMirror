from __future__ import annotations

import pytest

from ghostmirror.models.enriched_cve import EnrichedCVEModel
from ghostmirror.models.epss_profile import EPSSProfileModel
from ghostmirror.models.kev_profile import KEVProfileModel
from ghostmirror.models.exploit_profile import ExploitProfileModel, WeaponizationLevel
from ghostmirror.models.vulnerability_priority import VulnerabilityPriorityModel
from ghostmirror.modules.vulnerability_intelligence.prioritization import (
    VulnerabilityPrioritizationEngine,
)
from ghostmirror.modules.vulnerability_intelligence.scoring import AdvancedScoringEngine


@pytest.fixture()
def enriched_cves() -> list[EnrichedCVEModel]:
    return [
        EnrichedCVEModel(
            cve_id="CVE-2021-41773",
            cvss=7.5,
            severity="HIGH",
            product="Apache HTTP Server",
            version="2.4.49",
            attack_vector="NETWORK",
            complexity="LOW",
            privileges_required="NONE",
            user_interaction=False,
            impact="HIGH",
            description="Path traversal in Apache",
        ),
        EnrichedCVEModel(
            cve_id="CVE-2021-44228",
            cvss=10.0,
            severity="CRITICAL",
            product="Apache Log4j",
            version="2.14.1",
            attack_vector="NETWORK",
            complexity="LOW",
            privileges_required="NONE",
            user_interaction=False,
            impact="HIGH",
            description="Log4j RCE",
        ),
        EnrichedCVEModel(
            cve_id="CVE-LOW-001",
            cvss=4.0,
            severity="MEDIUM",
            product="Test Product",
            version="1.0.0",
            attack_vector="NETWORK",
            complexity="HIGH",
            privileges_required="LOW",
            user_interaction=True,
            impact="LOW",
            description="A medium severity test CVE",
        ),
    ]


class TestVulnerabilityPrioritization:
    def test_prioritize_orders_by_risk_score(self, enriched_cves):
        engine = VulnerabilityPrioritizationEngine()
        results = engine.prioritize(enriched_cves)
        assert len(results) == 3
        assert results[0].priority == 1
        assert results[1].priority == 2
        assert results[2].priority == 3
        assert results[0].risk_score >= results[1].risk_score >= results[2].risk_score

    def test_prioritize_with_kev_exploit(self, enriched_cves):
        engine = VulnerabilityPrioritizationEngine()
        epss_map = {
            "CVE-2021-44228": EPSSProfileModel(
                cve="CVE-2021-44228", epss_score=0.97, percentile=99.8, classification="CRITICAL"
            ),
        }
        kev_map = {
            "CVE-2021-44228": KEVProfileModel(
                cve="CVE-2021-44228", kev=True, ransomware_usage=True, known_exploitation=True,
            ),
        }
        exploit_map = {
            "CVE-2021-44228": ExploitProfileModel(
                cve="CVE-2021-44228", public_exploit=True, metasploit=True,
                nuclei_template=True, weaponization_level=WeaponizationLevel.CRITICAL,
            ),
        }
        results = engine.prioritize(
            enriched_cves, epss_map=epss_map, kev_map=kev_map, exploit_map=exploit_map,
        )
        assert results[0].cve == "CVE-2021-44228"
        assert "KEV listed" in results[0].reason
        assert "Ransomware usage" in results[0].reason
        assert results[0].epss is not None
        assert results[0].kev is not None
        assert results[0].exploit is not None

    def test_prioritize_empty_list(self):
        engine = VulnerabilityPrioritizationEngine()
        results = engine.prioritize([])
        assert results == []

    def test_prioritize_with_attack_opportunities(self, enriched_cves):
        engine = VulnerabilityPrioritizationEngine()
        opportunities = [
            {
                "cve": "CVE-2021-41773",
                "nuclei_confirmed": True,
                "admin_panel_exposed": True,
                "internet_exposed": True,
            }
        ]
        results = engine.prioritize(enriched_cves, attack_opportunities=opportunities)
        top = [r for r in results if r.cve == "CVE-2021-41773"][0]
        assert "Nuclei confirmed" in top.reason
        assert "Admin panel exposed" in top.reason

    def test_build_reasons_kev(self):
        reasons = VulnerabilityPrioritizationEngine._build_reasons(
            cve=EnrichedCVEModel(cve_id="CVE-TEST", cvss=9.0, severity="CRITICAL", product="P", version="1"),
            risk_score=95,
            epss=EPSSProfileModel(cve="CVE-TEST", epss_score=0.9, percentile=99.0, classification="CRITICAL"),
            kev=KEVProfileModel(cve="CVE-TEST", kev=True, ransomware_usage=True, known_exploitation=True),
            exploit=ExploitProfileModel(cve="CVE-TEST", public_exploit=True, metasploit=True, nuclei_template=True, weaponization_level=WeaponizationLevel.CRITICAL),
            opportunity={"nuclei_confirmed": True, "admin_panel_exposed": True, "internet_exposed": True},
        )
        assert "KEV listed" in reasons
        assert "Ransomware usage" in reasons
        assert "Public exploit available" in reasons
        assert "Metasploit module" in reasons
        assert "Weaponization: CRITICAL" in reasons


class TestAdvancedScoring:
    def test_calculate_risk_score_full(self):
        enriched = EnrichedCVEModel(cve_id="CVE-TEST", cvss=10.0, severity="CRITICAL", product="P", version="1")
        epss = EPSSProfileModel(cve="CVE-TEST", epss_score=0.9, percentile=99.0, classification="CRITICAL")
        score = AdvancedScoringEngine.calculate_risk_score(
            enriched=enriched, epss=epss, kev=True,
            exploit=ExploitProfileModel(cve="CVE-TEST", public_exploit=True, metasploit=True, nuclei_template=True, weaponization_level=WeaponizationLevel.CRITICAL),
            internet_exposed=True, admin_exposed=True,
        )
        assert 0 <= score <= 100
        assert score >= 70

    def test_calculate_risk_score_minimal(self):
        enriched = EnrichedCVEModel(cve_id="CVE-LOW", cvss=2.0, severity="LOW", product="P", version="1")
        score = AdvancedScoringEngine.calculate_risk_score(
            enriched=enriched, internet_exposed=False,
        )
        assert 0 <= score <= 30

    def test_cvss_weight(self):
        assert AdvancedScoringEngine._cvss_weight("CRITICAL") == 100
        assert AdvancedScoringEngine._cvss_weight("HIGH") == 70
        assert AdvancedScoringEngine._cvss_weight("MEDIUM") == 40
        assert AdvancedScoringEngine._cvss_weight("LOW") == 10
        assert AdvancedScoringEngine._cvss_weight("UNKNOWN") == 0

    def test_epss_weight(self):
        epss = EPSSProfileModel(cve="T", epss_score=0.5, percentile=50.0, classification="MEDIUM")
        assert AdvancedScoringEngine._epss_weight(epss) == 50

    def test_epss_weight_none(self):
        assert AdvancedScoringEngine._epss_weight(None) == 0

    def test_kev_weight(self):
        assert AdvancedScoringEngine._kev_weight(True) == 100
        assert AdvancedScoringEngine._kev_weight(False) == 0

    def test_exploit_weight(self):
        assert AdvancedScoringEngine._exploit_weight(ExploitProfileModel(cve="T", weaponization_level=WeaponizationLevel.CRITICAL)) == 100
        assert AdvancedScoringEngine._exploit_weight(ExploitProfileModel(cve="T", weaponization_level=WeaponizationLevel.NONE)) == 0
        assert AdvancedScoringEngine._exploit_weight(None) == 0

    def test_surface_weight(self):
        assert AdvancedScoringEngine._surface_weight(True, True) == 100
        assert AdvancedScoringEngine._surface_weight(True, False) == 50
        assert AdvancedScoringEngine._surface_weight(False, False) == 0
