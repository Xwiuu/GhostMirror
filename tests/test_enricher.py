import pytest

from ghostmirror.modules.finding_intelligence.enricher import FindingEnricher
from ghostmirror.models.finding_confidence import ConfidenceLevel
from ghostmirror.models.finding_priority import FindingPriority


class TestFindingEnricher:
    def setup_method(self) -> None:
        self.enricher = FindingEnricher()

    def test_enrich_minimal_finding(self) -> None:
        raw = {"title": "Missing Security Header", "severity": "MEDIUM"}
        result = self.enricher.enrich(raw)
        assert result.title == "Missing Security Header"
        assert result.severity == "MEDIUM"
        assert result.priority == FindingPriority.P4
        assert result.confidence == ConfidenceLevel.LOW
        assert result.business_impact is not None
        assert result.technical_impact is not None
        assert result.recommendation is not None
        assert len(result.references) > 0

    def test_enrich_with_cvss_and_epss(self) -> None:
        raw = {
            "title": "CVE-2024-1234",
            "severity": "CRITICAL",
            "cvss": 9.8,
            "epss": 0.95,
            "kev": True,
            "evidence": "Exploit found in the wild",
            "source": "nuclei",
        }
        result = self.enricher.enrich(raw)
        assert result.severity == "CRITICAL"
        assert result.cvss == 9.8
        assert result.epss == 0.95
        assert result.kev is True
        assert result.confidence == ConfidenceLevel.CONFIRMED
        assert result.priority == FindingPriority.P1

    def test_enrich_with_nuclei_and_cve(self) -> None:
        raw = {
            "title": "Apache Log4j RCE",
            "severity": "CRITICAL",
            "cvss": 10.0,
            "epss": 0.97,
            "kev": True,
            "evidence": "CVE-2021-44228 detected via nuclei",
            "source": "nuclei",
        }
        result = self.enricher.enrich(raw)
        assert result.priority == FindingPriority.P1
        assert result.confidence == ConfidenceLevel.CONFIRMED

    def test_enrich_full_finding(self) -> None:
        raw = {
            "title": "Open Database Exposure",
            "severity": "HIGH",
            "category": "Open Port",
            "cvss": 7.5,
            "epss": 0.5,
            "kev": False,
            "evidence": "Port 27017 open",
            "source": "nmap",
            "target": "10.0.0.1",
            "component": "MongoDB",
        }
        result = self.enricher.enrich(raw)
        assert result.affected_asset == "10.0.0.1"
        assert result.affected_component == "MongoDB"
        assert result.severity == "HIGH"
        assert result.priority == FindingPriority.P2
        assert result.confidence == ConfidenceLevel.LOW

    def test_likelihood_calculation(self) -> None:
        score = self.enricher._calculate_likelihood_score(cvss=9.0, epss=0.8, kev=True, exploit_score=80)
        expected = int(min(100, max(0, 45 + 40 + 20 + 24)))
        assert score == expected

    def test_likelihood_no_data(self) -> None:
        score = self.enricher._calculate_likelihood_score(cvss=None, epss=None, kev=False, exploit_score=0)
        assert score == 0

    def test_enrich_without_severity_defaults(self) -> None:
        raw = {"title": "some issue"}
        result = self.enricher.enrich(raw)
        assert result.severity == "INFO"
        assert result.priority == FindingPriority.P5

    def test_enrich_with_recommendation_preserved(self) -> None:
        raw = {"title": "Missing CSP", "severity": "MEDIUM", "recommendation": "Custom rec"}
        result = self.enricher.enrich(raw)
        assert result.recommendation == "Custom rec"

    def test_enrich_with_references_preserved(self) -> None:
        raw = {"title": "XSS", "severity": "HIGH", "references": ["https://example.com"]}
        result = self.enricher.enrich(raw)
        assert "https://example.com" in result.references
