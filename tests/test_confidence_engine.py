import pytest

from ghostmirror.models.finding_confidence import ConfidenceLevel
from ghostmirror.modules.finding_intelligence.confidence_engine import (
    evaluate_confidence,
    evaluate_from_finding,
)


class TestConfidenceEngine:
    def test_confirmed_nuclei_cve_version(self) -> None:
        assert evaluate_confidence(has_nuclei=True, has_cve_match=True, has_version_match=True) == ConfidenceLevel.CONFIRMED

    def test_high_nuclei_cve(self) -> None:
        assert evaluate_confidence(has_nuclei=True, has_cve_match=True) == ConfidenceLevel.HIGH

    def test_high_cve_version(self) -> None:
        assert evaluate_confidence(has_cve_match=True, has_version_match=True) == ConfidenceLevel.HIGH

    def test_medium_nuclei(self) -> None:
        assert evaluate_confidence(has_nuclei=True) == ConfidenceLevel.MEDIUM

    def test_medium_cve(self) -> None:
        assert evaluate_confidence(has_cve_match=True) == ConfidenceLevel.MEDIUM

    def test_low_evidence(self) -> None:
        assert evaluate_confidence(has_evidence=True) == ConfidenceLevel.LOW

    def test_low_default(self) -> None:
        assert evaluate_confidence() == ConfidenceLevel.LOW

    def test_evaluate_from_finding_nuclei_with_kev(self) -> None:
        result = evaluate_from_finding(source="nuclei", cvss=9.0, epss=0.8, kev=True, evidence="found")
        assert result == ConfidenceLevel.CONFIRMED

    def test_evaluate_from_finding_no_data(self) -> None:
        result = evaluate_from_finding()
        assert result == ConfidenceLevel.LOW

    def test_evaluate_from_finding_nuclei_only(self) -> None:
        result = evaluate_from_finding(source="nuclei")
        assert result == ConfidenceLevel.MEDIUM
