import pytest

from ghostmirror.models.finding_priority import FindingPriority
from ghostmirror.modules.finding_intelligence.priority_engine import calculate_priority


class TestPriorityEngine:
    def test_p1_critical_kev(self) -> None:
        assert calculate_priority("CRITICAL", kev=True) == FindingPriority.P1

    def test_p1_critical_exploitable(self) -> None:
        assert calculate_priority("CRITICAL", exploitability_label="Critical") == FindingPriority.P1

    def test_p1_high_kev(self) -> None:
        assert calculate_priority("HIGH", kev=True) == FindingPriority.P1

    def test_p2_critical(self) -> None:
        assert calculate_priority("CRITICAL") == FindingPriority.P2

    def test_p2_high_exploitable(self) -> None:
        assert calculate_priority("HIGH", exploitability_label="High") == FindingPriority.P2

    def test_p2_high_likelihood(self) -> None:
        assert calculate_priority("HIGH", likelihood="Critical") == FindingPriority.P2

    def test_p3_high(self) -> None:
        assert calculate_priority("HIGH") == FindingPriority.P3

    def test_p3_medium_exploitable(self) -> None:
        assert calculate_priority("MEDIUM", exploitability_label="High") == FindingPriority.P3

    def test_p3_medium_kev(self) -> None:
        assert calculate_priority("MEDIUM", kev=True) == FindingPriority.P3

    def test_p4_medium(self) -> None:
        assert calculate_priority("MEDIUM") == FindingPriority.P4

    def test_p4_low(self) -> None:
        assert calculate_priority("LOW") == FindingPriority.P4

    def test_p5_info(self) -> None:
        assert calculate_priority("INFO") == FindingPriority.P5

    def test_case_insensitive_severity(self) -> None:
        assert calculate_priority("critical", kev=True) == FindingPriority.P1
        assert calculate_priority("high") == FindingPriority.P3

    def test_all_priorities_covered(self) -> None:
        test_cases = [
            ("CRITICAL", "Critical", "Critical", True, FindingPriority.P1),
            ("CRITICAL", "Low", "Medium", False, FindingPriority.P2),
            ("HIGH", "Low", "Medium", False, FindingPriority.P3),
            ("MEDIUM", "Low", "Medium", False, FindingPriority.P4),
            ("LOW", "Low", "Low", False, FindingPriority.P4),
            ("INFO", "Very Low", "Very Low", False, FindingPriority.P5),
        ]
        for sev, expl, like, kev, expected in test_cases:
            assert calculate_priority(sev, expl, like, kev) == expected
