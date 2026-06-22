"""Tests for severity mapper module."""
from __future__ import annotations

import pytest
from ghostmirror.modules.hackerone_reporting.severity_mapper import SeverityMapper


class TestSeverityMapper:
    def setup_method(self):
        self.mapper = SeverityMapper()

    def test_map_severity_critical(self):
        assert self.mapper.map_severity("CRITICAL") == "Critical"

    def test_map_severity_high(self):
        assert self.mapper.map_severity("HIGH") == "High"

    def test_map_severity_medium(self):
        assert self.mapper.map_severity("MEDIUM") == "Medium"

    def test_map_severity_low(self):
        assert self.mapper.map_severity("LOW") == "Low"

    def test_map_severity_info(self):
        assert self.mapper.map_severity("INFO") == "Informational"

    def test_map_severity_unknown(self):
        assert self.mapper.map_severity("UNKNOWN") == "Informational"

    def test_map_severity_case_insensitive(self):
        assert self.mapper.map_severity("critical") == "Critical"
        assert self.mapper.map_severity("High") == "High"

    def test_map_priority_to_severity_p1(self):
        assert self.mapper.map_priority_to_severity("P1") == "Critical"

    def test_map_priority_to_severity_p2(self):
        assert self.mapper.map_priority_to_severity("P2") == "High"

    def test_map_priority_to_severity_p3(self):
        assert self.mapper.map_priority_to_severity("P3") == "Medium"

    def test_map_priority_to_severity_p4(self):
        assert self.mapper.map_priority_to_severity("P4") == "Low"

    def test_map_priority_to_severity_p5(self):
        assert self.mapper.map_priority_to_severity("P5") == "Informational"

    def test_map_confidence_low(self):
        assert self.mapper.map_confidence("LOW") == "Low"

    def test_map_confidence_medium(self):
        assert self.mapper.map_confidence("MEDIUM") == "Medium"

    def test_map_confidence_high(self):
        assert self.mapper.map_confidence("HIGH") == "High"

    def test_map_confidence_confirmed(self):
        assert self.mapper.map_confidence("CONFIRMED") == "Confirmed"

    def test_map_confidence_unknown(self):
        assert self.mapper.map_confidence("UNKNOWN") == "Low"

    def test_map_severity_to_priority_critical(self):
        assert self.mapper.map_severity_to_priority("CRITICAL") == "P1"

    def test_map_severity_to_priority_high(self):
        assert self.mapper.map_severity_to_priority("HIGH") == "P2"

    def test_map_severity_to_priority_medium(self):
        assert self.mapper.map_severity_to_priority("MEDIUM") == "P3"

    def test_map_severity_to_priority_low(self):
        assert self.mapper.map_severity_to_priority("LOW") == "P4"

    def test_map_severity_to_priority_info(self):
        assert self.mapper.map_severity_to_priority("INFO") == "P5"

    def test_map_severity_to_priority_unknown(self):
        assert self.mapper.map_severity_to_priority("UNKNOWN") == "P5"
