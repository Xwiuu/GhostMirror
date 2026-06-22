"""Map internal GhostMirror severities to bounty-program formats."""
from __future__ import annotations

SEVERITY_MAP = {
    "CRITICAL": "Critical",
    "HIGH": "High",
    "MEDIUM": "Medium",
    "LOW": "Low",
    "INFO": "Informational",
}
PRIORITY_MAP = {
    "P1": "Critical",
    "P2": "High",
    "P3": "Medium",
    "P4": "Low",
    "P5": "Informational",
}
CONFIDENCE_MAP = {
    "LOW": "Low",
    "MEDIUM": "Medium",
    "HIGH": "High",
    "CONFIRMED": "Confirmed",
}

class SeverityMapper:
    @staticmethod
    def map_severity(s): return SEVERITY_MAP.get(s.upper(), "Informational")
    @staticmethod
    def map_priority_to_severity(s): return PRIORITY_MAP.get(s.upper(), "Informational")
    @staticmethod
    def map_confidence(s): return CONFIDENCE_MAP.get(s.upper(), "Low")
    @staticmethod
    def map_severity_to_priority(s):
        b = SEVERITY_MAP.get(s.upper(), "Informational")
        r = {"Critical": "P1", "High": "P2", "Medium": "P3", "Low": "P4", "Informational": "P5"}
        return r.get(b, "P5")
