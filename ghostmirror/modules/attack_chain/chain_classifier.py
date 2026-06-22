from __future__ import annotations

from typing import Any


class ChainClassifier:
    def classify(self, score: float, confidence: float) -> str:
        if score >= 80:
            return "critical"
        if score >= 60:
            return "high"
        if score >= 40:
            return "medium"
        return "low"

    def get_priority_label(self, classification: str) -> str:
        labels = {
            "critical": "Immediate Investigation Required",
            "high": "High Priority",
            "medium": "Standard Review",
            "low": "Informational",
        }
        return labels.get(classification, "Unknown")
