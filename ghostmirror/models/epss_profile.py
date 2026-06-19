from __future__ import annotations

from pydantic import BaseModel, Field


class EPSSProfileModel(BaseModel):
    cve: str = Field(..., description="CVE identifier")
    epss_score: float = Field(..., ge=0.0, le=1.0, description="EPSS probability score (0-1)")
    percentile: float = Field(..., ge=0.0, le=100.0, description="EPSS percentile rank")
    classification: str = Field(..., description="VERY_LOW, LOW, MEDIUM, HIGH, CRITICAL")

    @staticmethod
    def classify(score: float) -> str:
        if score <= 0.20:
            return "VERY_LOW"
        elif score <= 0.40:
            return "LOW"
        elif score <= 0.60:
            return "MEDIUM"
        elif score <= 0.80:
            return "HIGH"
        return "CRITICAL"
