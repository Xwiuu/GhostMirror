from __future__ import annotations

from datetime import datetime, timezone
from pydantic import BaseModel, Field

from ghostmirror.models.attack_path import AttackPath
from ghostmirror.models.attack_surface_profile import AttackSurfaceProfile


class RiskMatrixEntry(BaseModel):
    category: str
    score: int
    level: str
    description: str | None = None


class RiskMatrix(BaseModel):
    likelihood: RiskMatrixEntry = Field(
        default_factory=lambda: RiskMatrixEntry(category="Likelihood", score=0, level="Unknown")
    )
    impact: RiskMatrixEntry = Field(
        default_factory=lambda: RiskMatrixEntry(category="Impact", score=0, level="Unknown")
    )
    exploitability: RiskMatrixEntry = Field(
        default_factory=lambda: RiskMatrixEntry(category="Exploitability", score=0, level="Unknown")
    )
    exposure: RiskMatrixEntry = Field(
        default_factory=lambda: RiskMatrixEntry(category="Exposure", score=0, level="Unknown")
    )
    business_risk: RiskMatrixEntry = Field(
        default_factory=lambda: RiskMatrixEntry(category="Business Risk", score=0, level="Unknown")
    )
    overall_level: str = "Unknown"


class PentestRecommendation(BaseModel):
    assessment_type: str
    priority: str
    justification: str
    findings_reference: list[str] = Field(default_factory=list)


class IntelligenceReport(BaseModel):
    target: str
    generated_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    overall_security_score: int = Field(default=0, ge=0, le=100)
    overall_attack_surface_score: int = Field(default=0, ge=0, le=100)
    overall_risk_score: int = Field(default=0, ge=0, le=100)
    attack_surface_profile: AttackSurfaceProfile | None = None
    risk_matrix: RiskMatrix | None = None
    attack_paths: list[AttackPath] = Field(default_factory=list)
    executive_summary: str = ""
    recommendations: list[PentestRecommendation] = Field(default_factory=list)
