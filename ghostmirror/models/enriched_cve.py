from __future__ import annotations

from pydantic import BaseModel, Field


class EnrichedCVEModel(BaseModel):
    cve_id: str = Field(..., description="CVE identifier")
    cvss: float = Field(..., ge=0, le=10, description="CVSS score")
    severity: str = Field(..., description="Severity level (CRITICAL, HIGH, MEDIUM, LOW)")
    product: str = Field(..., description="Affected product name")
    version: str = Field(default="", description="Affected version")
    attack_vector: str = Field(default="", description="Attack vector (NETWORK, ADJACENT, LOCAL, PHYSICAL)")
    complexity: str = Field(default="", description="Attack complexity (LOW, HIGH)")
    privileges_required: str = Field(default="", description="Privileges required (NONE, LOW, HIGH)")
    user_interaction: bool = Field(default=False, description="Whether user interaction is required")
    impact: str = Field(default="", description="Impact (HIGH, LOW, NONE)")
    description: str = Field(default="", description="CVE description")
    references: list[str] = Field(default_factory=list, description="Reference URLs")
