from __future__ import annotations

from pydantic import BaseModel, Field


class BusinessImpact(BaseModel):
    category: str = Field(..., description="Business impact category (e.g. Data Exposure, Regulatory)")
    description: str = Field(..., description="Detailed business impact description")


class TechnicalImpact(BaseModel):
    category: str = Field(..., description="Technical impact category (e.g. Code Execution, Data Access)")
    description: str = Field(..., description="Detailed technical impact description")
