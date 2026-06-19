from __future__ import annotations

from pydantic import BaseModel, Field


class KEVProfileModel(BaseModel):
    cve: str = Field(..., description="CVE identifier")
    kev: bool = Field(default=False, description="Whether CVE is in CISA KEV catalog")
    ransomware_usage: bool = Field(default=False, description="Known ransomware usage")
    known_exploitation: bool = Field(default=False, description="Known exploitation in wild")
    date_added: str | None = Field(default=None, description="Date added to KEV catalog")
    vendor_project: str | None = Field(default=None, description="Vendor or project name")
    product: str | None = Field(default=None, description="Product name")
    short_description: str | None = Field(default=None, description="Short description of the vulnerability")
