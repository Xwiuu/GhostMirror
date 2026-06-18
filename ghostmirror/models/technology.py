"""Pydantic model representing a detected technology."""

from __future__ import annotations

from pydantic import BaseModel, Field


class TechnologyModel(BaseModel):
    """Represents a specific detected technology (web server, framework, language, WAF, etc.)."""

    name: str = Field(..., description="Name of the technology (e.g. Apache, Laravel, Cloudflare)")
    category: str = Field(..., description="Category of the technology (e.g. WEB SERVER, CMS, WAF)")
    version: str | None = Field(default=None, description="Detected version of the technology")
    confidence: float = Field(..., description="Confidence score of detection (0.0 to 1.0)")
    source: str = Field(..., description="Detection source (e.g. WhatWeb, Fingerprint Engine)")
