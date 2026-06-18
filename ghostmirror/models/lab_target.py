"""Pydantic model for a lab target definition."""

from __future__ import annotations

from pydantic import BaseModel, Field


class LabTarget(BaseModel):
    """Describes a single controlled vulnerable environment (lab)."""

    id: str = Field(..., min_length=1, description="Unique lab identifier")
    name: str = Field(..., min_length=1, description="Human-readable name")
    description: str = Field("", description="Short description of the lab")
    docker_compose_file: str = Field(..., description="Path to the docker-compose file")
    default_url: str = Field(..., description="Default URL after container starts")
    default_port: int = Field(..., description="Port the service listens on")
    tags: list[str] = Field(default_factory=list, description="Searchable tags")
    difficulty: str = Field("medium", description="beginner / easy / medium / hard")
    expected_findings: list[str] = Field(
        default_factory=list,
        description="List of finding types this lab is expected to surface",
    )
