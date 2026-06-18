"""Pydantic models for projects and their persisted metadata (``metadata.json``)."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field

from ghostmirror import __version__


class ProjectStatus(str, Enum):
    """Lifecycle status of an engagement project."""

    ACTIVE = "active"
    PAUSED = "paused"
    COMPLETED = "completed"
    ARCHIVED = "archived"


def _utcnow() -> datetime:
    """Timezone-aware UTC timestamp (avoids naive ``datetime.utcnow``)."""

    return datetime.now(timezone.utc)


class ProjectModel(BaseModel):
    """Persisted project metadata, serialized to ``metadata.json``."""

    uuid: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = Field(..., min_length=1, description="Project / engagement name")
    client: str = Field(..., min_length=1, description="Client name")
    domain: str | None = Field(default=None, description="Primary domain")
    notes: str | None = Field(default=None, description="Free-form observations")
    status: ProjectStatus = Field(default=ProjectStatus.ACTIVE)
    created_at: datetime = Field(default_factory=_utcnow)
    ghostmirror_version: str = Field(default=__version__)
