from __future__ import annotations

from pydantic import BaseModel, Field


class DiscoveredSecret(BaseModel):
    type: str = ""  # api_key, firebase, google_maps, stripe, sentry, supabase, aws, jwt, generic
    original_snippet: str = ""  # NEVER persisted to disk, used only in-memory for redaction
    redacted_snippet: str = ""
    location: str = ""  # url where found
    confidence: str = "medium"
    severity: str = "medium"
