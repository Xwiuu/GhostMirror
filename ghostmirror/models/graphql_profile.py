from __future__ import annotations

from pydantic import BaseModel, Field


class GraphQLProfile(BaseModel):
    detected: bool = False
    endpoints: list[str] = Field(default_factory=list)
    frameworks: list[str] = Field(default_factory=list)
    has_playground: bool = False
    has_graphiql: bool = False
    has_introspection: bool = False
    schema_exposure_indicators: list[str] = Field(default_factory=list)
