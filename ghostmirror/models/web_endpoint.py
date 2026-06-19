from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class HttpMethod(str, Enum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"
    PATCH = "PATCH"
    OPTIONS = "OPTIONS"
    HEAD = "HEAD"


class WebForm(BaseModel):
    action: str = ""
    method: str = "GET"
    inputs: list[str] = Field(default_factory=list)


class WebEndpoint(BaseModel):
    url: str
    method: HttpMethod = HttpMethod.GET
    params: list[str] = Field(default_factory=list)
    forms: list[WebForm] = Field(default_factory=list)
    tech_hints: list[str] = Field(default_factory=list)
    source_page: str = ""
    status_code: int = 0
    content_type: str = ""
    is_api: bool = False
    is_auth: bool = False
    is_admin: bool = False
    is_static: bool = False
    response_body_sample: str = ""
    extra: dict[str, Any] = Field(default_factory=dict)
