from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class ParameterType(str, Enum):
    QUERY = "query"
    POST = "post"
    COOKIE = "cookie"
    HEADER = "header"
    PATH = "path"
    JSON = "json"


class ParameterSensitivity(str, Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


SENSITIVE_PARAM_NAMES: dict[str, ParameterSensitivity] = {
    "id": ParameterSensitivity.HIGH,
    "user": ParameterSensitivity.HIGH,
    "file": ParameterSensitivity.HIGH,
    "redirect": ParameterSensitivity.HIGH,
    "next": ParameterSensitivity.HIGH,
    "return": ParameterSensitivity.HIGH,
    "url": ParameterSensitivity.HIGH,
    "page": ParameterSensitivity.MEDIUM,
    "search": ParameterSensitivity.MEDIUM,
    "token": ParameterSensitivity.CRITICAL,
    "password": ParameterSensitivity.CRITICAL,
    "secret": ParameterSensitivity.CRITICAL,
    "key": ParameterSensitivity.CRITICAL,
    "api": ParameterSensitivity.HIGH,
    "filepath": ParameterSensitivity.HIGH,
    "path": ParameterSensitivity.HIGH,
    "template": ParameterSensitivity.HIGH,
    "include": ParameterSensitivity.HIGH,
    "document": ParameterSensitivity.HIGH,
    "download": ParameterSensitivity.HIGH,
    "callback": ParameterSensitivity.HIGH,
    "webhook": ParameterSensitivity.HIGH,
    "target": ParameterSensitivity.HIGH,
    "reference": ParameterSensitivity.MEDIUM,
    "order": ParameterSensitivity.MEDIUM,
    "email": ParameterSensitivity.MEDIUM,
    "username": ParameterSensitivity.HIGH,
    "role": ParameterSensitivity.HIGH,
    "admin": ParameterSensitivity.CRITICAL,
    "debug": ParameterSensitivity.HIGH,
    "source": ParameterSensitivity.MEDIUM,
    "lang": ParameterSensitivity.LOW,
    "ref": ParameterSensitivity.MEDIUM,
    "checkout": ParameterSensitivity.HIGH,
    "coupon": ParameterSensitivity.HIGH,
    "discount": ParameterSensitivity.HIGH,
    "promo": ParameterSensitivity.HIGH,
    "credit": ParameterSensitivity.HIGH,
    "wallet": ParameterSensitivity.HIGH,
    "balance": ParameterSensitivity.HIGH,
    "points": ParameterSensitivity.MEDIUM,
    "reward": ParameterSensitivity.MEDIUM,
    "cashback": ParameterSensitivity.HIGH,
    "bonus": ParameterSensitivity.MEDIUM,
    "quantity": ParameterSensitivity.MEDIUM,
    "price": ParameterSensitivity.HIGH,
    "total": ParameterSensitivity.HIGH,
}


class ParameterProfile(BaseModel):
    name: str
    param_type: ParameterType = ParameterType.QUERY
    locations: list[str] = Field(default_factory=list)
    values_seen: list[str] = Field(default_factory=list)
    reflected: bool = False
    reflection_context: str = ""
    sensitivity: ParameterSensitivity = ParameterSensitivity.NONE
    found_in_js: bool = False
    found_in_form: bool = False
    indicator_tags: list[str] = Field(default_factory=list)
    extra: dict[str, Any] = Field(default_factory=dict)

    @classmethod
    def classify_sensitivity(cls, name: str) -> ParameterSensitivity:
        lower = name.lower().strip()
        return SENSITIVE_PARAM_NAMES.get(lower, ParameterSensitivity.NONE)
