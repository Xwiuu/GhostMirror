from __future__ import annotations

from typing import Any

from ghostmirror.models.attack_chain_signal import SignalType


class ChainTemplate:
    def __init__(
        self, name: str, description: str,
        required_signals: list[SignalType],
        optional_signals: list[SignalType] | None = None,
        chain_type: str = "general",
    ) -> None:
        self.name = name
        self.description = description
        self.required_signals = required_signals
        self.optional_signals = optional_signals or []
        self.chain_type = chain_type


TEMPLATES: list[ChainTemplate] = [
    ChainTemplate(
        name="JWT + Admin API + Sensitive Object",
        description="JWT authentication on admin API endpoints accessing sensitive objects",
        required_signals=[SignalType.JWT_DETECTED, SignalType.EXPOSED_ADMIN, SignalType.SENSITIVE_OBJECT],
        optional_signals=[SignalType.AUTH_SURFACE],
        chain_type="authentication_bypass",
    ),
    ChainTemplate(
        name="Swagger/OpenAPI + Admin Endpoint + BOLA Indicator",
        description="Exposed API documentation revealing admin endpoints with potential BOLA",
        required_signals=[SignalType.EXPOSED_API, SignalType.EXPOSED_ADMIN, SignalType.BOLA_INDICATOR],
        optional_signals=[SignalType.AUTH_SURFACE, SignalType.SENSITIVE_OBJECT],
        chain_type="api_abuse",
    ),
    ChainTemplate(
        name="Source Map + Hidden Functionality + Internal API",
        description="Source map exposure revealing internal API endpoints and hidden functionality",
        required_signals=[SignalType.SOURCE_MAP_EXPOSED, SignalType.EXPOSED_API],
        optional_signals=[SignalType.BUSINESS_LOGIC_SURFACE, SignalType.SECRET_EXPOSED],
        chain_type="information_disclosure",
    ),
    ChainTemplate(
        name="Public CVE + Internet Exposed Service + No WAF",
        description="Known vulnerability in an internet-exposed service without WAF protection",
        required_signals=[SignalType.CVE_KNOWN_EXPLOITED, SignalType.PUBLIC_EXPLOIT_AVAILABLE],
        optional_signals=[SignalType.SENSITIVE_OBJECT, SignalType.MISSING_HEADER],
        chain_type="known_vulnerability",
    ),
    ChainTemplate(
        name="Business Logic Surface + Payment Object + Weak Auth Signal",
        description="Business logic function processing payments with weak authentication",
        required_signals=[SignalType.BUSINESS_LOGIC_SURFACE, SignalType.SENSITIVE_OBJECT, SignalType.AUTH_SURFACE],
        optional_signals=[SignalType.MASS_ASSIGNMENT_INDICATOR],
        chain_type="business_logic_abuse",
    ),
    ChainTemplate(
        name="GraphQL Surface + Sensitive Object + Auth Weakness",
        description="GraphQL endpoint exposing sensitive data with authentication weaknesses",
        required_signals=[SignalType.GRAPHQL_SURFACE, SignalType.SENSITIVE_OBJECT],
        optional_signals=[SignalType.AUTH_SURFACE, SignalType.MASS_ASSIGNMENT_INDICATOR],
        chain_type="api_abuse",
    ),
    ChainTemplate(
        name="Secret Exposure + API Endpoint + Cloud Service Indicator",
        description="Exposed secrets (API keys, tokens) providing access to cloud APIs",
        required_signals=[SignalType.SECRET_EXPOSED, SignalType.EXPOSED_API],
        optional_signals=[SignalType.SENSITIVE_OBJECT, SignalType.BUSINESS_LOGIC_SURFACE],
        chain_type="credential_exposure",
    ),
    ChainTemplate(
        name="Missing Security Header + XSS Indicator + Auth Flow",
        description="Missing security headers enabling XSS in authentication flows",
        required_signals=[SignalType.MISSING_HEADER],
        optional_signals=[SignalType.AUTH_SURFACE, SignalType.SENSITIVE_OBJECT],
        chain_type="client_side_attack",
    ),
    ChainTemplate(
        name="Rate Limit Unknown + Auth Endpoint + Sensitive Action",
        description="Authentication endpoint without rate limiting enabling brute force",
        required_signals=[SignalType.RATE_LIMIT_UNKNOWN, SignalType.AUTH_SURFACE],
        optional_signals=[SignalType.SENSITIVE_OBJECT, SignalType.BUSINESS_LOGIC_SURFACE],
        chain_type="authentication_bypass",
    ),
    ChainTemplate(
        name="Zero-Day Hypothesis + Business Logic + API Object",
        description="Hypothesized vulnerability in business logic API processing objects",
        required_signals=[SignalType.ZERO_DAY_HYPOTHESIS, SignalType.BUSINESS_LOGIC_SURFACE],
        optional_signals=[SignalType.SENSITIVE_OBJECT, SignalType.EXPOSED_API],
        chain_type="zero_day",
    ),
]


def get_template_by_name(name: str) -> ChainTemplate | None:
    for t in TEMPLATES:
        if t.name == name:
            return t
    return None


def get_templates_by_type(chain_type: str) -> list[ChainTemplate]:
    return [t for t in TEMPLATES if t.chain_type == chain_type]
