from __future__ import annotations

from typing import Any

from ghostmirror.core.logger import get_logger

logger = get_logger()

OAUTH_PROVIDERS = {
    "keycloak": ["keycloak", "key cloak"],
    "auth0": ["auth0"],
    "azure_ad": ["azure ad", "azuread", "login.microsoftonline", "microsoftonline"],
    "cognito": ["cognito", "amazoncognito"],
    "okta": ["okta"],
    "google": ["googleapis.com/auth", "accounts.google", "google.com/o/oauth"],
    "github": ["github.com/login/oauth"],
    "facebook": ["facebook.com/dialog/oauth", "facebook.com/v"],
    "fusionauth": ["fusionauth"],
}

OAUTH_ENDPOINTS = {
    "authorize": ["authorize", "oauth/authorize", "oidc/authorize"],
    "token": ["token", "oauth/token", "oidc/token"],
    "userinfo": ["userinfo", "oidc/userinfo", "me"],
    "jwks": ["jwks", "well-known/jwks", ".well-known/openid-configuration", "certs", "keys"],
}


class OAuthIntelligence:
    def __init__(self) -> None:
        self.providers: list[str] = []
        self.endpoints: dict[str, list[str]] = {}
        self.has_authorize: bool = False
        self.has_token: bool = False
        self.has_userinfo: bool = False
        self.has_jwks: bool = False

    def analyze(self, endpoints: list[dict[str, Any]]) -> dict[str, Any]:
        logger.info("OAUTH_INTELLIGENCE_START")
        self.providers = []
        self.endpoints = {k: [] for k in OAUTH_ENDPOINTS}
        self.has_authorize = False
        self.has_token = False
        self.has_userinfo = False
        self.has_jwks = False

        for ep in endpoints:
            path = ep.get("path", ep.get("url", "")).lower()
            headers = str(ep.get("headers", {})).lower()
            response_headers = str(ep.get("response_headers", {})).lower()
            body = str(ep.get("response_body", ep.get("body", ""))).lower()
            combined = path + headers + response_headers + body

            self._detect_providers(combined)
            self._detect_endpoints(path)

        result = {
            "detected": len(self.providers) > 0 or any(self.endpoints.values()),
            "providers": list(set(self.providers)),
            "endpoints": {k: list(set(v)) for k, v in self.endpoints.items() if v},
            "has_authorize": self.has_authorize,
            "has_token": self.has_token,
            "has_userinfo": self.has_userinfo,
            "has_jwks": self.has_jwks,
        }

        logger.info("OAUTH_INTELLIGENCE_DONE providers={}", self.providers)
        return result

    def _detect_providers(self, combined: str) -> None:
        for provider, indicators in OAUTH_PROVIDERS.items():
            for indicator in indicators:
                if indicator in combined:
                    if provider not in self.providers:
                        self.providers.append(provider)
                    break

    def _detect_endpoints(self, path: str) -> None:
        for etype, patterns in OAUTH_ENDPOINTS.items():
            for pattern in patterns:
                if pattern in path:
                    self.endpoints[etype].append(path)
                    if etype == "authorize":
                        self.has_authorize = True
                    elif etype == "token":
                        self.has_token = True
                    elif etype == "userinfo":
                        self.has_userinfo = True
                    elif etype == "jwks":
                        self.has_jwks = True
                    break
