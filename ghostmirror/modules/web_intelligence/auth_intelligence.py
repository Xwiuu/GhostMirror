from __future__ import annotations

import re
from typing import Any

from ghostmirror.core.logger import get_logger
from ghostmirror.models.web_endpoint import WebEndpoint

logger = get_logger()

LOGIN_PATTERNS = re.compile(
    r"(login|signin|sign-in|logon|log-in|auth|authenticate|sso|oauth|openid)",
    re.IGNORECASE,
)
REGISTER_PATTERNS = re.compile(
    r"(register|signup|sign-up|create-account|join|cadastro|cadastrar)",
    re.IGNORECASE,
)
RESET_PATTERNS = re.compile(
    r"(reset|forgot|recover|recuperar|esqueci|reset-password|forgot-password)",
    re.IGNORECASE,
)
ADMIN_PATTERNS = re.compile(r"(admin|dashboard|painel|backoffice|administrator|adm)", re.IGNORECASE)
MFA_PATTERNS = re.compile(r"(mfa|2fa|two-factor|otp|totp|authenticator|verification)", re.IGNORECASE)
SESSION_PATTERN = re.compile(
    r"(session[id]?|session_token|sessid|jsessionid|phpsessid|aspsessionid|token|jwt|bearer)",
    re.IGNORECASE,
)
PROFILE_PATTERNS = re.compile(
    r"(profile|account|me|user|my-account|settings|preferences|configuracoes)",
    re.IGNORECASE,
)


class AuthIntelligence:
    def analyze(self, endpoints: list[WebEndpoint], headers: dict[str, str] | None = None) -> dict[str, Any]:
        logger.info("AUTH_INTELLIGENCE_START endpoints={}", len(endpoints))
        profile: dict[str, Any] = {
            "login_endpoints": [],
            "register_endpoints": [],
            "reset_password_endpoints": [],
            "admin_endpoints": [],
            "mfa_endpoints": [],
            "profile_endpoints": [],
            "session_cookies_detected": [],
            "total_auth_endpoints": 0,
            "has_login": False,
            "has_register": False,
            "has_reset_password": False,
            "has_admin": False,
            "has_mfa": False,
        }

        for ep in endpoints:
            url_lower = ep.url.lower()

            if LOGIN_PATTERNS.search(url_lower) or ep.is_auth:
                if "login" in url_lower or "signin" in url_lower:
                    profile["login_endpoints"].append(ep.url)
                    profile["has_login"] = True

            if REGISTER_PATTERNS.search(url_lower):
                profile["register_endpoints"].append(ep.url)
                profile["has_register"] = True

            if RESET_PATTERNS.search(url_lower):
                profile["reset_password_endpoints"].append(ep.url)
                profile["has_reset_password"] = True

            if ADMIN_PATTERNS.search(url_lower) or ep.is_admin:
                profile["admin_endpoints"].append(ep.url)
                profile["has_admin"] = True

            if MFA_PATTERNS.search(url_lower):
                profile["mfa_endpoints"].append(ep.url)
                profile["has_mfa"] = True

            if PROFILE_PATTERNS.search(url_lower):
                profile["profile_endpoints"].append(ep.url)

        if headers:
            for header_name, header_value in headers.items():
                if SESSION_PATTERN.search(header_name) or SESSION_PATTERN.search(header_value):
                    profile["session_cookies_detected"].append(f"{header_name}={header_value[:50]}")

        profile["total_auth_endpoints"] = (
            len(profile["login_endpoints"])
            + len(profile["register_endpoints"])
            + len(profile["reset_password_endpoints"])
            + len(profile["admin_endpoints"])
            + len(profile["mfa_endpoints"])
        )

        logger.info("AUTH_INTELLIGENCE_DONE total_auth={}", profile["total_auth_endpoints"])
        return profile
