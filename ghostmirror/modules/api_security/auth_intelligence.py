from __future__ import annotations

from typing import Any

from ghostmirror.core.logger import get_logger

logger = get_logger()


class AuthIntelligence:
    def __init__(self) -> None:
        self.jwt_profile: dict[str, Any] = {}
        self.oauth_profile: dict[str, Any] = {}

    def analyze(
        self,
        jwt_profile: dict[str, Any],
        oauth_profile: dict[str, Any],
    ) -> dict[str, Any]:
        logger.info("AUTH_INTELLIGENCE_START")
        self.jwt_profile = jwt_profile
        self.oauth_profile = oauth_profile

        auth_surface = {
            "jwt_detected": jwt_profile.get("detected", False),
            "oauth_detected": oauth_profile.get("detected", False),
            "total_auth_mechanisms": sum([
                1 if jwt_profile.get("detected") else 0,
                1 if oauth_profile.get("detected") else 0,
            ]),
            "has_weak_jwt": len(jwt_profile.get("weak_algorithms", [])) > 0,
            "has_jwt_missing_exp": jwt_profile.get("detected", False) and not jwt_profile.get("has_exp", True),
            "oauth_providers": oauth_profile.get("providers", []),
            "oauth_endpoints": oauth_profile.get("endpoints", {}),
        }

        logger.info("AUTH_INTELLIGENCE_DONE jwt={} oauth={}",
                    auth_surface["jwt_detected"], auth_surface["oauth_detected"])
        return auth_surface
