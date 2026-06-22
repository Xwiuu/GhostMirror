from __future__ import annotations

from typing import Any

from ghostmirror.core.logger import get_logger

logger = get_logger()


class ExposureAnalysis:
    def calculate(self, inventory: dict[str, Any], swagger: dict[str, Any],
                  graphql: dict[str, Any], jwt: dict[str, Any],
                  oauth: dict[str, Any], rate_limit: dict[str, Any],
                  object_inventory: list[dict[str, Any]],
                  bola_indicators: list[dict[str, Any]],
                  bfla_indicators: list[dict[str, Any]]) -> dict[str, Any]:
        logger.info("EXPOSURE_ANALYSIS_START")

        total_endpoints = inventory.get("total_endpoints", 0)
        auth_required = inventory.get("auth_required_count", 0)
        swagger_detected = swagger.get("detected", False)
        graphql_detected = graphql.get("detected", False)
        jwt_detected = jwt.get("detected", False)
        oauth_detected = oauth.get("detected", False)
        rl_class = rate_limit.get("classification", "Unknown")

        sensitive_objects = len([o for o in object_inventory if o.get("type") in ("Financial", "Admin", "Security")])
        admin_count = sum(1 for ep in inventory.get("endpoints", [])
                          if ep.get("classification", {}).get("is_admin"))
        payment_count = sum(1 for ep in inventory.get("endpoints", [])
                            if ep.get("classification", {}).get("is_payment"))
        object_refs = len(bola_indicators)
        bola_high = sum(1 for b in bola_indicators if b.get("confidence", "") == "HIGH")
        bfla_high = sum(1 for b in bfla_indicators if b.get("confidence", "") == "HIGH")

        ep_score = min(total_endpoints / 20, 1.0) * 10
        auth_coverage = (auth_required / max(total_endpoints, 1)) * 15
        swagger_bonus = 5 if swagger_detected else 0
        graphql_bonus = 5 if graphql_detected else 0
        sensitive_score = min(sensitive_objects * 5, 20)
        admin_payment_score = min((admin_count + payment_count * 2) * 5, 25)
        rl_score = {"Unknown": 10, "Present": 5, "Strong": 0, "Weak": 8}.get(rl_class, 5)
        jwt_weak_score = 5 if jwt.get("has_none_alg_indicator") or not jwt.get("has_exp", True) else 0
        oauth_score = 5 if oauth_detected else 0
        bola_score = min(bola_high * 5, 10)
        bfla_score = min(bfla_high * 5, 10)

        raw_score = (ep_score + auth_coverage + swagger_bonus + graphql_bonus +
                     sensitive_score + admin_payment_score + rl_score +
                     jwt_weak_score + oauth_score + bola_score + bfla_score)

        exposure_score = min(round(raw_score), 100)

        result = {
            "exposure_score": exposure_score,
            "risk_level": self._risk_level(exposure_score),
            "factors": {
                "endpoint_density": round(ep_score, 1),
                "auth_coverage": round(auth_coverage, 1),
                "swagger_presence": swagger_bonus,
                "graphql_presence": graphql_bonus,
                "sensitive_objects": round(sensitive_score, 1),
                "admin_payment_exposure": round(admin_payment_score, 1),
                "rate_limit_weakness": rl_score,
                "jwt_weakness": jwt_weak_score,
                "oauth_presence": oauth_score,
                "bola_potential": round(bola_score, 1),
                "bfla_potential": round(bfla_score, 1),
            },
        }

        logger.info("EXPOSURE_ANALYSIS_DONE score={}", exposure_score)
        return result

    def _risk_level(self, score: int) -> str:
        if score >= 70:
            return "CRITICAL"
        if score >= 50:
            return "HIGH"
        if score >= 30:
            return "MEDIUM"
        if score >= 15:
            return "LOW"
        return "INFO"
