from __future__ import annotations

from typing import Any

from ghostmirror.core.logger import get_logger
from ghostmirror.models.api_security_report import APISecurityReport

logger = get_logger()


class APIReportBuilder:
    def build(self, target: str,
              inventory: dict[str, Any],
              swagger: dict[str, Any] | None,
              graphql: dict[str, Any] | None,
              jwt: dict[str, Any] | None,
              oauth: dict[str, Any] | None,
              object_inventory: list[dict[str, Any]],
              rate_limit: dict[str, Any] | None,
              attack_surface: dict[str, Any] | None,
              bola_indicators: list[dict[str, Any]],
              bfla_indicators: list[dict[str, Any]],
              mass_assignment_indicators: list[dict[str, Any]],
              correlations: list[dict[str, Any]],
              opportunities: list[dict[str, Any]],
              recommendations: list[str],
              findings: list[dict[str, Any]],
              overall_score: int,
              risk_level: str) -> APISecurityReport:
        logger.info("API_REPORT_BUILDER_START score={}", overall_score)

        return APISecurityReport(
            target=target,
            api_inventory=inventory,
            swagger_profile=swagger,
            graphql_profile=graphql,
            jwt_profile=jwt,
            oauth_profile=oauth,
            object_inventory=object_inventory,
            rate_limit_profile=rate_limit,
            attack_surface=attack_surface,
            bola_indicators=bola_indicators,
            bfla_indicators=bfla_indicators,
            mass_assignment_indicators=mass_assignment_indicators,
            correlations=correlations,
            opportunities=opportunities,
            recommendations=recommendations,
            findings=findings,
            overall_score=overall_score,
            risk_level=risk_level,
        )
