from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ghostmirror.core.logger import get_logger
from ghostmirror.models.api_security_report import APISecurityReport
from ghostmirror.modules.api_security.api_inventory import APIInventory
from ghostmirror.modules.api_security.swagger_discovery import SwaggerDiscovery
from ghostmirror.modules.api_security.openapi_parser import OpenAPIParser
from ghostmirror.modules.api_security.graphql_discovery import GraphQLDiscovery
from ghostmirror.modules.api_security.graphql_intelligence import GraphQLIntelligence
from ghostmirror.modules.api_security.jwt_intelligence import JWTIntelligence
from ghostmirror.modules.api_security.oauth_intelligence import OAuthIntelligence
from ghostmirror.modules.api_security.auth_intelligence import AuthIntelligence
from ghostmirror.modules.api_security.endpoint_classifier import EndpointClassifier
from ghostmirror.modules.api_security.object_mapper import ObjectMapper
from ghostmirror.modules.api_security.parameter_analyzer import ParameterAnalyzer
from ghostmirror.modules.api_security.rate_limit_intelligence import RateLimitIntelligence
from ghostmirror.modules.api_security.exposure_analysis import ExposureAnalysis
from ghostmirror.modules.api_security.bola_indicators import BOLAIndicators
from ghostmirror.modules.api_security.bfla_indicators import BFLAIndicators
from ghostmirror.modules.api_security.mass_assignment_indicators import MassAssignmentIndicators
from ghostmirror.modules.api_security.api_correlation import APICorrelation
from ghostmirror.modules.api_security.scoring import APIScoringEngine
from ghostmirror.modules.api_security.recommendations import APIRecommendations
from ghostmirror.modules.api_security.findings_mapper import APIFindingsMapper
from ghostmirror.modules.api_security.report_builder import APIReportBuilder

logger = get_logger()


class APISecurityEngine:
    def __init__(self) -> None:
        self.inventory = APIInventory()
        self.swagger_discovery = SwaggerDiscovery()
        self.openapi_parser = OpenAPIParser()
        self.graphql_discovery = GraphQLDiscovery()
        self.graphql_intelligence = GraphQLIntelligence()
        self.jwt_intelligence = JWTIntelligence()
        self.oauth_intelligence = OAuthIntelligence()
        self.auth_intelligence = AuthIntelligence()
        self.endpoint_classifier = EndpointClassifier()
        self.object_mapper = ObjectMapper()
        self.parameter_analyzer = ParameterAnalyzer()
        self.rate_limit_intelligence = RateLimitIntelligence()
        self.exposure_analysis = ExposureAnalysis()
        self.bola_indicators = BOLAIndicators()
        self.bfla_indicators = BFLAIndicators()
        self.mass_assignment_indicators = MassAssignmentIndicators()
        self.correlation_engine = APICorrelation()
        self.scoring_engine = APIScoringEngine()
        self.recommendation_engine = APIRecommendations()
        self.findings_mapper = APIFindingsMapper()
        self.report_builder = APIReportBuilder()

    def analyze_project(
        self,
        project_path: Path | str,
        target_url: str | None = None,
    ) -> APISecurityReport:
        project_path = Path(project_path)
        logger.info("API_SECURITY_ENGINE_START project={}", project_path.name)

        api_dir = project_path / "profiles" / "api_security"
        api_dir.mkdir(parents=True, exist_ok=True)

        tech_profile = self._load_json(project_path / "profiles" / "technology_profile.json") or {}
        target = target_url or tech_profile.get("target", "")

        if not target:
            logger.warning("API_SECURITY_SKIPPED no target available")
            return self._empty_report()

        normalized_target = target if target.startswith("http") else f"https://{target}"

        inventory = self.inventory.consolidate(project_path)
        self._save_json(api_dir / "api_inventory.json", inventory.model_dump(mode="json"))

        raw_endpoints = inventory.model_dump(mode="json").get("endpoints", [])
        classified_endpoints = self.endpoint_classifier.classify_batch(raw_endpoints)

        swagger = self.swagger_discovery.discover(classified_endpoints)
        self._save_json(api_dir / "swagger_profile.json", swagger)

        graphql = self.graphql_discovery.discover(classified_endpoints)
        self._save_json(api_dir / "graphql_profile.json", graphql)

        gql_intel = self.graphql_intelligence.analyze(classified_endpoints)
        graphql["intelligence"] = gql_intel
        self._save_json(api_dir / "graphql_intelligence.json", gql_intel)

        jwt = self.jwt_intelligence.analyze(classified_endpoints)
        self._save_json(api_dir / "jwt_profile.json", jwt)

        oauth = self.oauth_intelligence.analyze(classified_endpoints)
        self._save_json(api_dir / "oauth_profile.json", oauth)

        auth = self.auth_intelligence.analyze(jwt, oauth)
        self._save_json(api_dir / "auth_profile.json", auth)

        objects = self.object_mapper.map(classified_endpoints)
        self._save_json(api_dir / "object_inventory.json", objects)

        params = self.parameter_analyzer.analyze(classified_endpoints)
        self._save_json(api_dir / "parameter_analysis.json", params)

        rl = self.rate_limit_intelligence.analyze(classified_endpoints)
        self._save_json(api_dir / "rate_limit_profile.json", rl)

        bolas = self.bola_indicators.analyze(classified_endpoints, objects)
        self._save_json(api_dir / "bola_indicators.json", bolas)

        bflas = self.bfla_indicators.analyze(classified_endpoints)
        self._save_json(api_dir / "bfla_indicators.json", bflas)

        mass_asgn = self.mass_assignment_indicators.analyze(classified_endpoints)
        self._save_json(api_dir / "mass_assignment_indicators.json", mass_asgn)

        inventory_dict = inventory.model_dump(mode="json")
        inventory_dict["endpoints"] = classified_endpoints

        surface = self.exposure_analysis.calculate(
            inventory_dict, swagger, graphql, jwt, oauth, rl,
            objects, bolas, bflas,
        )
        self._save_json(api_dir / "api_attack_surface.json", surface)

        correlations = self.correlation_engine.correlate(
            inventory_dict, swagger, graphql, jwt, oauth,
            objects, bolas, bflas,
        )
        self._save_json(api_dir / "api_correlations.json", correlations)

        opportunities = self.scoring_engine.calculate_opportunities(
            correlations, surface, bolas, bflas, mass_asgn,
        )
        self._save_json(api_dir / "api_opportunities.json", opportunities)

        overall_score = self.scoring_engine.calculate_overall_score(surface, correlations, opportunities)
        risk_level = APIScoringEngine.classify_score(overall_score)

        report_dict = {
            "target": normalized_target,
            "api_inventory": inventory_dict,
            "swagger_profile": swagger,
            "graphql_profile": graphql,
            "jwt_profile": jwt,
            "oauth_profile": oauth,
            "object_inventory": objects,
            "rate_limit_profile": rl,
            "attack_surface": surface,
            "bola_indicators": bolas,
            "bfla_indicators": bflas,
            "mass_assignment_indicators": mass_asgn,
            "correlations": correlations,
            "opportunities": opportunities,
            "recommendations": [],
            "findings": [],
            "overall_score": overall_score,
            "risk_level": risk_level,
        }

        recommendations = self.recommendation_engine.generate(report_dict)
        report_dict["recommendations"] = recommendations
        self._save_json(api_dir / "api_recommendations.json", recommendations)

        findings = self.findings_mapper.map_to_findings(report_dict)
        report_dict["findings"] = [f.model_dump(mode="json") for f in findings]
        self._save_json(api_dir / "api_findings.json", report_dict["findings"])

        report = self.report_builder.build(
            target=normalized_target,
            inventory=inventory_dict,
            swagger=swagger,
            graphql=graphql,
            jwt=jwt,
            oauth=oauth,
            object_inventory=objects,
            rate_limit=rl,
            attack_surface=surface,
            bola_indicators=bolas,
            bfla_indicators=bflas,
            mass_assignment_indicators=mass_asgn,
            correlations=correlations,
            opportunities=opportunities,
            recommendations=recommendations,
            findings=report_dict["findings"],
            overall_score=overall_score,
            risk_level=risk_level,
        )

        self._save_json(api_dir / "api_security_report.json", report.model_dump(mode="json"))
        self._save_api_findings(project_path, findings)

        logger.info(
            "API_SECURITY_ENGINE_DONE inventory={} bolas={} bflas={} opportunities={} score={}",
            inventory.total_endpoints, len(bolas), len(bflas),
            len(opportunities), overall_score,
        )

        return report

    def _save_json(self, path: Path, data: Any) -> None:
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception as exc:
            logger.warning("API_SECURITY_SAVE_FAIL path={} error={}", path, exc)

    def _load_json(self, path: Path) -> dict[str, Any] | None:
        if not path.exists():
            return None
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return None

    def _save_api_findings(self, project_path: Path, findings: list[Any]) -> None:
        if not findings:
            return
        try:
            findings_dir = project_path / "findings"
            findings_dir.mkdir(parents=True, exist_ok=True)
            path = findings_dir / "api_security.json"
            with open(path, "w", encoding="utf-8") as f:
                json.dump(
                    [f.model_dump(mode="json") for f in findings],
                    f, indent=2, ensure_ascii=False,
                )
            logger.info("API_SECURITY_FINDINGS_SAVED count={}", len(findings))
        except Exception as exc:
            logger.warning("API_SECURITY_FINDINGS_SAVE_FAIL error={}", exc)

    def _empty_report(self) -> APISecurityReport:
        return APISecurityReport(overall_score=0, risk_level="INFO")
