from __future__ import annotations

import json
from pathlib import Path

import pytest

from ghostmirror.modules.api_security.engine import APISecurityEngine
from ghostmirror.modules.api_security.endpoint_classifier import EndpointClassifier
from ghostmirror.modules.api_security.parameter_analyzer import ParameterAnalyzer
from ghostmirror.modules.api_security.exposure_analysis import ExposureAnalysis
from ghostmirror.modules.api_security.scoring import APIScoringEngine
from ghostmirror.modules.api_security.recommendations import APIRecommendations
from ghostmirror.modules.api_security.findings_mapper import APIFindingsMapper
from ghostmirror.modules.api_security.report_builder import APIReportBuilder
from ghostmirror.modules.api_security.api_correlation import APICorrelation
from ghostmirror.modules.api_security.auth_intelligence import AuthIntelligence
from ghostmirror.modules.api_security.openapi_parser import OpenAPIParser
from ghostmirror.modules.api_security.swagger_discovery import SwaggerDiscovery
from ghostmirror.models.api_security_report import APISecurityReport
from ghostmirror.models.api_endpoint import APIEndpoint
from ghostmirror.models.api_inventory_profile import APIInventoryProfile
from ghostmirror.models.graphql_profile import GraphQLProfile
from ghostmirror.models.jwt_profile import JWTProfile
from ghostmirror.models.oauth_profile import OAuthProfile
from ghostmirror.models.api_risk import APIRisk
from ghostmirror.models.api_attack_surface import APIAttackSurface


class TestEndpointClassifier:
    def test_classify_api(self):
        classifier = EndpointClassifier()
        result = classifier.classify({"path": "/api/users"})
        assert result["is_api"]
        assert not result["is_admin"]

    def test_classify_admin(self):
        classifier = EndpointClassifier()
        result = classifier.classify({"path": "/admin/dashboard"})
        assert result["is_admin"]

    def test_classify_auth(self):
        classifier = EndpointClassifier()
        result = classifier.classify({"path": "/login"})
        assert result["is_auth"]

    def test_classify_payment(self):
        classifier = EndpointClassifier()
        result = classifier.classify({"path": "/checkout"})
        assert result["is_payment"]

    def test_classify_graphql(self):
        classifier = EndpointClassifier()
        result = classifier.classify({"path": "/graphql"})
        assert result["is_graphql"]

    def test_classify_batch(self):
        classifier = EndpointClassifier()
        eps = [{"path": "/api/users"}, {"path": "/admin"}, {"path": "/login"}]
        result = classifier.classify_batch(eps)
        assert len(result) == 3
        assert all("classification" in ep for ep in result)


class TestParameterAnalyzer:
    def test_identifies_path_params(self):
        analyzer = ParameterAnalyzer()
        result = analyzer.analyze([{"path": "/api/users/{id}", "method": "GET", "params": []}])
        assert result["total_object_references"] >= 1
        assert len(result["object_references"]) >= 1

    def test_identifies_query_params(self):
        analyzer = ParameterAnalyzer()
        result = analyzer.analyze([{"path": "/api/users", "method": "GET", "params": ["user_id", "name"]}])
        assert result["total_parameters"] == 2
        assert result["total_object_references"] >= 1

    def test_sensitive_param_detection(self):
        analyzer = ParameterAnalyzer()
        result = analyzer.analyze([{"path": "/api/login", "method": "POST", "params": ["password", "token"]}])
        assert len(result["sensitive_params"]) >= 2


class TestExposureAnalysis:
    def test_low_score_empty(self):
        analysis = ExposureAnalysis()
        result = analysis.calculate(
            {"total_endpoints": 0, "auth_required_count": 0, "endpoints": []},
            {"detected": False}, {"detected": False}, {"detected": False, "has_exp": True},
            {"detected": False}, {"classification": "Unknown"}, [], [], [],
        )
        assert 0 <= result["exposure_score"] <= 100

    def test_high_score_many_factors(self):
        analysis = ExposureAnalysis()
        result = analysis.calculate(
            {"total_endpoints": 50, "auth_required_count": 5, "endpoints": [
                {"classification": {"is_admin": True, "is_api": True, "is_payment": False}},
                {"classification": {"is_payment": True, "is_api": True, "is_admin": False}},
            ]},
            {"detected": True, "found_paths": ["/swagger"]},
            {"detected": True, "endpoints": ["/graphql"]},
            {"detected": True, "has_exp": False, "has_none_alg_indicator": True},
            {"detected": True},
            {"classification": "Weak"},
            [{"type": "Financial"}, {"type": "Admin"}],
            [{"confidence": "HIGH"}, {"confidence": "MEDIUM"}],
            [{"confidence": "HIGH"}],
        )
        assert result["exposure_score"] > 0
        assert len(result["factors"]) > 0

    def test_risk_level(self):
        analysis = ExposureAnalysis()
        assert analysis._risk_level(80) == "CRITICAL"
        assert analysis._risk_level(55) == "HIGH"
        assert analysis._risk_level(35) == "MEDIUM"
        assert analysis._risk_level(20) == "LOW"
        assert analysis._risk_level(5) == "INFO"


class TestAPIScoring:
    def test_classify_score(self):
        assert APIScoringEngine.classify_score(85) == "CRITICAL"
        assert APIScoringEngine.classify_score(65) == "HIGH"
        assert APIScoringEngine.classify_score(40) == "MEDIUM"
        assert APIScoringEngine.classify_score(20) == "LOW"
        assert APIScoringEngine.classify_score(5) == "INFO"

    def test_calculate_opportunities(self):
        scoring = APIScoringEngine()
        opportunities = scoring.calculate_opportunities(
            [{"type": "JWT_ADMIN_API", "title": "Test", "score": 80, "classification": "HIGH"}],
            {"exposure_score": 50},
            [{"confidence": "HIGH", "method": "GET", "endpoint": "/api/users/123",
              "description": "BOLA test"}],
            [{"confidence": "HIGH", "method": "DELETE", "endpoint": "/admin/users",
              "description": "BFLA test"}],
            [{"confidence": "MEDIUM", "method": "POST", "endpoint": "/api/users",
              "description": "MA test"}],
        )
        assert len(opportunities) >= 3
        assert opportunities[0]["score"] >= opportunities[-1]["score"]

    def test_calculate_overall_score(self):
        scoring = APIScoringEngine()
        score = scoring.calculate_overall_score(
            {"exposure_score": 50},
            [{"score": 80}, {"score": 60}],
            [{"score": 75}, {"score": 45}],
        )
        assert 0 <= score <= 100


class TestCorrelation:
    def test_correlate_empty(self):
        corr = APICorrelation()
        result = corr.correlate(
            {"total_endpoints": 0, "endpoints": []},
            {"detected": False}, {"detected": False},
            {"detected": False}, {"detected": False},
            [], [], [],
        )
        assert result == []

    def test_correlate_jwt_admin(self):
        corr = APICorrelation()
        result = corr.correlate(
            {"endpoints": [{"classification": {"is_admin": True}}]},
            {"detected": False}, {"detected": False},
            {"detected": True, "has_exp": True, "has_none_alg_indicator": False},
            {"detected": False}, [],
            [], [{"confidence": "HIGH"}],
        )
        assert any(c["type"] == "JWT_ADMIN_API" for c in result)


class TestRecommendations:
    def test_generates_recommendations(self):
        recs = APIRecommendations()
        result = recs.generate({
            "api_inventory": {"total_endpoints": 10, "auth_required_count": 2},
            "swagger_profile": {"detected": False},
            "graphql_profile": {"detected": False},
            "jwt_profile": {"detected": False},
            "oauth_profile": {"detected": False},
            "rate_limit_profile": {"classification": "Unknown"},
            "attack_surface": {"exposure_score": 30},
            "bola_indicators": [],
            "bfla_indicators": [],
            "mass_assignment_indicators": [],
        })
        assert len(result) > 0

    def test_recommends_swagger_restriction(self):
        recs = APIRecommendations()
        result = recs.generate({
            "api_inventory": {"total_endpoints": 5, "auth_required_count": 0},
            "swagger_profile": {"detected": True, "found_paths": ["/swagger"]},
            "graphql_profile": {"detected": False},
            "jwt_profile": {"detected": False},
            "oauth_profile": {"detected": False},
            "rate_limit_profile": {"classification": "Strong"},
            "attack_surface": {"exposure_score": 15},
            "bola_indicators": [],
            "bfla_indicators": [],
            "mass_assignment_indicators": [],
        })
        assert any("Swagger" in r for r in result)

    def test_recommends_jwt_fix(self):
        recs = APIRecommendations()
        result = recs.generate({
            "api_inventory": {"total_endpoints": 3, "auth_required_count": 1},
            "swagger_profile": {"detected": False},
            "graphql_profile": {"detected": False},
            "jwt_profile": {"detected": True, "has_none_alg_indicator": True,
                            "has_exp": False, "weak_algorithms": ["none"]},
            "oauth_profile": {"detected": False},
            "rate_limit_profile": {"classification": "Strong"},
            "attack_surface": {"exposure_score": 50},
            "bola_indicators": [],
            "bfla_indicators": [],
            "mass_assignment_indicators": [],
        })
        assert any("none" in r or "CRITICAL" in r for r in result)


class TestFindingsMapper:
    def test_empty_report(self):
        mapper = APIFindingsMapper()
        findings = mapper.map_to_findings({"target": "http://test.com"})
        assert isinstance(findings, list)

    def test_maps_jwt_none_alg(self):
        mapper = APIFindingsMapper()
        findings = mapper.map_to_findings({
            "target": "http://test.com",
            "jwt_profile": {"detected": True, "has_none_alg_indicator": True,
                            "has_exp": True, "redacted_tokens": []},
        })
        assert any("none" in f.title.lower() for f in findings)

    def test_maps_missing_exp(self):
        mapper = APIFindingsMapper()
        findings = mapper.map_to_findings({
            "target": "http://test.com",
            "jwt_profile": {"detected": True, "has_none_alg_indicator": False,
                            "has_exp": False, "redacted_tokens": []},
        })
        assert any("expiration" in f.title.lower() for f in findings)

    def test_maps_bola_indicators(self):
        mapper = APIFindingsMapper()
        findings = mapper.map_to_findings({
            "target": "http://test.com",
            "bola_indicators": [{"confidence": "HIGH", "auth_required": False,
                                 "method": "GET", "endpoint": "/api/users/123",
                                 "description": "Test BOLA"}],
        })
        assert any("BOLA" in f.title for f in findings)

    def test_maps_bfla_indicators(self):
        mapper = APIFindingsMapper()
        findings = mapper.map_to_findings({
            "target": "http://test.com",
            "bfla_indicators": [{"confidence": "HIGH", "auth_required": False,
                                 "method": "DELETE", "endpoint": "/admin/users",
                                 "description": "Test BFLA"}],
        })
        assert any("BFLA" in f.title for f in findings)

    def test_maps_swagger(self):
        mapper = APIFindingsMapper()
        findings = mapper.map_to_findings({
            "target": "http://test.com",
            "swagger_profile": {"detected": True, "found_paths": ["/swagger"]},
        })
        assert any("Swagger" in f.title for f in findings)


class TestReportBuilder:
    def test_build_report(self):
        builder = APIReportBuilder()
        report = builder.build(
            target="http://test.com",
            inventory={"total_endpoints": 5},
            swagger={"detected": False},
            graphql={"detected": True, "endpoints": ["/graphql"]},
            jwt={"detected": True, "has_exp": False},
            oauth={"detected": False},
            object_inventory=[{"type": "User", "pattern": "users"}],
            rate_limit={"classification": "Unknown"},
            attack_surface={"exposure_score": 30, "risk_level": "MEDIUM"},
            bola_indicators=[{"confidence": "HIGH", "endpoint": "/api/users/123"}],
            bfla_indicators=[{"confidence": "MEDIUM", "endpoint": "/admin"}],
            mass_assignment_indicators=[{"confidence": "LOW", "endpoint": "/api/users"}],
            correlations=[{"type": "JWT_ADMIN_API", "score": 75}],
            opportunities=[{"type": "BOLA", "score": 70}],
            recommendations=["Fix JWT"],
            findings=[{"title": "Test Finding"}],
            overall_score=55,
            risk_level="HIGH",
        )
        assert isinstance(report, APISecurityReport)
        assert report.target == "http://test.com"
        assert report.overall_score == 55
        assert report.risk_level == "HIGH"
        assert len(report.object_inventory) == 1
        assert len(report.bola_indicators) == 1
        assert len(report.bfla_indicators) == 1
        assert len(report.mass_assignment_indicators) == 1
        assert len(report.correlations) == 1
        assert len(report.opportunities) == 1
        assert len(report.recommendations) == 1


class TestModels:
    def test_api_endpoint(self):
        ep = APIEndpoint(method="POST", path="/api/users", auth_required=True, confidence="high")
        assert ep.method == "POST"
        assert ep.auth_required is True

    def test_api_inventory_profile(self):
        prof = APIInventoryProfile(total_endpoints=10, auth_required_count=3)
        assert prof.total_endpoints == 10

    def test_graphql_profile(self):
        prof = GraphQLProfile(detected=True, endpoints=["/graphql"], frameworks=["apollo"])
        assert prof.detected
        assert "apollo" in prof.frameworks

    def test_jwt_profile(self):
        prof = JWTProfile(detected=True, total_tokens_found=5, has_none_alg_indicator=True)
        assert prof.detected
        assert prof.has_none_alg_indicator

    def test_oauth_profile(self):
        prof = OAuthProfile(detected=True, providers=["keycloak"], has_authorize=True)
        assert prof.detected
        assert "keycloak" in prof.providers

    def test_api_risk(self):
        risk = APIRisk(endpoint="/api/users/123", method="GET", bola_potential=True, bola_confidence="HIGH")
        assert risk.bola_potential
        assert risk.bola_confidence == "HIGH"

    def test_api_attack_surface(self):
        surf = APIAttackSurface(exposure_score=75, total_endpoints=30)
        assert surf.exposure_score == 75
        assert surf.total_endpoints == 30

    def test_api_security_report(self):
        report = APISecurityReport(target="http://test.com", overall_score=45, risk_level="MEDIUM")
        assert report.target == "http://test.com"
        assert report.overall_score == 45


class TestAuthIntelligence:
    def test_no_auth(self):
        ai = AuthIntelligence()
        result = ai.analyze({"detected": False}, {"detected": False})
        assert not result["jwt_detected"]
        assert not result["oauth_detected"]
        assert result["total_auth_mechanisms"] == 0

    def test_jwt_detected(self):
        ai = AuthIntelligence()
        result = ai.analyze({"detected": True}, {"detected": False})
        assert result["jwt_detected"]

    def test_both_detected(self):
        ai = AuthIntelligence()
        result = ai.analyze({"detected": True}, {"detected": True})
        assert result["total_auth_mechanisms"] == 2

    def test_weak_jwt(self):
        ai = AuthIntelligence()
        result = ai.analyze({"detected": True, "weak_algorithms": ["none"]}, {"detected": False})
        assert result["has_weak_jwt"]


class TestOpenAPIParser:
    def test_parse_empty_spec(self):
        parser = OpenAPIParser()
        result = parser.parse({})
        assert result["total_paths"] == 0
        assert result["version"] == ""

    def test_parse_with_paths(self):
        parser = OpenAPIParser()
        spec = {
            "info": {"version": "3.0.0"},
            "paths": {
                "/users": {"get": {"summary": "List users"}, "post": {"summary": "Create user"}},
                "/users/{id}": {"get": {"summary": "Get user"}},
            },
            "components": {
                "securitySchemes": {"BearerAuth": {"type": "http"}},
                "schemas": {"User": {}, "Error": {}},
            },
        }
        result = parser.parse(spec)
        assert result["version"] == "3.0.0"
        assert result["total_paths"] == 3
        assert "GET" in result["methods"]
        assert "POST" in result["methods"]
        assert "User" in result["schemas"]
        assert "Error" in result["schemas"]
        assert len(result["auth_definitions"]) > 0


class TestSwaggerDiscovery:
    def test_no_swagger(self):
        sd = SwaggerDiscovery()
        result = sd.discover([{"path": "/api/users"}])
        assert not result["detected"]

    def test_detects_swagger_json(self):
        sd = SwaggerDiscovery()
        result = sd.discover([{"path": "/swagger.json"}])
        assert result["detected"]
        assert "/swagger.json" in result["found_paths"]

    def test_detects_openapi_json(self):
        sd = SwaggerDiscovery()
        result = sd.discover([{"path": "/openapi.json"}])
        assert result["detected"]

    def test_detects_api_docs(self):
        sd = SwaggerDiscovery()
        result = sd.discover([{"path": "/api-docs"}])
        assert result["detected"]
