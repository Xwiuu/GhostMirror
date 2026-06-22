from __future__ import annotations

from ghostmirror.modules.api_security.api_correlation import APICorrelation
from ghostmirror.modules.api_security.recommendations import APIRecommendations
from ghostmirror.modules.api_security.jwt_intelligence import JWTIntelligence
from ghostmirror.modules.api_security.bola_indicators import BOLAIndicators
from ghostmirror.modules.api_security.swagger_discovery import SwaggerDiscovery
from ghostmirror.modules.api_security.openapi_parser import OpenAPIParser
from ghostmirror.modules.api_security.parameter_analyzer import ParameterAnalyzer


class TestAPICorrelationEdgeCases:
    def test_correlate_swagger_sensitive(self):
        corr = APICorrelation()
        result = corr.correlate(
            {"endpoints": []}, {"detected": True, "found_paths": ["/swagger"]},
            {"detected": False}, {"detected": False}, {"detected": False},
            [{"type": "Financial"}, {"type": "Admin"}], [], [],
        )
        assert any(c["type"] == "SWAGGER_SENSITIVE" for c in result)

    def test_correlate_graphql_no_auth(self):
        corr = APICorrelation()
        result = corr.correlate(
            {"endpoints": []}, {"detected": False},
            {"detected": True, "endpoints": ["/graphql"]},
            {"detected": False}, {"detected": False},
            [], [], [],
        )
        assert any(c["type"] == "GRAPHQL_NO_AUTH" for c in result)

    def test_correlate_bola_unauthenticated(self):
        corr = APICorrelation()
        result = corr.correlate(
            {"endpoints": []}, {"detected": False}, {"detected": False},
            {"detected": False}, {"detected": False}, [],
            [{"confidence": "HIGH", "auth_required": False}], [],
        )
        assert any(c["type"] == "BOLA_UNAUTHENTICATED" for c in result)

    def test_correlate_mass_assignment_admin(self):
        corr = APICorrelation()
        result = corr.correlate(
            {"endpoints": [
                {"classification": {"is_admin": True}, "method": "PUT"},
                {"classification": {"is_admin": True}, "method": "PATCH"},
            ]},
            {"detected": False}, {"detected": False},
            {"detected": False}, {"detected": False}, [], [], [],
        )
        assert any(c["type"] == "MASS_ASSIGNMENT_ADMIN" for c in result)

    def test_correlate_unrestricted_api(self):
        corr = APICorrelation()
        result = corr.correlate(
            {"endpoints": [
                {"classification": {"is_api": True}, "auth_required": False},
                {"classification": {"is_api": True}, "auth_required": False},
                {"classification": {"is_api": True}, "auth_required": False},
                {"classification": {"is_api": True}, "auth_required": False},
                {"classification": {"is_api": True}, "auth_required": False},
                {"classification": {"is_api": True}, "auth_required": False},
            ]},
            {"detected": False}, {"detected": False},
            {"detected": False}, {"detected": False}, [], [], [],
        )
        assert any(c["type"] == "UNRESTRICTED_API_ACCESS" for c in result)

    def test_correlate_jwt_admin_with_weak_jwt(self):
        corr = APICorrelation()
        result = corr.correlate(
            {"endpoints": [{"classification": {"is_admin": True}}]},
            {"detected": False}, {"detected": False},
            {"detected": True, "has_exp": True, "has_none_alg_indicator": True},
            {"detected": False}, [],
            [], [{"confidence": "HIGH"}],
        )
        jwt_corr = [c for c in result if c["type"] == "JWT_ADMIN_API"]
        assert len(jwt_corr) > 0
        assert jwt_corr[0]["score"] >= 75


class TestRecommendationsEdgeCases:
    def test_recommendations_high_endpoints(self):
        recs = APIRecommendations()
        result = recs.generate({
            "api_inventory": {"total_endpoints": 30, "auth_required_count": 0},
            "swagger_profile": {"detected": False},
            "graphql_profile": {"detected": False},
            "jwt_profile": {"detected": False},
            "oauth_profile": {"detected": False},
            "rate_limit_profile": {"classification": "Unknown"},
            "attack_surface": {"exposure_score": 75},
            "bola_indicators": [],
            "bfla_indicators": [],
            "mass_assignment_indicators": [],
        })
        assert any("30" in r for r in result)

    def test_recommendations_graphql(self):
        recs = APIRecommendations()
        result = recs.generate({
            "api_inventory": {"total_endpoints": 5, "auth_required_count": 0},
            "swagger_profile": {"detected": False},
            "graphql_profile": {"detected": True, "endpoints": ["/graphql"], "frameworks": ["apollo"]},
            "jwt_profile": {"detected": False},
            "oauth_profile": {"detected": False},
            "rate_limit_profile": {"classification": "Strong"},
            "attack_surface": {"exposure_score": 10},
            "bola_indicators": [],
            "bfla_indicators": [],
            "mass_assignment_indicators": [],
        })
        assert any("GraphQL" in r or "apollo" in r for r in result)

    def test_recommendations_oauth(self):
        recs = APIRecommendations()
        result = recs.generate({
            "api_inventory": {"total_endpoints": 3, "auth_required_count": 1},
            "swagger_profile": {"detected": False},
            "graphql_profile": {"detected": False},
            "jwt_profile": {"detected": False},
            "oauth_profile": {"detected": True, "providers": ["keycloak"], "has_jwks": False},
            "rate_limit_profile": {"classification": "Strong"},
            "attack_surface": {"exposure_score": 20},
            "bola_indicators": [],
            "bfla_indicators": [],
            "mass_assignment_indicators": [],
        })
        assert any("JWKS" in r for r in result)

    def test_recommendations_bola_high(self):
        recs = APIRecommendations()
        result = recs.generate({
            "api_inventory": {"total_endpoints": 5, "auth_required_count": 1},
            "swagger_profile": {"detected": False},
            "graphql_profile": {"detected": False},
            "jwt_profile": {"detected": False},
            "oauth_profile": {"detected": False},
            "rate_limit_profile": {"classification": "Strong"},
            "attack_surface": {"exposure_score": 20},
            "bola_indicators": [{"confidence": "HIGH"}, {"confidence": "HIGH"}],
            "bfla_indicators": [],
            "mass_assignment_indicators": [],
        })
        assert any("BOLA" in r for r in result)

    def test_recommendations_bfla_high(self):
        recs = APIRecommendations()
        result = recs.generate({
            "api_inventory": {"total_endpoints": 3, "auth_required_count": 1},
            "swagger_profile": {"detected": False},
            "graphql_profile": {"detected": False},
            "jwt_profile": {"detected": False},
            "oauth_profile": {"detected": False},
            "rate_limit_profile": {"classification": "Strong"},
            "attack_surface": {"exposure_score": 20},
            "bola_indicators": [],
            "bfla_indicators": [{"confidence": "HIGH"}, {"confidence": "HIGH"}],
            "mass_assignment_indicators": [],
        })
        assert any("BFLA" in r for r in result)

    def test_recommendations_mass_assignment_high(self):
        recs = APIRecommendations()
        result = recs.generate({
            "api_inventory": {"total_endpoints": 3, "auth_required_count": 1},
            "swagger_profile": {"detected": False},
            "graphql_profile": {"detected": False},
            "jwt_profile": {"detected": False},
            "oauth_profile": {"detected": False},
            "rate_limit_profile": {"classification": "Strong"},
            "attack_surface": {"exposure_score": 20},
            "bola_indicators": [],
            "bfla_indicators": [],
            "mass_assignment_indicators": [{"confidence": "HIGH"}, {"confidence": "HIGH"}],
        })
        assert any("Mass Assignment" in r for r in result)

    def test_recommendations_critical_surface(self):
        recs = APIRecommendations()
        result = recs.generate({
            "api_inventory": {"total_endpoints": 3, "auth_required_count": 1},
            "swagger_profile": {"detected": False},
            "graphql_profile": {"detected": False},
            "jwt_profile": {"detected": False},
            "oauth_profile": {"detected": False},
            "rate_limit_profile": {"classification": "Strong"},
            "attack_surface": {"exposure_score": 80, "risk_level": "CRITICAL"},
            "bola_indicators": [],
            "bfla_indicators": [],
            "mass_assignment_indicators": [],
        })
        assert any("CRITICAL" in r for r in result)

    def test_recommendations_no_issues(self):
        recs = APIRecommendations()
        result = recs.generate({
            "api_inventory": {"total_endpoints": 0, "auth_required_count": 0},
            "swagger_profile": {"detected": False},
            "graphql_profile": {"detected": False},
            "jwt_profile": {"detected": False},
            "oauth_profile": {"detected": False},
            "rate_limit_profile": {"classification": "Strong"},
            "attack_surface": {"exposure_score": 5},
            "bola_indicators": [],
            "bfla_indicators": [],
            "mass_assignment_indicators": [],
        })
        assert any("No significant" in r for r in result)


class TestJWTEdgeCases:
    def test_jwt_in_x_authorization(self):
        jwt = JWTIntelligence()
        import base64, json
        h = base64.urlsafe_b64encode(json.dumps({"alg": "HS256"}).encode()).rstrip(b"=").decode()
        p = base64.urlsafe_b64encode(json.dumps({"sub": "1"}).encode()).rstrip(b"=").decode()
        token = f"{h}.{p}.sig"
        result = jwt.analyze([{"headers": {"X-Authorization": f"Bearer {token}"}}])
        assert result["detected"]

    def test_jwt_in_token_header(self):
        jwt = JWTIntelligence()
        import base64, json
        h = base64.urlsafe_b64encode(json.dumps({"alg": "HS256"}).encode()).rstrip(b"=").decode()
        p = base64.urlsafe_b64encode(json.dumps({"sub": "1"}).encode()).rstrip(b"=").decode()
        token = f"{h}.{p}.sig"
        result = jwt.analyze([{"headers": {"Token": f"Bearer {token}"}}])
        assert result["detected"]

    def test_jwt_with_array_audience(self):
        jwt = JWTIntelligence()
        import base64, json
        h = base64.urlsafe_b64encode(json.dumps({"alg": "HS256"}).encode()).rstrip(b"=").decode()
        p = base64.urlsafe_b64encode(json.dumps({"sub": "1", "aud": ["api1", "api2"]}).encode()).rstrip(b"=").decode()
        token = f"{h}.{p}.sig"
        result = jwt.analyze([{"headers": {"Authorization": f"Bearer {token}"}}])
        assert "api1" in result["audiences"]
        assert "api2" in result["audiences"]

    def test_jwt_response_headers(self):
        jwt = JWTIntelligence()
        import base64, json
        h = base64.urlsafe_b64encode(json.dumps({"alg": "HS256"}).encode()).rstrip(b"=").decode()
        p = base64.urlsafe_b64encode(json.dumps({"sub": "1"}).encode()).rstrip(b"=").decode()
        token = f"{h}.{p}.sig"
        result = jwt.analyze([{"path": "/api/users", "response_headers": {"Authorization": f"Bearer {token}"}}])
        assert result["detected"]


class TestBOLAEdgeCases:
    def test_bola_detects_order(self):
        bola = BOLAIndicators()
        result = bola.analyze([{"path": "/api/orders/123", "method": "GET", "auth_required": False}], [])
        assert len(result) >= 1

    def test_bola_detects_transaction(self):
        bola = BOLAIndicators()
        result = bola.analyze([{"path": "/api/transactions/123", "method": "GET", "auth_required": False}], [])
        assert len(result) >= 1

    def test_bola_confidence_by_method(self):
        bola = BOLAIndicators()
        get_result = bola.analyze([{"path": "/api/users/123", "method": "GET", "auth_required": False}], [])
        del_result = bola.analyze([{"path": "/api/users/123", "method": "DELETE", "auth_required": False}], [])
        assert get_result[0]["confidence"] == "HIGH"
        assert del_result[0]["confidence"] == "HIGH"

    def test_bola_admin_path_bonus(self):
        bola = BOLAIndicators()
        result = bola.analyze([{"path": "/admin/users/123", "method": "GET", "auth_required": False}], [])
        assert len(result) >= 1


class TestSwaggerDiscoveryEdgeCases:
    def test_detects_v2_api_docs(self):
        sd = SwaggerDiscovery()
        result = sd.discover([{"path": "/v2/api-docs"}])
        assert result["detected"]

    def test_detects_v3_api_docs(self):
        sd = SwaggerDiscovery()
        result = sd.discover([{"path": "/v3/api-docs"}])
        assert result["detected"]

    def test_detects_redoc(self):
        sd = SwaggerDiscovery()
        result = sd.discover([{"path": "/redoc"}])
        assert result["detected"]

    def test_detects_swagger_ui_html(self):
        sd = SwaggerDiscovery()
        result = sd.discover([{"path": "/swagger-ui.html"}])
        assert result["detected"]


class TestOpenAPIParserEdgeCases:
    def test_parse_with_definitions(self):
        parser = OpenAPIParser()
        spec = {
            "info": {"version": "2.0.0"},
            "paths": {"/users": {"get": {}}},
            "definitions": {"User": {}},
            "securityDefinitions": {"api_key": {"type": "apiKey"}},
        }
        result = parser.parse(spec)
        assert "User" in result["schemas"]
        assert len(result["auth_definitions"]) > 0


class TestParameterAnalyzerEdgeCases:
    def test_parameter_analyzer_uuid_in_path(self):
        analyzer = ParameterAnalyzer()
        result = analyzer.analyze([{"path": "/api/users/550e8400-e29b-41d4-a716-446655440000", "method": "GET", "params": []}])
        assert result["total_parameters"] == 0

    def test_parameter_analyzer_string_reference_in_path(self):
        analyzer = ParameterAnalyzer()
        result = analyzer.analyze([{"path": "/api/users/{user_id}/orders/{order_id}", "method": "GET", "params": []}])
        assert result["total_object_references"] >= 2

    def test_parameter_analyzer_mixed_params(self):
        analyzer = ParameterAnalyzer()
        result = analyzer.analyze([{"path": "/api/users", "method": "GET", "params": ["id", "name", "password", "secret_key"]}])
        assert result["total_parameters"] == 4
        assert len(result["sensitive_params"]) >= 2
