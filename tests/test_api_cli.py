from __future__ import annotations

from pathlib import Path

import pytest

from ghostmirror.modules.api_security.endpoint_classifier import EndpointClassifier
from ghostmirror.modules.api_security.parameter_analyzer import ParameterAnalyzer
from ghostmirror.modules.api_security.swagger_discovery import SwaggerDiscovery
from ghostmirror.modules.api_security.openapi_parser import OpenAPIParser
from ghostmirror.modules.api_security.graphql_discovery import GraphQLDiscovery
from ghostmirror.modules.api_security.graphql_intelligence import GraphQLIntelligence
from ghostmirror.modules.api_security.jwt_intelligence import JWTIntelligence
from ghostmirror.modules.api_security.oauth_intelligence import OAuthIntelligence
from ghostmirror.modules.api_security.object_mapper import ObjectMapper
from ghostmirror.modules.api_security.rate_limit_intelligence import RateLimitIntelligence
from ghostmirror.modules.api_security.bola_indicators import BOLAIndicators
from ghostmirror.modules.api_security.bfla_indicators import BFLAIndicators
from ghostmirror.modules.api_security.mass_assignment_indicators import MassAssignmentIndicators
from ghostmirror.modules.api_security.scoring import APIScoringEngine
from ghostmirror.modules.api_security.recommendations import APIRecommendations
from ghostmirror.modules.api_security.engine import APISecurityEngine
from ghostmirror.modules.api_security.auth_intelligence import AuthIntelligence
from ghostmirror.modules.api_security.api_correlation import APICorrelation
from ghostmirror.modules.api_security.exposure_analysis import ExposureAnalysis
from ghostmirror.modules.api_security.findings_mapper import APIFindingsMapper
from ghostmirror.modules.api_security.report_builder import APIReportBuilder


class TestModuleImports:
    """Verifies all 21 modules are importable without errors."""

    def test_endpoint_classifier(self):
        assert EndpointClassifier is not None

    def test_parameter_analyzer(self):
        assert ParameterAnalyzer is not None

    def test_swagger_discovery(self):
        assert SwaggerDiscovery is not None

    def test_openapi_parser(self):
        assert OpenAPIParser is not None

    def test_graphql_discovery(self):
        assert GraphQLDiscovery is not None

    def test_graphql_intelligence(self):
        assert GraphQLIntelligence is not None

    def test_jwt_intelligence(self):
        assert JWTIntelligence is not None

    def test_oauth_intelligence(self):
        assert OAuthIntelligence is not None

    def test_object_mapper(self):
        assert ObjectMapper is not None

    def test_rate_limit_intelligence(self):
        assert RateLimitIntelligence is not None

    def test_bola_indicators(self):
        assert BOLAIndicators is not None

    def test_bfla_indicators(self):
        assert BFLAIndicators is not None

    def test_mass_assignment_indicators(self):
        assert MassAssignmentIndicators is not None

    def test_scoring(self):
        assert APIScoringEngine is not None

    def test_recommendations(self):
        assert APIRecommendations is not None

    def test_engine(self):
        assert APISecurityEngine is not None

    def test_auth_intelligence(self):
        assert AuthIntelligence is not None

    def test_correlation(self):
        assert APICorrelation is not None

    def test_exposure_analysis(self):
        assert ExposureAnalysis is not None

    def test_findings_mapper(self):
        assert APIFindingsMapper is not None

    def test_report_builder(self):
        assert APIReportBuilder is not None

    def test_all_models_importable(self):
        import ghostmirror.models.api_endpoint
        import ghostmirror.models.api_inventory_profile
        import ghostmirror.models.graphql_profile
        import ghostmirror.models.jwt_profile
        import ghostmirror.models.oauth_profile
        import ghostmirror.models.api_risk
        import ghostmirror.models.api_security_report
        import ghostmirror.models.api_attack_surface
        assert True
