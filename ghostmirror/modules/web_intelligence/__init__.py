"""Web Vulnerability Intelligence Engine — passive analysis of web applications."""

from ghostmirror.modules.web_intelligence.engine import WebIntelligenceEngine
from ghostmirror.modules.web_intelligence.endpoint_mapper import EndpointMapper
from ghostmirror.modules.web_intelligence.parameter_discovery import ParameterDiscovery
from ghostmirror.modules.web_intelligence.js_intelligence import JSIntelligence
from ghostmirror.modules.web_intelligence.auth_intelligence import AuthIntelligence
from ghostmirror.modules.web_intelligence.injection_indicators import InjectionIndicators
from ghostmirror.modules.web_intelligence.xss_indicators import XSSIndicators
from ghostmirror.modules.web_intelligence.ssti_indicators import SSTIIndicators
from ghostmirror.modules.web_intelligence.ssrf_indicators import SSRFIndicators
from ghostmirror.modules.web_intelligence.idor_indicators import IDORIndicators
from ghostmirror.modules.web_intelligence.redirect_indicators import RedirectIndicators
from ghostmirror.modules.web_intelligence.traversal_indicators import TraversalIndicators
from ghostmirror.modules.web_intelligence.business_logic_indicators import BusinessLogicIndicators
from ghostmirror.modules.web_intelligence.correlation import CorrelationEngine
from ghostmirror.modules.web_intelligence.scoring import WebScoringEngine
from ghostmirror.modules.web_intelligence.recommendations import WebRecommendationEngine
from ghostmirror.modules.web_intelligence.findings_mapper import WebFindingsMapper

__all__ = [
    "WebIntelligenceEngine",
    "EndpointMapper",
    "ParameterDiscovery",
    "JSIntelligence",
    "AuthIntelligence",
    "InjectionIndicators",
    "XSSIndicators",
    "SSTIIndicators",
    "SSRFIndicators",
    "IDORIndicators",
    "RedirectIndicators",
    "TraversalIndicators",
    "BusinessLogicIndicators",
    "CorrelationEngine",
    "WebScoringEngine",
    "WebRecommendationEngine",
    "WebFindingsMapper",
]
