"""Domain models: strongly-typed, self-validating Pydantic schemas."""

from ghostmirror.models.project import ProjectModel, ProjectStatus
from ghostmirror.models.scope import (
    AllowedTests,
    ScopeModel,
    ScopeProjectInfo,
    ScopeTargets,
)
from ghostmirror.models.settings import AppInfo, PathsConfig, SettingsModel
from ghostmirror.models.technology import TechnologyModel
from ghostmirror.models.fingerprint import AIProfile, FingerprintProfile
from ghostmirror.models.technology_risk import TechnologyRisk
from ghostmirror.models.attack_surface import AttackSurfaceProfile as OldAttackSurfaceProfile
from ghostmirror.models.attack_surface_profile import (
    AttackSurfaceProfile,
    WAFProfile,
    CDNProfile,
    HostingProfile,
    DNSProfile,
    DNSFinding,
)
from ghostmirror.models.attack_path import AttackPath, AttackPathStep
from ghostmirror.models.intelligence_report import (
    IntelligenceReport,
    RiskMatrix,
    RiskMatrixEntry,
    PentestRecommendation,
)
from ghostmirror.models.risk_profile import RiskProfile
from ghostmirror.models.cve import CVEModel
from ghostmirror.models.cve_match import CVEMatchModel
from ghostmirror.models.vulnerability_profile import VulnerabilityProfile
from ghostmirror.models.nuclei_result import NucleiResult
from ghostmirror.models.nuclei_template import NucleiTemplate
from ghostmirror.models.owasp_finding import OWASPCategory, OWASPFinding
from ghostmirror.models.owasp_profile import OWASPProfile
from ghostmirror.models.payload_result import PayloadResult
from ghostmirror.models.payload_profile import (
    PayloadProfile,
    SafetyLevel,
    PayloadCategory,
)
from ghostmirror.models.finding_priority import FindingPriority
from ghostmirror.models.finding_confidence import ConfidenceLevel
from ghostmirror.models.finding_impact import BusinessImpact, TechnicalImpact
from ghostmirror.models.enriched_finding import EnrichedFinding
from ghostmirror.models.finding_intelligence_report import FindingIntelligenceReport

# Web Intelligence models
from ghostmirror.models.web_endpoint import WebEndpoint, HttpMethod, WebForm
from ghostmirror.models.parameter_profile import ParameterProfile, ParameterType, ParameterSensitivity
from ghostmirror.models.web_indicator import WebIndicator, IndicatorType, SeverityLevel
from ghostmirror.models.web_intelligence_report import (
    WebIntelligenceReport,
    CorrelationResult,
    OpportunityScore,
    BusinessLogicArea,
)
from ghostmirror.models.web_attack_surface import WebAttackSurface, IndicatorSummary

# API Security Intelligence models
from ghostmirror.models.api_endpoint import APIEndpoint
from ghostmirror.models.api_inventory_profile import APIInventoryProfile
from ghostmirror.models.graphql_profile import GraphQLProfile
from ghostmirror.models.jwt_profile import JWTProfile
from ghostmirror.models.oauth_profile import OAuthProfile
from ghostmirror.models.api_risk import APIRisk
from ghostmirror.models.api_security_report import APISecurityReport
from ghostmirror.models.api_attack_surface import APIAttackSurface

# Bounty / HackerOne Reporting models
from ghostmirror.models.bounty_severity import BountySeverity, BountyPriority
from ghostmirror.models.bounty_submission import BountySubmission
from ghostmirror.models.bounty_report import BountyReport
from ghostmirror.models.reproduction_step import ReproductionStep
from ghostmirror.models.evidence_block import EvidenceBlock

# Attack Chain Intelligence models
from ghostmirror.models.attack_chain_signal import AttackChainSignal, SignalType
from ghostmirror.models.attack_chain_node import AttackChainNode, NodeType
from ghostmirror.models.attack_chain_edge import AttackChainEdge, EdgeType
from ghostmirror.models.attack_chain_path import AttackChainPath
from ghostmirror.models.attack_chain_report import AttackChainReport
from ghostmirror.models.attack_chain_priority import AttackChainPriority

__all__ = [
    "ProjectModel",
    "ProjectStatus",
    "ScopeModel",
    "ScopeProjectInfo",
    "ScopeTargets",
    "AllowedTests",
    "SettingsModel",
    "AppInfo",
    "PathsConfig",
    "TechnologyModel",
    "AIProfile",
    "FingerprintProfile",
    "TechnologyRisk",
    "AttackSurfaceProfile",
    "WAFProfile",
    "CDNProfile",
    "HostingProfile",
    "DNSProfile",
    "DNSFinding",
    "AttackPath",
    "AttackPathStep",
    "IntelligenceReport",
    "RiskMatrix",
    "RiskMatrixEntry",
    "PentestRecommendation",
    "RiskProfile",
    "CVEModel",
    "CVEMatchModel",
    "VulnerabilityProfile",
    "NucleiResult",
    "NucleiTemplate",
    "OWASPCategory",
    "OWASPFinding",
    "OWASPProfile",
    "PayloadResult",
    "PayloadProfile",
    "SafetyLevel",
    "PayloadCategory",
    "FindingPriority",
    "ConfidenceLevel",
    "BusinessImpact",
    "TechnicalImpact",
    "EnrichedFinding",
    "FindingIntelligenceReport",
    # Web Intelligence
    "WebEndpoint",
    "HttpMethod",
    "WebForm",
    "ParameterProfile",
    "ParameterType",
    "ParameterSensitivity",
    "WebIndicator",
    "IndicatorType",
    "SeverityLevel",
    "WebIntelligenceReport",
    "CorrelationResult",
    "OpportunityScore",
    "BusinessLogicArea",
    "WebAttackSurface",
    "IndicatorSummary",
    # API Security Intelligence
    "APIEndpoint",
    "APIInventoryProfile",
    "GraphQLProfile",
    "JWTProfile",
    "OAuthProfile",
    "APIRisk",
    "APISecurityReport",
    "APIAttackSurface",
    # Bounty / HackerOne Reporting
    "BountySeverity",
    "BountyPriority",
    "BountySubmission",
    "BountyReport",
    "ReproductionStep",
    "EvidenceBlock",
    # Attack Chain Intelligence
    "AttackChainSignal",
    "SignalType",
    "AttackChainNode",
    "NodeType",
    "AttackChainEdge",
    "EdgeType",
    "AttackChainPath",
    "AttackChainReport",
    "AttackChainPriority",
]
