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
]

