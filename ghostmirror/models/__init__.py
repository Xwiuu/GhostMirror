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
from ghostmirror.models.attack_surface import AttackSurfaceProfile
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
]
