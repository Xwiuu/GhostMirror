"""CVE Intelligence Module containing scanner, engine, and correlation models."""

from __future__ import annotations

from ghostmirror.modules.cve_intelligence.scanner import CVEIntelligenceScanner
from ghostmirror.modules.cve_intelligence.engine import CVEIntelligenceEngine
from ghostmirror.modules.cve_intelligence.matcher import CVEVulnerabilityMatcher
from ghostmirror.modules.cve_intelligence.knowledge_base import CVEKnowledgeBase
from ghostmirror.modules.cve_intelligence.normalizer import TechnologyNormalizer
from ghostmirror.modules.cve_intelligence.scoring import VulnerabilityScoringEngine
from ghostmirror.modules.cve_intelligence.recommendations import CVERecommendationEngine

__all__ = [
    "CVEIntelligenceScanner",
    "CVEIntelligenceEngine",
    "CVEVulnerabilityMatcher",
    "CVEKnowledgeBase",
    "TechnologyNormalizer",
    "VulnerabilityScoringEngine",
    "CVERecommendationEngine",
]
