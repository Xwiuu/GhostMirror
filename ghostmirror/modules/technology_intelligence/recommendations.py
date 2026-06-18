"""Scan strategy and recommendation generator."""

from __future__ import annotations

from ghostmirror.core.logger import get_logger
from ghostmirror.models.technology import TechnologyModel
from ghostmirror.modules.technology_intelligence.knowledge_base import KnowledgeBase

logger = get_logger()

# Set of technologies with known Nuclei templates
NUCLEI_SUPPORTED_TECHS = {
    "apache", "nginx", "tomcat", "iis", "wordpress", "drupal", "joomla",
    "magento", "ghost cms", "ghost", "laravel", "spring", "redis", "django",
    "flask", "mongodb", "mysql", "postgresql"
}


class RecommendationEngine:
    """Generates scan strategies and maps targets to vulnerabilities templates."""

    @staticmethod
    def generate_recommendations(
        technologies: list[TechnologyModel],
        kb: KnowledgeBase
    ) -> tuple[list[str], list[str]]:
        """Analyzes tech stack and returns recommended security scans and Nuclei templates.

        Parameters
        ----------
        technologies : list[TechnologyModel]
            Detected technologies list.
        kb : KnowledgeBase
            The threat intelligence knowledge base instance.

        Returns
        -------
        tuple[list[str], list[str]]
            Recommended scans list, and recommended nuclei templates list.
        """
        recommended_scans = []
        recommended_nuclei_templates = []

        tech_names = {t.name for t in technologies}

        # 1. Fetch recommended scans from Knowledge Base
        for name in tech_names:
            risk_def = kb.get_technology_risk(name)
            if risk_def:
                # Add recommended scans from definitions
                recommended_scans.extend(risk_def.recommended_scans)
                
                # Check for Nuclei templates
                clean_name = name.lower()
                if "cms" in clean_name:
                    clean_name = clean_name.replace(" cms", "")
                
                if clean_name in NUCLEI_SUPPORTED_TECHS:
                    recommended_nuclei_templates.append(clean_name)

        # Deduplicate and sort
        recommended_scans = list(sorted(set(recommended_scans)))
        recommended_nuclei_templates = list(sorted(set(recommended_nuclei_templates)))

        logger.info(
            "RECOMMENDATIONS_GENERATED scans={} nuclei_templates={}",
            len(recommended_scans),
            len(recommended_nuclei_templates),
        )

        return recommended_scans, recommended_nuclei_templates
