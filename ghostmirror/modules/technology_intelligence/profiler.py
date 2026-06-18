"""Risk scoring engine and attack surface analyzer."""

from __future__ import annotations

from ghostmirror.core.logger import get_logger
from ghostmirror.models.technology import TechnologyModel
from ghostmirror.models.attack_surface import AttackSurfaceProfile
from ghostmirror.models.risk_profile import RiskProfile

logger = get_logger()

# Scoring tables for risk profiling
TECH_RISK_SCORES = {
    # Web Servers
    "Apache": 10,
    "Nginx": 5,
    "LiteSpeed": 5,
    "IIS": 10,
    "Tomcat": 20,
    # CMS
    "WordPress": 15,
    "WooCommerce": 20,
    "Drupal": 15,
    "Joomla": 20,
    "Magento": 20,
    "Ghost CMS": 5,
    # Frameworks
    "Laravel": 5,
    "Django": 5,
    "Flask": 8,
    "FastAPI": 3,
    "Express": 5,
    "NestJS": 4,
    "Spring": 12,
    "Rails": 5,
    # Databases
    "MySQL": 10,
    "PostgreSQL": 5,
    "MongoDB": 15,
    "Redis": 30,
    "MariaDB": 10,
    # Backend Languages
    "PHP": 10,
    "NodeJS": 5,
    "Python": 5,
    "Java": 15,
    "Ruby": 5,
    "Go": 2,
    # Security / WAF (reduces risk)
    "Cloudflare": -10,
    "AWS WAF": -10,
    "Akamai": -10,
    "Imperva": -10,
    "Sucuri": -10,
}


class TechnologyProfilerEngine:
    """Calculates risk levels and analyzes target attack surface signature."""

    @staticmethod
    def calculate_risk(target: str, technologies: list[TechnologyModel], tls_versions: list[str]) -> RiskProfile:
        """Calculates risk score (0-100) and maps to risk level classification.

        Parameters
        ----------
        target : str
            The target domain or IP.
        technologies : list[TechnologyModel]
            List of detected technologies.
        tls_versions : list[str]
            List of supported TLS versions from SSL scan.

        Returns
        -------
        RiskProfile
            Calculated RiskProfile model.
        """
        score = 0
        observations = []

        tech_names = {t.name for t in technologies}

        # 1. Base Score calculation from detected technologies
        for name in tech_names:
            if name in TECH_RISK_SCORES:
                val = TECH_RISK_SCORES[name]
                score += val
                modifier_type = "reduzido" if val < 0 else "aumentado"
                observations.append(f"Risco {modifier_type} por detecção de {name}: {val:+d}")
            else:
                # Add default risk addition for unknown web apps / frameworks
                score += 2

        # 2. TLS/SSL Score modifiers
        if "TLS 1.3" in tls_versions:
            score -= 5
            observations.append("Risco reduzido por suporte a TLS 1.3: -5")
        elif "TLS 1.2" in tls_versions:
            # Neutral, no modifier
            pass
        elif any(v in tls_versions for v in ["TLS 1.0", "TLS 1.1", "SSLv3", "SSLv2"]):
            score += 15
            observations.append("Risco aumentado por suporte a protocolos SSL/TLS obsoletos: +15")

        # Cap score between 0 and 100
        score = max(0, min(100, score))

        # Classify risk level
        if score <= 20:
            level = "LOW"
        elif score <= 40:
            level = "MEDIUM"
        elif score <= 70:
            level = "HIGH"
        else:
            level = "CRITICAL"

        return RiskProfile(
            target=target,
            risk_score=score,
            risk_level=level,
            observations=observations,
        )

    @staticmethod
    def analyze_attack_surface(
        target: str,
        technologies: list[TechnologyModel],
        risk_score: int
    ) -> AttackSurfaceProfile:
        """Categorizes technologies and identifies potential entry points and high-value assets.

        Parameters
        ----------
        target : str
            The target domain or IP.
        technologies : list[TechnologyModel]
            List of detected technologies.
        risk_score : int
            Calculated risk score.

        Returns
        -------
        AttackSurfaceProfile
            Constructed AttackSurfaceProfile model.
        """
        web_servers = []
        frameworks = []
        cms = []
        databases = []
        external_services = []
        tech_list = []
        entry_points = []
        high_value_assets = []

        for t in technologies:
            name = t.name
            tech_list.append(name)
            cat = t.category

            if cat == "WEB SERVER":
                web_servers.append(name)
            elif cat in ("BACKEND FRAMEWORKS", "FRONTEND FRAMEWORKS", "BACKEND FRAMEWORK"):
                frameworks.append(name)
            elif cat == "CMS":
                cms.append(name)
            elif cat == "DATABASE":
                databases.append(name)
            elif cat in ("INFRASTRUCTURE", "WAF", "ANALYTICS", "PAYMENTS"):
                external_services.append(name)

        # Deduplicate
        web_servers = list(sorted(set(web_servers)))
        frameworks = list(sorted(set(frameworks)))
        cms = list(sorted(set(cms)))
        databases = list(sorted(set(databases)))
        external_services = list(sorted(set(external_services)))
        tech_list = list(sorted(set(tech_list)))

        # Identify Entry Points
        for name in cms:
            if name == "WordPress":
                entry_points.append("WordPress Admin Panel (/wp-admin/)")
            elif name == "Joomla":
                entry_points.append("Joomla Administrator Console (/administrator/)")
            elif name == "Drupal":
                entry_points.append("Drupal Login Endpoint (/user/login)")
            elif name == "Magento":
                entry_points.append("Magento Admin Panel (/admin/)")
            elif name == "Ghost CMS":
                entry_points.append("Ghost CMS Admin (/ghost/)")

        for name in frameworks:
            if name == "FastAPI":
                entry_points.append("FastAPI Swagger Documentation (/docs)")
            elif name == "Django":
                entry_points.append("Django Admin Interface (/admin/)")

        for name in web_servers:
            if name == "Tomcat":
                entry_points.append("Tomcat Manager Application (/manager/)")

        for name in databases:
            entry_points.append(f"Exposed Database Service ({name})")

        # Identify High Value Assets
        for name in databases:
            high_value_assets.append(f"Database Service ({name})")
        for name in cms:
            high_value_assets.append(f"Content Management System ({name})")
        for name in external_services:
            # Check payments or infra
            if name in ("Stripe", "PayPal", "Mercado Pago", "Pagar.me"):
                high_value_assets.append(f"Payment Provider Integration ({name})")

        return AttackSurfaceProfile(
            target=target,
            web_servers=web_servers,
            frameworks=frameworks,
            cms=cms,
            databases=databases,
            external_services=external_services,
            technologies=tech_list,
            potential_entry_points=entry_points,
            high_value_assets=high_value_assets,
            risk_score=risk_score,
        )
