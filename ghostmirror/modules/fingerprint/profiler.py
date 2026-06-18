"""Technology Profiler to build target profiles from correlated technologies."""

from __future__ import annotations

from ghostmirror.models.technology import TechnologyModel
from ghostmirror.models.fingerprint import FingerprintProfile


class TechnologyProfiler:
    """Builds a complete tech stack profile of a target from normalized detections."""

    @staticmethod
    def build_profile(target: str, technologies: list[TechnologyModel]) -> FingerprintProfile:
        """Compiles a list of TechnologyModels into a FingerprintProfile.

        Parameters
        ----------
        target : str
            The target domain or IP.
        technologies : list[TechnologyModel]
            Correlated list of technology detections.

        Returns
        -------
        FingerprintProfile
            Aggregated technology profile of the target.
        """
        webserver = None
        backend_language = None
        backend_framework = None
        frontend_framework = None
        cms = None
        builder = None
        hosting = None
        waf = None
        cdn = None
        analytics = []
        payment_providers = []

        for t in technologies:
            cat = t.category
            name = t.name
            if cat == "WEB SERVER":
                webserver = name
            elif cat == "BACKEND LANGUAGE":
                backend_language = name
            elif cat == "BACKEND FRAMEWORKS":
                backend_framework = name
            elif cat == "FRONTEND FRAMEWORKS":
                frontend_framework = name
            elif cat == "CMS":
                cms = name
            elif cat == "BUILDERS":
                builder = name
            elif cat == "INFRASTRUCTURE":
                hosting = name
            elif cat == "WAF":
                waf = name
            elif cat == "ANALYTICS":
                analytics.append(name)
            elif cat == "PAYMENTS":
                payment_providers.append(name)

            if name == "Cloudflare":
                # Special casing Cloudflare to map to multiple roles if not set elsewhere
                if not waf:
                    waf = "Cloudflare"
                if not cdn:
                    cdn = "Cloudflare"
                if not hosting:
                    hosting = "Cloudflare"

        # Handle builder/hosting special mappings
        for t in technologies:
            if t.name == "Webflow":
                hosting = "Webflow"
                cdn = "Webflow"
            elif t.name == "Framer":
                hosting = "Framer"
                cdn = "Framer"
            elif t.name == "Shopify":
                hosting = "Shopify"
                cdn = "Shopify"

        # Deduplicate list fields
        analytics = list(sorted(set(analytics)))
        payment_providers = list(sorted(set(payment_providers)))

        conf_sum = sum(t.confidence for t in technologies)
        avg_conf = (conf_sum / len(technologies)) * 100.0 if technologies else 100.0

        return FingerprintProfile(
            target=target,
            webserver=webserver,
            backend_language=backend_language,
            backend_framework=backend_framework,
            frontend_framework=frontend_framework,
            cms=cms,
            builder=builder,
            hosting=hosting,
            waf=waf,
            cdn=cdn,
            analytics=analytics,
            payment_providers=payment_providers,
            technologies=technologies,
            confidence_score=round(avg_conf, 1),
        )
