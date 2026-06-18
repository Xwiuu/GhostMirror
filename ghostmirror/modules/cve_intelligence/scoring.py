"""Risk scoring engine for CVE correlation."""

from __future__ import annotations

from ghostmirror.models.cve_match import CVEMatchModel
from ghostmirror.models.technology import TechnologyModel


class VulnerabilityScoringEngine:
    """Calculates overall target vulnerability scores and risk classifications."""

    @staticmethod
    def calculate_risk(
        matches: list[CVEMatchModel],
        technologies: list[TechnologyModel],
        tls_versions: list[str]
    ) -> tuple[int, str]:
        """Calculates risk score (0-100) and risk level classification.

        Parameters
        ----------
        matches : list[CVEMatchModel]
            List of matched CVE entries.
        technologies : list[TechnologyModel]
            List of detected technologies on target.
        tls_versions : list[str]
            Supported TLS versions on target.

        Returns
        -------
        tuple[int, str]
            Tuple of score and risk level name.
        """
        score = 0
        has_exploit = False
        has_kev = False

        # 1. Base CVE severities
        for match in matches:
            sev = match.matched_cve.severity.upper()
            if sev == "CRITICAL":
                score += 30
            elif sev == "HIGH":
                score += 20
            elif sev == "MEDIUM":
                score += 10
            elif sev == "LOW":
                score += 5

            if match.matched_cve.exploit_available:
                has_exploit = True
            if match.matched_cve.kev_listed:
                has_kev = True

        # 2. Exploit Available
        if has_exploit:
            score += 15

        # 3. KEV Listed
        if has_kev:
            score += 20

        # 4. Internet-facing service (Default +10 since targets are domains/IPs scanned externally)
        score += 10

        # 5. Database exposed (+15)
        # Check if database category is present or if name matches database list
        db_keywords = ["redis", "mongodb", "mysql", "postgresql", "postgres", "sqlite", "mariadb"]
        has_db = any(
            t.category.upper() == "DATABASE" or t.name.lower() in db_keywords
            for t in technologies
        )
        if has_db:
            score += 15

        # 6. WAF/CDN present (-10)
        has_waf_cdn = any(
            t.category.upper() in ["WAF", "CDN"] or t.name.lower() == "cloudflare"
            for t in technologies
        )
        if has_waf_cdn:
            score -= 10

        # 7. TLS strong (-5)
        # Strong TLS implies TLS 1.2 or TLS 1.3 are enabled and no legacy versions are enabled
        legacy_tls = ["TLS 1.0", "TLS 1.1", "SSLv3", "SSLv2"]
        has_weak = any(v in tls_versions for v in legacy_tls)
        has_strong = any(v in ["TLS 1.2", "TLS 1.3"] for v in tls_versions)
        if tls_versions and has_strong and not has_weak:
            score -= 5

        # Ensure bound range [0, 100]
        final_score = max(0, min(100, score))

        if final_score <= 20:
            risk_level = "LOW"
        elif final_score <= 40:
            risk_level = "MEDIUM"
        elif final_score <= 70:
            risk_level = "HIGH"
        else:
            risk_level = "CRITICAL"

        return final_score, risk_level
