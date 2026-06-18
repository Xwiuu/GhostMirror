"""Orchestrator engine for CVE Correlation and Vulnerability Profiling."""

from __future__ import annotations

import json
from pathlib import Path
from datetime import datetime, timezone

from ghostmirror.core.logger import get_logger
from ghostmirror.models.fingerprint import FingerprintProfile
from ghostmirror.models.vulnerability_profile import VulnerabilityProfile
from ghostmirror.models.cve_match import CVEMatchModel
from ghostmirror.modules.models.finding import FindingModel, FindingSeverity
from ghostmirror.modules.cve_intelligence.knowledge_base import CVEKnowledgeBase
from ghostmirror.modules.cve_intelligence.matcher import CVEVulnerabilityMatcher
from ghostmirror.modules.cve_intelligence.scoring import VulnerabilityScoringEngine
from ghostmirror.modules.cve_intelligence.recommendations import CVERecommendationEngine

logger = get_logger()


class CVEIntelligenceEngine:
    """Orchestrates loading scans, executing matcher, scoring, and writing reports."""

    def __init__(self, knowledge_dir: Path | str | None = None) -> None:
        self.kb = CVEKnowledgeBase(knowledge_dir=knowledge_dir)
        self.matcher = CVEVulnerabilityMatcher(self.kb)

    def analyze_project(self, project_path: Path) -> dict:
        """Loads target technology profiles and findings, runs vulnerability profiling, and persists outputs.

        Parameters
        ----------
        project_path : Path
            Path to project folder.

        Returns
        -------
        dict
            Vulnerability intelligence report dictionary summary.
        """
        profiles_dir = project_path / "profiles"
        findings_dir = project_path / "findings"
        recommendations_dir = project_path / "recommendations"
        evidence_dir = project_path / "evidence" / "cve"

        tech_profile_path = profiles_dir / "technology_profile.json"
        ssl_findings_path = findings_dir / "ssl.json"

        if not tech_profile_path.exists():
            raise FileNotFoundError(
                f"Perfil de tecnologia não encontrado em {tech_profile_path}. "
                "Por favor, execute o scan de fingerprint no alvo primeiro."
            )

        # 1. Load technology fingerprint profile
        with open(tech_profile_path, "r", encoding="utf-8") as f:
            raw_profile = json.load(f)
        profile = FingerprintProfile.model_validate(raw_profile)
        target = profile.target

        # 2. Try loading TLS versions from SSL findings if available
        tls_versions = []
        if ssl_findings_path.exists():
            try:
                with open(ssl_findings_path, "r", encoding="utf-8") as f:
                    ssl_data = json.load(f)
                cert_summary = ssl_data.get("certificate_summary")
                if cert_summary:
                    tls_versions = cert_summary.get("tls_versions", [])
            except Exception as exc:
                logger.warning("Could not read TLS versions from ssl.json: {}", exc)

        # 3. Perform vulnerability mapping
        matches: list[CVEMatchModel] = []
        for tech in profile.technologies:
            tech_matches = self.matcher.match_technology(target, tech.name, tech.version)
            matches.extend(tech_matches)

        # Deduplicate matches if any are duplicated (by CVE ID and technology)
        unique_matches = []
        seen = set()
        for m in matches:
            key = (m.matched_cve.cve_id, m.technology)
            if key not in seen:
                seen.add(key)
                unique_matches.append(m)
        matches = unique_matches

        # 4. Perform Scoring
        score, level = VulnerabilityScoringEngine.calculate_risk(
            matches, profile.technologies, tls_versions
        )

        # 5. Compile Counts
        critical_count = sum(1 for m in matches if m.risk_level == "CRITICAL")
        high_count = sum(1 for m in matches if m.risk_level == "HIGH")
        medium_count = sum(1 for m in matches if m.risk_level == "MEDIUM")
        low_count = sum(1 for m in matches if m.risk_level == "LOW")
        info_count = sum(1 for m in matches if m.risk_level == "INFO")
        exploitable_count = sum(1 for m in matches if m.matched_cve.exploit_available)
        kev_count = sum(1 for m in matches if m.matched_cve.kev_listed)

        # Top risks sorted by priority (CRITICAL, HIGH, MEDIUM, LOW)
        priority_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        top_risks = sorted(matches, key=lambda m: priority_order.get(m.priority, 99))

        # Recommended scans derived from matching
        recommended_scans = []
        for m in matches:
            for s in m.recommended_scans:
                if s not in recommended_scans:
                    recommended_scans.append(s)
        # Default recommended scans if vulnerability profile suggests it
        if critical_count + high_count > 0:
            recommended_scans.append("Active Exploit Validation")

        # 6. Nuclei templates recommendations
        recommended_nuclei = CVERecommendationEngine.map_nuclei_templates(
            matches, profile.technologies, self.kb.nuclei_map
        )

        # 7. Create Vulnerability Profile Model
        vuln_profile = VulnerabilityProfile(
            target=target,
            total_cves=len(matches),
            critical_count=critical_count,
            high_count=high_count,
            medium_count=medium_count,
            low_count=low_count,
            informational_count=info_count,
            exploitable_count=exploitable_count,
            kev_count=kev_count,
            technologies_analyzed=len(profile.technologies),
            matches=matches,
            top_risks=top_risks,
            recommended_scans=recommended_scans,
            recommended_nuclei_templates=recommended_nuclei,
            overall_vulnerability_score=score,
            overall_risk_level=level,
        )

        # 8. Create Finding Models
        findings = self._generate_findings(matches)

        # 9. Save files to disk
        profiles_dir.mkdir(parents=True, exist_ok=True)
        findings_dir.mkdir(parents=True, exist_ok=True)
        recommendations_dir.mkdir(parents=True, exist_ok=True)
        evidence_dir.mkdir(parents=True, exist_ok=True)

        # Save vulnerability_profile.json
        with open(profiles_dir / "vulnerability_profile.json", "w", encoding="utf-8") as f:
            json.dump(vuln_profile.model_dump(mode="json"), f, indent=2, ensure_ascii=False)

        # Build final report for cve_intelligence.json
        report = {
            "target": target,
            "technologies_analyzed": vuln_profile.technologies_analyzed,
            "total_cves": vuln_profile.total_cves,
            "critical_count": vuln_profile.critical_count,
            "high_count": vuln_profile.high_count,
            "medium_count": vuln_profile.medium_count,
            "low_count": vuln_profile.low_count,
            "informational_count": vuln_profile.informational_count,
            "exploitable_count": vuln_profile.exploitable_count,
            "kev_count": vuln_profile.kev_count,
            "overall_vulnerability_score": vuln_profile.overall_vulnerability_score,
            "overall_risk_level": vuln_profile.overall_risk_level,
            "recommended_nuclei_templates": vuln_profile.recommended_nuclei_templates,
            "recommended_scans": vuln_profile.recommended_scans,
            "findings": [f.model_dump(mode="json") for f in findings],
        }

        # Save cve_intelligence.json
        with open(profiles_dir / "cve_intelligence.json", "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        # Save cve_findings.json
        with open(findings_dir / "cve_findings.json", "w", encoding="utf-8") as f:
            json.dump([f.model_dump(mode="json") for f in findings], f, indent=2, ensure_ascii=False)

        # Save recommended_nuclei_templates.json
        nuclei_report = {
            "target": target,
            "templates": recommended_nuclei
        }
        with open(recommendations_dir / "recommended_nuclei_templates.json", "w", encoding="utf-8") as f:
            json.dump(nuclei_report, f, indent=2, ensure_ascii=False)

        # Save cve_matches.json in evidence/cve/
        with open(evidence_dir / "cve_matches.json", "w", encoding="utf-8") as f:
            json.dump([m.model_dump(mode="json") for m in matches], f, indent=2, ensure_ascii=False)

        logger.info(
            "CVE_INTEL_ENGINE_COMPLETE target={} total_cves={} risk_score={} risk_level={}",
            target,
            vuln_profile.total_cves,
            score,
            level,
        )

        return report

    def _generate_findings(self, matches: list[CVEMatchModel]) -> list[FindingModel]:
        """Maps matched CVEs to standardized FindingModels."""
        findings = []
        for match in matches:
            cve = match.matched_cve
            sev_str = match.risk_level.upper()
            if sev_str == "CRITICAL":
                severity = FindingSeverity.CRITICAL
            elif sev_str == "HIGH":
                severity = FindingSeverity.HIGH
            elif sev_str == "MEDIUM":
                severity = FindingSeverity.MEDIUM
            else:
                severity = FindingSeverity.LOW

            if match.match_confidence == "CONFIRMED":
                title = f"Confirmed Vulnerable {match.technology} Version: {cve.cve_id}"
            elif match.match_confidence == "POTENTIAL":
                title = f"Potential {match.technology} CVE Exposure: {cve.cve_id}"
            else:
                title = f"{match.technology} Version Disclosure / Potential Risk: {cve.cve_id}"

            if cve.kev_listed:
                title = f"Known Exploited Vulnerability Risk: {cve.cve_id} ({match.technology})"

            description = (
                f"Vulnerabilidade identificada na tecnologia '{match.technology}'.\n"
                f"CVE ID: {cve.cve_id}\n"
                f"CVSS Score: {cve.cvss_score}\n"
                f"Descrição: {cve.description}"
            )

            evidence = (
                f"Tecnologia: {match.technology}\n"
                f"Versão Detectada: {match.detected_version or 'Não identificada'}\n"
                f"Confiança da Associação: {match.match_confidence}\n"
                f"Motivo: {match.match_reason}"
            )

            recommendation = (
                f"Remediação: {match.recommended_action}\n"
                f"Recomendação de Scans: Executar templates Nuclei mapeados para validar a exploração."
            )

            findings.append(
                FindingModel(
                    title=title,
                    description=description,
                    severity=severity,
                    target=match.target,
                    evidence=evidence,
                    recommendation=recommendation
                )
            )
        return findings
