"""Intelligence Engine — orchestrates all intelligence modules to produce the final report."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ghostmirror.core.logger import get_logger
from ghostmirror.models.attack_surface_profile import AttackSurfaceProfile
from ghostmirror.models.intelligence_report import IntelligenceReport
from ghostmirror.modules.intelligence.attack_surface import AttackSurfaceAnalyzer
from ghostmirror.modules.intelligence.attack_paths import AttackPathEngine
from ghostmirror.modules.intelligence.correlation import CorrelationEngine
from ghostmirror.modules.intelligence.executive_summary import ExecutiveSummaryGenerator
from ghostmirror.modules.intelligence.recommendations import RecommendationEngine
from ghostmirror.modules.intelligence.risk_matrix import RiskMatrixGenerator
from ghostmirror.modules.intelligence.scoring import ScoringEngine
from ghostmirror.modules.models.finding import FindingModel, FindingSeverity

logger = get_logger()


class IntelligenceEngine:
    """Orchestrates all intelligence modules to produce the consolidated intelligence report."""

    def __init__(self) -> None:
        self.analyzer = AttackSurfaceAnalyzer()

    def analyze_project(self, project_path: Path) -> IntelligenceReport:
        logger.info("INTELLIGENCE_ENGINE_START project={}", project_path.name)

        profiles_dir = project_path / "profiles"
        findings_dir = project_path / "findings"

        target = self._resolve_target(project_path)

        tech_profile = self._load_tech_profile(profiles_dir)
        headers_findings = self._load_json(findings_dir / "headers.json")
        ssl_findings = self._load_json(findings_dir / "ssl.json")
        nmap_findings = self._load_json(findings_dir / "nmap.json")

        surface_profile = self.analyzer.analyze(
            target=target,
            technology_profile=tech_profile,
            headers_findings=headers_findings.get("findings") if headers_findings else None,
            ssl_findings=ssl_findings,
            nmap_findings=nmap_findings,
        )

        self.analyzer.save_profiles(project_path, surface_profile)

        attack_surface_score, classification = ScoringEngine.calculate_attack_surface_score(surface_profile)
        surface_profile.attack_surface_score = attack_surface_score
        surface_profile.classification = classification

        critical_count, high_count, medium_count, low_count, total_findings = (
            self._count_findings(project_path, findings_dir)
        )

        cve_data = self._load_json(profiles_dir / "vulnerability_profile.json") or {}
        cve_matches = cve_data.get("matches", [])
        cve_count = len(cve_matches)
        exploit_available = any(
            c.get("matched_cve", {}).get("exploit_available", False) for c in cve_matches
        )
        kev_count = sum(
            1 for c in cve_matches if c.get("matched_cve", {}).get("kev_listed", False)
        )

        risk_score, risk_level = ScoringEngine.calculate_risk_score(
            attack_surface_score=attack_surface_score,
            findings_count=total_findings,
            critical_findings=critical_count,
            high_findings=high_count,
            medium_findings=medium_count,
            cve_count=cve_count,
            exploit_available=exploit_available,
            kev_listed=kev_count > 0,
        )

        risk_matrix = RiskMatrixGenerator.generate(
            attack_surface_score=attack_surface_score,
            critical_findings=critical_count,
            high_findings=high_count,
            medium_findings=medium_count,
            total_findings=total_findings,
            cve_count=cve_count,
            exploit_available=exploit_available,
            kev_count=kev_count,
            open_ports_count=len(surface_profile.open_ports),
            waf_detected=surface_profile.waf.detected,
            cdn_detected=surface_profile.cdn.detected,
        )

        correlation_findings = CorrelationEngine.correlate(project_path)
        if correlation_findings:
            logger.info("CORRELATION_FINDINGS count={}", len(correlation_findings))

        attack_paths = AttackPathEngine.generate_paths(project_path)

        dns_findings_dicts = [f.model_dump(mode="json") for f in surface_profile.dns.findings]
        dns_issues = [f.get("record_type", "") for f in dns_findings_dicts]

        recommendations = RecommendationEngine.generate(
            cms_list=surface_profile.cms,
            databases=surface_profile.databases,
            frameworks=surface_profile.frameworks,
            open_ports=surface_profile.open_ports,
            critical_findings=critical_count,
            high_findings=high_count,
            medium_findings=medium_count,
            cve_count=cve_count,
            exploit_available=exploit_available,
            waf_detected=surface_profile.waf.detected,
            dns_issues=dns_issues,
            technologies_count=len(surface_profile.technologies),
        )

        executive_summary = ExecutiveSummaryGenerator.generate(
            target=target,
            technologies=surface_profile.technologies,
            cms_list=surface_profile.cms,
            frameworks=surface_profile.frameworks,
            databases=surface_profile.databases,
            waf_vendor=surface_profile.waf.vendor,
            cdn_vendor=surface_profile.cdn.vendor,
            hosting_provider=surface_profile.hosting.provider,
            dns_findings=dns_findings_dicts,
            open_ports=surface_profile.open_ports,
            critical_findings=critical_count,
            high_findings=high_count,
            medium_findings=medium_count,
            low_findings=low_count,
            total_findings=total_findings,
            cve_count=cve_count,
            attack_surface_score=attack_surface_score,
            risk_score=risk_score,
            risk_level=risk_level,
            exploit_available=exploit_available,
            kev_count=kev_count,
        )

        overall_security_score, _ = ScoringEngine.overall_security_score(
            attack_surface_score=attack_surface_score,
            risk_score=risk_score,
        )

        report = IntelligenceReport(
            target=target,
            overall_security_score=overall_security_score,
            overall_attack_surface_score=attack_surface_score,
            overall_risk_score=risk_score,
            attack_surface_profile=surface_profile,
            risk_matrix=risk_matrix,
            attack_paths=attack_paths,
            executive_summary=executive_summary,
            recommendations=recommendations,
        )

        self._save_report(project_path, report)
        self._save_findings(project_path, report)

        logger.info(
            "INTELLIGENCE_ENGINE_COMPLETE target={} as_score={} risk_score={} security_score={}",
            target,
            attack_surface_score,
            risk_score,
            overall_security_score,
        )

        return report

    def _save_report(self, project_path: Path, report: IntelligenceReport) -> None:
        profiles_dir = project_path / "profiles"
        profiles_dir.mkdir(parents=True, exist_ok=True)

        data = report.model_dump(mode="json")
        with open(profiles_dir / "intelligence_report.json", "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        if report.risk_matrix:
            with open(profiles_dir / "risk_matrix.json", "w", encoding="utf-8") as f:
                json.dump(report.risk_matrix.model_dump(mode="json"), f, indent=2)

        attack_paths_data = [p.model_dump(mode="json") for p in report.attack_paths]
        with open(profiles_dir / "attack_paths.json", "w", encoding="utf-8") as f:
            json.dump(attack_paths_data, f, indent=2, ensure_ascii=False)

        with open(profiles_dir / "executive_summary.json", "w", encoding="utf-8") as f:
            json.dump({"target": report.target, "summary": report.executive_summary}, f, indent=2)

        if report.attack_surface_profile:
            with open(profiles_dir / "attack_surface_profile.json", "w", encoding="utf-8") as f:
                json.dump(report.attack_surface_profile.model_dump(mode="json"), f, indent=2)

        logger.info("INTELLIGENCE_REPORT_SAVED target={}", report.target)

    def _save_findings(self, project_path: Path, report: IntelligenceReport) -> None:
        findings_dir = project_path / "findings"
        findings_dir.mkdir(parents=True, exist_ok=True)

        findings: list[FindingModel] = []

        if report.attack_surface_profile:
            asp = report.attack_surface_profile
            if not asp.waf.detected and not asp.cdn.detected:
                findings.append(FindingModel(
                    title="No WAF or CDN Protection",
                    description="Target does not appear to use a Web Application Firewall or CDN.",
                    severity=FindingSeverity.MEDIUM,
                    target=report.target,
                    evidence=f"WAF: {asp.waf.detected}, CDN: {asp.cdn.detected}",
                    recommendation="Consider implementing a WAF/CDN solution for edge protection.",
                ))

            if asp.dns.spf_missing or asp.dns.dmarc_missing or asp.dns.dkim_missing:
                missing = []
                if asp.dns.spf_missing:
                    missing.append("SPF")
                if asp.dns.dmarc_missing:
                    missing.append("DMARC")
                if asp.dns.dkim_missing:
                    missing.append("DKIM")
                findings.append(FindingModel(
                    title="Missing Email Security Records",
                    description=f"DNS records missing: {', '.join(missing)}. Domain is vulnerable to email spoofing.",
                    severity=FindingSeverity.MEDIUM if asp.dns.spf_missing else FindingSeverity.LOW,
                    target=report.target,
                    evidence=f"SPF: {'missing' if asp.dns.spf_missing else 'present'}, "
                             f"DMARC: {'missing' if asp.dns.dmarc_missing else 'present'}, "
                             f"DKIM: {'missing' if asp.dns.dkim_missing else 'present'}",
                    recommendation="Configure SPF, DMARC, and DKIM records to prevent email spoofing.",
                ))

            if asp.attack_surface_score >= 61:
                findings.append(FindingModel(
                    title="High Attack Surface Score",
                    description=f"Attack surface score is {asp.attack_surface_score}/100 ({asp.classification}).",
                    severity=FindingSeverity.HIGH,
                    target=report.target,
                    evidence=f"Score: {asp.attack_surface_score}, Ports: {len(asp.open_ports)}, "
                             f"Services: {len(asp.services_exposed)}",
                    recommendation="Reduce attack surface by closing unnecessary ports and hardening services.",
                ))

        if report.recommendations:
            for rec in report.recommendations:
                if rec.priority == "Critical":
                    findings.append(FindingModel(
                        title=f"Recommended: {rec.assessment_type}",
                        description=rec.justification,
                        severity=FindingSeverity.HIGH,
                        target=report.target,
                        evidence=f"Priority: {rec.priority}",
                        recommendation=f"Conduct {rec.assessment_type} as next phase.",
                    ))

        if findings:
            findings_file = findings_dir / "intelligence_findings.json"
            with open(findings_file, "w", encoding="utf-8") as f:
                json.dump([f.model_dump(mode="json") for f in findings], f, indent=2, ensure_ascii=False)

    def _resolve_target(self, project_path: Path) -> str:
        profiles_dir = project_path / "profiles"
        findings_dir = project_path / "findings"

        tech = self._load_json(profiles_dir / "technology_profile.json")
        if tech and tech.get("target"):
            return tech["target"]

        vuln = self._load_json(profiles_dir / "vulnerability_profile.json")
        if vuln and vuln.get("target"):
            return vuln["target"]

        for name in ["headers", "ssl", "nmap", "fingerprint"]:
            scan = self._load_json(findings_dir / f"{name}.json")
            if scan and scan.get("target"):
                return scan["target"]

        return project_path.name

    def _load_tech_profile(self, profiles_dir: Path) -> Any:
        from ghostmirror.models.fingerprint import FingerprintProfile

        path = profiles_dir / "technology_profile.json"
        if not path.exists():
            return None
        try:
            with open(path, "r", encoding="utf-8") as f:
                return FingerprintProfile.model_validate(json.load(f))
        except Exception as exc:
            logger.warning("Failed to load technology profile: {}", exc)
            return None

    def _count_findings(self, project_path: Path, findings_dir: Path) -> tuple[int, int, int, int, int]:
        critical = high = medium = low = total = 0
        scanner_names = ["headers", "ssl", "nmap", "fingerprint"]

        for name in scanner_names:
            data = self._load_json(findings_dir / f"{name}.json")
            if data and "findings" in data:
                for f in data["findings"]:
                    sev = f.get("severity", "info").upper()
                    total += 1
                    if sev == "CRITICAL":
                        critical += 1
                    elif sev == "HIGH":
                        high += 1
                    elif sev == "MEDIUM":
                        medium += 1
                    elif sev == "LOW":
                        low += 1

        return critical, high, medium, low, total

    @staticmethod
    def _load_json(path: Path) -> dict | None:
        if not path.exists():
            return None
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return None
