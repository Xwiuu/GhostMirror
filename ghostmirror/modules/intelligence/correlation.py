"""Correlation engine — cross-references findings across modules."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ghostmirror.core.logger import get_logger

logger = get_logger()


class CorrelatedFinding:
    def __init__(
        self,
        title: str,
        description: str,
        severity: str,
        sources: list[str],
        evidence: str | None = None,
        recommendation: str | None = None,
    ) -> None:
        self.title = title
        self.description = description
        self.severity = severity
        self.sources = sources
        self.evidence = evidence
        self.recommendation = recommendation

    def to_dict(self) -> dict[str, Any]:
        return {
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "sources": self.sources,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
        }


SERVICE_PORT_MAP: dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    27017: "MongoDB",
    6379: "Redis",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt",
    9200: "Elasticsearch",
}

TECH_PORT_MAP: dict[str, list[int]] = {
    "mysql": [3306],
    "mariadb": [3306],
    "postgresql": [5432],
    "postgres": [5432],
    "mongodb": [27017],
    "redis": [6379],
    "elasticsearch": [9200],
    "apache": [80, 443, 8080],
    "nginx": [80, 443, 8080],
    "iis": [80, 443],
    "ssh": [22],
    "ftp": [21],
}


class CorrelationEngine:
    """Cross-references findings from Nmap, Technology, CVE, Nuclei, and OWASP."""

    @staticmethod
    def correlate(project_path: Path) -> list[CorrelatedFinding]:
        correlated: list[CorrelatedFinding] = []
        profiles_dir = project_path / "profiles"
        findings_dir = project_path / "findings"

        nmap_data = CorrelationEngine._load_json(findings_dir / "nmap.json")
        tech_data = CorrelationEngine._load_json(profiles_dir / "technology_profile.json")
        cve_data = CorrelationEngine._load_json(profiles_dir / "vulnerability_profile.json")
        nuclei_data = CorrelationEngine._load_json(profiles_dir / "nuclei_profile.json")
        owasp_data = CorrelationEngine._load_json(profiles_dir / "owasp_profile.json")

        open_ports: list[int] = []
        services: list[str] = []
        if nmap_data:
            open_ports = nmap_data.get("open_ports", [])
            services = nmap_data.get("services", [])

        tech_names: list[str] = []
        if tech_data:
            for t in tech_data.get("technologies", []):
                tech_names.append(t.get("name", "").lower())

        cve_matches: list[dict] = []
        if cve_data:
            cve_matches = cve_data.get("matches", [])

        nuclei_findings_list: list[dict] = []
        if nuclei_data:
            nuclei_findings_list = nuclei_data.get("findings", []) or nuclei_data.get("matched_templates", [])

        owasp_findings_list: list[dict] = []
        if owasp_data:
            owasp_findings_list = owasp_data.get("findings", [])

        for port in open_ports:
            expected_service = SERVICE_PORT_MAP.get(port, f"unknown-{port}")
            tech_match = None
            cve_match = None
            nuclei_match = None

            for tech_name in tech_names:
                expected_ports = TECH_PORT_MAP.get(tech_name, [])
                if port in expected_ports:
                    tech_match = tech_name
                    break

            for cve in cve_matches:
                cve_tech = cve.get("technology", "").lower()
                if tech_match and cve_tech == tech_match:
                    cve_match = cve.get("matched_cve", {}).get("cve_id", "CVE-Unknown")
                    break

            for nf in nuclei_findings_list:
                if isinstance(nf, dict):
                    nf_info = nf.get("info", nf)
                    nf_host = str(nf.get("host", "")).lower()
                    if expected_service.lower() in str(nf_info).lower() or str(port) in nf_host:
                        nuclei_match = nf.get("template_id", nf.get("id", "Nuclei-Match"))
                        break

            if tech_match and cve_match:
                correlated.append(CorrelatedFinding(
                    title=f"Correlated: {expected_service} ({tech_match}) + CVE",
                    description=f"Port {port}/{expected_service} matches technology {tech_match} with known CVE {cve_match}",
                    severity="HIGH",
                    sources=["nmap", "technology_intelligence", "cve_intelligence"],
                    evidence=f"Port: {port}, Technology: {tech_match}, CVE: {cve_match}",
                    recommendation=f"Review {tech_match} configuration and apply patches for {cve_match}",
                ))
            elif tech_match and not cve_match:
                port_finding = CorrelationEngine._check_owasp_for_service(port, expected_service, owasp_findings_list)
                if port_finding:
                    correlated.append(port_finding)

        enriched_count = len(correlated)
        if enriched_count > 0:
            logger.info("CORRELATION_COMPLETE enriched_findings={}", enriched_count)

        return correlated

    @staticmethod
    def _check_owasp_for_service(
        port: int, service: str, owasp_findings: list[dict]
    ) -> CorrelatedFinding | None:
        for of in owasp_findings:
            of_str = str(of).lower()
            if service.lower() in of_str or str(port) in of_str:
                return CorrelatedFinding(
                    title=f"Correlated: {service} (Port {port}) + OWASP",
                    description=f"Port {port}/{service} correlates with OWASP finding",
                    severity="MEDIUM",
                    sources=["nmap", "owasp"],
                    evidence=f"Port: {port}, Service: {service}",
                    recommendation=f"Review service exposure on port {port}",
                )
        return None

    @staticmethod
    def _load_json(path: Path) -> dict | None:
        if not path.exists():
            return None
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return None
