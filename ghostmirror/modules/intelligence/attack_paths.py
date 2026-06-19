"""Attack path engine — models potential attack paths without exploitation."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ghostmirror.core.logger import get_logger
from ghostmirror.models.attack_path import AttackPath, AttackPathStep

logger = get_logger()


class AttackPathEngine:
    """Models potential attack paths based on correlated intelligence data."""

    @staticmethod
    def generate_paths(project_path: Path) -> list[AttackPath]:
        paths: list[AttackPath] = []

        profiles_dir = project_path / "profiles"
        findings_dir = project_path / "findings"

        tech_data = AttackPathEngine._load_json(profiles_dir / "technology_profile.json")
        cve_data = AttackPathEngine._load_json(profiles_dir / "vulnerability_profile.json")
        nmap_data = AttackPathEngine._load_json(findings_dir / "nmap.json")
        nuclei_data = AttackPathEngine._load_json(profiles_dir / "nuclei_profile.json")
        owasp_data = AttackPathEngine._load_json(profiles_dir / "owasp_profile.json")

        tech_names: list[str] = []
        tech_versions: dict[str, str] = {}
        if tech_data:
            for t in tech_data.get("technologies", []):
                name = t.get("name", "")
                tech_names.append(name.lower())
                version = t.get("version")
                if version:
                    tech_versions[name.lower()] = version

        cve_matches: list[dict] = []
        if cve_data:
            cve_matches = cve_data.get("matches", [])

        open_ports: list[int] = []
        services: list[str] = []
        if nmap_data:
            open_ports = nmap_data.get("open_ports", [])
            services = nmap_data.get("services", [])

        nuclei_results: list[dict] = []
        if nuclei_data:
            nuclei_results = nuclei_data.get("findings", []) or nuclei_data.get("matched_templates", [])

        owasp_findings: list[dict] = []
        if owasp_data:
            owasp_findings = owasp_data.get("findings", [])

        path_id = 1

        cms_paths = AttackPathEngine._build_cms_paths(
            tech_names, tech_versions, cve_matches, nuclei_results, path_id
        )
        paths.extend(cms_paths)
        path_id += len(cms_paths)

        ssh_paths = AttackPathEngine._build_service_paths(
            open_ports, services, cve_matches, "SSH", 22, path_id
        )
        paths.extend(ssh_paths)
        path_id += len(ssh_paths)

        db_paths = AttackPathEngine._build_database_paths(
            open_ports, services, tech_names, cve_matches, path_id
        )
        paths.extend(db_paths)
        path_id += len(db_paths)

        web_paths = AttackPathEngine._build_web_paths(
            tech_names, owasp_findings, cve_matches, path_id
        )
        paths.extend(web_paths)
        path_id += len(web_paths)

        if not paths:
            paths.append(AttackPath(
                path_id=1,
                title="No attack paths identified",
                description="Insufficient intelligence data to model attack paths",
                steps=[],
                risk_score=0,
                risk_level="INFO",
            ))

        logger.info("ATTACK_PATHS_GENERATED count={}", len(paths))
        return paths

    @staticmethod
    def _build_cms_paths(
        tech_names: list[str],
        tech_versions: dict[str, str],
        cve_matches: list[dict],
        nuclei_results: list[dict],
        start_id: int,
    ) -> list[AttackPath]:
        paths: list[AttackPath] = []
        cms_keywords = ["wordpress", "joomla", "drupal", "magento", "shopify"]

        for cms_key in cms_keywords:
            if cms_key not in tech_names:
                continue

            version = tech_versions.get(cms_key, "unknown")
            steps: list[AttackPathStep] = []
            order = 1
            steps.append(AttackPathStep(order=order, label=cms_key.capitalize(), detail=f"Detected {cms_key} {version}"))

            order += 1
            if version and version != "unknown":
                steps.append(AttackPathStep(order=order, label="Version Identified", detail=f"Version: {version}"))

            matching_cves = []
            for cve in cve_matches:
                if cve.get("technology", "").lower() == cms_key:
                    matching_cves.append(cve)
                    if len(matching_cves) >= 3:
                        break

            if matching_cves:
                order += 1
                cve_ids = [c.get("matched_cve", {}).get("cve_id", "CVE-Unknown") for c in matching_cves]
                steps.append(AttackPathStep(
                    order=order,
                    label="Known CVEs Match",
                    detail=", ".join(cve_ids),
                    severity=max(c.get("risk_level", "MEDIUM") for c in matching_cves),
                ))

            order += 1
            steps.append(AttackPathStep(
                order=order,
                label="Admin Panel Potentially Exposed",
                detail=f"/{cms_key}/admin, /{cms_key}/wp-admin, etc.",
            ))

            order += 1
            steps.append(AttackPathStep(
                order=order,
                label="Potential Compromise",
                detail=f"Exploitation of {cms_key} could lead to data breach or RCE",
            ))

            risk_score = 65 if matching_cves else 40
            paths.append(AttackPath(
                path_id=start_id + len(paths),
                title=f"{cms_key.capitalize()} Attack Path",
                description=f"Potential attack path through {cms_key} {version} with {len(matching_cves)} matching CVEs",
                steps=steps,
                risk_score=risk_score,
                risk_level="HIGH" if risk_score > 50 else "MEDIUM",
                likelihood="High" if matching_cves else "Medium",
                impact="High",
                prerequisites=[f"Access to {cms_key} instance", f"Version {version} confirmed"],
                mitigations=[
                    f"Update {cms_key} to latest version",
                    "Restrict admin panel access by IP",
                    "Implement WAF rules",
                ],
            ))

        return paths

    @staticmethod
    def _build_service_paths(
        open_ports: list[int],
        services: list[str],
        cve_matches: list[dict],
        service_name: str,
        port: int,
        start_id: int,
    ) -> list[AttackPath]:
        paths: list[AttackPath] = []
        if port not in open_ports and service_name.lower() not in [s.lower() for s in services]:
            return paths

        steps: list[AttackPathStep] = []
        order = 1
        steps.append(AttackPathStep(order=order, label=f"{service_name} Exposed", detail=f"Port {port} open"))

        order += 1
        steps.append(AttackPathStep(order=order, label=f"{service_name} Banner Grabbed", detail="Banner information available"))

        matching_service_cves = [c for c in cve_matches if service_name.lower() in c.get("technology", "").lower()]
        if matching_service_cves:
            order += 1
            cve_id = matching_service_cves[0].get("matched_cve", {}).get("cve_id", "CVE-Unknown")
            steps.append(AttackPathStep(
                order=order,
                label=f"Known {service_name} CVE",
                detail=cve_id,
                severity=matching_service_cves[0].get("risk_level", "HIGH"),
            ))

        order += 1
        steps.append(AttackPathStep(
            order=order,
            label="Potential Access",
            detail=f"Brute-force or CVE-based access to {service_name}",
        ))

        risk_score = 70 if matching_service_cves else 45
        paths.append(AttackPath(
            path_id=start_id + len(paths),
            title=f"Exposed {service_name} Attack Path",
            description=f"Attack path through exposed {service_name} on port {port}",
            steps=steps,
            risk_score=risk_score,
            risk_level="HIGH" if risk_score > 50 else "MEDIUM",
            likelihood="High",
            impact="High",
            prerequisites=[f"Port {port} reachable", f"{service_name} service accessible"],
            mitigations=[
                f"Restrict {service_name} access by IP allowlist",
                "Use key-based authentication",
                "Apply latest security patches",
            ],
        ))
        return paths

    @staticmethod
    def _build_database_paths(
        open_ports: list[int],
        services: list[str],
        tech_names: list[str],
        cve_matches: list[dict],
        start_id: int,
    ) -> list[AttackPath]:
        paths: list[AttackPath] = []
        db_services = {"mysql": 3306, "postgresql": 5432, "mongodb": 27017, "redis": 6379, "elasticsearch": 9200}

        for db_name, db_port in db_services.items():
            if db_port not in open_ports and db_name not in tech_names:
                continue

            steps: list[AttackPathStep] = []
            order = 1
            steps.append(AttackPathStep(order=order, label=f"{db_name.capitalize()} Exposed", detail=f"Port {db_port} open / Technology detected"))

            if db_name in tech_names:
                order += 1
                steps.append(AttackPathStep(order=order, label="Technology Confirmed", detail=f"{db_name.capitalize()} in technology stack"))

            db_cves = [c for c in cve_matches if db_name in c.get("technology", "").lower()]
            if db_cves:
                order += 1
                cve_id = db_cves[0].get("matched_cve", {}).get("cve_id", "CVE-Unknown")
                steps.append(AttackPathStep(
                    order=order,
                    label=f"Known {db_name.capitalize()} Vulnerability",
                    detail=cve_id,
                    severity="CRITICAL",
                ))

            order += 1
            steps.append(AttackPathStep(
                order=order,
                label="Data Access Risk",
                detail=f"Potential data exfiltration from {db_name}",
            ))

            risk_score = 75 if db_cves else 55
            paths.append(AttackPath(
                path_id=start_id + len(paths),
                title=f"Database Exposure: {db_name.capitalize()}",
                description=f"Attack path through exposed {db_name} database",
                steps=steps,
                risk_score=risk_score,
                risk_level="HIGH",
                likelihood="Medium",
                impact="Critical",
                prerequisites=[f"Database port {db_port} accessible", "Authentication bypass or credentials"],
                mitigations=[
                    f"Do not expose {db_name} to public internet",
                    "Use strong authentication",
                    "Enable TLS for database connections",
                ],
            ))

        return paths

    @staticmethod
    def _build_web_paths(
        tech_names: list[str],
        owasp_findings: list[dict],
        cve_matches: list[dict],
        start_id: int,
    ) -> list[AttackPath]:
        paths: list[AttackPath] = []
        if not owasp_findings and not any("apache" in t or "nginx" in t or "iis" in t or "php" in t for t in tech_names):
            return paths

        steps: list[AttackPathStep] = []
        order = 1

        web_techs = [t for t in tech_names if t in ("apache", "nginx", "iis", "php", "tomcat", "jboss")]
        if web_techs:
            steps.append(AttackPathStep(order=order, label="Web Server Detected", detail=", ".join(web_techs)))
        else:
            steps.append(AttackPathStep(order=order, label="Web Application Running", detail="Web technologies detected"))

        if owasp_findings:
            order += 1
            owasp_cats = list(set(f.get("category", "Unknown") for f in owasp_findings))
            steps.append(AttackPathStep(
                order=order,
                label=f"OWASP Findings ({len(owasp_findings)})",
                detail=", ".join(owasp_cats[:5]),
                severity="MEDIUM",
            ))

        web_cves = [c for c in cve_matches if c.get("technology", "").lower() in web_techs]
        if web_cves:
            order += 1
            steps.append(AttackPathStep(
                order=order,
                label="Web Server CVEs Found",
                detail=web_cves[0].get("matched_cve", {}).get("cve_id", "CVE-Unknown"),
                severity="HIGH",
            ))

        order += 1
        steps.append(AttackPathStep(order=order, label="Web Application Compromise", detail="Potential web application takeover"))

        order += 1
        steps.append(AttackPathStep(order=order, label="Data Exfiltration / Lateral Movement", detail="Access to backend systems"))

        paths.append(AttackPath(
            path_id=start_id + len(paths),
            title="Web Application Attack Path",
            description="Attack path through web application vulnerabilities and exposed services",
            steps=steps,
            risk_score=60,
            risk_level="HIGH",
            likelihood="Medium",
            impact="High",
            prerequisites=["Web application accessible", "Vulnerable endpoint identified"],
            mitigations=[
                "Run regular security scans",
                "Apply WAF rules",
                "Implement proper input validation",
                "Keep web servers updated",
            ],
        ))
        return paths

    @staticmethod
    def _load_json(path: Path) -> dict | None:
        if not path.exists():
            return None
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return None
