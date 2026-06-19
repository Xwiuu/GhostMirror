"""Executive summary generator — automatic text generation from intelligence data."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ghostmirror.core.logger import get_logger

logger = get_logger()


class ExecutiveSummaryGenerator:
    """Generates an automated executive summary from collected intelligence."""

    @staticmethod
    def generate(
        target: str,
        technologies: list[str],
        cms_list: list[str],
        frameworks: list[str],
        databases: list[str],
        waf_vendor: str | None,
        cdn_vendor: str | None,
        hosting_provider: str | None,
        dns_findings: list[dict],
        open_ports: list[int],
        critical_findings: int,
        high_findings: int,
        medium_findings: int,
        low_findings: int,
        total_findings: int,
        cve_count: int,
        attack_surface_score: int,
        risk_score: int,
        risk_level: str,
        exploit_available: bool,
        kev_count: int,
    ) -> str:
        tech_block = ""
        if technologies:
            tech_list = technologies[:8]
            tech_block = "  * " + "\n  * ".join(tech_list)
            if len(technologies) > 8:
                tech_block += f"\n  * ... and {len(technologies) - 8} more technologies"

        concerns: list[str] = []

        if critical_findings > 0:
            concerns.append(f"{critical_findings} critical severity finding(s) identified")
        if high_findings > 0:
            concerns.append(f"{high_findings} high severity finding(s) identified")
        if cve_count > 0:
            concern = f"{cve_count} CVE(s) correlated with detected technologies"
            if exploit_available:
                concern += " (public exploit available)"
            if kev_count > 0:
                concern += f" ({kev_count} on CISA KEV list)"
            concerns.append(concern)
        if open_ports:
            concerns.append(f"{len(open_ports)} open port(s) detected: {open_ports}")
        if dns_findings:
            dns_issues = [f.get("record_type", "?") for f in dns_findings]
            concerns.append(f"DNS configuration issues: {', '.join(dns_issues)}")
        if cms_list:
            concerns.append(f"CMS platform(s) detected: {', '.join(cms_list)}")
        if databases:
            concerns.append(f"Database service(s) exposed: {', '.join(databases)}")
        if not waf_vendor and not cdn_vendor:
            concerns.append("No Web Application Firewall or CDN detected")

        infra_block = ""
        infra_parts = []
        if waf_vendor:
            infra_parts.append(f"WAF: {waf_vendor}")
        if cdn_vendor:
            infra_parts.append(f"CDN: {cdn_vendor}")
        if hosting_provider:
            infra_parts.append(f"Hosting: {hosting_provider}")
        if infra_parts:
            infra_block = "  * " + "\n  * ".join(infra_parts)

        concerns_block = ""
        if concerns:
            concerns_block = "  * " + "\n  * ".join(concerns)

        next_phase = ExecutiveSummaryGenerator._recommend_next_phase(
            critical_findings, high_findings, cve_count, databases, cms_list, frameworks
        )

        summary = f"""## Executive Summary

### Target Overview
Target: {target}
Overall Risk Level: **{risk_level}** (Attack Surface Score: {attack_surface_score}/100, Risk Score: {risk_score}/100)

### Technology Stack
{tech_block}

### Infrastructure
{infra_block if infra_block else "  * No infrastructure services detected"}

### Main Concerns
{concerns_block if concerns_block else "  * No significant concerns identified"}

### Risk Metrics
  * Total Findings: {total_findings} (Critical: {critical_findings}, High: {high_findings}, Medium: {medium_findings}, Low: {low_findings})
  * Correlated CVEs: {cve_count}
  * Exploit Available: {'Yes' if exploit_available else 'No'}
  * KEV Listed: {kev_count}

### Recommended Next Phase
{next_phase}"""

        return summary

    @staticmethod
    def _recommend_next_phase(
        critical_count: int,
        high_count: int,
        cve_count: int,
        databases: list[str],
        cms_list: list[str],
        frameworks: list[str],
    ) -> str:
        if critical_count > 0 or cve_count > 5:
            return (
                "**Web Application Penetration Test** — "
                f"The presence of {critical_count} critical issues and {cve_count} CVEs "
                "warrants a comprehensive manual web application assessment."
            )
        if high_count > 0 or databases or cms_list:
            return (
                "**Configuration Review and Security Assessment** — "
                "Medium-to-high risk findings combined with exposed services "
                "justify a thorough configuration review."
            )
        if frameworks:
            return (
                "**Security Architecture Review** — "
                "The identified technology stack should be reviewed for security best practices."
            )
        return (
            "**Standard Security Assessment** — "
            "A general security assessment is recommended to establish a baseline."
        )

    @staticmethod
    def from_project(project_path: Path) -> str:
        profiles_dir = project_path / "profiles"
        findings_dir = project_path / "findings"

        def load_json(path: Path) -> dict | None:
            if path.exists():
                try:
                    with open(path, "r", encoding="utf-8") as f:
                        return json.load(f)
                except Exception:
                    return None
            return None

        tech_data = load_json(profiles_dir / "technology_profile.json")
        cve_data = load_json(profiles_dir / "vulnerability_profile.json")
        nmap_data = load_json(findings_dir / "nmap.json")
        as_profile = load_json(profiles_dir / "attack_surface_profile.json")

        technologies = []
        cms_list = []
        frameworks_list = []
        databases_list = []
        if tech_data:
            for t in tech_data.get("technologies", []):
                technologies.append(t.get("name", ""))
                cat = t.get("category", "").upper()
                if cat == "CMS":
                    cms_list.append(t.get("name", ""))
                elif cat in ("FRAMEWORK", "BACKEND"):
                    frameworks_list.append(t.get("name", ""))
                elif cat in ("DATABASE", "STORAGE"):
                    databases_list.append(t.get("name", ""))

        target = (tech_data or {}).get("target", "Unknown")
        waf_vendor = None
        cdn_vendor = None
        hosting_provider = None
        dns_findings = []
        if as_profile:
            waf = as_profile.get("waf", {})
            if waf.get("detected"):
                waf_vendor = waf.get("vendor")
            cdn = as_profile.get("cdn", {})
            if cdn.get("detected"):
                cdn_vendor = cdn.get("vendor")
            hosting = as_profile.get("hosting", {})
            if hosting.get("detected"):
                hosting_provider = hosting.get("provider")
            dns = as_profile.get("dns", {})
            dns_findings = dns.get("findings", [])

        open_ports = []
        if nmap_data:
            open_ports = nmap_data.get("open_ports", [])

        cve_matches = []
        if cve_data:
            cve_matches = cve_data.get("matches", [])

        cve_count = len(cve_matches)
        exploit_available = any(
            c.get("matched_cve", {}).get("exploit_available", False) for c in cve_matches
        )
        kev_count = sum(
            1 for c in cve_matches if c.get("matched_cve", {}).get("kev_listed", False)
        )

        critical_findings = (as_profile or {}).get("observations", [])
        critical_count = 0
        high_count = 0
        medium_count = 0
        low_count = 0

        all_findings = []
        for fname in ["headers", "ssl", "nmap", "fingerprint"]:
            fdata = load_json(findings_dir / f"{fname}.json")
            if fdata and "findings" in fdata:
                all_findings.extend(fdata["findings"])

        for f in all_findings:
            sev = f.get("severity", "info").upper()
            if sev == "CRITICAL":
                critical_count += 1
            elif sev == "HIGH":
                high_count += 1
            elif sev == "MEDIUM":
                medium_count += 1
            elif sev == "LOW":
                low_count += 1

        attack_surface_score = (as_profile or {}).get("attack_surface_score", 0)
        risk_score = (cve_data or {}).get("overall_vulnerability_score", 0)
        risk_level = (cve_data or {}).get("overall_risk_level", "Unknown")

        return ExecutiveSummaryGenerator.generate(
            target=target,
            technologies=technologies,
            cms_list=cms_list,
            frameworks=frameworks_list,
            databases=databases_list,
            waf_vendor=waf_vendor,
            cdn_vendor=cdn_vendor,
            hosting_provider=hosting_provider,
            dns_findings=dns_findings,
            open_ports=open_ports,
            critical_findings=critical_count,
            high_findings=high_count,
            medium_findings=medium_count,
            low_findings=low_count,
            total_findings=len(all_findings),
            cve_count=cve_count,
            attack_surface_score=attack_surface_score,
            risk_score=risk_score,
            risk_level=risk_level,
            exploit_available=exploit_available,
            kev_count=kev_count,
        )
