"""Attack Surface Intelligence — WAF, CDN, Hosting, DNS detection and profiling."""

from __future__ import annotations

import json
import socket
from pathlib import Path
from typing import Any

from ghostmirror.core.logger import get_logger
from ghostmirror.models.attack_surface_profile import (
    AttackSurfaceProfile,
    CDNProfile,
    DNSFinding,
    DNSProfile,
    HostingProfile,
    WAFProfile,
)
from ghostmirror.models.fingerprint import FingerprintProfile
from ghostmirror.models.technology import TechnologyModel

logger = get_logger()

WAF_SIGNATURES: dict[str, list[str]] = {
    "Cloudflare": ["cloudflare", "__cfduid", "cf-ray", "cf-cache-status"],
    "Akamai": ["akamai", "akamaighost", "x-akamai-"],
    "Imperva": ["imperva", "incapsula", "x-iinfo"],
    "Sucuri": ["sucuri", "x-sucuri-id", "x-sucuri-cache"],
    "AWS WAF": ["aws-waf", "x-amzn-requestid", "x-amzn-errortype"],
    "Azure WAF": ["azure-waf", "x-azure-waf"],
    "Google Cloud Armor": ["cloud-armor", "x-goog-"],
    "Fastly": ["fastly", "x-fastly-"],
    "F5": ["f5", "big-ip", "x-f5"],
    "Barracuda": ["barracuda", "x-barracuda"],
}

CDN_SIGNATURES: dict[str, list[str]] = {
    "Cloudflare": ["cloudflare", "__cfduid", "cf-ray"],
    "Fastly": ["fastly", "x-fastly-", "x-served-by"],
    "CloudFront": ["cloudfront", "x-amz-cf-id", "x-amz-cf-pop"],
    "Akamai": ["akamai", "akamaighost", "x-akamai-"],
    "BunnyCDN": ["bunnycdn", "x-bunny-", "x-edge-location"],
    "KeyCDN": ["keycdn", "x-keycdn-"],
    "StackPath": ["stackpath", "x-stackpath-"],
}

HOSTING_SIGNATURES: dict[str, list[str]] = {
    "AWS": ["aws", "amazon", "ec2", "s3", "cloudfront", "amazonaws.com"],
    "Azure": ["azure", "windowsazure", "azurewebsites", "azureedge"],
    "GCP": ["google cloud", "gcp", "appspot", "googleapis", "compute.googleapis"],
    "DigitalOcean": ["digitalocean", "do-", "digitaloceanspaces"],
    "Vercel": ["vercel", "now.sh", ".vercel.app"],
    "Netlify": ["netlify", "netlify.app"],
    "Linode": ["linode", "linodeusercontent"],
    "Hetzner": ["hetzner", "hetzner.cloud"],
    "Oracle Cloud": ["oracle", "oraclecloud", "oci-"],
}

COMMON_DNS_RECORDS = ["A", "AAAA", "MX", "NS", "TXT", "SOA"]


class AttackSurfaceAnalyzer:
    """Analyzes a target's attack surface including WAF, CDN, hosting, and DNS."""

    def __init__(self) -> None:
        self.target: str = ""

    def analyze(
        self,
        target: str,
        technology_profile: FingerprintProfile | None = None,
        headers_findings: list[dict] | None = None,
        ssl_findings: dict | None = None,
        nmap_findings: dict | None = None,
    ) -> AttackSurfaceProfile:
        self.target = target

        waf = self._detect_waf(technology_profile, headers_findings)
        cdn = self._detect_cdn(technology_profile, headers_findings)
        hosting = self._detect_hosting(technology_profile, headers_findings)
        dns = self._analyze_dns(target)

        tech_list: list[str] = []
        web_servers: list[str] = []
        frameworks: list[str] = []
        cms_list: list[str] = []
        databases: list[str] = []
        external_services: list[str] = []
        if technology_profile:
            for t in technology_profile.technologies:
                tech_list.append(t.name)
                cat = t.category.upper() if t.category else ""
                if cat == "WEB SERVER":
                    web_servers.append(t.name)
                elif cat in ("FRAMEWORK", "BACKEND"):
                    frameworks.append(t.name)
                elif cat == "CMS":
                    cms_list.append(t.name)
                elif cat in ("DATABASE", "STORAGE"):
                    databases.append(t.name)
                elif cat in ("CDN", "WAF", "PAYMENT", "ANALYTICS"):
                    external_services.append(t.name)

        open_ports: list[int] = []
        services_exposed: list[str] = []
        if nmap_findings:
            open_ports = nmap_findings.get("open_ports", [])
            services_exposed = nmap_findings.get("services", [])

        entry_points: list[str] = []
        high_value: list[str] = []
        observations: list[str] = []

        if cms_list:
            entry_points.extend(f"{c}/admin" for c in cms_list)
            high_value.extend(cms_list)
        if databases:
            entry_points.extend(f"{d} exposed" for d in databases)
            high_value.extend(databases)
        if open_ports:
            observations.append(f"{len(open_ports)} port(s) open: {open_ports}")
        if not waf.detected and not cdn.detected:
            observations.append("No WAF or CDN detected — target is directly exposed")

        return AttackSurfaceProfile(
            target=target,
            web_servers=web_servers,
            frameworks=frameworks,
            cms=cms_list,
            databases=databases,
            external_services=external_services,
            technologies=tech_list,
            open_ports=open_ports,
            services_exposed=services_exposed,
            waf=waf,
            cdn=cdn,
            hosting=hosting,
            dns=dns,
            potential_entry_points=entry_points,
            high_value_assets=high_value,
            observations=observations,
        )

    def _detect_waf(
        self,
        tech_profile: FingerprintProfile | None,
        headers: list[dict] | None,
    ) -> WAFProfile:
        detected_techs: list[str] = []
        if tech_profile:
            for t in tech_profile.technologies:
                if t.category and t.category.upper() == "WAF":
                    detected_techs.append(t.name)

        if detected_techs:
            return WAFProfile(detected=True, vendor=detected_techs[0], confidence=90)

        header_str = ""
        if headers:
            header_str = str(headers).lower()

        for vendor, sigs in WAF_SIGNATURES.items():
            for sig in sigs:
                if sig.lower() in header_str:
                    return WAFProfile(detected=True, vendor=vendor, confidence=85)

        if tech_profile and tech_profile.waf:
            return WAFProfile(detected=True, vendor=tech_profile.waf, confidence=80)

        return WAFProfile()

    def _detect_cdn(
        self,
        tech_profile: FingerprintProfile | None,
        headers: list[dict] | None,
    ) -> CDNProfile:
        detected_techs: list[str] = []
        if tech_profile:
            for t in tech_profile.technologies:
                if t.category and t.category.upper() == "CDN":
                    detected_techs.append(t.name)

        if detected_techs:
            return CDNProfile(detected=True, vendor=detected_techs[0], confidence=90)

        header_str = ""
        if headers:
            header_str = str(headers).lower()

        for vendor, sigs in CDN_SIGNATURES.items():
            for sig in sigs:
                if sig.lower() in header_str:
                    return CDNProfile(detected=True, vendor=vendor, confidence=85)

        if tech_profile and tech_profile.cdn:
            return CDNProfile(detected=True, vendor=tech_profile.cdn, confidence=80)

        return CDNProfile()

    def _detect_hosting(
        self,
        tech_profile: FingerprintProfile | None,
        headers: list[dict] | None,
    ) -> HostingProfile:
        detected_hosting: list[str] = []
        if tech_profile:
            if tech_profile.hosting:
                detected_hosting.append(tech_profile.hosting)
            for t in tech_profile.technologies:
                for provider, sigs in HOSTING_SIGNATURES.items():
                    if t.name.lower() in sigs or any(s in t.name.lower() for s in sigs):
                        detected_hosting.append(provider)

        if detected_hosting:
            return HostingProfile(detected=True, provider=detected_hosting[0], confidence=85)

        header_str = ""
        if headers:
            header_str = str(headers).lower()

        for provider, sigs in HOSTING_SIGNATURES.items():
            for sig in sigs:
                if sig.lower() in header_str:
                    return HostingProfile(detected=True, provider=provider, confidence=80)

        return HostingProfile()

    def _analyze_dns(self, target: str) -> DNSProfile:
        records: dict[str, list[str]] = {}
        findings: list[DNSFinding] = []
        spf_missing = False
        dmarc_missing = False
        dkim_missing = False

        for rtype in COMMON_DNS_RECORDS:
            try:
                if rtype == "A":
                    result = socket.getaddrinfo(target, 0, socket.AF_INET)
                    records[rtype] = list(set(r[4][0] for r in result))
                elif rtype == "AAAA":
                    try:
                        result = socket.getaddrinfo(target, 0, socket.AF_INET6)
                        records[rtype] = list(set(r[4][0] for r in result))
                    except socket.gaierror:
                        records[rtype] = []
                elif rtype in ("MX", "NS", "TXT", "SOA"):
                    try:
                        import dns.resolver
                        answers = dns.resolver.resolve(target, rtype)
                        records[rtype] = [str(a) for a in answers]
                    except ImportError:
                        records[rtype] = []
                    except Exception:
                        records[rtype] = []
                else:
                    records[rtype] = []
            except Exception:
                records[rtype] = []

        txt_records = records.get("TXT", [])
        has_spf = any("v=spf1" in r for r in txt_records)
        has_dmarc = any("v=DMARC1" in r for r in txt_records)
        has_dkim = any("v=DKIM1" in r or "dkim" in r.lower() for r in txt_records)

        if not has_spf:
            spf_missing = True
            findings.append(DNSFinding(record_type="SPF", status="MISSING", details="SPF record not found — email spoofing possible"))
        if not has_dmarc:
            dmarc_missing = True
            findings.append(DNSFinding(record_type="DMARC", status="MISSING", details="DMARC record not found — no email authentication policy"))
        if not has_dkim:
            dkim_missing = True
            findings.append(DNSFinding(record_type="DKIM", status="MISSING", details="DKIM record not found — email signing not configured"))

        return DNSProfile(
            records=records,
            findings=findings,
            spf_missing=spf_missing,
            dmarc_missing=dmarc_missing,
            dkim_missing=dkim_missing,
        )

    def save_profiles(self, project_path: Path, profile: AttackSurfaceProfile) -> None:
        profiles_dir = project_path / "profiles"
        profiles_dir.mkdir(parents=True, exist_ok=True)

        with open(profiles_dir / "waf_profile.json", "w", encoding="utf-8") as f:
            json.dump(profile.waf.model_dump(mode="json"), f, indent=2)
        with open(profiles_dir / "cdn_profile.json", "w", encoding="utf-8") as f:
            json.dump(profile.cdn.model_dump(mode="json"), f, indent=2)
        with open(profiles_dir / "hosting_profile.json", "w", encoding="utf-8") as f:
            json.dump(profile.hosting.model_dump(mode="json"), f, indent=2)
        with open(profiles_dir / "dns_profile.json", "w", encoding="utf-8") as f:
            json.dump(profile.dns.model_dump(mode="json"), f, indent=2)

        logger.info("ATTACK_SURFACE_PROFILES_SAVED target={}", profile.target)
