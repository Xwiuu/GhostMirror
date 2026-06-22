"""Define the scan profiles and execution step pipelines."""
from __future__ import annotations
from typing import Literal

ProfileName = Literal["quick", "standard", "deep", "bounty"]

PIPELINE_PROFILES: dict[str, list[str]] = {
    "quick": [
        "headers",
        "ssl",
        "nmap",
        "fingerprint",
        "report",
    ],
    "standard": [
        "headers",
        "ssl",
        "nmap",
        "fingerprint",
        "technology_intelligence",
        "cve_intelligence",
        "nuclei",
        "owasp",
        "intelligence",
        "web_intelligence",
        "api_security",
        "zero_day",
        "attack_chain",
        "report",
    ],
    "deep": [
        "headers",
        "ssl",
        "nmap",
        "fingerprint",
        "technology_intelligence",
        "cve_intelligence",
        "nuclei",
        "owasp",
        "payloads",
        "intelligence",
        "web_intelligence",
        "api_security",
        "zero_day",
        "attack_chain",
        "report",
    ],
    "bounty": [
        "headers",
        "ssl",
        "nmap",
        "fingerprint",
        "technology_intelligence",
        "web_intelligence",
        "bug_bounty",
        "vulnerability_intelligence",
        "finding_intelligence",
        "intelligence",
        "api_security",
        "zero_day",
        "attack_chain",
        "report",
    ],
}

PIPELINE_DESCRIPTIONS: dict[str, str] = {
    "quick": "≈ 5 min — Headers, SSL, Nmap, Fingerprint",
    "standard": "≈ 20 min — Quick + Intelligence + Nuclei + OWASP + Web + Zero-Day + Attack Chain",
    "deep": "Completo — Standard + Payloads + Intelligence + Web + Zero-Day + Attack Chain + PDF Report",
    "bounty": "Bug Bounty — Full recon + JS Intelligence + API Discovery + Secrets + Subdomains + API Security + Zero-Day + Attack Chain",
}

ALIASES: dict[str, str] = {
    "lite": "quick",
}


def get_pipeline_steps(profile: str) -> list[str]:
    prof = profile.lower()
    prof = ALIASES.get(prof, prof)
    if prof not in PIPELINE_PROFILES:
        raise ValueError(
            f"Perfil inválido: {profile!r}. Opções válidas: {list(PIPELINE_PROFILES.keys())}"
        )
    return PIPELINE_PROFILES[prof]


def get_profile_descriptions() -> dict[str, str]:
    return dict(PIPELINE_DESCRIPTIONS)
