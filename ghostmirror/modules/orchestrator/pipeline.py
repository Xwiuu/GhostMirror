"""Define the scan profiles and execution step pipelines."""

from __future__ import annotations

from typing import Literal

ProfileName = Literal["quick", "standard", "deep"]

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
        "report",
    ],
}

PIPELINE_DESCRIPTIONS: dict[str, str] = {
    "quick": "≈ 5 min — Headers, SSL, Nmap, Fingerprint",
    "standard": "≈ 15 min — Quick + Intelligence + Nuclei + OWASP",
    "deep": "Completo — Standard + Payloads + PDF Report",
}

ALIASES: dict[str, str] = {
    "lite": "quick",
}


def get_pipeline_steps(profile: str) -> list[str]:
    """Get the ordered list of step names for a given execution profile."""
    prof = profile.lower()
    prof = ALIASES.get(prof, prof)
    if prof not in PIPELINE_PROFILES:
        raise ValueError(
            f"Perfil inválido: {profile!r}. Opções válidas: {list(PIPELINE_PROFILES.keys())}"
        )
    return PIPELINE_PROFILES[prof]


def get_profile_descriptions() -> dict[str, str]:
    """Return the profile descriptions for display."""
    return dict(PIPELINE_DESCRIPTIONS)
