"""Define the scan profiles and execution step pipelines."""

from __future__ import annotations

from typing import Literal

ProfileName = Literal["lite", "standard", "deep"]

# The list of execution steps mapped to each scan profile
PIPELINE_PROFILES: dict[ProfileName, list[str]] = {
    "lite": [
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
        "report",
    ],
}


def get_pipeline_steps(profile: str) -> list[str]:
    """Get the ordered list of step names for a given execution profile."""
    prof = profile.lower()
    if prof not in PIPELINE_PROFILES:
        raise ValueError(
            f"Perfil inválido: {profile!r}. Opções válidas: {list(PIPELINE_PROFILES.keys())}"
        )
    return PIPELINE_PROFILES[prof]
