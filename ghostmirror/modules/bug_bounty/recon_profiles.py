from __future__ import annotations

from typing import Literal

ProfileName = Literal["lite", "standard", "deep", "bounty"]

RECON_PROFILES: dict[str, list[str]] = {
    "lite": [
        "headless_crawler",
        "interesting_files",
    ],
    "standard": [
        "headless_crawler",
        "network_capture",
        "js_bundle_analyzer",
        "interesting_files",
    ],
    "deep": [
        "headless_crawler",
        "network_capture",
        "js_bundle_analyzer",
        "sourcemap_analyzer",
        "api_discovery",
        "parameter_mining",
        "interesting_files",
    ],
    "bounty": [
        "headless_crawler",
        "network_capture",
        "js_bundle_analyzer",
        "sourcemap_analyzer",
        "api_discovery",
        "parameter_mining",
        "secrets_discovery",
        "interesting_files",
        "subdomain_discovery",
    ],
}


class ReconProfiles:
    @staticmethod
    def get_steps(profile: str) -> list[str]:
        prof = profile.lower()
        if prof not in RECON_PROFILES:
            raise ValueError(f"Invalid recon profile: {profile!r}. Options: {list(RECON_PROFILES.keys())}")
        return RECON_PROFILES[prof]
