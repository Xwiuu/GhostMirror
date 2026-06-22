from __future__ import annotations

import pytest

from ghostmirror.modules.bug_bounty.recon_profiles import ReconProfiles, RECON_PROFILES


class TestReconProfiles:
    def test_get_steps_lite(self) -> None:
        steps = ReconProfiles.get_steps("lite")
        assert "headless_crawler" in steps
        assert "interesting_files" in steps
        assert len(steps) == 2

    def test_get_steps_standard(self) -> None:
        steps = ReconProfiles.get_steps("standard")
        assert "headless_crawler" in steps
        assert "network_capture" in steps
        assert "js_bundle_analyzer" in steps
        assert "interesting_files" in steps

    def test_get_steps_deep(self) -> None:
        steps = ReconProfiles.get_steps("deep")
        assert "sourcemap_analyzer" in steps
        assert "api_discovery" in steps
        assert "parameter_mining" in steps

    def test_get_steps_bounty(self) -> None:
        steps = ReconProfiles.get_steps("bounty")
        assert "headless_crawler" in steps
        assert "network_capture" in steps
        assert "js_bundle_analyzer" in steps
        assert "sourcemap_analyzer" in steps
        assert "api_discovery" in steps
        assert "parameter_mining" in steps
        assert "secrets_discovery" in steps
        assert "interesting_files" in steps
        assert "subdomain_discovery" in steps

    def test_get_steps_case_insensitive(self) -> None:
        steps = ReconProfiles.get_steps("BOUNTY")
        assert len(steps) == 9

    def test_get_steps_invalid_profile(self) -> None:
        with pytest.raises(ValueError, match="Invalid recon profile"):
            ReconProfiles.get_steps("invalid")

    def test_get_steps_empty_profile(self) -> None:
        with pytest.raises(ValueError):
            ReconProfiles.get_steps("")

    def test_recon_profiles_dict(self) -> None:
        assert "lite" in RECON_PROFILES
        assert "standard" in RECON_PROFILES
        assert "deep" in RECON_PROFILES
        assert "bounty" in RECON_PROFILES

    def test_bounty_has_all_steps(self) -> None:
        bounty_steps = set(RECON_PROFILES["bounty"])
        lite_steps = set(RECON_PROFILES["lite"])
        assert lite_steps.issubset(bounty_steps)

    def test_profile_order_matters(self) -> None:
        bounty = RECON_PROFILES["bounty"]
        lite = RECON_PROFILES["lite"]
        # Bounty should have more steps than lite
        assert len(bounty) > len(lite)
