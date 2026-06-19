from __future__ import annotations

import pytest

from ghostmirror.modules.web_intelligence.auth_intelligence import AuthIntelligence
from ghostmirror.models.web_endpoint import WebEndpoint


class TestAuthIntelligence:
    @pytest.fixture
    def auth_intel(self):
        return AuthIntelligence()

    def test_detect_login_endpoint(self, auth_intel):
        endpoints = [WebEndpoint(url="https://example.com/login")]
        profile = auth_intel.analyze(endpoints)
        assert profile["has_login"] is True
        assert "https://example.com/login" in profile["login_endpoints"]

    def test_detect_register_endpoint(self, auth_intel):
        endpoints = [WebEndpoint(url="https://example.com/register")]
        profile = auth_intel.analyze(endpoints)
        assert profile["has_register"] is True

    def test_detect_reset_password(self, auth_intel):
        endpoints = [WebEndpoint(url="https://example.com/reset-password")]
        profile = auth_intel.analyze(endpoints)
        assert profile["has_reset_password"] is True

    def test_detect_admin_panel(self, auth_intel):
        endpoints = [WebEndpoint(url="https://example.com/admin")]
        profile = auth_intel.analyze(endpoints)
        assert profile["has_admin"] is True

    def test_detect_mfa(self, auth_intel):
        endpoints = [WebEndpoint(url="https://example.com/2fa")]
        profile = auth_intel.analyze(endpoints)
        assert profile["has_mfa"] is True

    def test_empty_endpoints(self, auth_intel):
        profile = auth_intel.analyze([])
        assert profile["total_auth_endpoints"] == 0
        assert profile["has_login"] is False
        assert profile["has_admin"] is False

    def test_multiple_auth_endpoints(self, auth_intel):
        endpoints = [
            WebEndpoint(url="https://example.com/login"),
            WebEndpoint(url="https://example.com/register"),
            WebEndpoint(url="https://example.com/admin/dashboard"),
            WebEndpoint(url="https://example.com/profile"),
        ]
        profile = auth_intel.analyze(endpoints)
        assert profile["total_auth_endpoints"] >= 3

    def test_session_cookies_from_headers(self, auth_intel):
        endpoints = []
        headers = {"Set-Cookie": "sessionid=abc123; Path=/"}
        profile = auth_intel.analyze(endpoints, headers)
        assert len(profile["session_cookies_detected"]) > 0

    def test_no_false_positives(self, auth_intel):
        endpoints = [
            WebEndpoint(url="https://example.com/blog"),
            WebEndpoint(url="https://example.com/about"),
            WebEndpoint(url="https://example.com/contact"),
        ]
        profile = auth_intel.analyze(endpoints)
        assert profile["total_auth_endpoints"] == 0
        assert profile["has_login"] is False
        assert profile["has_admin"] is False

    def test_auth_flag_from_is_auth(self, auth_intel):
        endpoints = [WebEndpoint(url="https://example.com/signin", is_auth=True)]
        profile = auth_intel.analyze(endpoints)
        assert profile["login_endpoints"]  # Should match due to 'signin' in url

    def test_profile_detection(self, auth_intel):
        endpoints = [WebEndpoint(url="https://example.com/account/settings")]
        profile = auth_intel.analyze(endpoints)
        assert len(profile["profile_endpoints"]) > 0

    def test_pt_br_auth_patterns(self, auth_intel):
        endpoints = [
            WebEndpoint(url="https://example.com/cadastro"),
            WebEndpoint(url="https://example.com/painel"),
        ]
        profile = auth_intel.analyze(endpoints)
        assert profile["has_register"] is True
        assert profile["has_admin"] is True
