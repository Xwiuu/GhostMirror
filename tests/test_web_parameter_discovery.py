from __future__ import annotations

import pytest

from ghostmirror.modules.web_intelligence.parameter_discovery import ParameterDiscovery
from ghostmirror.models.parameter_profile import ParameterProfile, ParameterType, ParameterSensitivity
from ghostmirror.models.web_endpoint import WebEndpoint, WebForm


class TestParameterDiscovery:
    @pytest.fixture
    def discovery(self):
        return ParameterDiscovery()

    def test_extract_query_params(self, discovery):
        endpoints = [
            WebEndpoint(
                url="https://example.com/search?q=hello&page=2",
                params=["q", "page"],
            )
        ]

        profiles = discovery.discover(endpoints)
        assert len(profiles) == 2

        param_names = {p.name for p in profiles}
        assert "q" in param_names
        assert "page" in param_names

    def test_extract_form_params(self, discovery):
        endpoints = [
            WebEndpoint(
                url="https://example.com/login",
                params=[],
                forms=[WebForm(action="/login", method="POST", inputs=["username", "password"])],
                response_body_sample='<input name="username"><input name="password">',
            )
        ]

        profiles = discovery.discover(endpoints)
        assert len(profiles) == 2

        param_names = {p.name for p in profiles}
        assert "username" in param_names
        assert "password" in param_names

    def test_sensitive_param_detection(self, discovery):
        endpoints = [
            WebEndpoint(
                url="https://example.com/admin?token=abc123&redirect=/home&file=report.pdf",
                params=["token", "redirect", "file"],
            )
        ]

        profiles = discovery.discover(endpoints)
        names_map = {p.name: p for p in profiles}

        assert names_map["token"].sensitivity == ParameterSensitivity.CRITICAL
        assert names_map["redirect"].sensitivity == ParameterSensitivity.HIGH
        assert names_map["file"].sensitivity == ParameterSensitivity.HIGH

    def test_duplicate_params_dedup(self, discovery):
        endpoints = [
            WebEndpoint(url="https://example.com/page?q=hello", params=["q"]),
            WebEndpoint(url="https://example.com/other?q=world", params=["q"]),
        ]

        profiles = discovery.discover(endpoints)
        assert len(profiles) == 1
        assert len(profiles[0].locations) == 2

    def test_classify_sensitivity(self):
        assert ParameterProfile.classify_sensitivity("token") == ParameterSensitivity.CRITICAL
        assert ParameterProfile.classify_sensitivity("id") == ParameterSensitivity.HIGH
        assert ParameterProfile.classify_sensitivity("page") == ParameterSensitivity.MEDIUM
        assert ParameterProfile.classify_sensitivity("unknown_param") == ParameterSensitivity.NONE

    def test_extract_form_params_from_html(self, discovery):
        endpoints = [
            WebEndpoint(
                url="https://example.com/register",
                params=[],
                response_body_sample="""
                    <input name="email">
                    <textarea name="bio"></textarea>
                    <select name="country"></select>
                """,
            )
        ]

        profiles = discovery.discover(endpoints)
        param_names = {p.name for p in profiles}
        assert "email" in param_names
        assert "bio" in param_names
        assert "country" in param_names
