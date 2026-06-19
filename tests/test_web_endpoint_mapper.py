from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from ghostmirror.modules.web_intelligence.endpoint_mapper import EndpointMapper


class TestEndpointMapper:
    @pytest.fixture
    def mapper(self):
        return EndpointMapper(max_depth=1)

    def test_parse_endpoint_with_query_params(self, mapper):
        mock_resp = MagicMock()
        mock_resp.text = "<html><body>Test</body></html>"
        mock_resp.status_code = 200
        mock_resp.headers = {"content-type": "text/html", "server": "nginx"}
        mock_resp.url = "https://example.com/page?q=hello&id=42"

        ep = mapper._parse_endpoint(
            "https://example.com/page?q=hello&id=42",
            mock_resp,
            mock_resp.text,
            "https://example.com",
        )

        assert ep.url == "https://example.com/page?q=hello&id=42"
        assert "q" in ep.params
        assert "id" in ep.params
        assert ep.status_code == 200
        assert "nginx" in ep.tech_hints

    def test_parse_endpoint_with_forms(self, mapper):
        html = """
        <html>
        <form action="/login" method="POST">
            <input name="username">
            <input name="password">
        </form>
        </html>
        """
        mock_resp = MagicMock()
        mock_resp.text = html
        mock_resp.status_code = 200
        mock_resp.headers = {}

        ep = mapper._parse_endpoint(
            "https://example.com/",
            mock_resp,
            html,
            "https://example.com",
        )

        assert len(ep.forms) > 0
        assert ep.forms[0].action.endswith("/login")

    def test_auth_endpoint_detection(self, mapper):
        html = "<html>Login Page</html>"
        mock_resp = MagicMock()
        mock_resp.text = html
        mock_resp.status_code = 200
        mock_resp.headers = {}

        ep = mapper._parse_endpoint(
            "https://example.com/login",
            mock_resp,
            html,
            "https://example.com",
        )

        assert ep.is_auth is True
        assert ep.is_api is False

    def test_api_endpoint_detection(self, mapper):
        html = "<html>API</html>"
        mock_resp = MagicMock()
        mock_resp.text = html
        mock_resp.status_code = 200
        mock_resp.headers = {}

        ep = mapper._parse_endpoint(
            "https://example.com/api/users",
            mock_resp,
            html,
            "https://example.com",
        )

        assert ep.is_api is True

    def test_is_same_origin(self, mapper):
        mapper._base = "https://example.com"
        assert mapper._is_same_origin("https://example.com/page") is True
        assert mapper._is_same_origin("https://other.com/page") is False

    def test_is_static(self, mapper):
        assert mapper._is_static("https://example.com/style.css") is True
        assert mapper._is_static("https://example.com/script.js") is True
        assert mapper._is_static("https://example.com/page.html") is False
        assert mapper._is_static("/api/users") is False

    def test_get_script_urls(self, mapper):
        html = '<html><script src="/app.js"></script><script src="https://cdn.com/lib.js"></script></html>'
        urls = mapper.get_script_urls(html, "https://example.com")

        assert any("app.js" in u for u in urls)
        assert any("cdn.com" in u for u in urls)

    @patch("httpx.Client")
    def test_discover_empty_handles_errors(self, mock_client, mapper):
        mock_instance = MagicMock()
        mock_client.return_value.__enter__.return_value = mock_instance
        mock_instance.get.side_effect = Exception("Connection error")

        endpoints = mapper.discover("https://example.com")
        assert isinstance(endpoints, list)

    def test_parse_endpoint_admin_detection(self, mapper):
        html = "<html>Admin Panel</html>"
        mock_resp = MagicMock()
        mock_resp.text = html
        mock_resp.status_code = 200
        mock_resp.headers = {}

        ep = mapper._parse_endpoint(
            "https://example.com/admin/dashboard",
            mock_resp,
            html,
            "https://example.com",
        )

        assert ep.is_admin is True


class TestWebForm:
    def test_form_defaults(self):
        from ghostmirror.models.web_endpoint import WebForm
        form = WebForm()
        assert form.action == ""
        assert form.method == "GET"
        assert form.inputs == []


class TestHttpMethod:
    def test_enum_values(self):
        from ghostmirror.models.web_endpoint import HttpMethod
        assert HttpMethod.GET.value == "GET"
        assert HttpMethod.POST.value == "POST"
