from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from ghostmirror.modules.bug_bounty.interesting_files import InterestingFiles
from ghostmirror.modules.bug_bounty.scope_guard import BountyScopeGuard


class TestInterestingFiles:
    @pytest.fixture
    def checker(self) -> InterestingFiles:
        return InterestingFiles()

    def test_init(self, checker: InterestingFiles) -> None:
        assert checker._findings == []
        assert checker._results == []

    @patch("httpx.Client")
    def test_check_all_not_found(self, mock_client: MagicMock, checker: InterestingFiles) -> None:
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_resp.headers = {"content-type": "text/html"}
        mock_resp.content = b""

        mock_client_instance = MagicMock()
        mock_client_instance.__enter__.return_value = mock_client_instance
        mock_client_instance.get.return_value = mock_resp
        mock_client.return_value = mock_client_instance

        results = checker.check("https://example.com")
        found = [r for r in results if r["found"]]
        assert len(found) == 0

    @patch("httpx.Client")
    def test_check_robots_found(self, mock_client: MagicMock, checker: InterestingFiles) -> None:
        def mock_get(url: str, **kwargs):
            resp = MagicMock()
            if "robots.txt" in url:
                resp.status_code = 200
                resp.headers = {"content-type": "text/plain"}
                resp.content = b"User-agent: *\nDisallow: /admin"
            else:
                resp.status_code = 404
                resp.headers = {"content-type": "text/html"}
                resp.content = b""
            return resp

        mock_client_instance = MagicMock()
        mock_client_instance.__enter__.return_value = mock_client_instance
        mock_client_instance.get.side_effect = mock_get
        mock_client.return_value = mock_client_instance

        results = checker.check("https://example.com")
        robots = [r for r in results if r["path"] == "/robots.txt"]
        assert len(robots) == 1
        assert robots[0]["found"] is True

    @patch("httpx.Client")
    def test_check_sensitive_file_high_severity(self, mock_client: MagicMock, checker: InterestingFiles) -> None:
        def mock_get(url: str, **kwargs):
            resp = MagicMock()
            resp.status_code = 200
            resp.headers = {"content-type": "text/plain"}
            resp.content = b"sensitive content"
            return resp

        mock_client_instance = MagicMock()
        mock_client_instance.__enter__.return_value = mock_client_instance
        mock_client_instance.get.side_effect = mock_get
        mock_client.return_value = mock_client_instance

        results = checker.check("https://example.com")
        env = [r for r in results if r["path"] == "/.env"]
        assert len(env) == 1
        assert env[0]["found"] is True

    @patch("httpx.Client")
    def test_check_with_scope_guard(self, mock_client: MagicMock, checker: InterestingFiles) -> None:
        scope_guard = MagicMock(spec=BountyScopeGuard)
        scope_guard.enforce_scope.return_value = None
        scope_guard.check_rate_limit.return_value = None

        mock_resp = MagicMock()
        mock_resp.status_code = 404
        mock_resp.headers = {"content-type": "text/html"}
        mock_resp.content = b""

        mock_client_instance = MagicMock()
        mock_client_instance.__enter__.return_value = mock_client_instance
        mock_client_instance.get.return_value = mock_resp
        mock_client.return_value = mock_client_instance

        checker.check("https://example.com", scope_guard)
        assert scope_guard.enforce_scope.called
        assert scope_guard.check_rate_limit.called

    @patch("httpx.Client")
    def test_check_scope_guard_blocks(self, mock_client: MagicMock, checker: InterestingFiles) -> None:
        scope_guard = MagicMock(spec=BountyScopeGuard)
        scope_guard.enforce_scope.side_effect = Exception("Out of scope")

        mock_client_instance = MagicMock()
        mock_client_instance.__enter__.return_value = mock_client_instance
        mock_client.return_value = mock_client_instance

        checker.check("https://example.com", scope_guard)
        assert mock_client_instance.get.call_count == 0

    @patch("httpx.Client")
    def test_findings_generated(self, mock_client: MagicMock, checker: InterestingFiles) -> None:
        def mock_get(url: str, **kwargs):
            resp = MagicMock()
            resp.status_code = 200
            resp.headers = {"content-type": "text/plain"}
            resp.content = b"data"
            return resp

        mock_client_instance = MagicMock()
        mock_client_instance.__enter__.return_value = mock_client_instance
        mock_client_instance.get.side_effect = mock_get
        mock_client.return_value = mock_client_instance

        checker.check("https://example.com")
        findings = checker.get_findings()
        assert len(findings) >= 1
        assert findings[0].category == "bug_bounty_interesting_file"

    def test_interesting_paths_defined(self, checker: InterestingFiles) -> None:
        from ghostmirror.modules.bug_bounty.interesting_files import INTERESTING_PATHS
        assert "/.well-known/security.txt" in INTERESTING_PATHS
        assert "/robots.txt" in INTERESTING_PATHS
        assert "/.env" in INTERESTING_PATHS
        assert "/.git/config" in INTERESTING_PATHS
        assert "/backup.zip" in INTERESTING_PATHS
