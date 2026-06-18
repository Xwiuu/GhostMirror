from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from ghostmirror.modules.platform.logger import get_current_user, log_audit


class TestPlatformLogger:
    def test_get_current_user(self):
        user = get_current_user()
        assert isinstance(user, str)
        assert len(user) > 0

    def test_get_current_user_fallback(self):
        with patch("getpass.getuser", side_effect=Exception("no user")):
            with patch.dict("os.environ", {}, clear=True):
                user = get_current_user()
                assert user == "unknown"

    def test_get_current_user_env_fallback(self):
        with patch("getpass.getuser", side_effect=Exception("no user")):
            with patch.dict("os.environ", {"USERNAME": "testuser"}):
                user = get_current_user()
                assert user == "testuser"

    def test_log_audit_defaults(self, tmp_path: Path):
        log_file = tmp_path / "audit.log"
        log_file.write_text("", encoding="utf-8")

        with patch("ghostmirror.modules.platform.logger.logger.bind") as mock_bind:
            mock_logger = mock_bind.return_value
            log_audit(
                event="test event",
                project="test-project",
                scanner="test-scanner",
                result="completed",
                user="testuser",
                timestamp="2026-01-01 00:00:00",
            )
            mock_bind.assert_called_once_with(channel="audit")
            mock_logger.info.assert_called_once()

    def test_log_audit_without_timestamp(self):
        with patch("ghostmirror.modules.platform.logger.logger.bind") as mock_bind:
            mock_logger = mock_bind.return_value
            log_audit(
                event="scan started",
                project="proj-x",
                scanner="nmap",
                result="pending",
            )
            mock_bind.assert_called_once_with(channel="audit")
            call_args = mock_logger.info.call_args
            assert call_args is not None
            args, _ = call_args
            assert len(args) >= 2
            # The first arg is the format string, the second is the event value
            assert args[1] == "scan started"
