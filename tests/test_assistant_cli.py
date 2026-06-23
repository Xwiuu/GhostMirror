"""Tests for Assistant CLI commands."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest
from typer.testing import CliRunner

from ghostmirror.app.cli import app

runner = CliRunner()


@pytest.fixture()
def mock_context():
    with patch("ghostmirror.app.cli.bootstrap") as mock_boot:
        mock_ctx = MagicMock()
        mock_boot.return_value = mock_ctx
        yield mock_ctx


class TestAssistantCLI:
    def test_assistant_run_help(self):
        result = runner.invoke(app, ["assistant", "run", "--help"])
        assert result.exit_code == 0
        assert "Pentester Assistant" in result.stdout or "assistant" in result.stdout.lower()

    def test_assistant_priorities_help(self):
        result = runner.invoke(app, ["assistant", "priorities", "--help"])
        assert result.exit_code == 0

    def test_assistant_next_steps_help(self):
        result = runner.invoke(app, ["assistant", "next-steps", "--help"])
        assert result.exit_code == 0

    def test_assistant_checklist_help(self):
        result = runner.invoke(app, ["assistant", "checklist", "--help"])
        assert result.exit_code == 0

    def test_assistant_questions_help(self):
        result = runner.invoke(app, ["assistant", "questions", "--help"])
        assert result.exit_code == 0

    def test_analyze_assistant_help(self):
        result = runner.invoke(app, ["analyze", "assistant", "--help"])
        assert result.exit_code == 0

    def test_assistant_run_no_project(self, mock_context):
        mock_context.projects.list_projects.return_value = []
        result = runner.invoke(app, ["assistant", "run"])
        assert result.exit_code == 1

    def test_assistant_priorities_no_data(self, mock_context, tmp_path: Path):
        mock_handle = MagicMock()
        mock_handle.path = tmp_path
        mock_context.projects.list_projects.return_value = [mock_handle]
        mock_context.projects.open_project.return_value = mock_handle
        result = runner.invoke(app, ["assistant", "priorities"])
        assert result.exit_code == 1
