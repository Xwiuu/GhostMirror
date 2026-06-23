"""Tests for Pipeline Integration — pentester_assistant step."""

from __future__ import annotations

import pytest

from ghostmirror.modules.orchestrator.pipeline import (
    PIPELINE_PROFILES,
    get_pipeline_steps,
)
from ghostmirror.modules.orchestrator.full_scan import STEP_DEPENDENCIES


class TestPipelineIntegration:
    def test_pentester_assistant_in_standard(self):
        steps = get_pipeline_steps("standard")
        assert "pentester_assistant" in steps
        assert steps.index("pentester_assistant") > steps.index("attack_chain")
        assert steps.index("pentester_assistant") < steps.index("report")

    def test_pentester_assistant_in_deep(self):
        steps = get_pipeline_steps("deep")
        assert "pentester_assistant" in steps
        assert steps.index("pentester_assistant") > steps.index("attack_chain")

    def test_pentester_assistant_in_bounty(self):
        steps = get_pipeline_steps("bounty")
        assert "pentester_assistant" in steps
        assert steps.index("pentester_assistant") > steps.index("attack_chain")

    def test_not_in_quick(self):
        steps = get_pipeline_steps("quick")
        assert "pentester_assistant" not in steps

    def test_step_dependencies(self):
        assert "pentester_assistant" in STEP_DEPENDENCIES
        assert STEP_DEPENDENCIES["pentester_assistant"] == ["attack_chain"]
