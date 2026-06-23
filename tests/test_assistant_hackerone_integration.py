"""Tests for HackerOne Integration."""

from __future__ import annotations

import pytest

from ghostmirror.models.assistant_context import AssistantContext
from ghostmirror.models.assistant_priority import AssistantPriorities, InvestigationPriority
from ghostmirror.modules.pentester_assistant.hackerone_integration import HackerOneIntegration


class TestHackerOneIntegration:
    def test_no_medium_or_above(self):
        ctx = AssistantContext(target="t", project="p")
        priorities = AssistantPriorities(
            target="t",
            project="p",
            priorities=[
                InvestigationPriority(rank=1, title="Low", category="General", severity="LOW"),
            ],
        )
        integ = HackerOneIntegration()
        guidance = integ.generate_guidance(ctx, priorities)
        assert len(guidance) == 0

    def test_generates_guidance(self):
        ctx = AssistantContext(target="t", project="p")
        priorities = AssistantPriorities(
            target="t",
            project="p",
            priorities=[
                InvestigationPriority(rank=1, title="API Risk", category="API Security", severity="HIGH"),
            ],
        )
        integ = HackerOneIntegration()
        guidance = integ.generate_guidance(ctx, priorities)
        assert len(guidance) == 1
        assert guidance[0]["severity"] == "HIGH"
        assert len(guidance[0]["validation_steps"]) > 0

    def test_confidence_assessment(self):
        ctx = AssistantContext(target="t", project="p")
        priorities = AssistantPriorities(
            target="t",
            project="p",
            priorities=[
                InvestigationPriority(rank=1, title="A", category="General", severity="HIGH", confidence="HIGH"),
                InvestigationPriority(rank=2, title="B", category="General", severity="HIGH", confidence="LOW"),
            ],
        )
        integ = HackerOneIntegration()
        guidance = integ.generate_guidance(ctx, priorities)
        assert "Sufficient" in guidance[0]["confidence_assessment"]
        assert "Needs additional" in guidance[1]["confidence_assessment"]

    def test_additional_evidence_by_category(self):
        ctx = AssistantContext(target="t", project="p")
        priorities = AssistantPriorities(
            target="t",
            project="p",
            priorities=[
                InvestigationPriority(rank=1, title="CVE", category="CVE", severity="CRITICAL"),
            ],
        )
        integ = HackerOneIntegration()
        guidance = integ.generate_guidance(ctx, priorities)
        assert any("patch" in e.lower() for e in guidance[0]["additional_evidence"])
