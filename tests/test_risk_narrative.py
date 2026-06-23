"""Tests for Risk Narrative."""

from __future__ import annotations

import pytest

from ghostmirror.models.assistant_context import AssistantContext
from ghostmirror.models.assistant_priority import AssistantPriorities, InvestigationPriority
from ghostmirror.modules.pentester_assistant.risk_narrative import RiskNarrative


class TestRiskNarrative:
    def test_empty_priorities(self):
        ctx = AssistantContext(target="t", project="p")
        priorities = AssistantPriorities(target="t", project="p")
        gen = RiskNarrative()
        narrative = gen.generate(ctx, priorities)
        assert "No significant" in narrative

    def test_includes_categories(self):
        ctx = AssistantContext(target="t", project="p")
        priorities = AssistantPriorities(
            target="t",
            project="p",
            priorities=[
                InvestigationPriority(rank=1, title="API", category="API Security", severity="HIGH"),
                InvestigationPriority(rank=2, title="Chain", category="Attack Chain", severity="CRITICAL"),
            ],
        )
        gen = RiskNarrative()
        narrative = gen.generate(ctx, priorities)
        assert "API" in narrative
        assert "Attack Chain" in narrative

    def test_counts_crit_high(self):
        ctx = AssistantContext(target="t", project="p")
        priorities = AssistantPriorities(
            target="t",
            project="p",
            priorities=[
                InvestigationPriority(rank=1, title="A", category="General", severity="CRITICAL"),
                InvestigationPriority(rank=2, title="B", category="General", severity="HIGH"),
                InvestigationPriority(rank=3, title="C", category="General", severity="LOW"),
            ],
        )
        gen = RiskNarrative()
        narrative = gen.generate(ctx, priorities)
        assert "2" in narrative

    def test_mentions_manual_validation(self):
        ctx = AssistantContext(target="t", project="p")
        priorities = AssistantPriorities(
            target="t",
            project="p",
            priorities=[
                InvestigationPriority(rank=1, title="Test", category="General"),
            ],
        )
        gen = RiskNarrative()
        narrative = gen.generate(ctx, priorities)
        assert "manual validation" in narrative.lower()

    def test_zero_day_mention(self):
        ctx = AssistantContext(target="t", project="p")
        priorities = AssistantPriorities(
            target="t",
            project="p",
            priorities=[
                InvestigationPriority(rank=1, title="Hypothesis", category="Zero-Day Hypothesis"),
            ],
        )
        gen = RiskNarrative()
        narrative = gen.generate(ctx, priorities)
        assert "research opportunit" in narrative.lower()
        assert "not confirmed" in narrative.lower()
