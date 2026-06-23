"""Tests for Evidence Reasoner."""

from __future__ import annotations

import pytest

from ghostmirror.models.assistant_context import AssistantContext
from ghostmirror.models.assistant_priority import AssistantPriorities, InvestigationPriority
from ghostmirror.modules.pentester_assistant.evidence_reasoner import EvidenceReasoner


class TestEvidenceReasoner:
    def test_empty_priorities(self):
        ctx = AssistantContext(target="t", project="p")
        priorities = AssistantPriorities(target="t", project="p")
        reasoner = EvidenceReasoner()
        result = reasoner.reason(ctx, priorities)
        assert result.total == 0

    def test_generates_recommendations(self):
        ctx = AssistantContext(target="t", project="p")
        priorities = AssistantPriorities(
            target="t",
            project="p",
            priorities=[
                InvestigationPriority(
                    rank=1, title="Test", category="API Security",
                    severity="HIGH", confidence="HIGH",
                    evidence_refs=["/api/users"],
                ),
            ],
        )
        reasoner = EvidenceReasoner()
        result = reasoner.reason(ctx, priorities)
        assert result.total == 1
        rec = result.recommendations[0]
        assert rec.category == "API Security"
        assert "API Security" in rec.reasoning
        assert len(rec.evidence) == 1

    def test_kev_in_reasoning(self):
        ctx = AssistantContext(target="t", project="p")
        priorities = AssistantPriorities(
            target="t",
            project="p",
            priorities=[
                InvestigationPriority(
                    rank=1, title="KEV", category="CVE",
                    severity="CRITICAL", kev=True,
                ),
            ],
        )
        reasoner = EvidenceReasoner()
        result = reasoner.reason(ctx, priorities)
        assert "KEV" in result.recommendations[0].reasoning

    def test_attack_chain_narrative(self):
        ctx = AssistantContext(target="t", project="p")
        priorities = AssistantPriorities(
            target="t",
            project="p",
            priorities=[
                InvestigationPriority(
                    rank=1, title="Chain", category="Attack Chain",
                    severity="CRITICAL",
                ),
            ],
        )
        reasoner = EvidenceReasoner()
        result = reasoner.reason(ctx, priorities)
        assert "multi-step" in result.recommendations[0].risk_narrative.lower()

    def test_manual_validation_required(self):
        ctx = AssistantContext(target="t", project="p")
        priorities = AssistantPriorities(
            target="t",
            project="p",
            priorities=[
                InvestigationPriority(rank=1, title="Test", category="General"),
            ],
        )
        reasoner = EvidenceReasoner()
        result = reasoner.reason(ctx, priorities)
        assert result.recommendations[0].manual_validation_required is True
