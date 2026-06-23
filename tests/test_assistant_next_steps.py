"""Tests for Next Steps Engine."""

from __future__ import annotations

import pytest

from ghostmirror.models.assistant_context import AssistantContext
from ghostmirror.models.assistant_priority import AssistantPriorities, InvestigationPriority
from ghostmirror.modules.pentester_assistant.next_steps_engine import NextStepsEngine, _DENY_KEYWORDS


class TestNextStepsEngine:
    def test_empty_priorities(self):
        ctx = AssistantContext(target="t", project="p")
        priorities = AssistantPriorities(target="t", project="p")
        engine = NextStepsEngine()
        steps = engine.generate(ctx, priorities)
        assert len(steps) >= 1

    def test_generates_safe_steps(self):
        ctx = AssistantContext(target="t", project="p")
        priorities = AssistantPriorities(
            target="t",
            project="p",
            priorities=[
                InvestigationPriority(rank=1, title="API Risk", category="API Security"),
                InvestigationPriority(rank=2, title="CVE", category="CVE"),
            ],
        )
        engine = NextStepsEngine()
        steps = engine.generate(ctx, priorities)
        assert len(steps) > 0
        for step in steps:
            assert "brute force" not in step.lower()
            assert "bypass" not in step.lower()
            assert "dos" not in step.lower()

    def test_deny_keywords(self):
        assert "brute force" in _DENY_KEYWORDS
        assert "bypass" in _DENY_KEYWORDS
        assert "dos" in _DENY_KEYWORDS
        assert "destructive" in _DENY_KEYWORDS
        assert "dump" in _DENY_KEYWORDS

    def test_no_denied_steps_generated(self):
        ctx = AssistantContext(target="t", project="p")
        priorities = AssistantPriorities(
            target="t",
            project="p",
            priorities=[
                InvestigationPriority(rank=1, title="Test", category="General"),
            ],
        )
        engine = NextStepsEngine()
        steps = engine.generate(ctx, priorities)
        for step in steps:
            lower = step.lower()
            for kw in _DENY_KEYWORDS:
                assert kw not in lower, f"Denied keyword '{kw}' found in step: {step}"

    def test_attack_chain_steps(self):
        ctx = AssistantContext(target="t", project="p")
        priorities = AssistantPriorities(
            target="t",
            project="p",
            priorities=[
                InvestigationPriority(rank=1, title="Chain", category="Attack Chain"),
            ],
        )
        engine = NextStepsEngine()
        steps = engine.generate(ctx, priorities)
        assert any("attack chain" in s.lower() or "chain" in s.lower() for s in steps)
