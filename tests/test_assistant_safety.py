"""Tests for Assistant safety rules."""

from __future__ import annotations

import pytest

from ghostmirror.models.assistant_report import SAFETY_DISCLAIMER
from ghostmirror.modules.pentester_assistant.next_steps_engine import _DENY_KEYWORDS
from ghostmirror.modules.pentester_assistant.risk_narrative import RiskNarrative
from ghostmirror.modules.pentester_assistant.findings_mapper import AssistantFindingsMapper
from ghostmirror.models.assistant_priority import AssistantPriorities, InvestigationPriority
from ghostmirror.models.assistant_context import AssistantContext


class TestSafetyDisclaimer:
    def test_disclaimer_content(self):
        assert "authorized manual review" in SAFETY_DISCLAIMER
        assert "does not confirm exploitation" in SAFETY_DISCLAIMER
        assert "replace professional judgment" in SAFETY_DISCLAIMER


class TestDenyKeywords:
    def test_no_brute_force(self):
        assert "brute force" in _DENY_KEYWORDS

    def test_no_bypass(self):
        assert "bypass" in _DENY_KEYWORDS

    def test_no_dos(self):
        assert "dos" in _DENY_KEYWORDS

    def test_no_destructive(self):
        assert "destructive" in _DENY_KEYWORDS

    def test_no_dump(self):
        assert "dump" in _DENY_KEYWORDS

    def test_no_unauthorized_access(self):
        assert "unauthorized access" in _DENY_KEYWORDS

    def test_no_out_of_scope(self):
        assert "out of scope" in _DENY_KEYWORDS


class TestFindingsMapper:
    def test_findings_are_info_severity(self):
        mapper = AssistantFindingsMapper()
        priorities = AssistantPriorities(
            priorities=[
                InvestigationPriority(rank=1, title="Critical", severity="CRITICAL"),
            ],
        )
        findings = mapper.map_to_findings(priorities)
        assert findings[0]["severity"] == "INFO"

    def test_findings_category(self):
        mapper = AssistantFindingsMapper()
        priorities = AssistantPriorities(
            priorities=[
                InvestigationPriority(rank=1, title="Test", severity="HIGH"),
            ],
        )
        findings = mapper.map_to_findings(priorities)
        assert findings[0]["category"] == "pentest_guidance"

    def test_findings_never_claim_exploitation(self):
        mapper = AssistantFindingsMapper()
        priorities = AssistantPriorities(
            priorities=[
                InvestigationPriority(
                    rank=1, title="Test", severity="HIGH",
                    reason="Potential issue",
                ),
            ],
        )
        findings = mapper.map_to_findings(priorities)
        desc = findings[0]["description"].lower()
        assert "confirmed" not in desc
        assert "exploited" not in desc


class TestZeroDaySafety:
    def test_zero_day_not_confirmed(self):
        ctx = AssistantContext(
            target="t", project="p",
            top_hypotheses=[{"title": "Hypothesis", "score": 50}],
        )
        priorities = AssistantPriorities(
            target="t", project="p",
            priorities=[
                InvestigationPriority(rank=1, title="Hypothesis", category="Zero-Day Hypothesis"),
            ],
        )
        from ghostmirror.modules.pentester_assistant.risk_narrative import RiskNarrative
        narrative = RiskNarrative().generate(ctx, priorities)
        assert "research opportunit" in narrative.lower()
        assert "not confirmed" in narrative.lower()
