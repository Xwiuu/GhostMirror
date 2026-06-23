"""Tests for Triage Engine."""

from __future__ import annotations

import pytest

from ghostmirror.models.assistant_context import AssistantContext
from ghostmirror.modules.pentester_assistant.triage_engine import TriageEngine


class TestTriageEngine:
    def test_empty_context(self):
        ctx = AssistantContext(target="t", project="p")
        engine = TriageEngine()
        result = engine.triage(ctx)
        assert result.total_priorities == 0
        assert "No investigation areas" in result.summary

    def test_triage_findings(self):
        ctx = AssistantContext(
            target="t",
            project="p",
            top_findings=[
                {"title": "XSS", "severity": "HIGH", "confidence": "HIGH", "priority": "P1"},
                {"title": "Info", "severity": "INFO", "confidence": "LOW", "priority": "P5"},
            ],
        )
        engine = TriageEngine()
        result = engine.triage(ctx)
        assert result.total_priorities == 2
        assert result.priorities[0].severity == "HIGH"
        assert result.priorities[1].severity == "INFO"

    def test_triage_cves(self):
        ctx = AssistantContext(
            target="t",
            project="p",
            top_cves=[{"cve": "CVE-2024-1234", "risk_score": 95}],
        )
        engine = TriageEngine()
        result = engine.triage(ctx)
        assert result.total_priorities == 1
        assert result.priorities[0].category == "CVE"

    def test_triage_attack_chains(self):
        ctx = AssistantContext(
            target="t",
            project="p",
            top_attack_chains=[{"title": "Chain 1", "score": 85}],
        )
        engine = TriageEngine()
        result = engine.triage(ctx)
        assert result.priorities[0].category == "Attack Chain"

    def test_triage_zero_day(self):
        ctx = AssistantContext(
            target="t",
            project="p",
            top_hypotheses=[{"title": "Hypothesis 1", "score": 60}],
        )
        engine = TriageEngine()
        result = engine.triage(ctx)
        assert result.priorities[0].category == "Zero-Day Hypothesis"

    def test_triage_api_risks(self):
        ctx = AssistantContext(
            target="t",
            project="p",
            top_api_risks=[{"type": "BOLA", "severity": "HIGH"}],
        )
        engine = TriageEngine()
        result = engine.triage(ctx)
        assert result.priorities[0].category == "API Security"

    def test_kev_bonus(self):
        ctx = AssistantContext(
            target="t",
            project="p",
            top_findings=[
                {"title": "With KEV", "severity": "HIGH", "kev": True, "confidence": "HIGH"},
                {"title": "Without KEV", "severity": "HIGH", "kev": False, "confidence": "HIGH"},
            ],
        )
        engine = TriageEngine()
        result = engine.triage(ctx)
        assert result.priorities[0].kev is True

    def test_evidence_refs(self):
        ctx = AssistantContext(
            target="t",
            project="p",
            top_findings=[
                {"title": "Finding", "severity": "HIGH", "evidence": "/api/test", "endpoint": "/api/test"},
            ],
        )
        engine = TriageEngine()
        result = engine.triage(ctx)
        assert len(result.priorities[0].evidence_refs) >= 1

    def test_next_steps_assigned(self):
        ctx = AssistantContext(
            target="t",
            project="p",
            top_findings=[{"title": "XSS", "severity": "HIGH", "category": "xss"}],
        )
        engine = TriageEngine()
        result = engine.triage(ctx)
        assert len(result.priorities[0].next_steps) >= 1
