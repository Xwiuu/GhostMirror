"""Tests for Validation Checklists."""

from __future__ import annotations

import pytest

from ghostmirror.models.assistant_context import AssistantContext
from ghostmirror.models.assistant_priority import AssistantPriorities, InvestigationPriority
from ghostmirror.modules.pentester_assistant.validation_checklists import (
    ValidationChecklistGenerator,
    _detect_types,
)


class TestDetectTypes:
    def test_detects_bola(self):
        ctx = AssistantContext(
            top_findings=[{"title": "BOLA vulnerability", "category": "bola"}],
        )
        priorities = AssistantPriorities()
        types = _detect_types(ctx, priorities)
        assert "BOLA" in types

    def test_detects_xss(self):
        ctx = AssistantContext(
            top_findings=[{"title": "Cross-Site Scripting", "category": "xss"}],
        )
        priorities = AssistantPriorities()
        types = _detect_types(ctx, priorities)
        assert "XSS" in types

    def test_detects_cve(self):
        ctx = AssistantContext(
            top_findings=[{"title": "CVE-2024-1234", "category": "cve"}],
        )
        priorities = AssistantPriorities()
        types = _detect_types(ctx, priorities)
        assert "CVE" in types

    def test_detects_zero_day(self):
        ctx = AssistantContext()
        priorities = AssistantPriorities(
            priorities=[
                InvestigationPriority(title="Zero-Day Hypothesis", category="Zero-Day Hypothesis"),
            ],
        )
        types = _detect_types(ctx, priorities)
        assert "Zero-Day" in types

    def test_detects_auth(self):
        ctx = AssistantContext(
            top_findings=[{"title": "JWT weakness", "category": "auth"}],
        )
        priorities = AssistantPriorities()
        types = _detect_types(ctx, priorities)
        assert "Auth" in types

    def test_defaults_to_web_security(self):
        ctx = AssistantContext()
        priorities = AssistantPriorities()
        types = _detect_types(ctx, priorities)
        assert "WebSecurity" in types


class TestValidationChecklistGenerator:
    def test_empty_context(self):
        ctx = AssistantContext(target="t", project="p")
        priorities = AssistantPriorities(target="t", project="p")
        gen = ValidationChecklistGenerator()
        result = gen.generate(ctx, priorities)
        assert result.total_checklists >= 1

    def test_generates_bola_checklist(self):
        ctx = AssistantContext(
            top_findings=[{"title": "BOLA", "category": "bola"}],
        )
        priorities = AssistantPriorities()
        gen = ValidationChecklistGenerator()
        result = gen.generate(ctx, priorities)
        bola = [cl for cl in result.checklists if cl.vulnerability_type == "BOLA"]
        assert len(bola) == 1
        assert bola[0].total_items >= 4

    def test_checklist_items_have_safety_notes(self):
        ctx = AssistantContext(
            top_findings=[{"title": "BOLA", "category": "bola"}],
        )
        priorities = AssistantPriorities()
        gen = ValidationChecklistGenerator()
        result = gen.generate(ctx, priorities)
        bola = [cl for cl in result.checklists if cl.vulnerability_type == "BOLA"][0]
        safety_items = [item for item in bola.items if item.safety_note is not None]
        assert len(safety_items) >= 2

    def test_xss_checklist(self):
        ctx = AssistantContext(
            top_findings=[{"title": "XSS", "category": "xss"}],
        )
        priorities = AssistantPriorities()
        gen = ValidationChecklistGenerator()
        result = gen.generate(ctx, priorities)
        xss = [cl for cl in result.checklists if cl.vulnerability_type == "XSS"]
        assert len(xss) == 1
