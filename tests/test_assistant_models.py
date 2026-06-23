"""Tests for Pentester Assistant models."""

from __future__ import annotations

from datetime import datetime, timezone

from ghostmirror.models.assistant_context import AssistantContext
from ghostmirror.models.assistant_priority import AssistantPriorities, InvestigationPriority
from ghostmirror.models.investigation_task import InvestigationTask, InvestigationPlan
from ghostmirror.models.validation_checklist import (
    AssistantChecklists,
    ChecklistItem,
    ValidationChecklist,
)
from ghostmirror.models.pentest_question import AssistantQuestions, PentestQuestion
from ghostmirror.models.assistant_recommendation import (
    AssistantRecommendation,
    AssistantRecommendations,
)
from ghostmirror.models.assistant_report import AssistantReport, SAFETY_DISCLAIMER


class TestAssistantContext:
    def test_default(self):
        ctx = AssistantContext()
        assert ctx.target == ""
        assert ctx.project == ""
        assert ctx.total_sources_loaded == 0
        assert ctx.top_findings == []

    def test_with_data(self):
        ctx = AssistantContext(
            target="example.com",
            project="test-proj",
            top_findings=[{"title": "XSS", "severity": "HIGH"}],
            total_sources_loaded=5,
        )
        assert ctx.target == "example.com"
        assert len(ctx.top_findings) == 1
        assert ctx.total_sources_loaded == 5

    def test_serialization(self):
        ctx = AssistantContext(target="t", project="p", total_sources_loaded=3)
        data = ctx.model_dump(mode="json")
        assert data["target"] == "t"
        restored = AssistantContext.model_validate(data)
        assert restored.total_sources_loaded == 3


class TestInvestigationPriority:
    def test_default(self):
        p = InvestigationPriority()
        assert p.rank == 0
        assert p.severity == "INFO"
        assert p.kev is False

    def test_with_data(self):
        p = InvestigationPriority(
            rank=1,
            title="Test",
            category="API Security",
            severity="HIGH",
            confidence="HIGH",
            kev=True,
            epss=0.75,
            evidence_refs=["/api/users"],
            next_steps=["Step 1"],
        )
        assert p.rank == 1
        assert p.kev is True
        assert p.epss == 0.75
        assert len(p.evidence_refs) == 1


class TestAssistantPriorities:
    def test_default(self):
        ap = AssistantPriorities()
        assert ap.total_priorities == 0
        assert ap.priorities == []

    def test_serialization(self):
        ap = AssistantPriorities(
            target="t",
            project="p",
            priorities=[
                InvestigationPriority(rank=1, title="T1", category="API"),
            ],
            total_priorities=1,
        )
        data = ap.model_dump(mode="json")
        assert data["total_priorities"] == 1
        restored = AssistantPriorities.model_validate(data)
        assert len(restored.priorities) == 1


class TestInvestigationTask:
    def test_default(self):
        t = InvestigationTask()
        assert t.id == ""
        assert t.priority == "P3"

    def test_with_data(self):
        t = InvestigationTask(
            id="t-1",
            title="Review API",
            task_type="API Security Review",
            steps=["Step 1", "Step 2"],
            safety_notes=["Use authorized accounts"],
        )
        assert len(t.steps) == 2
        assert len(t.safety_notes) == 1


class TestInvestigationPlan:
    def test_default(self):
        plan = InvestigationPlan()
        assert plan.total_tasks == 0


class TestChecklistItem:
    def test_default(self):
        ci = ChecklistItem()
        assert ci.step == 0
        assert ci.safety_note is None

    def test_with_safety(self):
        ci = ChecklistItem(step=1, instruction="Do X", safety_note="Be careful")
        assert ci.safety_note == "Be careful"


class TestValidationChecklist:
    def test_default(self):
        vc = ValidationChecklist()
        assert vc.total_items == 0


class TestAssistantChecklists:
    def test_default(self):
        ac = AssistantChecklists()
        assert ac.total_checklists == 0


class TestPentestQuestion:
    def test_default(self):
        q = PentestQuestion()
        assert q.id == ""
        assert q.priority == "P3"


class TestAssistantQuestions:
    def test_default(self):
        aq = AssistantQuestions()
        assert aq.total_questions == 0


class TestAssistantRecommendation:
    def test_default(self):
        r = AssistantRecommendation()
        assert r.manual_validation_required is True


class TestAssistantRecommendations:
    def test_default(self):
        ar = AssistantRecommendations()
        assert ar.total == 0


class TestAssistantReport:
    def test_default(self):
        r = AssistantReport()
        assert r.total_priorities == 0
        assert r.safety_disclaimer == SAFETY_DISCLAIMER

    def test_safety_disclaimer_constant(self):
        assert "authorized manual review" in SAFETY_DISCLAIMER
        assert "does not confirm exploitation" in SAFETY_DISCLAIMER

    def test_serialization(self):
        r = AssistantReport(
            target="t",
            project="p",
            priorities=[{"rank": 1}],
            next_steps=["Step 1"],
            total_priorities=1,
        )
        data = r.model_dump(mode="json")
        assert data["total_priorities"] == 1
        assert len(data["next_steps"]) == 1
