"""Tests for Report Builder."""

from __future__ import annotations

from pathlib import Path

import pytest

from ghostmirror.models.assistant_context import AssistantContext
from ghostmirror.models.assistant_priority import AssistantPriorities, InvestigationPriority
from ghostmirror.models.investigation_task import InvestigationPlan, InvestigationTask
from ghostmirror.models.validation_checklist import AssistantChecklists, ValidationChecklist, ChecklistItem
from ghostmirror.models.pentest_question import AssistantQuestions, PentestQuestion
from ghostmirror.models.assistant_recommendation import AssistantRecommendations, AssistantRecommendation
from ghostmirror.modules.pentester_assistant.report_builder import AssistantReportBuilder


@pytest.fixture()
def full_report():
    ctx = AssistantContext(
        target="target.com", project="test-proj",
        top_findings=[{"title": "XSS"}],
        top_hypotheses=[{"title": "Hypothesis"}],
        top_attack_chains=[{"title": "Chain"}],
        total_sources_loaded=5,
    )
    priorities = AssistantPriorities(
        target="target.com", project="test-proj",
        priorities=[
            InvestigationPriority(rank=1, title="API Risk", category="API Security", severity="HIGH"),
        ],
        total_priorities=1,
    )
    plan = InvestigationPlan(
        tasks=[InvestigationTask(id="t-1", title="Review API", task_type="API Security Review")],
        total_tasks=1,
    )
    checklists = AssistantChecklists(
        checklists=[ValidationChecklist(id="cl-1", title="BOLA", vulnerability_type="BOLA",
                                         items=[ChecklistItem(step=1, instruction="Do X")])],
        total_checklists=1,
    )
    questions = AssistantQuestions(
        questions=[PentestQuestion(id="q-1", question="Is auth required?", category="API Security")],
        total_questions=1,
    )
    recs = AssistantRecommendations(
        recommendations=[AssistantRecommendation(id="r-1", title="Review API", category="API Security")],
        total=1,
    )
    builder = AssistantReportBuilder()
    return builder.build(
        context=ctx,
        priorities=priorities,
        next_steps=["Step 1", "Step 2"],
        plan=plan,
        checklists=checklists,
        questions=questions,
        recommendations=recs,
        risk_narrative="High risk area identified.",
        hackerone_guidance=[{"title": "API Risk", "severity": "HIGH"}],
    )


class TestReportBuilder:
    def test_report_structure(self, full_report):
        assert full_report.target == "target.com"
        assert full_report.total_priorities == 1
        assert full_report.total_tasks == 1
        assert full_report.total_checklists == 1
        assert full_report.total_questions == 1
        assert len(full_report.next_steps) == 2

    def test_safety_disclaimer(self, full_report):
        assert "authorized manual review" in full_report.safety_disclaimer

    def test_zero_day_notes(self, full_report):
        assert len(full_report.zero_day_notes) == 1
        assert "research opportunity" in full_report.zero_day_notes[0]["status"].lower()

    def test_executive_summary(self, full_report):
        assert "5 intelligence sources" in full_report.executive_summary

    def test_save(self, full_report, tmp_path: Path):
        builder = AssistantReportBuilder()
        builder.save(tmp_path, full_report)
        assert (tmp_path / "profiles" / "assistant" / "assistant_report.json").exists()
        assert (tmp_path / "profiles" / "assistant" / "assistant_priorities.json").exists()
        assert (tmp_path / "reports" / "assistant_report.md").exists()
        assert (tmp_path / "reports" / "assistant_report.html").exists()

    def test_markdown_content(self, full_report):
        builder = AssistantReportBuilder()
        md = builder._render_markdown(full_report)
        assert "Pentester Assistant Report" in md
        assert "authorized manual review" in md
        assert "API Risk" in md

    def test_html_content(self, full_report):
        builder = AssistantReportBuilder()
        html = builder._render_html(full_report)
        assert "Pentester Assistant Report" in html
        assert "authorized manual review" in html
