"""Tests for Question Generator."""

from __future__ import annotations

import pytest

from ghostmirror.models.assistant_context import AssistantContext
from ghostmirror.models.assistant_priority import AssistantPriorities, InvestigationPriority
from ghostmirror.modules.pentester_assistant.question_generator import QuestionGenerator


class TestQuestionGenerator:
    def test_empty_priorities(self):
        ctx = AssistantContext(target="t", project="p")
        priorities = AssistantPriorities(target="t", project="p")
        gen = QuestionGenerator()
        result = gen.generate(ctx, priorities)
        assert result.total_questions == 0

    def test_generates_api_questions(self):
        ctx = AssistantContext(target="t", project="p")
        priorities = AssistantPriorities(
            target="t",
            project="p",
            priorities=[
                InvestigationPriority(rank=1, title="API Risk", category="API Security"),
            ],
        )
        gen = QuestionGenerator()
        result = gen.generate(ctx, priorities)
        assert result.total_questions >= 2
        assert any("authentication" in q.question.lower() for q in result.questions)

    def test_generates_cve_questions(self):
        ctx = AssistantContext(target="t", project="p")
        priorities = AssistantPriorities(
            target="t",
            project="p",
            priorities=[
                InvestigationPriority(rank=1, title="CVE", category="CVE"),
            ],
        )
        gen = QuestionGenerator()
        result = gen.generate(ctx, priorities)
        assert any("product" in q.question.lower() or "patch" in q.question.lower() for q in result.questions)

    def test_no_duplicate_questions(self):
        ctx = AssistantContext(target="t", project="p")
        priorities = AssistantPriorities(
            target="t",
            project="p",
            priorities=[
                InvestigationPriority(rank=1, title="API", category="API Security"),
                InvestigationPriority(rank=2, title="API 2", category="API Security"),
            ],
        )
        gen = QuestionGenerator()
        result = gen.generate(ctx, priorities)
        questions = [q.question for q in result.questions]
        assert len(questions) == len(set(questions))

    def test_questions_have_ids(self):
        ctx = AssistantContext(target="t", project="p")
        priorities = AssistantPriorities(
            target="t",
            project="p",
            priorities=[
                InvestigationPriority(rank=1, title="Test", category="General"),
            ],
        )
        gen = QuestionGenerator()
        result = gen.generate(ctx, priorities)
        for q in result.questions:
            assert len(q.id) == 12

    def test_zero_day_questions(self):
        ctx = AssistantContext(target="t", project="p")
        priorities = AssistantPriorities(
            target="t",
            project="p",
            priorities=[
                InvestigationPriority(rank=1, title="Hypothesis", category="Zero-Day Hypothesis"),
            ],
        )
        gen = QuestionGenerator()
        result = gen.generate(ctx, priorities)
        assert any("reproducible" in q.question.lower() or "anomaly" in q.question.lower() for q in result.questions)
