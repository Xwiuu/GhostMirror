"""Tests for Investigation Planner."""

from __future__ import annotations

import pytest

from ghostmirror.models.assistant_context import AssistantContext
from ghostmirror.models.assistant_priority import AssistantPriorities, InvestigationPriority
from ghostmirror.modules.pentester_assistant.investigation_planner import InvestigationPlanner


class TestInvestigationPlanner:
    def test_empty_priorities(self):
        ctx = AssistantContext(target="t", project="p")
        priorities = AssistantPriorities(target="t", project="p")
        planner = InvestigationPlanner()
        plan = planner.plan(ctx, priorities)
        assert plan.total_tasks == 0

    def test_creates_tasks(self):
        ctx = AssistantContext(target="t", project="p")
        priorities = AssistantPriorities(
            target="t",
            project="p",
            priorities=[
                InvestigationPriority(rank=1, title="API Risk", category="API Security"),
                InvestigationPriority(rank=2, title="CVE", category="CVE"),
                InvestigationPriority(rank=3, title="Auth", category="Authentication"),
            ],
        )
        planner = InvestigationPlanner()
        plan = planner.plan(ctx, priorities)
        assert plan.total_tasks == 3
        assert plan.tasks[0].task_type == "API Security Review"
        assert plan.tasks[1].task_type == "CVE Verification"
        assert plan.tasks[2].task_type == "Auth Review"

    def test_safety_notes_present(self):
        ctx = AssistantContext(target="t", project="p")
        priorities = AssistantPriorities(
            target="t",
            project="p",
            priorities=[
                InvestigationPriority(rank=1, title="XSS", category="Injection"),
            ],
        )
        planner = InvestigationPlanner()
        plan = planner.plan(ctx, priorities)
        assert len(plan.tasks) == 1
        assert len(plan.tasks[0].safety_notes) > 0

    def test_effort_based_on_severity(self):
        ctx = AssistantContext(target="t", project="p")
        priorities = AssistantPriorities(
            target="t",
            project="p",
            priorities=[
                InvestigationPriority(rank=1, title="Critical", category="General", severity="CRITICAL"),
                InvestigationPriority(rank=2, title="Low", category="General", severity="LOW"),
            ],
        )
        planner = InvestigationPlanner()
        plan = planner.plan(ctx, priorities)
        assert plan.tasks[0].estimated_effort == "high"
        assert plan.tasks[1].estimated_effort == "low"

    def test_zero_day_task_type(self):
        ctx = AssistantContext(target="t", project="p")
        priorities = AssistantPriorities(
            target="t",
            project="p",
            priorities=[
                InvestigationPriority(rank=1, title="Hypothesis", category="Zero-Day Hypothesis"),
            ],
        )
        planner = InvestigationPlanner()
        plan = planner.plan(ctx, priorities)
        assert plan.tasks[0].task_type == "Zero-Day Hypothesis Review"
        assert "research" in plan.tasks[0].objective.lower()
