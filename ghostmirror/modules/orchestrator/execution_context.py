"""Track and manage the runtime context of the full scan orchestrator."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any


class ExecutionStatus(str, Enum):
    """Standardised status values for pipeline steps and modules."""

    PENDING = "pending"
    SUCCESS = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    WARNING = "warning"


class ExecutionContext:
    """Manages the full scan execution state, tracking steps, durations, and status."""

    def __init__(self, project_slug: str, target: str, profile: str) -> None:
        self.run_id: str = uuid.uuid4().hex[:12]
        self.project_slug = project_slug
        self.target = target
        self.profile = profile.lower()
        self.started_at: datetime = datetime.now(timezone.utc)
        self.finished_at: datetime | None = None
        self.steps: list[dict[str, Any]] = []

    def start_step(self, step_name: str) -> _StepTracker:
        """Context manager to measure the duration and status of a pipeline step."""
        return _StepTracker(self, step_name)

    def add_step_result(
        self,
        name: str,
        status: str,
        started_at: datetime,
        finished_at: datetime,
        duration: float,
        findings: int,
        errors: list[str] | None = None,
    ) -> None:
        """Directly append a step execution result to the timeline."""
        if errors is None:
            errors = []

        self.steps.append(
            {
                "name": name,
                "module": name,
                "status": status,
                "started_at": started_at.isoformat(),
                "finished_at": finished_at.isoformat(),
                "duration": round(duration, 3),
                "findings": findings,
                "findings_count": findings,
                "errors": errors,
            }
        )

    def finalize(self) -> None:
        """Mark the overall execution as completed."""
        self.finished_at = datetime.now(timezone.utc)

    def to_dict(self) -> dict[str, Any]:
        """Convert context to standard dict format matching timeline expectations."""
        return {
            "run_id": self.run_id,
            "project": self.project_slug,
            "target": self.target,
            "profile": self.profile,
            "started_at": self.started_at.isoformat(),
            "finished_at": (
                self.finished_at.isoformat() if self.finished_at else None
            ),
            "steps": self.steps,
        }

    def get_summary(self) -> dict[str, int]:
        """Return a summary of step execution counts.

        Returns
        -------
        dict
            Keys: executed, skipped, failed, warnings.
        """
        executed = sum(1 for s in self.steps if s["status"] == ExecutionStatus.SUCCESS.value)
        skipped = sum(1 for s in self.steps if s["status"] == ExecutionStatus.SKIPPED.value)
        failed = sum(1 for s in self.steps if s["status"] == ExecutionStatus.FAILED.value)
        warnings = sum(1 for s in self.steps if s["status"] == ExecutionStatus.WARNING.value)
        return {
            "executed": executed,
            "skipped": skipped,
            "failed": failed,
            "warnings": warnings,
        }

    def get_executed_modules(self) -> list[dict[str, Any]]:
        """Return steps with status SUCCESS."""
        return [s for s in self.steps if s["status"] == ExecutionStatus.SUCCESS.value]

    def get_skipped_modules(self) -> list[dict[str, Any]]:
        """Return steps with status SKIPPED."""
        return [s for s in self.steps if s["status"] == ExecutionStatus.SKIPPED.value]

    def get_failed_modules(self) -> list[dict[str, Any]]:
        """Return steps with status FAILED."""
        return [s for s in self.steps if s["status"] == ExecutionStatus.FAILED.value]

    def save_timeline(self, project_path: Path) -> Path:
        """Persists the timeline to projects/<slug>/execution/full_scan_timeline.json."""
        exec_dir = project_path / "execution"
        exec_dir.mkdir(parents=True, exist_ok=True)
        file_path = exec_dir / "full_scan_timeline.json"

        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, indent=2, ensure_ascii=False)

        return file_path


class _StepTracker:
    """Helper context manager to automatically track step duration and result status."""

    def __init__(self, context: ExecutionContext, name: str) -> None:
        self.context = context
        self.name = name
        self.start_perf: float = 0.0
        self.started_at: datetime = datetime.now(timezone.utc)
        self.findings_count: int = 0
        self.status = ExecutionStatus.PENDING
        self.errors: list[str] = []

    def __enter__(self) -> _StepTracker:
        import time

        self.start_perf = time.perf_counter()
        self.started_at = datetime.now(timezone.utc)
        return self

    def mark_skipped(self, reason: str = "") -> None:
        """Mark the step as skipped without having to exit the context manager."""
        self.status = ExecutionStatus.SKIPPED
        if reason:
            self.errors.append(reason)

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> bool:
        import time

        finished_at = datetime.now(timezone.utc)
        duration = time.perf_counter() - self.start_perf

        # Respect status already set by _run_step (SKIPPED, FAILED)
        if self.status not in (ExecutionStatus.PENDING,):
            pass
        elif exc_type is None:
            self.status = ExecutionStatus.SUCCESS
        else:
            self.status = ExecutionStatus.FAILED
            self.errors.append(str(exc_val))

        self.context.add_step_result(
            name=self.name,
            status=self.status.value,
            started_at=self.started_at,
            finished_at=finished_at,
            duration=duration,
            findings=self.findings_count,
            errors=self.errors,
        )
        return False
