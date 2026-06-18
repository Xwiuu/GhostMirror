"""Track and manage the runtime context of the full scan orchestrator."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


class ExecutionContext:
    """Manages the full scan execution state, tracking steps, durations, and status."""

    def __init__(self, project_slug: str, target: str, profile: str) -> None:
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
            "project": self.project_slug,
            "target": self.target,
            "profile": self.profile,
            "started_at": self.started_at.isoformat(),
            "finished_at": (
                self.finished_at.isoformat() if self.finished_at else None
            ),
            "steps": self.steps,
        }

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
        self.status = "failed"
        self.errors: list[str] = []

    def __enter__(self) -> _StepTracker:
        import time

        self.start_perf = time.perf_counter()
        self.started_at = datetime.now(timezone.utc)
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> bool:
        import time

        finished_at = datetime.now(timezone.utc)
        duration = time.perf_counter() - self.start_perf

        if exc_type is None:
            self.status = "completed"
        else:
            self.status = "failed"
            self.errors.append(str(exc_val))

        self.context.add_step_result(
            name=self.name,
            status=self.status,
            started_at=self.started_at,
            finished_at=finished_at,
            duration=duration,
            findings=self.findings_count,
            errors=self.errors,
        )
        return False  # Do not suppress exceptions; let orchestrator handle them
