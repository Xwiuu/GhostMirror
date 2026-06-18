"""Lab Benchmark — runs a full deep scan and captures performance metrics."""

from __future__ import annotations

import json as j
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ghostmirror.core.config_manager import ConfigManager
from ghostmirror.core.exceptions import ProjectNotFoundError
from ghostmirror.core.logger import get_logger
from ghostmirror.core.project_manager import ProjectManager
from ghostmirror.core.scope_manager import ScopeManager
from ghostmirror.models.lab_profile import LabBenchmarkResult, LabBenchmarkStep
from ghostmirror.modules.lab.catalog import LabCatalog
from ghostmirror.modules.lab.manager import LabManager
from ghostmirror.modules.lab.project_factory import LabProjectFactory
from ghostmirror.storage.filesystem import FileSystemStorage

logger = get_logger()


class LabBenchmark:
    """Runs a full-scan benchmark against a lab target and saves results."""

    def __init__(self, config: ConfigManager | None = None) -> None:
        self.config = config or ConfigManager()
        self.config.load()
        self.manager = LabManager(config=self.config)
        self.project_manager = ProjectManager(
            config=self.config, scope_manager=ScopeManager()
        )

    def run(self, lab_id: str) -> LabBenchmarkResult:
        """Execute the benchmark pipeline.

        1. Get or create lab project
        2. Run full-scan with deep profile
        3. Collect per-step duration and findings
        4. Save benchmark JSON
        """
        lab = LabCatalog.get(lab_id)
        started_at = datetime.now(timezone.utc)

        # 1. Ensure project exists
        project_path = LabProjectFactory.find_lab_project(
            self.config.projects_dir, lab_id
        )
        if project_path is None:
            logger.info("BENCHMARK_CREATE_PROJECT lab={}", lab_id)
            handle = self.manager.create_project(lab_id)
            project_path = handle.path
        else:
            handle = self.project_manager.open_project(project_path.name)

        # 2. Run full-scan deep
        from ghostmirror.modules.orchestrator.full_scan import FullScanOrchestrator

        target = lab.default_url
        profile = "deep"

        logger.info(
            "BENCHMARK_START lab={} project={} target={} profile={}",
            lab_id,
            project_path.name,
            target,
            profile,
        )

        orchestrator = FullScanOrchestrator(
            project_path=project_path,
            target=target,
            profile=profile,
        )

        steps: list[LabBenchmarkStep] = []
        total_findings = 0
        error: str | None = None

        try:
            result = orchestrator.run()
            timeline = result.get("timeline", {})
            steps_data = timeline.get("steps", [])

            for step_data in steps_data:
                step = LabBenchmarkStep(
                    step_name=step_data.get("step_name", "unknown"),
                    duration_seconds=step_data.get("duration", 0.0),
                    findings_count=step_data.get("findings_count", 0),
                    status=step_data.get("status", "completed"),
                )
                steps.append(step)
                total_findings += step.findings_count

            total_duration = timeline.get("total_duration", 0.0)

        except Exception as exc:
            logger.exception("BENCHMARK_FAILED lab={}", lab_id)
            total_duration = (datetime.now(timezone.utc) - started_at).total_seconds()
            error = str(exc)

        finished_at = datetime.now(timezone.utc)
        result_model = LabBenchmarkResult(
            lab_id=lab_id,
            project_slug=project_path.name,
            profile=profile,
            started_at=started_at,
            finished_at=finished_at,
            total_duration_seconds=total_duration,
            total_findings=total_findings,
            steps=steps,
            error=error,
        )

        # 3. Save benchmark
        self._save(project_path, result_model)

        logger.info(
            "BENCHMARK_COMPLETE lab={} duration={:.2f}s findings={}",
            lab_id,
            total_duration,
            total_findings,
        )

        return result_model

    @staticmethod
    def _save(project_path: Path, result: LabBenchmarkResult) -> Path:
        benchmarks_dir = project_path / "benchmarks"
        FileSystemStorage.ensure_dir(benchmarks_dir)

        dest = benchmarks_dir / "lab_benchmark.json"
        FileSystemStorage.write_json(
            dest,
            result.model_dump(mode="json"),
        )
        logger.info("BENCHMARK_SAVED path={}", dest)
        return dest
