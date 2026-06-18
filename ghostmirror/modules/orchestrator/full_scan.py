"""Authorized full scan orchestrator to execute the pipeline of security tests."""

from __future__ import annotations

import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ghostmirror.core.logger import get_logger
from ghostmirror.core.scope_manager import ScopeManager
from ghostmirror.modules.base.scanner import OutOfScopeError, normalize_target
from ghostmirror.modules.orchestrator.execution_context import ExecutionContext
from ghostmirror.modules.orchestrator.pipeline import get_pipeline_steps

logger = get_logger()


class FullScanOrchestrator:
    """Orchestrates the execution of a suite of security scanners against an authorized target."""

    def __init__(
        self,
        project_path: Path | str,
        target: str,
        profile: str = "standard",
    ) -> None:
        self.project_path = Path(project_path)
        self.target = target.strip()
        self.profile = profile.lower()
        self.scope_manager = ScopeManager()

    def run(self) -> dict[str, Any]:
        """Runs the scan orchestrator pipeline, validating scopes and catching step errors."""
        # 1. Scope and Target Authorization Checks
        scope_path = self.project_path / ScopeManager.SCOPE_FILENAME
        if not scope_path.exists():
            raise FileNotFoundError(f"Scope file not found: {scope_path}")

        scope = self.scope_manager.load_scope(scope_path)
        if not self.scope_manager.is_ready_for_testing(scope):
            raise OutOfScopeError("Scope is not ready for testing (no targets defined).")

        # Basic target validation
        normalized = normalize_target(self.target)
        in_scope = False
        for domain in scope.targets.domains:
            if normalized == domain or normalized.endswith("." + domain):
                in_scope = True
                break

        if not in_scope:
            import ipaddress
            try:
                target_ip = ipaddress.ip_address(normalized)
                for ip_net_str in scope.targets.ips:
                    net = ipaddress.ip_network(ip_net_str, strict=False)
                    if target_ip in net:
                        in_scope = True
                        break
            except ValueError:
                pass

        if not in_scope:
            raise OutOfScopeError(
                f"Target {self.target!r} is not in scope for project {self.project_path.name!r}."
            )

        # Destructive tests check (Scope Guard)
        # Even though we don't have destructive tests, enforce safety check
        if not scope.allowed_tests.destructive_tests:
            logger.info("Scope Guard: Destructive tests are disabled.")

        # 2. Build Execution Context
        context = ExecutionContext(
            project_slug=self.project_path.name,
            target=self.target,
            profile=self.profile,
        )

        from ghostmirror.modules.platform.logger import log_audit

        steps = get_pipeline_steps(self.profile)
        logger.info(
            "FULL_SCAN_START project={} target={} profile={} steps={}",
            self.project_path.name,
            self.target,
            self.profile,
            steps,
        )
        log_audit(
            event="scan iniciado",
            project=self.project_path.name,
            scanner="orchestrator",
            result="pendente",
        )

        try:
            # 3. Execute Pipeline Steps
            for step in steps:
                if step == "report":
                    # We handle reports at the very end
                    continue

                try:
                    with context.start_step(step) as tracker:
                        findings_count = self._run_step(step)
                        tracker.findings_count = findings_count
                        logger.info("FULL_SCAN_STEP_COMPLETED step={} findings={}", step, findings_count)
                except Exception as exc:
                    logger.exception("FULL_SCAN_STEP_FAILED step={} error={}", step, exc)

            # 4. Report Generation Step
            # Report format selection based on profile
            formats = ["html"]
            if self.profile == "standard":
                formats = ["html", "md"]
            elif self.profile == "deep":
                formats = ["html", "md", "pdf"]

            logger.info("FULL_SCAN_REPORT_GENERATION formats={}", formats)
            with context.start_step("report") as tracker:
                try:
                    self._run_report_generation(formats)
                    tracker.findings_count = 0
                except Exception as exc:
                    logger.exception("FULL_SCAN_REPORT_GENERATION_FAILED error={}", exc)
                    raise

            # 5. Finalize and Save Timeline
            context.finalize()
            timeline_path = context.save_timeline(self.project_path)
            logger.info("FULL_SCAN_COMPLETE timeline_saved={}", timeline_path)
            log_audit(
                event="scan finalizado",
                project=self.project_path.name,
                scanner="orchestrator",
                result="completed",
            )
        except Exception as exc:
            log_audit(
                event="scan finalizado",
                project=self.project_path.name,
                scanner="orchestrator",
                result="failed",
            )
            raise

        return context.to_dict()

    def _run_step(self, step_name: str) -> int:
        """Executes a single scanner/engine step and returns its finding count."""
        if step_name == "headers":
            from ghostmirror.modules.headers.scanner import HeadersScanner
            scanner = HeadersScanner(
                project_path=self.project_path,
                target=self.target,
                scope_manager=self.scope_manager,
            )
            result = scanner.run()
            return len(result.findings)

        elif step_name == "ssl":
            from ghostmirror.modules.ssl.scanner import SSLScanner
            scanner = SSLScanner(
                project_path=self.project_path,
                target=self.target,
                scope_manager=self.scope_manager,
            )
            result = scanner.run()
            return len(result.findings)

        elif step_name == "nmap":
            from ghostmirror.modules.nmap.scanner import NmapScanner
            scanner = NmapScanner(
                project_path=self.project_path,
                target=self.target,
                scope_manager=self.scope_manager,
            )
            result = scanner.run()
            return len(result.findings)

        elif step_name == "fingerprint":
            from ghostmirror.modules.fingerprint.scanner import FingerprintScanner
            scanner = FingerprintScanner(
                project_path=self.project_path,
                target=self.target,
                scope_manager=self.scope_manager,
            )
            result = scanner.run()
            return len(result.findings)

        elif step_name == "technology_intelligence":
            from ghostmirror.modules.technology_intelligence.engine import (
                TechnologyIntelligenceEngine,
            )
            engine = TechnologyIntelligenceEngine()
            report = engine.analyze_project(self.project_path)
            return len(report.get("findings", []))

        elif step_name == "cve_intelligence":
            from ghostmirror.modules.cve_intelligence.engine import (
                CVEIntelligenceEngine,
            )
            engine = CVEIntelligenceEngine()
            report = engine.analyze_project(self.project_path)
            return len(report.get("findings", []))

        elif step_name == "nuclei":
            from ghostmirror.modules.nuclei.scanner import NucleiScanner
            # Use standard or deep profile mapping for nuclei execution
            nuclei_profile = "deep" if self.profile == "deep" else "standard"
            scanner = NucleiScanner(
                project_path=self.project_path,
                target=self.target,
                scope_manager=self.scope_manager,
                profile=nuclei_profile,
            )
            result = scanner.run()
            return len(result.findings)

        elif step_name == "owasp":
            from ghostmirror.modules.owasp.scanner import OWASPScanner
            scanner = OWASPScanner(
                project_path=self.project_path,
                target=self.target,
                scope_manager=self.scope_manager,
            )
            result = scanner.run()
            return len(result.findings)

        else:
            raise ValueError(f"Etapa de pipeline desconhecida: {step_name!r}")

    def _run_report_generation(self, formats: list[str]) -> None:
        """Invokes the reporting engine to generate documents in the specified formats."""
        from ghostmirror.modules.reporting.generator import ReportGenerator
        generator = ReportGenerator(self.project_path)
        for fmt in formats:
            generator.generate(fmt)
