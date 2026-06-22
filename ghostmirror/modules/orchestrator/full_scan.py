"""Authorized full scan orchestrator to execute the pipeline of security tests."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ghostmirror.core.exceptions import ToolNotFoundError
from ghostmirror.core.logger import get_logger
from ghostmirror.core.scope_manager import ScopeManager
from ghostmirror.modules.base.scanner import OutOfScopeError, normalize_target
from ghostmirror.modules.orchestrator.execution_context import ExecutionContext, ExecutionStatus
from ghostmirror.modules.orchestrator.pipeline import get_pipeline_steps

logger = get_logger()

STEP_DEPENDENCIES: dict[str, list[str]] = {
    "technology_intelligence": ["fingerprint"],
    "cve_intelligence": ["fingerprint"],
    "nuclei": ["cve_intelligence", "technology_intelligence"],
    "web_intelligence": ["fingerprint"],
    "bug_bounty": ["web_intelligence", "fingerprint"],
    "vulnerability_intelligence": ["cve_intelligence"],
    "finding_intelligence": ["vulnerability_intelligence"],
    "api_security": ["web_intelligence"],
    "zero_day": ["web_intelligence", "api_security"],
    "attack_chain": ["zero_day", "finding_intelligence", "api_security", "bug_bounty", "web_intelligence"],
}


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
        scope_path = self.project_path / ScopeManager.SCOPE_FILENAME
        if not scope_path.exists():
            raise FileNotFoundError(f"Scope file not found: {scope_path}")

        scope = self.scope_manager.load_scope(scope_path)
        if not self.scope_manager.is_ready_for_testing(scope):
            raise OutOfScopeError("Scope is not ready for testing (no targets defined).")

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

        if not scope.allowed_tests.destructive_tests:
            logger.info("Scope Guard: Destructive tests are disabled.")

        context = ExecutionContext(
            project_slug=self.project_path.name,
            target=self.target,
            profile=self.profile,
        )

        from ghostmirror.modules.platform.logger import log_audit

        steps = get_pipeline_steps(self.profile)
        log = logger.bind(run_id=context.run_id, module="orchestrator")
        log.info(
            "FULL_SCAN_START run_id={} project={} target={} profile={} steps={}",
            context.run_id,
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
            for step in steps:
                if step == "report":
                    continue

                # Check if dependencies were skipped → cascade skip
                deps = STEP_DEPENDENCIES.get(step, [])
                all_deps_skipped = all(
                    s["status"] == ExecutionStatus.SKIPPED.value
                    for s in context.steps
                    if s["name"] in deps
                )
                if all_deps_skipped and deps:
                    with context.start_step(step) as tracker:
                        dep_names = ", ".join(deps)
                        reason = f"Dependency skipped: {dep_names}"
                        tracker.mark_skipped(reason=reason)
                    continue

                with context.start_step(step) as tracker:
                    findings_count = self._run_step(step, tracker)
                    tracker.findings_count = findings_count
                    sl = logger.bind(
                        run_id=context.run_id,
                        module=step,
                        status=tracker.status.value,
                        findings=findings_count,
                        duration=tracker.duration if hasattr(tracker, "duration") and tracker.duration else 0,
                    )
                    sl.info(
                        "FULL_SCAN_STEP_COMPLETED run_id={} step={} status={} findings={}",
                        context.run_id,
                        step,
                        tracker.status.value,
                        findings_count,
                    )

            formats = ["html"]
            if self.profile == "standard":
                formats = ["html", "md"]
            elif self.profile in ("deep", "bounty"):
                formats = ["html", "md", "pdf"]

            log.info("FULL_SCAN_REPORT_GENERATION run_id={} formats={}", context.run_id, formats)
            with context.start_step("report") as tracker:
                try:
                    self._run_report_generation(formats)
                    tracker.findings_count = 0
                except Exception as exc:
                    log.exception("FULL_SCAN_REPORT_GENERATION_FAILED run_id={} error={}", context.run_id, exc)
                    raise

            context.finalize()
            timeline_path = context.save_timeline(self.project_path)
            log.info("FULL_SCAN_COMPLETE run_id={} timeline_saved={}", context.run_id, timeline_path)
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

    def _run_step(self, step_name: str, tracker: Any) -> int:
        """Executes a single scanner/engine step and returns its finding count.

        Catches all exceptions so the pipeline never crashes:
        - ToolNotFoundError → SKIPPED
        - FileNotFoundError → SKIPPED (dependency profile missing)
        - Anything else → FAILED (logged, step continues)
        """
        try:
            return self._execute_step(step_name)
        except ToolNotFoundError as exc:
            tool_hint = str(exc).split("'")[1] if "'" in str(exc) else step_name
            el = logger.bind(run_id=getattr(tracker.context, "run_id", "?"), module=step_name, status="skipped")
            el.warning(
                "STEP_SKIPPED run_id={} step={} tool={} reason={}",
                getattr(tracker.context, "run_id", "?"),
                step_name,
                tool_hint,
                exc,
            )
            tracker.mark_skipped(reason=f"Ferramenta não encontrada: {tool_hint}")
            return 0
        except FileNotFoundError as exc:
            el = logger.bind(run_id=getattr(tracker.context, "run_id", "?"), module=step_name, status="skipped")
            el.warning(
                "STEP_SKIPPED run_id={} step={} reason={}",
                getattr(tracker.context, "run_id", "?"),
                step_name,
                exc,
            )
            tracker.mark_skipped(reason=str(exc))
            return 0
        except Exception as exc:
            el = logger.bind(run_id=getattr(tracker.context, "run_id", "?"), module=step_name, status="failed")
            el.exception(
                "STEP_FAILED run_id={} step={} error={}",
                getattr(tracker.context, "run_id", "?"),
                step_name,
                exc,
            )
            tracker.status = ExecutionStatus.FAILED
            tracker.errors.append(str(exc))
            return 0

    def _execute_step(self, step_name: str) -> int:
        """Execute a single scanner step."""
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
            if report.get("status") == "skipped":
                raise FileNotFoundError(report.get("reason", "Dependency not available"))
            return len(report.get("findings", []))

        elif step_name == "cve_intelligence":
            from ghostmirror.modules.cve_intelligence.engine import (
                CVEIntelligenceEngine,
            )
            engine = CVEIntelligenceEngine()
            report = engine.analyze_project(self.project_path)
            if report.get("status") == "skipped":
                raise FileNotFoundError(report.get("reason", "Dependency not available"))
            return len(report.get("findings", []))

        elif step_name == "nuclei":
            from ghostmirror.modules.nuclei.scanner import NucleiScanner
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

        elif step_name == "bug_bounty":
            from ghostmirror.modules.bug_bounty.engine import BugBountyEngine
            engine = BugBountyEngine(profile="bounty")
            result = engine.analyze_project(self.project_path, self.target)
            if result.get("status") == "skipped":
                raise FileNotFoundError(result.get("reason", "Dependency not available"))
            return result.get("findings_generated", 0)

        elif step_name == "intelligence":
            from ghostmirror.modules.intelligence.engine import IntelligenceEngine
            engine = IntelligenceEngine()
            report = engine.analyze_project(self.project_path)
            findings_count = len(report.attack_paths) + len(report.recommendations)
            return findings_count

        elif step_name == "web_intelligence":
            from ghostmirror.modules.web_intelligence.engine import WebIntelligenceEngine
            engine = WebIntelligenceEngine()
            report = engine.analyze_project(self.project_path)
            findings_count = len(report.indicators) + len(report.opportunities)
            return findings_count

        elif step_name == "api_security":
            from ghostmirror.modules.api_security.engine import APISecurityEngine
            engine = APISecurityEngine()
            report = engine.analyze_project(self.project_path)
            findings_count = len(report.bola_indicators) + len(report.bfla_indicators) + len(report.mass_assignment_indicators) + len(report.opportunities)
            return findings_count

        elif step_name == "zero_day":
            from ghostmirror.modules.zero_day.engine import ZeroDayEngine
            engine = ZeroDayEngine()
            report = engine.analyze_project(self.project_path, self.target)
            findings_count = report.total_signals + report.total_hypotheses + report.total_opportunities + report.total_attack_chains
            return findings_count

        elif step_name == "payloads":
            from ghostmirror.modules.payloads.engine import PayloadEngine
            engine = PayloadEngine(
                project_path=self.project_path,
                target=self.target,
                dry_run=True,
                confirm_sensitive=False,
            )
            report = engine.analyze_project()
            return report.get("findings_generated", 0)

        elif step_name == "attack_chain":
            from ghostmirror.modules.attack_chain.engine import AttackChainEngine
            engine = AttackChainEngine()
            report = engine.analyze_project(self.project_path)
            findings_count = report.total_signals + report.total_chains
            return findings_count

        else:
            raise ValueError(f"Etapa de pipeline desconhecida: {step_name!r}")

    def _run_report_generation(self, formats: list[str]) -> None:
        """Invokes the reporting engine to generate documents in the specified formats."""
        from ghostmirror.modules.reporting.generator import ReportGenerator
        generator = ReportGenerator(self.project_path)
        for fmt in formats:
            generator.generate(fmt)

