"""Orchestrator scanner class running Nuclei execution profiles, parser, selector, and correlation."""

from __future__ import annotations

import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ghostmirror.core.exceptions import ToolNotFoundError
from ghostmirror.core.logger import get_logger
from ghostmirror.integrations.nuclei.runner import NucleiRunner
from ghostmirror.integrations.nuclei.parser import NucleiParser
from ghostmirror.modules.base.scanner import OutOfScopeError, ScannerBase, ScannerError
from ghostmirror.modules.models.finding import FindingModel, ScanResultModel
from ghostmirror.modules.nuclei.template_selector import NucleiTemplateSelector
from ghostmirror.modules.nuclei.findings_mapper import NucleiFindingsMapper
from ghostmirror.modules.nuclei.correlation_engine import NucleiCorrelationEngine
from ghostmirror.storage.filesystem import FileSystemStorage

logger = get_logger()


class NucleiScanner(ScannerBase):
    """Orchestrates Nuclei smart scanning, parsing, correlation, and profile saving."""

    SCANNER_NAME = "nuclei"
    SCANNER_VERSION = "0.1.0"

    def __init__(
        self,
        project_path: Path | str,
        target: str,
        scope_manager: Any | None = None,
        findings_manager: Any | None = None,
        nuclei_runner: NucleiRunner | None = None,
        profile: str = "standard",
    ) -> None:
        super().__init__(project_path, target, scope_manager, findings_manager)
        self.nuclei_runner = nuclei_runner or NucleiRunner()
        self.profile = profile.lower()

    def get_metadata(self) -> dict[str, Any]:
        """Return NucleiScanner metadata."""
        return {
            "name": self.SCANNER_NAME,
            "version": self.SCANNER_VERSION,
            "description": "Smart Nuclei Vulnerability Scan Orchestrator",
        }

    def run(self) -> ScanResultModel:
        """Run the Nuclei intelligence-guided scan on the target.

        Validates scope, checks binary installation, resolves target-relevant templates,
        executes nuclei, parses findings, correlatess them, saves outputs, and returns results.
        """
        from ghostmirror.modules.platform.logger import log_audit

        logger.info("SCAN_STARTED scanner={} target={} profile={}", self.SCANNER_NAME, self.target, self.profile)
        log_audit(
            event="scan iniciado",
            project=self.project_path.name,
            scanner=self.SCANNER_NAME,
            result="pendente",
        )
        started_at = datetime.now(timezone.utc)

        # 1. Validate Scope
        try:
            self.validate_scope()
        except OutOfScopeError as exc:
            logger.error("SCAN_BLOCKED scanner={} target={} reason={}", self.SCANNER_NAME, self.target, exc)
            log_audit(
                event="scan finalizado",
                project=self.project_path.name,
                scanner=self.SCANNER_NAME,
                result="bloqueado",
            )
            raise

        # 2. Check Nuclei Installation
        if not self.nuclei_runner.is_installed():
            logger.error("NUCLEI_NOT_INSTALLED")
            raise ToolNotFoundError("Nuclei is not installed or not available in the system PATH.")

        # 3. Setup Directories
        evidence_dir = self.project_path / "evidence" / "nuclei"
        findings_dir = self.project_path / "findings"
        profiles_dir = self.project_path / "profiles"

        FileSystemStorage.ensure_dir(evidence_dir)
        FileSystemStorage.ensure_dir(findings_dir)
        FileSystemStorage.ensure_dir(profiles_dir)

        raw_jsonl_path = evidence_dir / "raw.jsonl"
        parsed_results_path = evidence_dir / "parsed_results.json"
        nuclei_findings_path = findings_dir / "nuclei_findings.json"
        nuclei_profile_path = profiles_dir / "nuclei_profile.json"

        # 4. Select Templates using intelligence mappings
        templates = NucleiTemplateSelector.select_templates(self.project_path)
        if not templates:
            logger.warning("No templates resolved for target. Using basic exposures category fallback.")
            # Fallback directories as specified in prompt / example
            templates = ["http/exposures/configs/", "network/services/"]

        # 5. Determine severities by Execution Profile
        # Profiles: LITE (critical, high), STANDARD (critical, high, medium), DEEP (critical, high, medium, low)
        profile_severities: list[str] = []
        if self.profile == "lite":
            profile_severities = ["critical", "high"]
        elif self.profile == "deep":
            profile_severities = ["critical", "high", "medium", "low"]
        else:  # standard
            profile_severities = ["critical", "high", "medium"]

        # Run scan by calling nuclei integrations wrapper
        status = "failed"
        findings: list[FindingModel] = []
        results: list[Any] = []
        correlated_count = 0
        execution_time = 0.0

        try:
            # We filter templates by running nuclei on chosen templates
            # To apply severity restriction, nuclei binary filters them natively if we pass `-severity` or we filter them post-scan.
            # However, since standard nuclei command execution in the prompt mentions:
            # `nuclei -target <target> -jsonl -rate-limit <rate> -concurrency <concurrency> -template <templates>`
            # We can run nuclei then filter results post-scan by execution profile severities.
            # To do both, we configure runner call, then filter raw lines.
            start_time = time.perf_counter()
            exec_result = self.nuclei_runner.scan(
                target=self.target,
                templates=templates,
                output_jsonl_path=raw_jsonl_path,
                rate_limit=150,
                concurrency=25,
                timeout=300.0,
            )
            execution_time = time.perf_counter() - start_time

            # Validate raw JSONL was generated (it might be empty if no findings triggered, which is fine, but file might not exist)
            # If exec failed completely, raise ScannerError
            if not exec_result.success and exec_result.exit_code != 0:
                # Some versions of nuclei exit non-zero on error, but some exit 0 even if no findings.
                # Check stderr to see if target was completely offline
                if "could not resolve" in exec_result.stderr.lower() or "no targets specified" in exec_result.stderr.lower():
                    raise ScannerError("Target indisponível ou inacessível para o Nuclei.")

            # Parse results
            parsed_all = NucleiParser.parse_file(raw_jsonl_path)

            # Filter by severity corresponding to current execution profile
            # Note: nuclei output severity is usually lowercase
            results = [r for r in parsed_all if r.severity.lower() in profile_severities]

            # Save parsed_results.json under evidence/nuclei
            FileSystemStorage.write_json(
                parsed_results_path,
                [r.model_dump(mode="json") for r in results]
            )

            # 6. Map parsed results to standardized Findings
            for res in results:
                finding = NucleiFindingsMapper.map_to_finding(res, self.target)
                findings.append(finding)

            # 7. Run Correlation Engine to map CVEs and Technology matches
            correlated_count = NucleiCorrelationEngine.correlate(
                project_path=self.project_path,
                results=results,
                findings=findings,
            )

            status = "completed"

        except Exception as exc:
            logger.exception("NUCLEI_SCANNER_RUN_FAILED error={}", exc)
            if isinstance(exc, (ScannerError, ToolNotFoundError)):
                raise
            raise ScannerError(f"Erro ao executar scan do Nuclei: {exc}") from exc

        # Calculate statistics
        stats = self.calculate_statistics(findings)
        
        # Build ScanResultModel
        finished_at = datetime.now(timezone.utc)
        result_model = ScanResultModel(
            scanner_name=self.SCANNER_NAME,
            target=self.target,
            started_at=started_at,
            finished_at=finished_at,
            status=status,
            findings=findings,
            statistics=stats,
        )

        # Save standard findings/nuclei.json or nuclei_findings.json
        # The prompt says: "findings/nuclei_findings.json" and "projects/CLIENTE/findings/"
        # We save both standard scan findings (fingerprint manager maps to scanner name "nuclei") and nuclei_findings.json
        if status == "completed":
            self.save_findings(result_model)
            # Write findings directly to findings/nuclei_findings.json
            FileSystemStorage.write_json(
                nuclei_findings_path,
                [f.model_dump(mode="json") for f in findings]
            )

        # 8. Create and write nuclei_profile.json
        # Format:
        # {
        #   "target": "...",
        #   "templates_executed": 150,
        #   "findings": 12,
        #   "critical": 2,
        #   "high": 4,
        #   "medium": 3,
        #   "low": 2,
        #   "info": 1,
        #   "execution_time": 34.5,
        #   "correlated_findings": 8
        # }
        profile_data = {
            "target": self.target,
            "templates_executed": len(templates),
            "findings": len(findings),
            "critical": stats.get("critical", 0),
            "high": stats.get("high", 0),
            "medium": stats.get("medium", 0),
            "low": stats.get("low", 0),
            "info": stats.get("info", 0),
            "execution_time": round(execution_time, 1),
            "correlated_findings": correlated_count,
        }

        FileSystemStorage.write_json(nuclei_profile_path, profile_data)

        logger.info(
            "SCAN_FINISHED scanner={} target={} status={} findings={} elapsed={:.2f}s",
            self.SCANNER_NAME,
            self.target,
            status,
            len(findings),
            (finished_at - started_at).total_seconds(),
        )
        log_audit(
            event="scan finalizado",
            project=self.project_path.name,
            scanner=self.SCANNER_NAME,
            result=status,
        )

        return result_model
