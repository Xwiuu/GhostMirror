"""Standard scanner wrapper for the CVE Intelligence Engine."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ghostmirror.core.logger import get_logger
from ghostmirror.core.scope_manager import ScopeManager
from ghostmirror.modules.base.scanner import ScannerBase, ScannerError, OutOfScopeError
from ghostmirror.modules.findings.manager import FindingsManager
from ghostmirror.modules.models.finding import FindingModel, ScanResultModel
from ghostmirror.modules.cve_intelligence.engine import CVEIntelligenceEngine

logger = get_logger()


class CVEIntelligenceScanner(ScannerBase):
    """Wrapper that runs local CVE intelligence analysis within the standard scanner framework."""

    SCANNER_NAME = "cve_intelligence"
    SCANNER_VERSION = "0.1.0"

    def __init__(
        self,
        project_path: Path | str,
        target: str,
        scope_manager: ScopeManager | None = None,
        findings_manager: FindingsManager | None = None,
        knowledge_dir: Path | str | None = None,
    ) -> None:
        super().__init__(project_path, target, scope_manager, findings_manager)
        self.engine = CVEIntelligenceEngine(knowledge_dir=knowledge_dir)

    def get_metadata(self) -> dict[str, Any]:
        """Return scanner metadata."""
        return {
            "name": self.SCANNER_NAME,
            "version": self.SCANNER_VERSION,
            "description": "CVE Threat Intelligence, Vulnerability Knowledge Base, and Risk Correlation Engine",
        }

    def run(self) -> ScanResultModel:
        """Runs CVE analysis and returns standard ScanResultModel.

        Validates scope first, executes engine analysis, saves standardized findings, and returns results.
        """
        logger.info("SCAN_STARTED scanner={} target={}", self.SCANNER_NAME, self.target)
        started_at = datetime.now(timezone.utc)

        # 1. Scope Validation
        try:
            self.validate_scope()
        except OutOfScopeError as exc:
            logger.error("SCAN_BLOCKED scanner={} target={} reason={}", self.SCANNER_NAME, self.target, exc)
            raise

        # 2. Run Engine Analysis
        try:
            report = self.engine.analyze_project(self.project_path)

            # Map raw findings dicts back to FindingModels
            findings = []
            for f_data in report.get("findings", []):
                findings.append(FindingModel.model_validate(f_data))

            status = "completed"
        except FileNotFoundError as exc:
            logger.error("SCAN_FAILED scanner={} target={} reason={}", self.SCANNER_NAME, self.target, exc)
            raise ScannerError(str(exc)) from exc
        except Exception as exc:
            logger.exception("SCAN_UNEXPECTED_ERROR scanner={} target={} error={}", self.SCANNER_NAME, self.target, exc)
            raise ScannerError(f"Erro ao executar a análise de CVEs: {exc}") from exc

        finished_at = datetime.now(timezone.utc)
        stats = self.calculate_statistics(findings)

        result_model = ScanResultModel(
            scanner_name=self.SCANNER_NAME,
            target=self.target,
            started_at=started_at,
            finished_at=finished_at,
            status=status,
            findings=findings,
            statistics=stats,
        )

        # 3. Save standard scan findings via findings manager
        self.save_findings(result_model)

        logger.info(
            "SCAN_FINISHED scanner={} target={} status={} findings={} elapsed={:.2f}s",
            self.SCANNER_NAME,
            self.target,
            status,
            len(findings),
            (finished_at - started_at).total_seconds(),
        )

        return result_model
