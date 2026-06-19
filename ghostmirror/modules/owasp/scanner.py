"""OWASP Scanner — standard ScannerBase wrapper for OWASP Top 10 Light Engine."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ghostmirror.app.url_normalizer import normalize_url
from ghostmirror.core.logger import get_logger
from ghostmirror.core.scope_manager import ScopeManager
from ghostmirror.modules.base.scanner import ScannerBase, ScannerError, OutOfScopeError
from ghostmirror.modules.findings.manager import FindingsManager
from ghostmirror.modules.models.finding import FindingModel, FindingSeverity, ScanResultModel
from ghostmirror.modules.owasp.engine import OWASPEngine

logger = get_logger()


class OWASPScanner(ScannerBase):
    """Standard scanner wrapper for OWASP Top 10 Light assessment.

    This scanner **does not** perform exploitation, brute force, or destructive
    testing. It identifies security indicators, exposures, and misconfigurations
    based on OWASP Top 10 categories A01–A10.
    """

    SCANNER_NAME = "owasp"
    SCANNER_VERSION = "0.1.0"

    def __init__(
        self,
        project_path: Path | str,
        target: str,
        scope_manager: ScopeManager | None = None,
        findings_manager: FindingsManager | None = None,
    ) -> None:
        super().__init__(project_path, target, scope_manager, findings_manager)
        self.engine = OWASPEngine()

    def get_metadata(self) -> dict[str, Any]:
        return {
            "name": self.SCANNER_NAME,
            "version": self.SCANNER_VERSION,
            "description": "OWASP Top 10 Light Security Assessment Engine",
        }

    def run(self) -> ScanResultModel:
        """Execute OWASP Top 10 Light assessment and return standard result."""
        logger.info("SCAN_STARTED scanner={} target={}", self.SCANNER_NAME, self.target)
        started_at = datetime.now(timezone.utc)

        try:
            self.validate_scope()
        except OutOfScopeError as exc:
            logger.error(
                "SCAN_BLOCKED scanner={} target={} reason={}",
                self.SCANNER_NAME,
                self.target,
                exc,
            )
            raise

        try:
            try:
                normalized_target = normalize_url(self.target)
            except ValueError:
                normalized_target = self.target
            report = self.engine.analyze_project(self.project_path, normalized_target)
            owasp_findings = report.get("findings", [])

            findings = [
                FindingModel.model_validate(f) for f in owasp_findings
            ]

            status = "completed"
        except Exception as exc:
            logger.exception(
                "SCAN_FAILED scanner={} target={} error={}",
                self.SCANNER_NAME,
                self.target,
                exc,
            )
            raise ScannerError(f"OWASP assessment failed: {exc}") from exc

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
