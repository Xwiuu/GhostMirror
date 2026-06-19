from __future__ import annotations

from typing import Any

from ghostmirror.core.logger import get_logger
from ghostmirror.models.web_indicator import IndicatorType, SeverityLevel
from ghostmirror.modules.models.finding import FindingModel, FindingSeverity

logger = get_logger()

SEVERITY_MAP: dict[SeverityLevel, FindingSeverity] = {
    SeverityLevel.INFO: FindingSeverity.INFO,
    SeverityLevel.LOW: FindingSeverity.LOW,
    SeverityLevel.MEDIUM: FindingSeverity.MEDIUM,
    SeverityLevel.HIGH: FindingSeverity.HIGH,
    SeverityLevel.CRITICAL: FindingSeverity.CRITICAL,
}


class WebFindingsMapper:
    def map_to_findings(
        self,
        indicators: list[WebIndicator],
        target: str,
    ) -> list[FindingModel]:
        logger.info("WEB_FINDINGS_MAPPER_START indicators={}", len(indicators))
        findings: list[FindingModel] = []

        for ind in indicators:
            if ind.severity in (SeverityLevel.LOW, SeverityLevel.INFO):
                continue

            finding = FindingModel(
                title=f"[Web] {ind.title}",
                description=ind.description,
                severity=SEVERITY_MAP.get(ind.severity, FindingSeverity.INFO),
                target=ind.endpoint or target,
                evidence=ind.evidence,
                recommendation=ind.recommendation,
                source="web_intelligence",
            )
            findings.append(finding)

        logger.info("WEB_FINDINGS_MAPPER_DONE findings={}", len(findings))
        return findings
