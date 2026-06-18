"""Maps OWASPFinding domain models to standard FindingModel for reporting."""

from __future__ import annotations

from ghostmirror.models.owasp_finding import OWASPFinding
from ghostmirror.modules.models.finding import FindingModel, FindingSeverity

SEVERITY_MAP: dict[str, FindingSeverity] = {
    "CRITICAL": FindingSeverity.CRITICAL,
    "HIGH": FindingSeverity.HIGH,
    "MEDIUM": FindingSeverity.MEDIUM,
    "LOW": FindingSeverity.LOW,
    "INFO": FindingSeverity.INFO,
}


class OWASPFindingsMapper:
    """Converts OWASP-specific findings to the standard pipeline FindingModel."""

    @staticmethod
    def to_finding_model(owasp_finding: OWASPFinding) -> FindingModel:
        """Convert a single OWASPFinding to FindingModel."""
        sev_str = owasp_finding.severity.value.upper()
        severity = SEVERITY_MAP.get(sev_str, FindingSeverity.INFO)

        recommendation = owasp_finding.recommendation or "No recommendation provided."
        return FindingModel(
            title=f"[OWASP {owasp_finding.category.value}] {owasp_finding.title}",
            description=(
                f"Categoria OWASP: {owasp_finding.category.value}\n\n"
                f"{owasp_finding.description}"
            ),
            severity=severity,
            target=owasp_finding.target,
            evidence=owasp_finding.evidence,
            recommendation=recommendation,
        )

    @staticmethod
    def to_finding_list(
        owasp_findings: list[OWASPFinding],
    ) -> list[FindingModel]:
        """Convert a list of OWASPFinding to a list of FindingModel."""
        return [
            OWASPFindingsMapper.to_finding_model(f) for f in owasp_findings
        ]
