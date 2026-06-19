from ghostmirror.models.finding_confidence import ConfidenceLevel


def evaluate_confidence(
    source: str | None = None,
    has_cve_match: bool = False,
    has_version_match: bool = False,
    has_evidence: bool = False,
    has_nuclei: bool = False,
) -> ConfidenceLevel:
    if has_nuclei and has_cve_match and has_version_match:
        return ConfidenceLevel.CONFIRMED
    if has_nuclei and has_cve_match:
        return ConfidenceLevel.HIGH
    if has_cve_match and has_version_match:
        return ConfidenceLevel.HIGH
    if has_nuclei:
        return ConfidenceLevel.MEDIUM
    if has_cve_match:
        return ConfidenceLevel.MEDIUM
    if has_evidence:
        return ConfidenceLevel.LOW
    return ConfidenceLevel.LOW


def evaluate_from_finding(
    category: str | None = None,
    cvss: float | None = None,
    epss: float | None = None,
    kev: bool | None = False,
    evidence: str | None = None,
    source: str | None = None,
) -> ConfidenceLevel:
    has_evidence = bool(evidence and len(evidence) > 5)
    has_cve_match = kev or False
    has_version_match = epss is not None and epss > 0

    source_lower = (source or "").lower()
    has_nuclei = "nuclei" in source_lower

    return evaluate_confidence(
        source=source,
        has_cve_match=has_cve_match,
        has_version_match=has_version_match,
        has_evidence=has_evidence,
        has_nuclei=has_nuclei,
    )
