from ghostmirror.models.finding_priority import FindingPriority


def calculate_priority(
    severity: str,
    exploitability_label: str = "Low",
    likelihood: str = "Medium",
    kev: bool = False,
    cvss: float | None = None,
) -> FindingPriority:
    sev = severity.upper().strip()

    if sev == "CRITICAL" and kev:
        return FindingPriority.P1
    if sev == "CRITICAL" and exploitability_label in ("Critical", "High"):
        return FindingPriority.P1
    if sev == "HIGH" and kev:
        return FindingPriority.P1

    if sev == "CRITICAL":
        return FindingPriority.P2
    if sev == "HIGH" and exploitability_label in ("Critical", "High"):
        return FindingPriority.P2
    if sev == "HIGH" and likelihood in ("High", "Critical"):
        return FindingPriority.P2

    if sev == "HIGH":
        return FindingPriority.P3
    if sev == "MEDIUM" and exploitability_label in ("Critical", "High"):
        return FindingPriority.P3
    if sev == "MEDIUM" and kev:
        return FindingPriority.P3

    if sev == "MEDIUM":
        return FindingPriority.P4
    if sev == "LOW":
        return FindingPriority.P4

    return FindingPriority.P5
