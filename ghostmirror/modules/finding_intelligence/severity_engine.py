SEVERITY_SCORE_MAP: dict[str, int] = {
    "INFO": 10,
    "LOW": 25,
    "MEDIUM": 50,
    "HIGH": 75,
    "CRITICAL": 100,
}

SCORE_TO_SEVERITY: list[tuple[int, str]] = [
    (90, "CRITICAL"),
    (65, "HIGH"),
    (40, "MEDIUM"),
    (20, "LOW"),
    (0, "INFO"),
]


def severity_to_score(severity: str) -> int:
    normalized = severity.upper().strip()
    return SEVERITY_SCORE_MAP.get(normalized, 0)


def score_to_severity(score: int) -> str:
    for threshold, sev in SCORE_TO_SEVERITY:
        if score >= threshold:
            return sev
    return "INFO"


def likelihood_label_from_score(score: int) -> str:
    if score >= 80:
        return "Critical"
    if score >= 60:
        return "High"
    if score >= 40:
        return "Medium"
    if score >= 20:
        return "Low"
    return "Very Low"


def exploitability_label_from_score(score: int) -> str:
    if score >= 80:
        return "Critical"
    if score >= 60:
        return "High"
    if score >= 40:
        return "Medium"
    if score >= 20:
        return "Low"
    return "Very Low"
