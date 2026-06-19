from ghostmirror.models.finding_priority import FindingPriority
from ghostmirror.models.enriched_finding import EnrichedFinding
from ghostmirror.models.finding_intelligence_report import FindingIntelligenceReport


def generate_executive_summary(report: FindingIntelligenceReport) -> str:
    parts = []
    parts.append(f"## Executive Summary\n")
    parts.append(f"Dos {report.total_findings} findings identificados:\n")

    p1 = report.priority_counts.get("P1", 0)
    p2 = report.priority_counts.get("P2", 0)
    p3 = report.priority_counts.get("P3", 0)
    p4 = report.priority_counts.get("P4", 0)
    p5 = report.priority_counts.get("P5", 0)

    parts.append(f"- {p1} são P1 (Críticos)")
    parts.append(f"- {p2} são P2 (Altos)")
    parts.append(f"- {p3} são P3 (Médios)")
    parts.append(f"- {p4} são P4 (Baixos)")
    parts.append(f"- {p5} são P5 (Informativos)\n")

    if report.kev_count > 0:
        parts.append(f"- {report.kev_count} estão presentes no catálogo KEV (CISA Known Exploited Vulnerabilities)")

    if report.exploit_count > 0:
        parts.append(f"- {report.exploit_count} possuem exploração conhecida disponível")

    crit = report.severity_counts.get("CRITICAL", 0)
    high = report.severity_counts.get("HIGH", 0)
    if crit > 0 or high > 0:
        parts.append(f"\n### Prioridades Imediatas\n")
        parts.append(f"{crit} vulnerabilidades críticas e {high} vulnerabilidades altas requerem atenção imediata.")
        parts.append("Recomenda-se a mitigação dos findings P1 e P2 na primeira sprint de correção.\n")

    conf_counts = report.confidence_counts
    confirmed = conf_counts.get("CONFIRMED", 0)
    high_conf = conf_counts.get("HIGH", 0)
    if confirmed > 0 or high_conf > 0:
        parts.append(f"\n### Confiança das Descobertas\n")
        parts.append(f"{confirmed} findings confirmados e {high_conf} com alta confiança.")
        parts.append("Findings com confiança CONFIRMED possuem correlação positiva entre múltiplas fontes.\n")

    if report.quick_wins:
        parts.append(f"\n### Quick Wins\n")
        parts.append(f"{len(report.quick_wins)} correções rápidas identificadas que podem ser implementadas imediatamente.\n")

    if report.priority_matrix:
        parts.append(f"\n### Distribution de Prioridades\n")
        for priority in ["P1", "P2", "P3", "P4", "P5"]:
            count = report.priority_matrix.get(priority, 0)
            bar = "█" * count if count > 0 else "∅"
            parts.append(f"  {priority}: {bar} ({count})")

    return "\n".join(parts)


def build_priority_matrix(enriched_findings: list[EnrichedFinding]) -> dict[str, int]:
    matrix: dict[str, int] = {}
    for finding in enriched_findings:
        p = finding.priority.value
        matrix[p] = matrix.get(p, 0) + 1
    return matrix
