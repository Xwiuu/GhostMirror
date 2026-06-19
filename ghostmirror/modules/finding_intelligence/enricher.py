from __future__ import annotations

from ghostmirror.models.enriched_finding import EnrichedFinding
from ghostmirror.models.finding_confidence import ConfidenceLevel
from ghostmirror.models.finding_priority import FindingPriority
from ghostmirror.modules.finding_intelligence.confidence_engine import evaluate_from_finding
from ghostmirror.modules.finding_intelligence.exploitability_engine import exploitability_from_finding
from ghostmirror.modules.finding_intelligence.impact_engine import get_business_impact, get_technical_impact
from ghostmirror.modules.finding_intelligence.priority_engine import calculate_priority
from ghostmirror.modules.finding_intelligence.recommendation_engine import generate_recommendation
from ghostmirror.modules.finding_intelligence.reference_engine import get_references
from ghostmirror.modules.finding_intelligence.severity_engine import likelihood_label_from_score


class FindingEnricher:
    def enrich(self, raw: dict) -> EnrichedFinding:
        title = raw.get("title") or raw.get("name", "")
        severity = (raw.get("severity") or "INFO").upper()
        category = raw.get("category")
        cvss = raw.get("cvss")
        epss = raw.get("epss")
        kev = bool(raw.get("kev", False))
        evidence = raw.get("evidence")
        source = raw.get("source") or raw.get("scanner_name") or raw.get("scanner")

        confidence = evaluate_from_finding(
            category=category, cvss=cvss, epss=epss, kev=kev, evidence=evidence, source=source
        )

        business_impact = get_business_impact(title, category)
        technical_impact = get_technical_impact(title, category)

        exploit_score, exploit_label = exploitability_from_finding(
            cvss=cvss, epss=epss, kev=kev, evidence=evidence
        )

        likelihood_score = self._calculate_likelihood_score(cvss, epss, kev, exploit_score)
        likelihood = likelihood_label_from_score(likelihood_score)

        priority = calculate_priority(
            severity=severity,
            exploitability_label=exploit_label,
            likelihood=likelihood,
            kev=kev,
            cvss=cvss,
        )

        recommendation = raw.get("recommendation") or generate_recommendation(title, category)
        references = raw.get("references") or get_references(category=category, title=title)

        affected_asset = raw.get("target") or raw.get("host") or raw.get("asset")
        affected_component = raw.get("component") or category

        return EnrichedFinding(
            title=title,
            category=category or "General",
            severity=severity,
            cvss=cvss,
            epss=epss,
            kev=kev,
            confidence=confidence,
            likelihood=likelihood,
            exploitability=exploit_label,
            business_impact=business_impact,
            technical_impact=technical_impact,
            priority=priority,
            evidence=evidence,
            recommendation=recommendation,
            references=references,
            affected_asset=affected_asset,
            affected_component=affected_component,
            source_finding=raw,
        )

    def _calculate_likelihood_score(
        self, cvss: float | None, epss: float | None, kev: bool, exploit_score: int
    ) -> int:
        score = 0
        if cvss is not None:
            score += cvss * 5
        if epss is not None:
            score += epss * 50
        if kev:
            score += 20
        score += exploit_score * 0.3
        return int(min(100, max(0, score)))
