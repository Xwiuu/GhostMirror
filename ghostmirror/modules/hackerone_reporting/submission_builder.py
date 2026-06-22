"""Build bounty submissions from various GhostMirror intelligence sources."""
from __future__ import annotations
from typing import Any
from ghostmirror.models.bounty_submission import BountySubmission
from ghostmirror.models.bounty_severity import BountySeverity, BountyPriority
from ghostmirror.modules.hackerone_reporting.severity_mapper import SeverityMapper
from ghostmirror.modules.hackerone_reporting.reproduction_steps import SafeReproductionStepGenerator
from ghostmirror.modules.hackerone_reporting.impact_writer import ImpactWriter
from ghostmirror.modules.hackerone_reporting.evidence_formatter import EvidenceFormatter
from ghostmirror.modules.hackerone_reporting.remediation_writer import RemediationWriter
from ghostmirror.modules.hackerone_reporting.references_mapper import ReferencesMapper

class SubmissionBuilder:
    def __init__(self):
        self.mapper = SeverityMapper()
        self.steps_gen = SafeReproductionStepGenerator()
        self.impact = ImpactWriter()
        self.evidence = EvidenceFormatter()
        self.remediation = RemediationWriter()
        self.references = ReferencesMapper()

    def from_enriched_finding(self, finding: Any) -> BountySubmission:
        if isinstance(finding, dict):
            title = finding.get("title", "")
            severity = finding.get("severity", "INFO")
            category = finding.get("category", "")
            cvss = finding.get("cvss")
            epss = finding.get("epss")
            confidence = finding.get("confidence", "MEDIUM")
            affected = finding.get("affected_asset", "")
            endpoint = finding.get("affected_endpoint", "")
            evidence_raw = finding.get("evidence", "")
            cwe = finding.get("cwe", "")
        else:
            title = getattr(finding, "title", "")
            severity = getattr(finding, "severity", "INFO")
            category = getattr(finding, "category", "")
            cvss = getattr(finding, "cvss", None)
            epss = getattr(finding, "epss", None)
            confidence = getattr(finding, "confidence", "MEDIUM")
            affected = getattr(finding, "affected_asset", "")
            endpoint = getattr(finding, "affected_endpoint", "")
            evidence_raw = getattr(finding, "evidence", "")
            cwe = getattr(finding, "cwe", "")
        if isinstance(severity, str):
            bounty_sev = self.mapper.map_severity(severity)
        else:
            bounty_sev = self.mapper.map_severity(severity.value if hasattr(severity, "value") else "INFO")
        priority = self.mapper.map_severity_to_priority(severity if isinstance(severity, str) else (severity.value if hasattr(severity, "value") else "INFO"))
        conf_str = confidence.value if hasattr(confidence, "value") else str(confidence)
        steps = self.steps_gen.from_finding(finding)
        imp = self.impact.write_impact_section(title, category)
        blocks = self.evidence.format_from_finding(finding)
        rem = self.remediation.generate(category, title)
        refs = self.references.get_references(category, title, cwe)
        summary = f"A {bounty_sev.lower()} severity finding: {title}"
        return BountySubmission(
            title=title,
            severity=BountySeverity(bounty_sev) if hasattr(BountySeverity, bounty_sev.upper().replace(" ", "_")) else BountySeverity.INFORMATIONAL,
            priority=BountyPriority(priority),
            affected_asset=affected,
            affected_endpoint=endpoint,
            category=category,
            cwe=cwe,
            cvss=cvss,
            epss=epss,
            confidence=conf_str,
            summary=summary,
            impact=imp,
            steps_to_reproduce=steps,
            evidence=blocks,
            remediation=rem,
            references=refs,
            generated_from="enriched_finding",
        )

    def from_web_indicator(self, indicator: Any) -> BountySubmission:
        if isinstance(indicator, dict):
            title = indicator.get("name") or indicator.get("title", "Web Security Indicator")
            severity = indicator.get("severity", "MEDIUM")
            category = indicator.get("category", "Web Intelligence")
            endpoint = indicator.get("endpoint", "")
            affected = indicator.get("target", "")
        else:
            title = getattr(indicator, "name", "") or getattr(indicator, "title", "Web Security Indicator")
            severity = getattr(indicator, "severity", "MEDIUM")
            category = getattr(indicator, "category", "Web Intelligence")
            endpoint = getattr(indicator, "endpoint", "")
            affected = getattr(indicator, "target", "")
        bounty_sev = self.mapper.map_severity(severity.value if hasattr(severity, "value") else str(severity))
        priority = self.mapper.map_severity_to_priority(severity.value if hasattr(severity, "value") else str(severity))
        steps = self.steps_gen.from_finding({"title": title, "category": category})
        imp = self.impact.write_impact_section(title, category)
        blocks = self.evidence.format_from_finding(indicator)
        if endpoint and not blocks:
            blocks.append(self.evidence.create_url_evidence(endpoint))
        rem = self.remediation.generate(category, title)
        refs = self.references.get_references(category, title)
        summary = f"Web security indicator: {title}"
        sev_str = bounty_sev
        sev_map = {"Critical": BountySeverity.CRITICAL, "High": BountySeverity.HIGH, "Medium": BountySeverity.MEDIUM, "Low": BountySeverity.LOW, "Informational": BountySeverity.INFORMATIONAL}
        return BountySubmission(
            title=title, severity=sev_map.get(sev_str, BountySeverity.INFORMATIONAL), priority=BountyPriority(priority),
            affected_asset=affected, affected_endpoint=endpoint, category=category,
            summary=summary, impact=imp, steps_to_reproduce=steps, evidence=blocks,
            remediation=rem, references=refs, generated_from="web_indicator",
        )

    def from_zero_day_hypothesis(self, hypothesis: Any) -> BountySubmission:
        if isinstance(hypothesis, dict):
            title = hypothesis.get("title", "Research Hypothesis")
            confidence = hypothesis.get("confidence", "LOW")
        else:
            title = getattr(hypothesis, "title", "Research Hypothesis")
            confidence = getattr(hypothesis, "confidence", "LOW")
        steps = self.steps_gen.from_finding({"title": title, "category": "hypothesis"})
        imp = self.impact.write_impact_section(title, "hypothesis")
        rem = self.remediation.generate("hypothesis", title)
        refs = self.references.get_references("", title)
        summary = f"Research hypothesis requiring manual validation: {title}"
        return BountySubmission(
            title=f"[HYPOTHESIS] {title}", severity=BountySeverity.INFORMATIONAL, priority=BountyPriority.P5,
            category="Zero-Day Hypothesis", confidence=confidence,
            summary=summary, impact=imp, steps_to_reproduce=steps,
            remediation=rem, references=refs, generated_from="zero_day_hypothesis",
        )

    def build_all(self, project_data: dict[str, Any]) -> list[BountySubmission]:
        submissions: list[BountySubmission] = []
        profiles = project_data.get("profiles", {})
        enriched = profiles.get("enriched_findings", [])
        for item in enriched:
            try:
                submissions.append(self.from_enriched_finding(item))
            except Exception:
                pass
        indicators = profiles.get("web_indicators", [])
        for ind in indicators:
            try:
                submissions.append(self.from_web_indicator(ind))
            except Exception:
                pass
        hypotheses = profiles.get("zero_day_hypotheses", [])
        for hyp in hypotheses:
            try:
                submissions.append(self.from_zero_day_hypothesis(hyp))
            except Exception:
                pass
        for vuln_item in (profiles.get("vulnerability_intelligence_report") or {}).get("priorities", []):
            try:
                s = self.from_enriched_finding(vuln_item)
                s.generated_from = "vulnerability_intelligence"
                submissions.append(s)
            except Exception:
                pass
        api_items = (profiles.get("api_opportunities") or []) + (profiles.get("api_bola_indicators") or [])
        for item in api_items:
            try:
                submissions.append(self.from_web_indicator(item))
                submissions[-1].generated_from = "api_indicator"
            except Exception:
                pass
        return submissions
