"""Render bounty submissions in HackerOne and Bugcrowd template formats."""
from __future__ import annotations
from ghostmirror.models.bounty_submission import BountySubmission
from ghostmirror.models.bounty_report import BountyReport

class TemplateRenderer:
    @staticmethod
    def render_hackerone(sub: BountySubmission) -> str:
        md = f"# {sub.title}\n\n"
        md += f"**Severity:** {sub.severity.value}\n"
        md += f"**Priority:** {sub.priority.value}\n"
        md += f"**Asset:** {sub.affected_asset}\n"
        md += f"**Endpoint:** {sub.affected_endpoint}\n"
        md += f"**Category:** {sub.category}\n"
        md += f"**CWE:** {sub.cwe}\n"
        md += f"**CVSS:** {sub.cvss if sub.cvss is not None else 'N/A'}\n"
        md += f"**Confidence:** {sub.confidence}\n"
        md += f"**Generated:** {sub.created_at}\n\n"
        md += "---\n\n## Summary\n\n"
        md += f"{sub.summary}\n\n---\n\n## Impact\n\n"
        md += "### Business Impact\n\n"
        md += f"{sub.impact.get('business', '')}\n\n"
        md += "### Technical Impact\n\n"
        md += f"{sub.impact.get('technical', '')}\n\n"
        md += "---\n\n## Steps to Reproduce\n\n"
        for step in sub.steps_to_reproduce:
            md += f"{step.step_number}. {step.description}  \n"
            if step.expected_observation:
                md += f"   - *Expected: {step.expected_observation}*  \n"
        md += "\n---\n\n## Evidence\n\n"
        for block in sub.evidence:
            md += f"### {block.label}  \n"
            md += f"\n```\n{block.content}\n```\n\n"
            if block.redacted:
                md += "*Sensitive data has been redacted.*\n\n"
        md += "---\n\n## Remediation\n\n"
        md += f"{sub.remediation}\n\n"
        md += "---\n\n## References\n\n"
        for ref in sub.references:
            md += f"- {ref}\n"
        return md

    @staticmethod
    def render_bugcrowd(sub: BountySubmission) -> str:
        md = f"# Vulnerability Report: {sub.title}\n\n"
        md += f"**VRT Classification:** {sub.category}\n"
        md += f"**Severity:** {sub.severity.value} ({sub.priority.value})\n"
        md += f"**Target:** {sub.affected_asset}\n\n"
        md += "---\n\n## Description\n\n"
        md += f"{sub.summary}\n\n"
        md += "## Impact\n\n"
        md += f"{sub.impact.get('technical', '')}\n\n"
        md += "## Steps to Reproduce\n\n"
        for step in sub.steps_to_reproduce:
            md += f"{step.step_number}. {step.description}\n"
        md += "\n## Evidence\n\n"
        for block in sub.evidence:
            md += f"**{block.label}:**\n\n```\n{block.content}\n```\n\n"
        md += "## Remediation\n\n"
        md += f"{sub.remediation}\n\n"
        md += "## References\n\n"
        for ref in sub.references:
            md += f"- {ref}\n"
        return md

    @staticmethod
    def render_internal_pentest(sub: BountySubmission) -> str:
        md = f"# {sub.severity.value} - {sub.title}\n\n"
        md += f"**Asset:** {sub.affected_asset}\n"
        md += f"**Endpoint:** {sub.affected_endpoint}\n"
        md += f"**CWE:** {sub.cwe}\n"
        md += f"**OWASP:** {sub.owasp}\n"
        md += f"**CVSS Score:** {sub.cvss if sub.cvss is not None else 'N/A'}\n"
        md += f"**Confidence:** {sub.confidence}\n\n"
        md += "## Technical Details\n\n"
        md += f"{sub.summary}\n\n"
        md += "## Impact\n\n"
        md += f"{sub.impact.get('business', '')}\n\n"
        md += f"{sub.impact.get('technical', '')}\n\n"
        md += "## Steps to Reproduce\n\n"
        for step in sub.steps_to_reproduce:
            md += f"{step.step_number}. {step.description}\n"
        md += "\n## Evidence\n\n"
        for block in sub.evidence:
            md += f"**{block.label}:**\n```\n{block.content}\n```\n\n"
        md += "## Remediation\n\n"
        md += f"{sub.remediation}\n\n"
        md += "## References\n\n"
        for ref in sub.references:
            md += f"- {ref}\n"
        return md
