from __future__ import annotations

from ghostmirror.modules.models.finding import FindingModel, FindingSeverity


class BountyFindingsMapper:
    def map(self, report) -> list[FindingModel]:
        findings: list[FindingModel] = []

        if report.sourcemap_findings:
            for sm in report.sourcemap_findings:
                if sm.get("exposed"):
                    findings.append(FindingModel(
                        title="Exposed Source Map",
                        description=f"Source map exposed at {sm.get('sourcemap_url', '')}",
                        severity=FindingSeverity.HIGH,
                        target=report.target,
                        evidence=f"Files: {len(sm.get('files', []))}, Endpoints: {len(sm.get('endpoints', []))}",
                        recommendation="Remove source maps from production.",
                        category="bug_bounty_sourcemap",
                    ))

        if report.secrets:
            for secret in report.secrets:
                severity_map = {"critical": FindingSeverity.CRITICAL, "high": FindingSeverity.HIGH,
                                "medium": FindingSeverity.MEDIUM, "low": FindingSeverity.LOW}
                findings.append(FindingModel(
                    title=f"Potential Exposed Secret: {secret.type}",
                    description=f"Potential {secret.type} found at {secret.location}. Redacted: {secret.redacted_snippet}",
                    severity=severity_map.get(secret.severity, FindingSeverity.MEDIUM),
                    target=report.target,
                    evidence=f"Location: {secret.location}\nType: {secret.type}\nRedacted: {secret.redacted_snippet}",
                    recommendation="Review and rotate the exposed secret.",
                    category="bug_bounty_secret",
                ))

        if report.interesting_files:
            for entry in report.interesting_files:
                if entry.get("found"):
                    findings.append(FindingModel(
                        title=f"Interesting File: {entry.get('path', '')}",
                        description=f"File accessible at {entry.get('url', '')}",
                        severity=FindingSeverity.MEDIUM,
                        target=report.target,
                        evidence=f"URL: {entry.get('url', '')}\nStatus: {entry.get('status', 0)}",
                        recommendation="Restrict access to this file.",
                        category="bug_bounty_interesting_file",
                    ))

        return findings
