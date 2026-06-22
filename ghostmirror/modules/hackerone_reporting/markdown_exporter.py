"""Export bounty reports and submissions to Markdown."""
from __future__ import annotations
from pathlib import Path
from ghostmirror.models.bounty_submission import BountySubmission
from ghostmirror.models.bounty_report import BountyReport
from ghostmirror.modules.hackerone_reporting.template_renderer import TemplateRenderer

class MarkdownExporter:
    def __init__(self):
        self.template = TemplateRenderer()

    def export_submission_hackerone(self, sub: BountySubmission, path: str | Path) -> str:
        md = self.template.render_hackerone(sub)
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(md, encoding="utf-8")
        return md

    def export_submission_bugcrowd(self, sub: BountySubmission, path: str | Path) -> str:
        md = self.template.render_bugcrowd(sub)
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(md, encoding="utf-8")
        return md

    def export_report(self, report: BountyReport, path: str | Path) -> str:
        md = f"# Bug Bounty Report - {report.target}\n\n"
        md += f"**Generated At:** {report.generated_at}\n"
        md += f"**Total Submissions:** {report.summary_stats.get('total', 0)}\n\n"
        md += "---\n\n## Summary Statistics\n\n"
        md += "| Severity | Count |\n| :--- | :--- |\n"
        for sev in ["critical", "high", "medium", "low", "informational"]:
            md += f"| {sev.title()} | {report.summary_stats.get(sev, 0)} |\n"
        md += "\n## Top 10 Findings\n\n"
        top = report.index.get("top_10", [])
        if top:
            for i, item in enumerate(top[:10], 1):
                md += f"{i}. **{item.get('title', '')}** - {item.get('severity', '')}\n"
        else:
            md += "*No findings generated.*\n"
        md += "\n## Submissions\n\n"
        for i, sub in enumerate(report.submissions, 1):
            md += f"### {i}. {sub.title}\n"
            md += f"- **Severity:** {sub.severity.value} | **Priority:** {sub.priority.value}\n"
            md += f"- **Asset:** {sub.affected_asset}\n"
            md += f"- **Confidence:** {sub.confidence}\n"
            md += f"- **Generated From:** {sub.generated_from}\n\n"
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(md, encoding="utf-8")
        return md
