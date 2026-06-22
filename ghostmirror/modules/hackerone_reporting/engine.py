"""Main engine for HackerOne-style bounty reporting."""
from __future__ import annotations
import json
from pathlib import Path
from datetime import datetime, timezone
from typing import Any
from ghostmirror.core.logger import get_logger
from ghostmirror.models.bounty_report import BountyReport
from ghostmirror.modules.hackerone_reporting.submission_builder import SubmissionBuilder
from ghostmirror.modules.hackerone_reporting.template_renderer import TemplateRenderer
from ghostmirror.modules.hackerone_reporting.markdown_exporter import MarkdownExporter
from ghostmirror.modules.hackerone_reporting.json_exporter import JSONExporter
from ghostmirror.modules.hackerone_reporting.html_exporter import HTMLExporter
from ghostmirror.modules.hackerone_reporting.report_index import ReportIndex

logger = get_logger()

class HackerOneReportingEngine:
    def __init__(self, project_path: Path | str):
        self.project_path = Path(project_path)
        self.bounty_dir = Path("reports") / "bounty"
        self.bounty_dir.mkdir(parents=True, exist_ok=True)
        self.submissions_dir = self.bounty_dir / "submissions"
        self.submissions_dir.mkdir(parents=True, exist_ok=True)
        self.builder = SubmissionBuilder()
        self.template = TemplateRenderer()
        self.md_exporter = MarkdownExporter()
        self.json_exporter = JSONExporter()
        self.html_exporter = HTMLExporter()
        self.index_builder = ReportIndex()

    def analyze_project(self, project_data: dict[str, Any]) -> BountyReport:
        logger.info("HACKERONE_REPORT_ENGINE_START project={}", self.project_path.name)
        target = "Unknown Target"
        profiles = project_data.get("profiles", {})
        tp = profiles.get("technology_profile") or {}
        if tp and "target" in tp:
            target = tp["target"]
        if not target or target == "Unknown Target":
            findings = project_data.get("findings", {})
            for scanner in ["headers", "ssl", "nmap", "fingerprint"]:
                res = findings.get(scanner)
                if res and hasattr(res, "target"):
                    target = res.target
                    break
        submissions = self.builder.build_all(project_data)
        index_data = self.index_builder.build_index(submissions)
        report = BountyReport(
            target=target,
            submissions=submissions,
            summary_stats=index_data["stats"],
            index={
                "top_10": index_data.get("top_10", []),
                "quick_wins": index_data.get("quick_wins", []),
                "research_opportunities": index_data.get("research_opportunities", []),
            },
        )
        self._save_report(report)
        return report

    def _save_report(self, report: BountyReport) -> None:
        self.json_exporter.export_report(report, self.bounty_dir / "bounty_report.json")
        md_content = self.md_exporter.export_report(report, self.bounty_dir / "bounty_report.md")
        self.html_exporter.export_report(report, self.bounty_dir / "bounty_report.html")
        for i, sub in enumerate(report.submissions):
            h1_id = f"H1-{i+1:03d}"
            safe_title = "".join(c if c.isalnum() or c in " -" else "" for c in sub.title).strip().replace(" ", "-").lower()[:50]
            filename = f"{h1_id}-{safe_title}.md"
            sub_path = self.submissions_dir / filename
            self.md_exporter.export_submission_hackerone(sub, sub_path)
        index_data = self.index_builder.build_index(report.submissions)
        self.index_builder.export_index(index_data, self.bounty_dir / "index.json")
        logger.info("HACKERONE_REPORT_ENGINE_DONE submissions={}", len(report.submissions))
