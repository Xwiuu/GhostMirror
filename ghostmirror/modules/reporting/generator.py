"""Central Report Generator class to orchestrate collecting, scoring, and rendering reports."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ghostmirror.core.logger import get_logger
from ghostmirror.modules.reporting.collector import ReportCollector
from ghostmirror.modules.reporting.html_renderer import HTMLReportRenderer
from ghostmirror.modules.reporting.markdown_renderer import MarkdownReportRenderer
from ghostmirror.modules.reporting.pdf_renderer import PDFReportRenderer
from ghostmirror.modules.reporting.scoring import ReportScorer

logger = get_logger()


class ReportGenerator:
    """Orchestrator to generate standard security reports in HTML, MD, and PDF formats."""

    def __init__(self, project_path: Path | str) -> None:
        self.project_path = Path(project_path)
        self.collector = ReportCollector(self.project_path)
        self.reports_dir = self.project_path / "reports"
        self.reports_dir.mkdir(parents=True, exist_ok=True)

    def generate(self, format_name: str) -> dict[str, Any]:
        """Loads data, calculates score, and generates the requested report format.

        Parameters
        ----------
        format_name : str
            The format to generate ('html', 'md', 'pdf', 'all').

        Returns
        -------
        dict[str, Any]
            Dictionary summarizing execution details (score, risk_level, files generated).
        """
        format_name = format_name.lower().strip()
        logger.info(
            "REPORT_GENERATION_START project={} format={}",
            self.project_path.name,
            format_name,
        )

        # 1. Collect findings and profiles
        data = self.collector.collect()

        # 2. Extract target and metadata
        target = "Alvo Interno"
        if data["profiles"].get("technology_profile"):
            target = data["profiles"]["technology_profile"].get("target", target)
        elif data["profiles"].get("vulnerability_profile"):
            target = data["profiles"]["vulnerability_profile"].get(
                "target", target
            )
        else:
            # Fallback to checking any scan result target
            for name in ["headers", "ssl", "nmap", "fingerprint"]:
                res = data["findings"].get(name)
                if res:
                    target = res.target
                    break

        # Load project metadata
        project_name = self.project_path.name
        metadata_path = self.project_path / "metadata.json"
        if metadata_path.exists():
            try:
                with open(metadata_path, "r", encoding="utf-8") as f:
                    meta = json.load(f)
                project_name = meta.get("name", project_name)
            except Exception as exc:
                logger.warning("Failed to load project metadata: {}", exc)

        # Detect lab target from scope
        is_lab = False
        scope_path = self.project_path / "scope.yaml"
        if scope_path.exists():
            try:
                from ghostmirror.core.scope_manager import ScopeManager
                sm = ScopeManager()
                scope_model = sm.load_scope(scope_path)
                is_lab = scope_model.project.lab
            except Exception as exc:
                logger.warning("Failed to read scope for lab detection: {}", exc)

        # 3. Calculate Consolidated Score
        score, level = ReportScorer.calculate_score(
            all_findings=data["all_findings"],
            risk_profile=data["profiles"]["risk_profile"],
            vulnerability_profile=data["profiles"]["vulnerability_profile"],
            owasp_profile=data["profiles"]["owasp_profile"],
        )

        # 4. Render formats
        generated_files = []

        html_content = ""
        # We always render HTML if we need to compile PDF
        if format_name in ("html", "pdf", "all"):
            html_content = HTMLReportRenderer.render(
                project_name=project_name,
                target=target,
                profile=format_name,
                score=score,
                risk_level=level,
                collected_data=data,
                is_lab=is_lab,
            )

        if format_name in ("html", "all"):
            html_path = self.reports_dir / "report.html"
            with open(html_path, "w", encoding="utf-8") as f:
                f.write(html_content)
            generated_files.append(html_path)
            logger.info("REPORT_GENERATION_SUCCESS html={}", html_path)

        if format_name in ("md", "markdown", "all"):
            md_content = MarkdownReportRenderer.render(
                project_name=project_name,
                target=target,
                profile=format_name,
                score=score,
                risk_level=level,
                collected_data=data,
                is_lab=is_lab,
            )
            md_path = self.reports_dir / "report.md"
            with open(md_path, "w", encoding="utf-8") as f:
                f.write(md_content)
            generated_files.append(md_path)
            logger.info("REPORT_GENERATION_SUCCESS md={}", md_path)

        if format_name in ("pdf", "all"):
            pdf_path = self.reports_dir / "report.pdf"
            # If we don't have HTML content yet (because format_name == 'pdf'), generate it
            if not html_content:
                html_content = HTMLReportRenderer.render(
                    project_name=project_name,
                    target=target,
                    profile=format_name,
                    score=score,
                    risk_level=level,
                    collected_data=data,
                    is_lab=is_lab,
                )
            success = PDFReportRenderer.render(html_content, pdf_path)
            if success:
                generated_files.append(pdf_path)
                logger.info("REPORT_GENERATION_SUCCESS pdf={}", pdf_path)
            else:
                logger.warning("REPORT_GENERATION_SKIPPED pdf={}", pdf_path)

        return {
            "score": score,
            "risk_level": level,
            "target": target,
            "generated_files": [str(p) for p in generated_files],
        }
