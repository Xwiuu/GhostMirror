from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ghostmirror.core.logger import get_logger
from ghostmirror.models.enriched_finding import EnrichedFinding
from ghostmirror.models.finding_confidence import ConfidenceLevel
from ghostmirror.models.finding_intelligence_report import FindingIntelligenceReport
from ghostmirror.models.finding_priority import FindingPriority
from ghostmirror.modules.finding_intelligence.enricher import FindingEnricher
from ghostmirror.modules.finding_intelligence.executive_mapper import (
    build_priority_matrix,
    generate_executive_summary,
)

logger = get_logger()

QUICK_WIN_CATEGORIES = [
    "missing security header",
    "missing content security policy",
    "missing x-frame-options",
    "missing x-content-type-options",
    "missing strict-transport-security",
    "directory listing",
    "version disclosure",
    "information disclosure",
    "missing referrer-policy",
    "missing permissions-policy",
    "weak cipher",
    "self-signed certificate",
]


class FindingIntelligenceEngine:
    def __init__(self) -> None:
        self.enricher = FindingEnricher()

    def analyze_project(self, project_path: Path | str) -> FindingIntelligenceReport:
        project_path = Path(project_path)
        logger.info("FINDING_INTELLIGENCE_START project={}", project_path.name)

        all_raw_findings = self._load_all_findings(project_path)
        target = self._resolve_target(project_path)

        enriched = []
        for raw in all_raw_findings:
            try:
                ef = self.enricher.enrich(raw)
                enriched.append(ef)
            except Exception as exc:
                logger.warning("FINDING_INTELLIGENCE_SKIP error={} finding={}", exc, raw.get("title", "?"))

        report = self._build_report(project_path.name, target, enriched, total_raw=len(all_raw_findings))
        self._save_report(project_path, report)
        self._save_findings_list(project_path, enriched)
        self._save_top_findings(project_path, report.top_findings)
        self._save_quick_wins(project_path, report.quick_wins)

        logger.info("FINDING_INTELLIGENCE_COMPLETE total={} enriched={}", report.total_findings, report.total_enriched)
        return report

    def _load_all_findings(self, project_path: Path) -> list[dict[str, Any]]:
        findings_dir = project_path / "findings"
        all_raw: list[dict[str, Any]] = []

        if not findings_dir.exists():
            logger.warning("FINDINGS_DIR_NOT_FOUND path={}", findings_dir)
            return all_raw

        for fpath in findings_dir.glob("*.json"):
            try:
                with open(fpath, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, dict):
                    for item in data.get("findings", []):
                        if isinstance(item, dict):
                            item["source"] = fpath.stem
                            all_raw.append(item)
                elif isinstance(data, list):
                    for item in data:
                        if isinstance(item, dict):
                            item["source"] = fpath.stem
                            all_raw.append(item)
            except Exception as exc:
                logger.warning("FINDING_LOAD_FAIL file={} error={}", fpath.name, exc)

        return all_raw

    def _resolve_target(self, project_path: Path) -> str:
        meta_path = project_path / "metadata.json"
        if meta_path.exists():
            try:
                with open(meta_path, "r", encoding="utf-8") as f:
                    meta = json.load(f)
                return meta.get("domain", meta.get("name", ""))
            except Exception:
                pass
        return ""

    def _build_report(
        self, project_name: str, target: str, enriched: list[EnrichedFinding], total_raw: int = 0
    ) -> FindingIntelligenceReport:
        enriched.sort(key=self._sort_key, reverse=True)

        priority_counts: dict[str, int] = {}
        confidence_counts: dict[str, int] = {}
        severity_counts: dict[str, int] = {}
        kev_count = 0
        exploit_count = 0

        for ef in enriched:
            p = ef.priority.value
            priority_counts[p] = priority_counts.get(p, 0) + 1

            c = ef.confidence.value if isinstance(ef.confidence, ConfidenceLevel) else str(ef.confidence)
            confidence_counts[c] = confidence_counts.get(c, 0) + 1

            s = ef.severity.upper()
            severity_counts[s] = severity_counts.get(s, 0) + 1

            if ef.kev:
                kev_count += 1
            if ef.exploitability in ("High", "Critical"):
                exploit_count += 1

        for p in ["P1", "P2", "P3", "P4", "P5"]:
            priority_counts.setdefault(p, 0)
        for c in ["LOW", "MEDIUM", "HIGH", "CONFIRMED"]:
            confidence_counts.setdefault(c, 0)
        for s in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            severity_counts.setdefault(s, 0)

        top_findings = enriched[:10]
        quick_wins = [ef for ef in enriched if self._is_quick_win(ef)][:10]
        priority_matrix = build_priority_matrix(enriched)

        report = FindingIntelligenceReport(
            project=project_name,
            target=target,
            total_findings=total_raw or len(enriched),
            total_enriched=len(enriched),
            enriched_findings=enriched,
            priority_counts=priority_counts,
            confidence_counts=confidence_counts,
            severity_counts=severity_counts,
            kev_count=kev_count,
            exploit_count=exploit_count,
            top_findings=top_findings,
            quick_wins=quick_wins,
            priority_matrix=priority_matrix,
        )

        report.executive_summary = generate_executive_summary(report)
        return report

    def _sort_key(self, ef: EnrichedFinding) -> tuple:
        priority_order = {"P1": 5, "P2": 4, "P3": 3, "P4": 2, "P5": 1}
        severity_order = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
        exploit_order = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Very Low": 1}
        likelihood_order = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Very Low": 1}

        return (
            priority_order.get(ef.priority.value, 0),
            severity_order.get(ef.severity.upper(), 0),
            likelihood_order.get(ef.likelihood, 0),
            exploit_order.get(ef.exploitability, 0),
        )

    def _is_quick_win(self, ef: EnrichedFinding) -> bool:
        title_lower = ef.title.lower()
        cat_lower = (ef.category or "").lower()

        for kw in QUICK_WIN_CATEGORIES:
            if kw in title_lower or kw in cat_lower:
                return True

        return ef.priority in (FindingPriority.P4, FindingPriority.P5)

    def _save_report(self, project_path: Path, report: FindingIntelligenceReport) -> None:
        profiles_dir = project_path / "profiles"
        profiles_dir.mkdir(parents=True, exist_ok=True)
        path = profiles_dir / "finding_intelligence_report.json"
        with open(path, "w", encoding="utf-8") as f:
            json.dump(report.model_dump(mode="json"), f, indent=2, ensure_ascii=False)
        logger.info("FINDING_INTELLIGENCE_SAVED path={}", path)

    def _save_findings_list(self, project_path: Path, enriched: list[EnrichedFinding]) -> None:
        profiles_dir = project_path / "profiles"
        profiles_dir.mkdir(parents=True, exist_ok=True)
        path = profiles_dir / "enriched_findings.json"
        with open(path, "w", encoding="utf-8") as f:
            json.dump(
                [ef.model_dump(mode="json") for ef in enriched],
                f, indent=2, ensure_ascii=False,
            )
        logger.info("ENRICHED_FINDINGS_SAVED count={} path={}", len(enriched), path)

    def _save_top_findings(self, project_path: Path, top: list[EnrichedFinding]) -> None:
        profiles_dir = project_path / "profiles"
        profiles_dir.mkdir(parents=True, exist_ok=True)
        path = profiles_dir / "top_findings.json"
        with open(path, "w", encoding="utf-8") as f:
            json.dump(
                [ef.model_dump(mode="json") for ef in top],
                f, indent=2, ensure_ascii=False,
            )
        logger.info("TOP_FINDINGS_SAVED count={} path={}", len(top), path)

    def _save_quick_wins(self, project_path: Path, wins: list[EnrichedFinding]) -> None:
        profiles_dir = project_path / "profiles"
        profiles_dir.mkdir(parents=True, exist_ok=True)
        path = profiles_dir / "quick_wins.json"
        with open(path, "w", encoding="utf-8") as f:
            json.dump(
                [ef.model_dump(mode="json") for ef in wins],
                f, indent=2, ensure_ascii=False,
            )
        logger.info("QUICK_WINS_SAVED count={} path={}", len(wins), path)
