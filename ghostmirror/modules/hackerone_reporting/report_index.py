"""Build and export report index with statistics."""
from __future__ import annotations
import json
from pathlib import Path
from typing import Any
from ghostmirror.models.bounty_submission import BountySubmission

class ReportIndex:
    @staticmethod
    def build_index(submissions: list[BountySubmission]) -> dict[str, Any]:
        stats = {"total": len(submissions), "critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}
        for sub in submissions:
            sev = sub.severity.value.lower()
            if sev in stats:
                stats[sev] += 1
        sorted_subs = sorted(submissions, key=lambda s: ["critical", "high", "medium", "low", "informational"].index(s.severity.value.lower()) if s.severity.value.lower() in ["critical", "high", "medium", "low", "informational"] else 99)
        top_10 = []
        for sub in sorted_subs[:10]:
            top_10.append({"title": sub.title, "severity": sub.severity.value, "priority": sub.priority.value, "asset": sub.affected_asset, "confidence": sub.confidence})
        quick_wins = []
        for sub in submissions:
            if sub.severity.value.lower() in ("high", "critical") and sub.confidence.lower() in ("high", "confirmed"):
                quick_wins.append({"title": sub.title, "severity": sub.severity.value, "confidence": sub.confidence, "asset": sub.affected_asset})
        research_opps = []
        for sub in submissions:
            if sub.generated_from in ("zero_day_hypothesis",) or sub.confidence.lower() == "low":
                research_opps.append({"title": sub.title, "severity": sub.severity.value, "confidence": sub.confidence, "source": sub.generated_from})
        return {
            "stats": stats,
            "top_10": top_10,
            "quick_wins": quick_wins,
            "research_opportunities": research_opps,
        }

    @staticmethod
    def export_index(index_data: dict[str, Any], path: str | Path) -> None:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(index_data, indent=2, default=str), encoding="utf-8")
