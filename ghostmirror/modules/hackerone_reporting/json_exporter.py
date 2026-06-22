"""Export bounty reports and submissions to JSON."""
from __future__ import annotations
import json
from pathlib import Path
from typing import Any
from ghostmirror.models.bounty_submission import BountySubmission
from ghostmirror.models.bounty_report import BountyReport

class JSONExporter:
    @staticmethod
    def _sub_to_dict(sub: BountySubmission) -> dict[str, Any]:
        return {
            "id": sub.id,
            "title": sub.title,
            "severity": sub.severity.value,
            "priority": sub.priority.value,
            "affected_asset": sub.affected_asset,
            "affected_endpoint": sub.affected_endpoint,
            "category": sub.category,
            "cwe": sub.cwe,
            "cvss": sub.cvss,
            "epss": sub.epss,
            "confidence": sub.confidence,
            "summary": sub.summary,
            "impact": sub.impact,
            "steps_to_reproduce": [s.model_dump() for s in sub.steps_to_reproduce],
            "evidence": [e.model_dump() for e in sub.evidence],
            "remediation": sub.remediation,
            "references": sub.references,
            "generated_from": sub.generated_from,
            "created_at": sub.created_at,
        }

    def export_submission(self, sub: BountySubmission, path: str | Path) -> dict[str, Any]:
        data = self._sub_to_dict(sub)
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
        return data

    def export_report(self, report: BountyReport, path: str | Path) -> dict[str, Any]:
        data = {
            "target": report.target,
            "generated_at": report.generated_at,
            "summary_stats": report.summary_stats,
            "index": report.index,
            "submissions": [self._sub_to_dict(s) for s in report.submissions],
        }
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
        return data
