"""EvidenceCapture — sanitize and persist payload execution evidence."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ghostmirror.core.logger import get_logger
from ghostmirror.models.payload_result import PayloadResult

logger = get_logger()

SANITIZE_PATTERNS: list[re.Pattern] = [
    re.compile(r"(?i)(token|api_key|secret|password|passwd|credential)\s*[:=]\s*\S+"),
    re.compile(r"(?i)(authorization|bearer)\s+\S+"),
    re.compile(r"(?i)(session|sid|jsessionid)\s*[:=]\s*\S+"),
    re.compile(r"\b[A-Za-z0-9-_]{40,}\b"),
    re.compile(r"\b[A-Fa-f0-9]{32,}\b"),
]


def sanitize_body(body: str, max_length: int = 500) -> str:
    """Sanitize a response body by removing sensitive patterns and truncating."""
    sanitized = body
    for pattern in SANITIZE_PATTERNS:
        sanitized = pattern.sub("[REDACTED]", sanitized)
    if len(sanitized) > max_length:
        sanitized = sanitized[:max_length] + "... [truncated]"
    return sanitized


class EvidenceCapture:
    """Capture and persist sanitized evidence from payload execution."""

    def __init__(self, evidence_dir: Path | str) -> None:
        self.evidence_dir = Path(evidence_dir)

    def save_result(
        self, result: PayloadResult, body_snippet: str = ""
    ) -> str:
        """Save a single payload result with sanitized evidence.

        Returns the relative path to the saved evidence file.
        """
        self.evidence_dir.mkdir(parents=True, exist_ok=True)

        evidence = {
            "target": result.target,
            "url": result.url,
            "method": result.method,
            "parameter": result.parameter,
            "payload_id": result.payload_id,
            "payload_category": result.payload_category,
            "status_code_baseline": result.status_code_baseline,
            "status_code_probe": result.status_code_probe,
            "content_length_diff": result.content_length_diff,
            "matched_signal": result.matched_signal,
            "signal_detail": result.signal_detail,
            "body_snippet_sanitized": sanitize_body(body_snippet),
            "blocked": result.blocked,
            "blocked_reason": result.blocked_reason,
            "dry_run": result.dry_run,
            "error": result.error,
            "timestamp": result.timestamp,
        }

        filename = (
            f"{result.payload_id}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json"
        )
        filepath = self.evidence_dir / filename
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(evidence, f, indent=2, ensure_ascii=False)

        logger.debug("Evidence saved: {}", filepath)
        return str(filepath.relative_to(self.evidence_dir.parent.parent))

    def save_sanitized_batch(
        self, results: list[PayloadResult]
    ) -> list[str]:
        """Save multiple payload results and return their file paths."""
        paths: list[str] = []
        for r in results:
            path = self.save_result(r)
            paths.append(path)
        return paths

    @staticmethod
    def build_evidence_index(
        evidence_dir: Path | str,
    ) -> list[dict[str, Any]]:
        """Build an index of all evidence files in the directory."""
        evidence_dir = Path(evidence_dir)
        if not evidence_dir.exists():
            return []

        index: list[dict[str, Any]] = []
        for f in sorted(evidence_dir.glob("*.json")):
            try:
                with open(f, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
                index.append(
                    {
                        "file": f.name,
                        "target": data.get("target", ""),
                        "payload_id": data.get("payload_id", ""),
                        "matched_signal": data.get("matched_signal"),
                        "timestamp": data.get("timestamp", ""),
                    }
                )
            except Exception as exc:
                logger.warning("Failed to read evidence {}: {}", f, exc)
        return index
