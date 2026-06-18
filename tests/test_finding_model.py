"""Unit tests for the Finding Pydantic models."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
import pytest
from pydantic import ValidationError

from ghostmirror.modules.models.finding import (
    FindingModel,
    FindingSeverity,
    ScanResultModel,
)


def test_finding_model_defaults() -> None:
    finding = FindingModel(
        title="Insecure Header",
        description="The header is missing.",
        severity=FindingSeverity.MEDIUM,
        target="example.com",
        recommendation="Enable it.",
    )

    # UUID is generated and valid
    uuid.UUID(finding.id)
    assert finding.created_at.tzinfo is not None  # timezone-aware UTC
    assert finding.severity == FindingSeverity.MEDIUM
    assert finding.evidence is None


def test_finding_model_validation() -> None:
    # Requires title, description, severity, target, recommendation
    with pytest.raises(ValidationError):
        FindingModel(
            title="",
            description="The header is missing.",
            severity=FindingSeverity.MEDIUM,
            target="example.com",
            recommendation="Enable it.",
        )


def test_scan_result_model_valid() -> None:
    started = datetime.now(timezone.utc)
    finished = datetime.now(timezone.utc)
    
    result = ScanResultModel(
        scanner_name="headers",
        target="example.com",
        started_at=started,
        finished_at=finished,
        status="completed",
        findings=[
            FindingModel(
                title="Missing CSP",
                description="CSP is absent.",
                severity=FindingSeverity.MEDIUM,
                target="example.com",
                recommendation="Add CSP.",
            )
        ],
        statistics={"total": 1, "medium": 1},
    )

    assert result.scanner_name == "headers"
    assert len(result.findings) == 1
    assert result.statistics["total"] == 1
