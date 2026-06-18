"""Scanner framework model definitions."""

from __future__ import annotations

from ghostmirror.modules.models.finding import (
    FindingModel,
    FindingSeverity,
    ScanResultModel,
)

__all__ = ["FindingSeverity", "FindingModel", "ScanResultModel"]
