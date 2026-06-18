"""OWASP Top 10 Light Engine — safe security assessment for OWASP Top 10 indicators."""

from __future__ import annotations

from ghostmirror.modules.owasp.scanner import OWASPScanner
from ghostmirror.modules.owasp.engine import OWASPEngine

__all__ = [
    "OWASPScanner",
    "OWASPEngine",
]
