"""Format and redact evidence for bounty submissions."""
from __future__ import annotations
import re
from typing import Any
from ghostmirror.models.evidence_block import EvidenceBlock

SENSITIVE_PATTERNS = [
    (r"(?i)(authorization:\s*)(Bearer\s+)?[A-Za-z0-9\-._~+/]+=*", r"\1Bearer [REDACTED]"),
    (r"(?i)(x-api-key:\s*)[A-Za-z0-9\-._~+/]+=*", r"\1[REDACTED]"),
    (r"(?i)(secret[\"\']?\s*[:=]\s*[\"\']?)[A-Za-z0-9\-._~+/]+=*", r"\1[REDACTED]"),
    (r"(?i)(token[\"\']?\s*[:=]\s*[\"\']?)[A-Za-z0-9\-._~+/]+=*", r"\1[REDACTED]"),
    (r"(?i)(password[\"\']?\s*[:=]\s*[\"\']?)[^\"\';\s]+", r"\1[REDACTED]"),
    (r"(?i)(cookie:\s*)[A-Za-z0-9\-._~+/%=;, ]+", r"\1[REDACTED]"),
    (r"(?i)(ey[Jz][A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+)", "[JWT REDACTED]"),
    (r"(?i)(ghp_|gho_|github_pat_)[A-Za-z0-9_]+", "[GITHUB_TOKEN REDACTED]"),
    (r"(?i)(AKIA[0-9A-Z]{16})", "AKIA[REDACTED]"),
    (r"(?i)(sk_live_|pk_live_)[A-Za-z0-9]+", "[STRIPE_KEY REDACTED]"),
]

class EvidenceFormatter:
    @staticmethod
    def redact_sensitive(text):
        r = text
        for p, rep in SENSITIVE_PATTERNS:
            r = re.sub(p, rep, r)
        return r

    @staticmethod
    def create_header_evidence(headers, label="HTTP Response Headers"):
        if isinstance(headers, dict):
            content = "\n".join(f"{k}: {v}" for k, v in headers.items())
        else:
            content = str(headers)
        redacted = EvidenceFormatter.redact_sensitive(content)
        return EvidenceBlock(type="http_headers", label=label, content=redacted, redacted=(redacted != content))

    @staticmethod
    def create_url_evidence(url, label="Affected URL"):
        return EvidenceBlock(type="url", label=label, content=url, redacted=False)

    @staticmethod
    def create_sanitized_secret_evidence(secret_type, hint="", label=""):
        content = f"Detected {secret_type}"
        if hint:
            content += " - " + hint
        content += " [FULL VALUE REDACTED]"
        return EvidenceBlock(type="sanitized_secret", label=label or f"{secret_type.title()} Detected", content=content, redacted=True)

    @staticmethod
    def create_hypothesis_evidence(signals, label=""):
        content = "Observed signals:\n" + "\n".join(f"- {s}" for s in signals)
        return EvidenceBlock(type="hypothesis_signal", label=label or "Hypothesis Signals", content=content, redacted=False)

    @staticmethod
    def format_from_finding(finding):
        blocks = []
        evidence_raw = ""
        if isinstance(finding, dict):
            evidence_raw = finding.get("evidence", "") or ""
        else:
            evidence_raw = getattr(finding, "evidence", "") or ""
        if evidence_raw:
            redacted = EvidenceFormatter.redact_sensitive(evidence_raw)
            blocks.append(EvidenceBlock(type="http_headers", label="Evidence", content=redacted, redacted=(redacted != evidence_raw)))
        return blocks
