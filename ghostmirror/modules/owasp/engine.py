"""OWASP Engine — orchestrates A01–A10 checks, scoring, persistence, and reporting."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from ghostmirror.core.logger import get_logger
from ghostmirror.models.owasp_finding import OWASPCategory, OWASPFinding
from ghostmirror.models.owasp_profile import OWASPProfile
from ghostmirror.modules.owasp.checks import (
    check_admin_endpoints,
    check_auth_indicators,
    check_cryptographic_failures,
    check_injection_surface,
    check_insecure_design,
    check_integrity,
    check_logging_indicators,
    check_misconfigurations,
    check_ssrf_surface,
    check_vulnerable_components,
)
from ghostmirror.modules.owasp.recommendations import OWASPRecommendationEngine

logger = get_logger()


class OWASPScoreEngine:
    """Computes OWASP risk score from findings."""

    SEVERITY_WEIGHTS = {
        "CRITICAL": 25,
        "HIGH": 15,
        "MEDIUM": 8,
        "LOW": 3,
        "INFO": 1,
    }

    @staticmethod
    def calculate(findings: list[OWASPFinding]) -> tuple[int, str]:
        """Calculate OWASP risk score (0–100) and level."""
        score = sum(
            OWASPScoreEngine.SEVERITY_WEIGHTS.get(
                f.severity.value.upper(), 1
            )
            for f in findings
        )
        score = min(max(score, 0), 100)

        if score <= 20:
            level = "LOW"
        elif score <= 40:
            level = "MEDIUM"
        elif score <= 70:
            level = "HIGH"
        else:
            level = "CRITICAL"

        return score, level


class OWASPEngine:
    """Orchestrates OWASP Top 10 Light assessment, scoring, and persistence."""

    def analyze_project(
        self,
        project_path: Path | str,
        target: str,
    ) -> dict:
        """Run all OWASP A01–A10 checks, score, persist, and return report."""
        project_path = Path(project_path)

        logger.info(
            "OWASP_ENGINE_START target={} project={}",
            target,
            project_path.name,
        )

        # Gather all findings from each category
        all_findings: list[OWASPFinding] = []

        # A01 — Broken Access Control
        a01: list = []
        try:
            a01 = check_admin_endpoints(target)
            all_findings.extend(a01)
        except Exception as exc:
            logger.warning("OWASP A01 check failed: {}", exc)

        has_admin = bool(a01)

        # A02 — Cryptographic Failures (consumes SSL findings)
        try:
            a02 = check_cryptographic_failures(project_path)
            all_findings.extend(a02)
        except Exception as exc:
            logger.warning("OWASP A02 check failed: {}", exc)

        # A03 — Injection Indicators
        try:
            a03 = check_injection_surface(target)
            all_findings.extend(a03)
        except Exception as exc:
            logger.warning("OWASP A03 check failed: {}", exc)

        # A04 — Insecure Design
        try:
            a04 = check_insecure_design(target, has_admin_endpoints=has_admin)
            all_findings.extend(a04)
        except Exception as exc:
            logger.warning("OWASP A04 check failed: {}", exc)

        # A05 — Security Misconfiguration
        try:
            a05 = check_misconfigurations(target)
            all_findings.extend(a05)
        except Exception as exc:
            logger.warning("OWASP A05 check failed: {}", exc)

        # A06 — Vulnerable Components (consumes tech, CVE, Nuclei)
        try:
            a06 = check_vulnerable_components(project_path)
            all_findings.extend(a06)
        except Exception as exc:
            logger.warning("OWASP A06 check failed: {}", exc)

        # A07 — Authentication Indicators
        try:
            a07 = check_auth_indicators(target)
            all_findings.extend(a07)
        except Exception as exc:
            logger.warning("OWASP A07 check failed: {}", exc)

        # A08 — Software and Data Integrity
        try:
            a08 = check_integrity(target)
            all_findings.extend(a08)
        except Exception as exc:
            logger.warning("OWASP A08 check failed: {}", exc)

        # A09 — Security Logging Indicators
        try:
            a09 = check_logging_indicators(target)
            all_findings.extend(a09)
        except Exception as exc:
            logger.warning("OWASP A09 check failed: {}", exc)

        # A10 — SSRF Indicators
        try:
            a10 = check_ssrf_surface(target)
            all_findings.extend(a10)
        except Exception as exc:
            logger.warning("OWASP A10 check failed: {}", exc)

        # Deduplicate by title
        seen_titles: set[str] = set()
        unique_findings: list[OWASPFinding] = []
        for f in all_findings:
            if f.title not in seen_titles:
                seen_titles.add(f.title)
                unique_findings.append(f)
        all_findings = unique_findings

        # Calculate risk score
        score, level = OWASPScoreEngine.calculate(all_findings)

        # Collect active categories
        active_categories = list(
            dict.fromkeys(f.category.value for f in all_findings)
        )

        # Generate recommendations
        active_category_enums = list(
            dict.fromkeys(f.category for f in all_findings)
        )
        recommendations = OWASPRecommendationEngine.generate(
            active_category_enums, all_findings
        )

        # Build profile
        profile = OWASPProfile(
            target=target,
            categories=active_categories,
            findings=all_findings,
            risk_score=score,
            risk_level=level,
            recommendations=recommendations,
            scan_timestamp=datetime.now(timezone.utc).isoformat(),
        )

        # Persist to disk
        self._save_outputs(project_path, profile, all_findings)

        logger.info(
            "OWASP_ENGINE_COMPLETE target={} categories={} findings={} "
            "risk_score={} risk_level={}",
            target,
            len(active_categories),
            len(all_findings),
            score,
            level,
        )

        return {
            "target": target,
            "categories": active_categories,
            "total_categories": len(active_categories),
            "findings": [f.model_dump(mode="json") for f in all_findings],
            "total_findings": len(all_findings),
            "risk_score": score,
            "risk_level": level,
            "recommendations": recommendations,
            "profile": profile.model_dump(mode="json"),
        }

    def _save_outputs(
        self,
        project_path: Path,
        profile: OWASPProfile,
        findings: list[OWASPFinding],
    ) -> None:
        """Persist OWASP findings, profile, and evidence to disk."""
        findings_dir = project_path / "findings"
        profiles_dir = project_path / "profiles"
        evidence_dir = project_path / "evidence" / "owasp"

        findings_dir.mkdir(parents=True, exist_ok=True)
        profiles_dir.mkdir(parents=True, exist_ok=True)
        evidence_dir.mkdir(parents=True, exist_ok=True)

        # Save owasp_findings.json
        with open(
            findings_dir / "owasp_findings.json", "w", encoding="utf-8"
        ) as f:
            json.dump(
                [fm.model_dump(mode="json") for fm in findings],
                f,
                indent=2,
                ensure_ascii=False,
            )

        # Save owasp_profile.json
        with open(
            profiles_dir / "owasp_profile.json", "w", encoding="utf-8"
        ) as f:
            json.dump(
                profile.model_dump(mode="json"),
                f,
                indent=2,
                ensure_ascii=False,
            )

        # Save evidence files
        self._save_enumeration_evidence(evidence_dir, profile)
        self._save_summary_counts(findings_dir, findings, len(profile.categories))

    def _save_enumeration_evidence(
        self, evidence_dir: Path, profile: OWASPProfile
    ) -> None:
        """Save evidence/enumeration.json with basic scan metadata."""
        enum_data = {
            "target": profile.target,
            "scan_timestamp": profile.scan_timestamp,
            "categories_checked": list(OWASPCategory),
            "total_findings": len(profile.findings),
            "risk_score": profile.risk_score,
            "risk_level": profile.risk_level,
        }
        with open(
            evidence_dir / "enumeration.json", "w", encoding="utf-8"
        ) as f:
            json.dump(enum_data, f, indent=2, ensure_ascii=False)

    def _save_summary_counts(
        self,
        findings_dir: Path,
        findings: list[OWASPFinding],
        total_categories: int,
    ) -> None:
        """Save a summary JSON with finding counts by severity."""
        from collections import Counter
        sev_counts: Counter[str] = Counter()
        cat_counts: Counter[str] = Counter()

        for f in findings:
            sev_counts[f.severity.value.upper()] += 1
            cat_counts[f.category.value] += 1

        summary = {
            "total_findings": len(findings),
            "total_categories": total_categories,
            "by_severity": dict(sev_counts),
            "by_category": dict(cat_counts),
        }
        with open(
            findings_dir / "owasp_summary.json", "w", encoding="utf-8"
        ) as f:
            json.dump(summary, f, indent=2, ensure_ascii=False)
