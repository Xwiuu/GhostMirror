"""PayloadEngine — orchestrates safe payload scan lifecycle."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ghostmirror.core.logger import get_logger
from ghostmirror.models.payload_profile import (
    PayloadCategory,
    PayloadProfile,
    SafetyLevel,
)
from ghostmirror.models.payload_result import PayloadResult
from ghostmirror.modules.models.finding import FindingModel
from ghostmirror.modules.payloads.evidence import EvidenceCapture
from ghostmirror.modules.payloads.executor import PayloadExecutor
from ghostmirror.modules.payloads.findings_mapper import PayloadFindingsMapper
from ghostmirror.modules.payloads.payload_sets import get_default_payloads
from ghostmirror.modules.payloads.rate_limiter import RateLimiter
from ghostmirror.modules.payloads.registry import PayloadRegistry
from ghostmirror.modules.payloads.safety import SafetyPolicy

logger = get_logger()

OWASP_CATEGORY_MAP: dict[str, list[PayloadCategory]] = {
    "A03": [
        PayloadCategory.XSS_REFLECTION,
        PayloadCategory.SQL_ERROR_INDICATOR,
        PayloadCategory.TEMPLATE_INJECTION_INDICATOR,
        PayloadCategory.HEADER_INJECTION_INDICATOR,
    ],
    "A10": [
        PayloadCategory.SSRF_SURFACE_INDICATOR,
    ],
    "A01": [
        PayloadCategory.OPEN_REDIRECT_INDICATOR,
        PayloadCategory.PATH_TRAVERSAL_INDICATOR,
    ],
}


class PayloadEngine:
    """Orchestrates a safe payload scan.

    Flow:
    1. Load/register payloads
    2. (Optional) Consume OWASP evidence for surface detection
    3. Execute payloads via PayloadExecutor
    4. Map results to findings
    5. Persist outputs (profile, findings, evidence)
    """

    def __init__(
        self,
        project_path: Path | str,
        target: str,
        dry_run: bool = False,
        confirm_sensitive: bool = False,
    ) -> None:
        self.project_path = Path(project_path)
        self.target = target.strip()
        self.dry_run = dry_run
        self.confirm_sensitive = confirm_sensitive

        self.registry = PayloadRegistry()
        self.safety_policy = SafetyPolicy(confirm_sensitive=confirm_sensitive)
        self.rate_limiter = RateLimiter()
        self.evidence_capture = EvidenceCapture(
            self.project_path / "evidence" / "payloads"
        )
        self.executor = PayloadExecutor(
            target=self.target,
            rate_limiter=self.rate_limiter,
            safety_policy=self.safety_policy,
            evidence_capture=self.evidence_capture,
            dry_run=self.dry_run,
        )
        self.mapper = PayloadFindingsMapper()

    def analyze_project(
        self,
        category: PayloadCategory | None = None,
        parameter: str = "q",
        base_url: str = "",
    ) -> dict[str, Any]:
        """Run the full payload analysis pipeline.

        Args:
            category: Optional filter to run only a specific payload category.
            parameter: The query parameter to inject payloads into.
            base_url: Optional override URL (defaults to self.target).

        Returns:
            A report dictionary with results, findings, profile, and paths.
        """
        logger.info(
            "PAYLOAD_ENGINE_START target={} project={} dry_run={} category={}",
            self.target,
            self.project_path.name,
            self.dry_run,
            category.value if category else "all",
        )

        # 1. Initialize registry with defaults
        self.registry.register_defaults()
        total_registered = self.registry.count()

        # 2. Select payloads
        if category:
            payloads = self.registry.list_by_category(category)
        else:
            payloads = self.registry.list_all()

        # 3. Run OWASP integration (consume evidence)
        owasp_surfaces = self._load_owasp_surfaces()

        logger.info(
            "PAYLOAD_ENGINE_PAYLOADS total={} selected={} owasp_surfaces={}",
            total_registered,
            len(payloads),
            len(owasp_surfaces),
        )

        # 4. Execute payloads
        url = base_url or self.target
        results: list[PayloadResult] = []
        for payload in payloads:
            result = self.executor.execute(payload, base_url=url, parameter=parameter)
            results.append(result)

        # 5. Map results to findings
        findings = self.mapper.to_finding_list(results)

        # 6. Calculate stats
        executed = sum(1 for r in results if not r.blocked and not r.dry_run)
        blocked = sum(1 for r in results if r.blocked)
        matched = sum(1 for r in results if r.matched_signal is not None)

        categories_tested = list(
            dict.fromkeys(r.payload_category for r in results)
        )

        risk_score = min(matched * 5, 100)
        if risk_score <= 20:
            risk_level = "LOW"
        elif risk_score <= 40:
            risk_level = "MEDIUM"
        elif risk_score <= 70:
            risk_level = "HIGH"
        else:
            risk_level = "CRITICAL"

        # 7. Build profile
        profile = PayloadProfile(
            target=self.target,
            total_payloads_registered=total_registered,
            payloads_executed=executed,
            payloads_blocked=blocked,
            findings_generated=len(findings),
            categories_tested=categories_tested,
            risk_score=risk_score,
            risk_level=risk_level,
            dry_run=self.dry_run,
        )

        # 8. Persist outputs
        self._save_outputs(profile, results, findings)

        logger.info(
            "PAYLOAD_ENGINE_COMPLETE target={} executed={} blocked={} "
            "findings={} risk_score={} risk_level={}",
            self.target,
            executed,
            blocked,
            len(findings),
            risk_score,
            risk_level,
        )

        return {
            "target": self.target,
            "total_payloads_registered": total_registered,
            "payloads_executed": executed,
            "payloads_blocked": blocked,
            "findings_generated": len(findings),
            "categories_tested": categories_tested,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "dry_run": self.dry_run,
            "findings": [f.model_dump(mode="json") for f in findings],
            "profile": profile.model_dump(mode="json"),
            "results": [r.model_dump(mode="json") for r in results],
            "owasp_surfaces_consumed": len(owasp_surfaces),
        }

    def _load_owasp_surfaces(self) -> list[dict[str, Any]]:
        """Load OWASP evidence files to identify testable surfaces.

        Returns a list of surface descriptors with parameter names and types.
        """
        surfaces: list[dict[str, Any]] = []
        evidence_dir = self.project_path / "evidence" / "owasp"

        forms_path = evidence_dir / "forms.json"
        if forms_path.exists():
            try:
                with open(forms_path, "r", encoding="utf-8") as f:
                    forms_data = json.load(f)
                for form in forms_data.get("forms", []):
                    for inp in form.get("inputs", []):
                        if inp.get("type") in ("text", "search", "url"):
                            surfaces.append(
                                {
                                    "source": "owasp_forms",
                                    "parameter": inp.get("name", "q"),
                                    "method": form.get("method", "GET"),
                                    "type": "form_field",
                                }
                            )
            except Exception as exc:
                logger.warning("Failed to load OWASP forms evidence: {}", exc)

        enum_path = evidence_dir / "enumeration.json"
        if enum_path.exists():
            try:
                with open(enum_path, "r", encoding="utf-8") as f:
                    enum_data = json.load(f)
                for param in enum_data.get("get_parameters", []):
                    surfaces.append(
                        {
                            "source": "owasp_enumeration",
                            "parameter": param,
                            "method": "GET",
                            "type": "url_parameter",
                        }
                    )
            except Exception as exc:
                logger.warning("Failed to load OWASP enumeration evidence: {}", exc)

        return surfaces

    def _save_outputs(
        self,
        profile: PayloadProfile,
        results: list[PayloadResult],
        findings: list[FindingModel],
    ) -> None:
        """Persist payload profile, findings, and evidence to disk."""
        findings_dir = self.project_path / "findings"
        profiles_dir = self.project_path / "profiles"
        evidence_dir = self.project_path / "evidence" / "payloads"

        findings_dir.mkdir(parents=True, exist_ok=True)
        profiles_dir.mkdir(parents=True, exist_ok=True)
        evidence_dir.mkdir(parents=True, exist_ok=True)

        # payload_findings.json
        with open(
            findings_dir / "payload_findings.json", "w", encoding="utf-8"
        ) as f:
            json.dump(
                [f.model_dump(mode="json") for f in findings],
                f,
                indent=2,
                ensure_ascii=False,
            )

        # payload_profile.json
        with open(
            profiles_dir / "payload_profile.json", "w", encoding="utf-8"
        ) as f:
            json.dump(
                profile.model_dump(mode="json"),
                f,
                indent=2,
                ensure_ascii=False,
            )

        # payload_results.json (all raw results, not findings)
        with open(
            evidence_dir / "payload_results.json", "w", encoding="utf-8"
        ) as f:
            json.dump(
                [r.model_dump(mode="json") for r in results],
                f,
                indent=2,
                ensure_ascii=False,
            )

        # sanitized_evidence.json
        sanitized_list = []
        for r in results:
            sanitized_list.append(
                {
                    "target": r.target,
                    "url": r.url,
                    "method": r.method,
                    "parameter": r.parameter,
                    "payload_id": r.payload_id,
                    "payload_category": r.payload_category,
                    "status_code_baseline": r.status_code_baseline,
                    "status_code_probe": r.status_code_probe,
                    "content_length_diff": r.content_length_diff,
                    "matched_signal": r.matched_signal,
                    "signal_detail": r.signal_detail,
                    "body_snippet_sanitized": r.body_snippet_sanitized,
                    "blocked": r.blocked,
                    "dry_run": r.dry_run,
                    "timestamp": r.timestamp,
                }
            )

        with open(
            evidence_dir / "sanitized_evidence.json", "w", encoding="utf-8"
        ) as f:
            json.dump(sanitized_list, f, indent=2, ensure_ascii=False)

        logger.info(
            "PAYLOAD_OUTPUTS_SAVED findings={} profile={} evidence={}",
            findings_dir / "payload_findings.json",
            profiles_dir / "payload_profile.json",
            evidence_dir,
        )

    @staticmethod
    def check_health(project_path: Path | str) -> dict[str, Any]:
        """Health check for the payload engine.

        Validates registry integrity and safety policy.
        """
        registry = PayloadRegistry()
        registry.register_defaults()
        registry_valid, registry_msg = registry.validate_all()

        safety_valid = True
        safety_msg = "SafetyPolicy OK"
        for p in registry.list_all():
            if not SafetyPolicy.check_payload_value(p.value):
                safety_valid = False
                safety_msg = f"Payload {p.id} contém valor perigoso"
                break

        return {
            "registry_valid": registry_valid,
            "registry_message": registry_msg,
            "safety_policy_valid": safety_valid,
            "safety_policy_message": safety_msg,
            "total_payloads_registered": registry.count(),
            "categories": [c.value for c in registry.list_categories()],
        }
