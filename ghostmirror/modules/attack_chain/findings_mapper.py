from __future__ import annotations

from typing import Any

from ghostmirror.core.logger import get_logger
from ghostmirror.models.attack_chain_signal import AttackChainSignal, SignalType
from ghostmirror.modules.models.finding import FindingModel

logger = get_logger()


class AttackChainFindingsMapper:
    def map_to_findings(
        self, signals: list[AttackChainSignal], report_dict: dict[str, Any],
    ) -> list[FindingModel]:
        findings: list[FindingModel] = []
        for signal in signals:
            import json as _json
            evidence_str = _json.dumps(signal.evidence, default=str) if signal.evidence else ""
            finding = FindingModel(
                id=signal.id,
                title=f"Attack Chain Signal: {signal.signal_type.value}",
                description=self._build_description(signal),
                severity=signal.severity.upper(),
                target=signal.asset,
                evidence=evidence_str,
                recommendation=self._build_recommendation(signal),
                category="attack_chain_intelligence",
                tags=signal.tags,
                created_at=signal.created_at,
            )
            findings.append(finding)
        return findings

    def _build_description(self, signal: AttackChainSignal) -> str:
        parts = [f"Signal type: {signal.signal_type.value}"]
        if signal.asset:
            parts.append(f"Asset: {signal.asset}")
        if signal.endpoint:
            parts.append(f"Endpoint: {signal.endpoint}")
        parts.append(f"Confidence: {signal.confidence}")
        return " | ".join(parts)

    def _build_recommendation(self, signal: AttackChainSignal) -> str:
        recs: dict[SignalType, str] = {
            SignalType.JWT_DETECTED: "Review JWT implementation for security weaknesses",
            SignalType.EXPOSED_ADMIN: "Restrict admin endpoint access",
            SignalType.EXPOSED_API: "Review API endpoint access controls",
            SignalType.SENSITIVE_OBJECT: "Review object-level access controls",
            SignalType.BOLA_INDICATOR: "Implement object-level authorization checks",
            SignalType.BFLA_INDICATOR: "Implement function-level authorization checks",
            SignalType.SECRET_EXPOSED: "Rotate exposed secrets immediately",
            SignalType.SOURCE_MAP_EXPOSED: "Disable source maps in production",
            SignalType.CVE_KNOWN_EXPLOITED: "Patch affected software",
            SignalType.PUBLIC_EXPLOIT_AVAILABLE: "Prioritize patching",
            SignalType.MISSING_HEADER: "Implement missing security headers",
        }
        return recs.get(signal.signal_type, "Investigate this signal further")
