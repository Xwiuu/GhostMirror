from __future__ import annotations

from typing import Any

from ghostmirror.models.attack_chain_signal import AttackChainSignal, SignalType


class BusinessImpactAnalyzer:
    IMPACT_MAP: dict[SignalType, list[str]] = {
        SignalType.JWT_DETECTED: ["Account takeover risk"],
        SignalType.EXPOSED_ADMIN: ["Admin function abuse", "Unauthorized data access"],
        SignalType.EXPOSED_API: ["API abuse", "Unauthorized data access"],
        SignalType.SENSITIVE_OBJECT: ["Customer data exposure", "Regulatory exposure"],
        SignalType.BOLA_INDICATOR: ["Unauthorized data access", "Customer data exposure"],
        SignalType.BFLA_INDICATOR: ["Account takeover risk", "Unauthorized data access"],
        SignalType.MASS_ASSIGNMENT_INDICATOR: ["Privilege escalation", "Data manipulation"],
        SignalType.CVE_KNOWN_EXPLOITED: ["Brand/reputation impact", "Regulatory exposure"],
        SignalType.PUBLIC_EXPLOIT_AVAILABLE: ["Brand/reputation impact", "Regulatory exposure"],
        SignalType.MISSING_HEADER: ["Brand/reputation impact"],
        SignalType.SOURCE_MAP_EXPOSED: ["Intellectual property exposure"],
        SignalType.SECRET_EXPOSED: ["Account takeover risk", "Unauthorized data access"],
        SignalType.BUSINESS_LOGIC_SURFACE: ["Payment manipulation", "Business logic abuse"],
        SignalType.ZERO_DAY_HYPOTHESIS: ["Brand/reputation impact", "Regulatory exposure"],
        SignalType.GRAPHQL_SURFACE: ["Customer data exposure", "API abuse"],
        SignalType.RATE_LIMIT_UNKNOWN: ["Account takeover risk", "API abuse"],
        SignalType.AUTH_SURFACE: ["Account takeover risk", "Unauthorized data access"],
    }

    def analyze(self, signals: list[AttackChainSignal]) -> list[str]:
        impacts: list[str] = []
        seen: set[str] = set()
        for s in signals:
            for impact in self.IMPACT_MAP.get(s.signal_type, []):
                if impact not in seen:
                    impacts.append(impact)
                    seen.add(impact)
        return impacts
