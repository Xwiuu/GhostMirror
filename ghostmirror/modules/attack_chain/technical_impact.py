from __future__ import annotations

from typing import Any

from ghostmirror.models.attack_chain_signal import AttackChainSignal, SignalType


class TechnicalImpactAnalyzer:
    IMPACT_MAP: dict[SignalType, list[str]] = {
        SignalType.JWT_DETECTED: ["potential authorization bypass surface"],
        SignalType.EXPOSED_ADMIN: ["exposed administrative functionality"],
        SignalType.EXPOSED_API: ["exposed API attack surface"],
        SignalType.SENSITIVE_OBJECT: ["possible sensitive object access"],
        SignalType.BOLA_INDICATOR: ["potential authorization bypass surface", "possible sensitive object access"],
        SignalType.BFLA_INDICATOR: ["potential authorization bypass surface"],
        SignalType.MASS_ASSIGNMENT_INDICATOR: ["privilege boundary review required"],
        SignalType.CVE_KNOWN_EXPLOITED: ["known exploited vulnerability surface"],
        SignalType.PUBLIC_EXPLOIT_AVAILABLE: ["increased exploitation risk"],
        SignalType.MISSING_HEADER: ["increased XSS attack surface"],
        SignalType.SOURCE_MAP_EXPOSED: ["exposed API attack surface"],
        SignalType.SECRET_EXPOSED: ["credential compromise surface"],
        SignalType.BUSINESS_LOGIC_SURFACE: ["business logic abuse surface"],
        SignalType.ZERO_DAY_HYPOTHESIS: ["potential unknown vulnerability surface"],
        SignalType.GRAPHQL_SURFACE: ["exposed API attack surface", "possible sensitive object access"],
        SignalType.RATE_LIMIT_UNKNOWN: ["brute force attack surface"],
        SignalType.AUTH_SURFACE: ["potential authorization bypass surface", "privilege boundary review required"],
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
