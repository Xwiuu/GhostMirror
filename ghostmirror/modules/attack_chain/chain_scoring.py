from __future__ import annotations

import math
from typing import Any

from ghostmirror.models.attack_chain_path import AttackChainPath
from ghostmirror.models.attack_chain_signal import AttackChainSignal, SignalType


class ChainScoringEngine:
    SEVERITY_MAP = {
        "critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.2, "info": 0.0,
    }

    def calculate(
        self, chain: AttackChainPath, signals: list[AttackChainSignal],
    ) -> float:
        severity_score = self._severity_score(signals)
        confidence_score = self._confidence_score(signals)
        count_score = self._signal_count_score(len(signals))
        exploitability_score = self._exploitability_score(signals)
        exposure_score = self._exposure_score(signals)
        business_score = self._business_impact_score(signals)
        known_exploit_score = self._known_exploitation_score(signals)
        sensitive_score = self._sensitive_object_score(signals)
        auth_score = self._auth_context_score(signals)

        weights = {
            "severity": 0.20, "confidence": 0.15, "count": 0.10,
            "exploitability": 0.15, "exposure": 0.10, "business": 0.10,
            "known_exploit": 0.10, "sensitive": 0.05, "auth": 0.05,
        }

        score = (
            weights["severity"] * severity_score
            + weights["confidence"] * confidence_score
            + weights["count"] * count_score
            + weights["exploitability"] * exploitability_score
            + weights["exposure"] * exposure_score
            + weights["business"] * business_score
            + weights["known_exploit"] * known_exploit_score
            + weights["sensitive"] * sensitive_score
            + weights["auth"] * auth_score
        )

        final_score = round(score * 100, 2)
        self._update_chain(chain, final_score, signals)
        return final_score

    def _severity_score(self, signals: list[AttackChainSignal]) -> float:
        if not signals:
            return 0.0
        max_sev = max(
            self.SEVERITY_MAP.get(s.severity.lower(), 0.0) for s in signals
        )
        return max_sev

    def _confidence_score(self, signals: list[AttackChainSignal]) -> float:
        if not signals:
            return 0.0
        return sum(s.confidence for s in signals) / len(signals)

    def _signal_count_score(self, count: int) -> float:
        return min(1.0, count / 10.0)

    def _exploitability_score(self, signals: list[AttackChainSignal]) -> float:
        exploit_types = {
            SignalType.CVE_KNOWN_EXPLOITED,
            SignalType.PUBLIC_EXPLOIT_AVAILABLE,
            SignalType.BOLA_INDICATOR,
            SignalType.BFLA_INDICATOR,
        }
        exploit_count = sum(
            1 for s in signals if s.signal_type in exploit_types
        )
        return min(1.0, exploit_count * 0.4)

    def _exposure_score(self, signals: list[AttackChainSignal]) -> float:
        exposure_types = {
            SignalType.EXPOSED_ADMIN, SignalType.EXPOSED_API,
            SignalType.SOURCE_MAP_EXPOSED, SignalType.SECRET_EXPOSED,
        }
        exp_count = sum(
            1 for s in signals if s.signal_type in exposure_types
        )
        return min(1.0, exp_count * 0.35)

    def _business_impact_score(self, signals: list[AttackChainSignal]) -> float:
        biz_count = sum(
            1 for s in signals
            if s.signal_type == SignalType.BUSINESS_LOGIC_SURFACE
        )
        return min(1.0, biz_count * 0.5)

    def _known_exploitation_score(self, signals: list[AttackChainSignal]) -> float:
        kev = sum(
            1 for s in signals
            if s.signal_type == SignalType.CVE_KNOWN_EXPLOITED
        )
        pub = sum(
            1 for s in signals
            if s.signal_type == SignalType.PUBLIC_EXPLOIT_AVAILABLE
        )
        return min(1.0, kev * 0.5 + pub * 0.3)

    def _sensitive_object_score(self, signals: list[AttackChainSignal]) -> float:
        sens_count = sum(
            1 for s in signals
            if s.signal_type == SignalType.SENSITIVE_OBJECT
        )
        return min(1.0, sens_count * 0.3)

    def _auth_context_score(self, signals: list[AttackChainSignal]) -> float:
        auth_types = {
            SignalType.JWT_DETECTED, SignalType.OAUTH_DETECTED,
            SignalType.AUTH_SURFACE, SignalType.RATE_LIMIT_UNKNOWN,
        }
        auth_count = sum(
            1 for s in signals if s.signal_type in auth_types
        )
        return min(1.0, auth_count * 0.3)

    def _update_chain(
        self, chain: AttackChainPath, score: float, signals: list[AttackChainSignal],
    ) -> None:
        chain.score = score
        chain.confidence = self._confidence_score(signals)
        chain.likelihood = self._calculate_likelihood(signals)
        chain.impact = score
        chain.exploitability = self._exploitability_score(signals)

    def _calculate_likelihood(self, signals: list[AttackChainSignal]) -> float:
        sev = self._severity_score(signals)
        conf = self._confidence_score(signals)
        exploit = self._exploitability_score(signals)
        return round((sev * 0.3 + conf * 0.4 + exploit * 0.3), 2)

    @staticmethod
    def classify_score(score: float) -> str:
        if score >= 80:
            return "critical"
        if score >= 60:
            return "high"
        if score >= 40:
            return "medium"
        return "low"
