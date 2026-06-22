from __future__ import annotations

from typing import Any

from ghostmirror.core.logger import get_logger

logger = get_logger()

SIGNAL_QUALITY_MAP: dict[str, int] = {
    "rare_endpoint": 30,
    "unexpected_status": 20,
    "size_inconsistency": 15,
    "differential_status": 25,
    "differential_size": 10,
    "differential_content_type": 10,
    "rare_header": 20,
    "sensitive_header": 35,
    "feature_flag": 40,
    "debug_route": 35,
    "internal_function": 25,
    "sourcemap_exposed": 45,
    "sourcemap_routes": 40,
    "sourcemap_comment": 10,
}


class ConfidenceEngine:
    def __init__(self) -> None:
        pass

    def evaluate_from_signals(self, signals: list[dict[str, Any]]) -> str:
        if not signals:
            return "LOW"

        total_quality = 0
        strong_signals = 0
        unique_sources = set()

        for sig in signals:
            signal_type = sig.get("signal_type", "")
            quality = SIGNAL_QUALITY_MAP.get(signal_type, 10)
            total_quality += quality

            if quality >= 30:
                strong_signals += 1

            source = sig.get("source", "")
            if source:
                unique_sources.add(source)

        signal_count = len(signals)
        source_diversity = len(unique_sources)

        if signal_count >= 4 and strong_signals >= 2 and source_diversity >= 2 and total_quality >= 120:
            return "VERY_HIGH"
        if signal_count >= 3 and strong_signals >= 1 and source_diversity >= 1 and total_quality >= 70:
            return "HIGH"
        if signal_count >= 2 and total_quality >= 30:
            return "MEDIUM"

        return "LOW"

    def evaluate_from_hypothesis_data(
        self,
        anomalies: list[dict[str, Any]],
        attack_chains: list[dict[str, Any]],
        opportunities: list[dict[str, Any]],
    ) -> str:
        score = 0

        for a in anomalies:
            sev = a.get("severity", "LOW")
            if sev == "CRITICAL":
                score += 20
            elif sev == "HIGH":
                score += 15
            elif sev == "MEDIUM":
                score += 10
            else:
                score += 3

        for ac in attack_chains:
            sev = ac.get("severity", "LOW")
            if sev == "CRITICAL":
                score += 30
            elif sev == "HIGH":
                score += 20
            elif sev == "MEDIUM":
                score += 12
            else:
                score += 5

        for o in opportunities:
            prio = o.get("priority", "LOW")
            if prio == "CRITICAL":
                score += 15
            elif prio == "HIGH":
                score += 10
            elif prio == "MEDIUM":
                score += 5
            else:
                score += 2

        if score >= 80:
            return "VERY_HIGH"
        if score >= 50:
            return "HIGH"
        if score >= 20:
            return "MEDIUM"
        return "LOW"

    def evaluate_correlation(
        self,
        signal_types: list[str],
        correlation_strength: float,
    ) -> str:
        base = len(signal_types) * 15
        weighted = base * correlation_strength

        if weighted >= 70:
            return "VERY_HIGH"
        if weighted >= 45:
            return "HIGH"
        if weighted >= 20:
            return "MEDIUM"
        return "LOW"
