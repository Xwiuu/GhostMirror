from __future__ import annotations

from typing import Any

from ghostmirror.core.logger import get_logger

logger = get_logger()


class APIScoringEngine:
    def __init__(self) -> None:
        self.opportunities: list[dict[str, Any]] = []

    def calculate_opportunities(self, correlations: list[dict[str, Any]],
                                 attack_surface: dict[str, Any],
                                 bolas: list[dict[str, Any]],
                                 bflas: list[dict[str, Any]],
                                 mass_assignments: list[dict[str, Any]]) -> list[dict[str, Any]]:
        logger.info("API_SCORING_START")
        self.opportunities = []

        for corr in correlations:
            score = corr.get("score", 0)
            classification = corr.get("classification", "LOW")
            self.opportunities.append({
                "type": corr.get("type", ""),
                "title": corr.get("title", ""),
                "description": corr.get("description", ""),
                "score": score,
                "classification": classification,
                "source": "correlation",
            })

        for bola in bolas:
            confidence = bola.get("confidence", "LOW")
            base_score = {"HIGH": 75, "MEDIUM": 50, "LOW": 25}.get(confidence, 25)
            self.opportunities.append({
                "type": "BOLA",
                "title": f"BOLA: {bola.get('method', 'GET')} {bola.get('endpoint', '')}",
                "description": bola.get("description", ""),
                "score": base_score,
                "classification": confidence,
                "source": "bola",
            })

        for bfla in bflas:
            confidence = bfla.get("confidence", "LOW")
            base_score = {"HIGH": 70, "MEDIUM": 45, "LOW": 20}.get(confidence, 20)
            self.opportunities.append({
                "type": "BFLA",
                "title": f"BFLA: {bfla.get('method', 'GET')} {bfla.get('endpoint', '')}",
                "description": bfla.get("description", ""),
                "score": base_score,
                "classification": confidence,
                "source": "bfla",
            })

        for ma in mass_assignments:
            confidence = ma.get("confidence", "LOW")
            base_score = {"HIGH": 65, "MEDIUM": 40, "LOW": 15}.get(confidence, 15)
            self.opportunities.append({
                "type": "MASS_ASSIGNMENT",
                "title": f"Mass Assignment: {ma.get('method', 'POST')} {ma.get('endpoint', '')}",
                "description": ma.get("description", ""),
                "score": base_score,
                "classification": confidence,
                "source": "mass_assignment",
            })

        self.opportunities.sort(key=lambda o: o["score"], reverse=True)

        logger.info("API_SCORING_DONE opportunities={}", len(self.opportunities))
        return self.opportunities

    def calculate_overall_score(self, attack_surface: dict[str, Any],
                                 correlations: list[dict[str, Any]],
                                 opportunities: list[dict[str, Any]]) -> int:
        surface_score = attack_surface.get("exposure_score", 0)

        corr_scores = [c.get("score", 0) for c in correlations]
        avg_corr = sum(corr_scores) / max(len(corr_scores), 1)

        opp_scores = [o.get("score", 0) for o in opportunities]
        avg_opp = sum(opp_scores) / max(len(opp_scores), 1)

        overall = round(0.4 * surface_score + 0.3 * avg_corr + 0.3 * avg_opp)
        return min(overall, 100)

    @staticmethod
    def classify_score(score: int) -> str:
        if score >= 80:
            return "CRITICAL"
        if score >= 60:
            return "HIGH"
        if score >= 35:
            return "MEDIUM"
        if score >= 15:
            return "LOW"
        return "INFO"
