from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ghostmirror.core.logger import get_logger
from ghostmirror.models.hypothesis_report import HypothesisReport
from ghostmirror.modules.zero_day.anomaly_engine import AnomalyEngine
from ghostmirror.modules.zero_day.attack_chain_engine import AttackChainEngine
from ghostmirror.modules.zero_day.business_logic_engine import BusinessLogicEngine
from ghostmirror.modules.zero_day.confidence_engine import ConfidenceEngine
from ghostmirror.modules.zero_day.differential_engine import DifferentialEngine
from ghostmirror.modules.zero_day.findings_mapper import ZeroDayFindingsMapper
from ghostmirror.modules.zero_day.hidden_functionality import HiddenFunctionalityEngine
from ghostmirror.modules.zero_day.hypothesis_builder import HypothesisBuilder
from ghostmirror.modules.zero_day.recommendations import ZeroDayRecommendations
from ghostmirror.modules.zero_day.report_builder import ZeroDayReportBuilder
from ghostmirror.modules.zero_day.research_queue import ResearchQueue
from ghostmirror.modules.zero_day.scoring import ZeroDayScoring

logger = get_logger()


class ZeroDayEngine:
    def __init__(self) -> None:
        self.anomaly_engine = AnomalyEngine()
        self.differential_engine = DifferentialEngine()
        self.hidden_functionality_engine = HiddenFunctionalityEngine()
        self.business_logic_engine = BusinessLogicEngine()
        self.attack_chain_engine = AttackChainEngine()
        self.hypothesis_builder = HypothesisBuilder()
        self.research_queue = ResearchQueue()
        self.scoring_engine = ZeroDayScoring()
        self.recommendation_engine = ZeroDayRecommendations()
        self.findings_mapper = ZeroDayFindingsMapper()
        self.report_builder = ZeroDayReportBuilder()
        self.confidence_engine = ConfidenceEngine()

    def analyze_project(
        self,
        project_path: Path | str,
        target_url: str | None = None,
    ) -> HypothesisReport:
        project_path = Path(project_path)
        logger.info("ZERO_DAY_ENGINE_START project={}", project_path.name)

        zero_day_dir = project_path / "profiles" / "zero_day"
        zero_day_dir.mkdir(parents=True, exist_ok=True)

        tech_profile = self._load_json(project_path / "profiles" / "technology_profile.json") or {}
        target = target_url or tech_profile.get("target", "")

        if not target:
            logger.warning("ZERO_DAY_ENGINE_SKIPPED no target available")
            return self._empty_report()

        normalized_target = target if target.startswith("http") else f"https://{target}"

        anomalies = self.anomaly_engine.analyze(project_path)
        self._save_json(zero_day_dir / "anomalies.json", anomalies)

        differential_signals = self.differential_engine.analyze(project_path)
        self._save_json(zero_day_dir / "differential_signals.json", differential_signals)

        hidden_hypotheses = self.hidden_functionality_engine.analyze(project_path)
        self._save_json(zero_day_dir / "hidden_functionality.json", hidden_hypotheses)

        business_opportunities = self.business_logic_engine.analyze(project_path)
        self._save_json(zero_day_dir / "business_logic_opportunities.json", business_opportunities)

        attack_chains = self.attack_chain_engine.analyze(project_path)
        self._save_json(zero_day_dir / "attack_chains.json", attack_chains)

        all_signals = self._collect_all_signals(
            anomalies, differential_signals, hidden_hypotheses,
            attack_chains, business_opportunities,
        )

        opportunities = business_opportunities

        hypotheses = self.hypothesis_builder.build(
            anomalies=anomalies,
            attack_chains=attack_chains,
            opportunities=opportunities,
            signals=all_signals,
        )
        hypotheses.extend(hidden_hypotheses)
        self._save_json(zero_day_dir / "hypotheses.json", hypotheses)

        research_queue = self.research_queue.build(
            hypotheses=hypotheses,
            opportunities=opportunities,
            attack_chains=attack_chains,
        )
        self._save_json(zero_day_dir / "research_queue.json", research_queue)

        overall_score, risk_level = self.scoring_engine.calculate_overall_score(
            anomalies=anomalies,
            attack_chains=attack_chains,
            hypotheses=hypotheses,
            opportunities=opportunities,
        )

        recommendations = self.recommendation_engine.generate(
            anomalies=anomalies,
            attack_chains=attack_chains,
            hypotheses=hypotheses,
            opportunities=opportunities,
            overall_score=overall_score,
        )
        self._save_json(zero_day_dir / "recommendations.json", recommendations)

        findings = self.findings_mapper.map_to_findings(
            anomalies=anomalies,
            attack_chains=attack_chains,
            hypotheses=hypotheses,
            opportunities=opportunities,
        )

        report = self.report_builder.build(
            target=normalized_target,
            anomalies=anomalies,
            differential_signals=differential_signals,
            hidden_hypotheses=hidden_hypotheses,
            business_opportunities=business_opportunities,
            attack_chains=attack_chains,
            hypotheses=hypotheses,
            opportunities=opportunities,
            research_queue=research_queue,
            recommendations=recommendations,
            findings=findings,
            overall_score=overall_score,
            risk_level=risk_level,
        )

        self._save_json(zero_day_dir / "zero_day_report.json", report.model_dump(mode="json"))
        self._save_zero_day_findings(project_path, findings)

        logger.info(
            "ZERO_DAY_ENGINE_DONE anomalies={} chains={} hypotheses={} opps={} queue={} score={}",
            len(anomalies), len(attack_chains), len(hypotheses),
            len(opportunities), len(research_queue), overall_score,
        )

        return report

    def _collect_all_signals(
        self,
        anomalies: list[dict[str, Any]],
        differential_signals: list[dict[str, Any]],
        hidden_hypotheses: list[dict[str, Any]],
        attack_chains: list[dict[str, Any]],
        opportunities: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        signals: list[dict[str, Any]] = []

        for a in anomalies:
            signals.extend(a.get("signals", []))

        signals.extend(differential_signals)

        for h in hidden_hypotheses:
            for sig_str in h.get("signals", []):
                if isinstance(sig_str, str):
                    signals.append({
                        "signal_type": "hidden_functionality",
                        "source": "hidden_functionality_engine",
                        "endpoint": sig_str,
                        "method": "N/A",
                        "expected": "standard",
                        "observed": "hidden",
                        "severity": "MEDIUM",
                        "description": sig_str,
                    })

        return signals

    def _save_json(self, path: Path, data: Any) -> None:
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception as exc:
            logger.warning("ZERO_DAY_SAVE_FAIL path={} error={}", path, exc)

    def _load_json(self, path: Path) -> dict[str, Any] | None:
        if not path.exists():
            return None
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return None

    def _save_zero_day_findings(self, project_path: Path, findings: list[dict[str, Any]]) -> None:
        if not findings:
            return
        try:
            findings_dir = project_path / "findings"
            findings_dir.mkdir(parents=True, exist_ok=True)
            path = findings_dir / "zero_day.json"
            with open(path, "w", encoding="utf-8") as f:
                json.dump(findings, f, indent=2, ensure_ascii=False)
            logger.info("ZERO_DAY_FINDINGS_SAVED count={}", len(findings))
        except Exception as exc:
            logger.warning("ZERO_DAY_FINDINGS_SAVE_FAIL error={}", exc)

    def _empty_report(self) -> HypothesisReport:
        return HypothesisReport(overall_score=0, risk_level="INFO")
