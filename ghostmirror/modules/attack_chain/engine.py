from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ghostmirror.core.logger import get_logger
from ghostmirror.models.attack_chain_report import AttackChainReport
from ghostmirror.modules.attack_chain.signal_collector import SignalCollector
from ghostmirror.modules.attack_chain.graph_builder import GraphBuilder
from ghostmirror.modules.attack_chain.chain_builder import ChainBuilder
from ghostmirror.modules.attack_chain.chain_scoring import ChainScoringEngine
from ghostmirror.modules.attack_chain.chain_classifier import ChainClassifier
from ghostmirror.modules.attack_chain.chain_prioritizer import ChainPrioritizer
from ghostmirror.modules.attack_chain.evidence_linker import EvidenceLinker
from ghostmirror.modules.attack_chain.findings_mapper import AttackChainFindingsMapper
from ghostmirror.modules.attack_chain.report_builder import AttackChainReportBuilder

logger = get_logger()


class AttackChainEngine:
    def __init__(self) -> None:
        self.signal_collector = SignalCollector()
        self.graph_builder = GraphBuilder()
        self.chain_builder = ChainBuilder()
        self.scoring = ChainScoringEngine()
        self.classifier = ChainClassifier()
        self.prioritizer = ChainPrioritizer()
        self.evidence_linker = EvidenceLinker()
        self.findings_mapper = AttackChainFindingsMapper()
        self.report_builder = AttackChainReportBuilder()

    def analyze_project(
        self,
        project_path: Path | str,
        target_url: str | None = None,
    ) -> AttackChainReport:
        project_path = Path(project_path)
        logger.info("ATTACK_CHAIN_ENGINE_START project={}", project_path.name)

        attack_chain_dir = project_path / "profiles" / "attack_chain"
        attack_chain_dir.mkdir(parents=True, exist_ok=True)

        tech_profile = self._load_json(
            project_path / "profiles" / "technology_profile.json"
        ) or {}
        target = target_url or tech_profile.get("target", project_path.name)
        project = project_path.name

        signals = self.signal_collector.collect(project_path)
        self._save_json(attack_chain_dir / "signals.json",
                        [s.model_dump(mode="json") for s in signals])

        nodes, edges = self.graph_builder.build(signals)
        self.graph_builder.save_graph(attack_chain_dir / "attack_graph.json",
                                       nodes, edges)

        chains = self.chain_builder.build_chains(signals, nodes, edges)
        self._save_json(attack_chain_dir / "chains.json",
                        [c.model_dump(mode="json") for c in chains])

        priorities = self.prioritizer.prioritize(chains)
        self._save_json(attack_chain_dir / "attack_chain_priorities.json",
                        [p.model_dump(mode="json") for p in priorities])

        linked_evidence = self.evidence_linker.link(signals, project_path)
        self._save_json(attack_chain_dir / "linked_evidence.json", linked_evidence)

        report = self.report_builder.build(
            target=target,
            project=project,
            signals=signals,
            nodes=nodes,
            edges=edges,
            chains=chains,
            priorities=priorities,
            linked_evidence=linked_evidence,
        )

        self._save_json(attack_chain_dir / "attack_chain_report.json",
                        report.model_dump(mode="json"))

        self._save_findings(project_path, signals)

        logger.info(
            "ATTACK_CHAIN_ENGINE_DONE signals={} nodes={} edges={} chains={} score={}",
            len(signals), len(nodes), len(edges),
            len(chains), report.overall_score,
        )

        return report

    def _save_json(self, path: Path, data: Any) -> None:
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception as exc:
            logger.warning("ATTACK_CHAIN_SAVE_FAIL path={} error={}", path, exc)

    def _load_json(self, path: Path) -> dict[str, Any] | None:
        if not path.exists():
            return None
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return None

    def _save_findings(
        self, project_path: Path, signals: list,
    ) -> None:
        findings = self.findings_mapper.map_to_findings(signals, {})
        if not findings:
            return
        try:
            findings_dir = project_path / "findings"
            findings_dir.mkdir(parents=True, exist_ok=True)
            path = findings_dir / "attack_chain.json"
            with open(path, "w", encoding="utf-8") as f:
                json.dump(
                    [f.model_dump(mode="json") for f in findings],
                    f, indent=2, ensure_ascii=False,
                )
            logger.info("ATTACK_CHAIN_FINDINGS_SAVED count={}", len(findings))
        except Exception as exc:
            logger.warning("ATTACK_CHAIN_FINDINGS_SAVE_FAIL error={}", exc)
