from __future__ import annotations

import uuid
from typing import Any

from ghostmirror.core.logger import get_logger
from ghostmirror.models.attack_chain_node import AttackChainNode
from ghostmirror.models.attack_chain_edge import AttackChainEdge
from ghostmirror.models.attack_chain_path import AttackChainPath
from ghostmirror.models.attack_chain_signal import AttackChainSignal, SignalType
from ghostmirror.modules.attack_chain.chain_templates import TEMPLATES, ChainTemplate
from ghostmirror.modules.attack_chain.chain_scoring import ChainScoringEngine
from ghostmirror.modules.attack_chain.business_impact import BusinessImpactAnalyzer
from ghostmirror.modules.attack_chain.technical_impact import TechnicalImpactAnalyzer
from ghostmirror.modules.attack_chain.recommendations import RecommendationsEngine

logger = get_logger()


class ChainBuilder:
    def __init__(self) -> None:
        self.scoring = ChainScoringEngine()
        self.business_impact = BusinessImpactAnalyzer()
        self.technical_impact = TechnicalImpactAnalyzer()
        self.recommendations = RecommendationsEngine()

    def build_chains(
        self, signals: list[AttackChainSignal],
        nodes: list[AttackChainNode], edges: list[AttackChainEdge],
    ) -> list[AttackChainPath]:
        unused_signals = set(range(len(signals)))
        chains: list[AttackChainPath] = []

        for i, template in enumerate(TEMPLATES):
            matched_indices = self._match_template(template, signals)
            if matched_indices:
                chain_signals = [signals[idx] for idx in matched_indices]
                for idx in matched_indices:
                    unused_signals.discard(idx)
                chain = self._build_chain(template, chain_signals, nodes, edges, i)
                chains.append(chain)

        for idx in unused_signals:
            s = signals[idx]
            chain = AttackChainPath(
                id=f"chain_single_{idx}",
                title=f"Single Signal: {s.signal_type.value}",
                chain_type="single_signal",
                signals=[s.model_dump(mode="json")],
                nodes=self._find_related_nodes(s, nodes),
                edges=[],
            )
            chain.score = self.scoring.calculate(chain, [s])
            chain.business_impact = self.business_impact.analyze([s])
            chain.technical_impact = self.technical_impact.analyze([s])
            chain.defensive_recommendations = self.recommendations.generate([s], chain)
            chain.manual_validation_steps = self._generate_validation_steps([s], chain)
            chain.evidence_summary = self._build_evidence_summary([s])
            chain.priority = "low"
            chains.append(chain)

        logger.info("CHAIN_BUILDER total_chains={}", len(chains))
        return chains

    def _match_template(
        self, template: ChainTemplate, signals: list[AttackChainSignal],
    ) -> list[int]:
        signal_types = [s.signal_type for s in signals]
        required = set(template.required_signals)
        matched = []
        remaining = list(required)

        for i, st in enumerate(signal_types):
            if st in remaining:
                matched.append(i)
                remaining.remove(st)
                if not remaining:
                    break

        if remaining:
            return []

        optional = set(template.optional_signals)
        for i, st in enumerate(signal_types):
            if st in optional and i not in matched:
                matched.append(i)

        return matched

    def _build_chain(
        self, template: ChainTemplate, chain_signals: list[AttackChainSignal],
        nodes: list[AttackChainNode], edges: list[AttackChainEdge],
        template_index: int,
    ) -> AttackChainPath:
        chain_id = f"chain_{template_index}_{uuid.uuid4().hex[:8]}"
        chain = AttackChainPath(
            id=chain_id,
            title=template.name,
            chain_type=template.chain_type,
            signals=[s.model_dump(mode="json") for s in chain_signals],
            nodes=self._find_related_nodes_from_signals(chain_signals, nodes),
            edges=self._find_related_edges_from_signals(chain_signals, edges),
        )

        chain.score = self.scoring.calculate(chain, chain_signals)
        chain.business_impact = self.business_impact.analyze(chain_signals)
        chain.technical_impact = self.technical_impact.analyze(chain_signals)
        chain.defensive_recommendations = self.recommendations.generate(chain_signals, chain)
        chain.manual_validation_steps = self._generate_validation_steps(chain_signals, chain)
        chain.evidence_summary = self._build_evidence_summary(chain_signals)
        chain.priority = "medium"

        return chain

    def _find_related_nodes(
        self, signal: AttackChainSignal, nodes: list[AttackChainNode],
    ) -> list[dict[str, Any]]:
        related: list[dict[str, Any]] = []
        for n in nodes:
            if signal.asset and signal.asset in n.label:
                related.append(n.model_dump(mode="json"))
            if signal.endpoint and signal.endpoint in n.label:
                related.append(n.model_dump(mode="json"))
        return related

    def _find_related_nodes_from_signals(
        self, signals: list[AttackChainSignal], nodes: list[AttackChainNode],
    ) -> list[dict[str, Any]]:
        node_ids: set[str] = set()
        for s in signals:
            for n in nodes:
                if s.asset and s.asset in n.label:
                    node_ids.add(n.id)
                if s.endpoint and s.endpoint in n.label:
                    node_ids.add(n.id)
        return [n.model_dump(mode="json") for n in nodes if n.id in node_ids]

    def _find_related_edges_from_signals(
        self, signals: list[AttackChainSignal], edges: list[AttackChainEdge],
    ) -> list[dict[str, Any]]:
        node_ids: set[str] = set()
        for s in signals:
            node_ids.add(f"sig_{s.id}")
            if s.endpoint:
                node_ids.add(f"ep_{s.endpoint}")
            node_ids.add(f"asset_{s.asset}")
        return [
            e.model_dump(mode="json") for e in edges
            if e.source_id in node_ids or e.target_id in node_ids
        ]

    def _generate_validation_steps(
        self, signals: list[AttackChainSignal], chain: AttackChainPath,
    ) -> list[str]:
        steps: list[str] = []
        for s in signals:
            if s.signal_type == SignalType.JWT_DETECTED:
                steps.append("Review JWT implementation: check algorithm, signature verification, and expiration")
            elif s.signal_type == SignalType.EXPOSED_ADMIN:
                steps.append(f"Verify if admin endpoint {s.endpoint} requires authentication")
            elif s.signal_type == SignalType.EXPOSED_API:
                steps.append(f"Review API endpoint {s.endpoint} for proper access controls")
            elif s.signal_type == SignalType.SENSITIVE_OBJECT:
                steps.append(f"Investigate exposed sensitive objects at {s.asset or s.endpoint}")
            elif s.signal_type == SignalType.BOLA_INDICATOR:
                steps.append("Manually test BOLA by modifying object IDs in API requests")
            elif s.signal_type == SignalType.BFLA_INDICATOR:
                steps.append("Manually test BFLA by accessing other users' resources")
            elif s.signal_type == SignalType.SECRET_EXPOSED:
                steps.append(f"Verify exposed secret at {s.endpoint} and rotate if confirmed")
            elif s.signal_type == SignalType.SOURCE_MAP_EXPOSED:
                steps.append(f"Review source map at {s.endpoint} for sensitive code or API keys")
            elif s.signal_type == SignalType.GRAPHQL_SURFACE:
                steps.append("Review GraphQL introspection and query depth limits")
            elif s.signal_type == SignalType.AUTH_SURFACE:
                steps.append("Review authentication flow for weaknesses and missing controls")
            elif s.signal_type == SignalType.ZERO_DAY_HYPOTHESIS:
                steps.append("Research hypothesis manually - review code, logs, and input handling")
            elif s.signal_type == SignalType.MASS_ASSIGNMENT_INDICATOR:
                steps.append("Test mass assignment by adding unexpected fields to API requests")
        if not steps:
            steps.append("Review the signal evidence and validate the hypothesis manually")
        return steps

    def _build_evidence_summary(
        self, signals: list[AttackChainSignal],
    ) -> str:
        parts = [f"Signal: {s.signal_type.value} (severity={s.severity}, confidence={s.confidence})" for s in signals]
        return "; ".join(parts)
