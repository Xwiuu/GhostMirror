from __future__ import annotations

from pathlib import Path
from typing import Any

from ghostmirror.core.logger import get_logger
from ghostmirror.models.attack_chain_edge import AttackChainEdge, EdgeType
from ghostmirror.models.attack_chain_node import AttackChainNode, NodeType
from ghostmirror.models.attack_chain_signal import AttackChainSignal, SignalType

logger = get_logger()


class GraphBuilder:
    def build(
        self, signals: list[AttackChainSignal]
    ) -> tuple[list[AttackChainNode], list[AttackChainEdge]]:
        nodes: dict[str, AttackChainNode] = {}
        edges: list[AttackChainEdge] = []

        for signal in signals:
            asset_node = self._ensure_node(
                nodes, f"asset_{signal.asset}", signal.asset or "unknown",
                NodeType.ASSET, {"severity": signal.severity},
            )
            if signal.endpoint:
                ep_node = self._ensure_node(
                    nodes, f"ep_{signal.endpoint}", signal.endpoint,
                    NodeType.ENDPOINT, {"severity": signal.severity},
                )
                edges.append(AttackChainEdge(
                    source_id=asset_node.id, target_id=ep_node.id,
                    edge_type=EdgeType.EXPOSES,
                ))

            sig_node = self._ensure_node(
                nodes, f"sig_{signal.id}", signal.signal_type.value,
                NodeType.VULNERABILITY,
                {"severity": signal.severity, "confidence": signal.confidence},
            )

            if signal.endpoint:
                edges.append(AttackChainEdge(
                    source_id=sig_node.id,
                    target_id=f"ep_{signal.endpoint}",
                    edge_type=EdgeType.AFFECTS,
                ))
            else:
                edges.append(AttackChainEdge(
                    source_id=sig_node.id,
                    target_id=asset_node.id,
                    edge_type=EdgeType.AFFECTS,
                ))

            if signal.signal_type in (
                SignalType.JWT_DETECTED, SignalType.OAUTH_DETECTED,
                SignalType.AUTH_SURFACE,
            ):
                auth_node = self._ensure_node(
                    nodes, "auth_system", "Authentication System",
                    NodeType.AUTH, {},
                )
                edges.append(AttackChainEdge(
                    source_id=sig_node.id, target_id=auth_node.id,
                    edge_type=EdgeType.AUTHENTICATES_WITH,
                ))

            if signal.signal_type == SignalType.SENSITIVE_OBJECT:
                obj_node = self._ensure_node(
                    nodes, f"obj_{signal.asset}", signal.asset or "sensitive_data",
                    NodeType.OBJECT, {"severity": signal.severity},
                )
                edges.append(AttackChainEdge(
                    source_id=sig_node.id, target_id=obj_node.id,
                    edge_type=EdgeType.INCREASES_RISK_OF,
                ))

            if signal.signal_type in (
                SignalType.CVE_KNOWN_EXPLOITED, SignalType.PUBLIC_EXPLOIT_AVAILABLE,
            ):
                vuln_node = self._ensure_node(
                    nodes, f"vuln_{signal.id}", signal.signal_type.value,
                    NodeType.VULNERABILITY,
                    {"severity": signal.severity, "technology": signal.technology},
                )
                edges.append(AttackChainEdge(
                    source_id=vuln_node.id, target_id=asset_node.id,
                    edge_type=EdgeType.AFFECTS,
                ))

            if signal.signal_type == SignalType.ZERO_DAY_HYPOTHESIS:
                hyp_node = self._ensure_node(
                    nodes, f"hyp_{signal.id}", signal.signal_type.value,
                    NodeType.HYPOTHESIS, {},
                )
                edges.append(AttackChainEdge(
                    source_id=hyp_node.id, target_id=asset_node.id,
                    edge_type=EdgeType.RELATED_TO,
                ))

            if signal.signal_type == SignalType.BUSINESS_LOGIC_SURFACE:
                biz_node = self._ensure_node(
                    nodes, "biz_logic", "Business Logic",
                    NodeType.BUSINESS_FUNCTION, {},
                )
                edges.append(AttackChainEdge(
                    source_id=sig_node.id, target_id=biz_node.id,
                    edge_type=EdgeType.DEPENDS_ON,
                ))

        logger.info("GRAPH_BUILDER nodes={} edges={}", len(nodes), len(edges))
        return list(nodes.values()), edges

    def _ensure_node(
        self, nodes: dict[str, AttackChainNode], node_id: str, label: str,
        node_type: NodeType, properties: dict[str, Any],
    ) -> AttackChainNode:
        if node_id in nodes:
            return nodes[node_id]
        node = AttackChainNode(
            id=node_id, label=label, node_type=node_type,
            properties=properties,
        )
        nodes[node_id] = node
        return node

    def to_dict(
        self, nodes: list[AttackChainNode], edges: list[AttackChainEdge],
    ) -> dict[str, Any]:
        return {
            "nodes": [n.model_dump(mode="json") for n in nodes],
            "edges": [e.model_dump(mode="json") for e in edges],
        }

    def save_graph(
        self, path: Path, nodes: list[AttackChainNode], edges: list[AttackChainEdge],
    ) -> None:
        import json
        data = self.to_dict(nodes, edges)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        logger.info("GRAPH_SAVED path={}", path)
