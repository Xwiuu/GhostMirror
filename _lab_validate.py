"""Lab validation script for Attack Chain Intelligence."""
from __future__ import annotations

import json
from pathlib import Path

from ghostmirror.modules.attack_chain.engine import AttackChainEngine


def validate_lab(name: str):
    project = Path(f"projects/{name}")
    print(f"\n{'='*60}")
    print(f"=== {name.upper()}")
    print(f"{'='*60}")

    engine = AttackChainEngine()
    report = engine.analyze_project(project)

    print(f"Overall Score: {report.overall_score}/100 ({report.risk_level})")
    print(f"Signals: {report.total_signals} | Nodes: {report.total_nodes} | Edges: {report.total_edges} | Chains: {report.total_chains}")

    print(f"\nTop Attack Chains:")
    for tc in report.top_chains[:5]:
        print(f"  #{tc.get('rank', '?')} {tc.get('title', 'N/A')} (Score: {tc.get('score', 0)}, Priority: {tc.get('priority', 'N/A')})")

    print(f"\nBusiness Impact Summary:")
    for bi in report.business_impact_summary[:5]:
        print(f"  - {bi.get('impact', '')} ({bi.get('count', 0)} chains)")

    print(f"\nTechnical Impact Summary:")
    for ti in report.technical_impact_summary[:5]:
        print(f"  - {ti}")

    # Check output files
    ac_dir = project / "profiles" / "attack_chain"
    print(f"\nOutput files:")
    for fname in ["attack_graph.json", "chains.json", "attack_chain_priorities.json", "attack_chain_report.json"]:
        path = ac_dir / fname
        exists = path.exists()
        size = path.stat().st_size if exists else 0
        print(f"  {fname}: {'OK' if exists else 'MISSING'} ({size} bytes)")

    # Check for specific scenarios
    chains_path = ac_dir / "chains.json"
    if chains_path.exists():
        with open(chains_path, "r", encoding="utf-8") as f:
            chains = json.load(f)
        titles = [c.get("title", "") for c in chains]
        print(f"\nChain titles ({len(chains)} total):")
        for t in titles[:10]:
            print(f"  - {t}")

    # Check graph
    graph_path = ac_dir / "attack_graph.json"
    if graph_path.exists():
        with open(graph_path, "r", encoding="utf-8") as f:
            graph = json.load(f)
        nodes = graph.get("nodes", [])
        edges = graph.get("edges", [])
        node_types = {}
        for n in nodes:
            nt = n.get("node_type", "Unknown")
            node_types[nt] = node_types.get(nt, 0) + 1
        print(f"\nAttack Graph: {len(nodes)} nodes, {len(edges)} edges")
        print(f"  Node types: {node_types}")


if __name__ == "__main__":
    for name in ["lab-juice-shop", "lab-dvwa", "lab-vuln-demo"]:
        validate_lab(name)
