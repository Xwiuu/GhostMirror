from __future__ import annotations

import json
from pathlib import Path

import pytest

from ghostmirror.models.attack_chain_edge import AttackChainEdge, EdgeType
from ghostmirror.models.attack_chain_node import AttackChainNode, NodeType
from ghostmirror.models.attack_chain_path import AttackChainPath
from ghostmirror.models.attack_chain_signal import AttackChainSignal, SignalType
from ghostmirror.modules.attack_chain.chain_builder import ChainBuilder
from ghostmirror.modules.attack_chain.chain_scoring import ChainScoringEngine
from ghostmirror.modules.attack_chain.chain_templates import (
    get_template_by_name, get_templates_by_type, TEMPLATES,
)
from ghostmirror.modules.attack_chain.engine import AttackChainEngine
from ghostmirror.modules.attack_chain.graph_builder import GraphBuilder
from ghostmirror.modules.attack_chain.signal_collector import SignalCollector


class TestChainScoringExtras:
    def test_exploitability_score_no_exploit(self):
        scoring = ChainScoringEngine()
        signals = [AttackChainSignal(
            id="s1", signal_type=SignalType.MISSING_HEADER,
            severity="low", confidence=0.5, asset="a",
        )]
        assert scoring._exploitability_score(signals) == 0.0

    def test_exposure_score_no_exposure(self):
        scoring = ChainScoringEngine()
        signals = [AttackChainSignal(
            id="s1", signal_type=SignalType.JWT_DETECTED,
            severity="medium", confidence=0.5, asset="a",
        )]
        assert scoring._exposure_score(signals) == 0.0

    def test_classify_static(self):
        assert ChainScoringEngine.classify_score(85) == "critical"
        assert ChainScoringEngine.classify_score(65) == "high"
        assert ChainScoringEngine.classify_score(45) == "medium"
        assert ChainScoringEngine.classify_score(25) == "low"


class TestChainTemplatesExtras:
    def test_get_template_by_name_nonexistent(self):
        assert get_template_by_name("Fake Template") is None

    def test_get_templates_by_type_info_disclosure(self):
        results = get_templates_by_type("information_disclosure")
        assert len(results) >= 1

    def test_all_templates_have_chain_types(self):
        for t in TEMPLATES:
            assert t.chain_type in (
                "authentication_bypass", "api_abuse", "information_disclosure",
                "known_vulnerability", "business_logic_abuse", "credential_exposure",
                "client_side_attack", "zero_day", "general",
            )


class TestChainBuilderExtras:
    def test_find_related_nodes_no_match(self):
        builder = ChainBuilder()
        signal = AttackChainSignal(
            id="s1", signal_type=SignalType.JWT_DETECTED,
            severity="medium", confidence=0.5, asset="nonexistent",
        )
        nodes = [AttackChainNode(id="n1", label="other", node_type=NodeType.ASSET)]
        result = builder._find_related_nodes(signal, nodes)
        assert result == []

    def test_find_related_nodes_match(self):
        builder = ChainBuilder()
        signal = AttackChainSignal(
            id="s1", signal_type=SignalType.JWT_DETECTED,
            severity="medium", confidence=0.5, asset="test.com",
        )
        nodes = [
            AttackChainNode(id="n1", label="test.com", node_type=NodeType.ASSET),
            AttackChainNode(id="n2", label="other", node_type=NodeType.ASSET),
        ]
        result = builder._find_related_nodes(signal, nodes)
        assert len(result) == 1


class TestGraphBuilderExtras:
    def test_build_with_signal_with_endpoint_and_auth(self):
        builder = GraphBuilder()
        signals = [
            AttackChainSignal(id="s1", signal_type=SignalType.OAUTH_DETECTED,
                              asset="app.com", endpoint="/oauth/callback",
                              severity="medium", confidence=0.7),
        ]
        nodes, edges = builder.build(signals)
        auth_nodes = [n for n in nodes if n.node_type == NodeType.AUTH]
        assert len(auth_nodes) >= 1
        api_nodes = [n for n in nodes if n.node_type == NodeType.ENDPOINT]
        assert len(api_nodes) >= 1

    def test_build_with_bfla_and_rate_limit(self):
        builder = GraphBuilder()
        signals = [
            AttackChainSignal(id="s1", signal_type=SignalType.BFLA_INDICATOR,
                              asset="app.com", endpoint="/admin/users",
                              severity="high", confidence=0.7),
            AttackChainSignal(id="s2", signal_type=SignalType.RATE_LIMIT_UNKNOWN,
                              asset="app.com",
                              severity="medium", confidence=0.5),
        ]
        nodes, edges = builder.build(signals)
        assert len(nodes) >= 3


class TestEngineExtras:
    def test_save_json_failure(self):
        engine = AttackChainEngine()
        bad_path = Path("") / "nonexistent_dir" / "file.json"
        engine._save_json(bad_path, {"test": True})

    def test_load_json_nonexistent(self, tmp_path: Path):
        engine = AttackChainEngine()
        result = engine._load_json(tmp_path / "nonexistent.json")
        assert result is None

    def test_analyze_with_save_findings_failure(self, tmp_path: Path):
        engine = AttackChainEngine()
        base = tmp_path / "project"
        base.mkdir(parents=True)
        prof = base / "profiles"
        prof.mkdir()
        find = base / "findings"
        find.mkdir()
        with open(prof / "technology_profile.json", "w", encoding="utf-8") as f:
            json.dump({"target": "test.com"}, f)
        engine._save_findings(base, [])

    def test_analyze_with_mixed_signals(self, tmp_path: Path):
        engine = AttackChainEngine()
        base = tmp_path / "project"
        base.mkdir(parents=True)
        prof = base / "profiles"
        prof.mkdir()
        find = base / "findings"
        find.mkdir()
        with open(prof / "technology_profile.json", "w", encoding="utf-8") as f:
            json.dump({"target": "test.com"}, f)
        wi = prof / "web_intelligence"
        wi.mkdir(parents=True, exist_ok=True)
        with open(wi / "web_indicators.json", "w", encoding="utf-8") as f:
            json.dump([{"id": "xss1", "indicator_type": "xss", "asset": "test.com",
                        "severity": "high", "confidence": 0.8, "tags": ["xss"]}], f)
        report = engine.analyze_project(base)
        assert report.total_signals >= 1


class TestSignalCollectorExtras:
    def test_collect_from_finding_intelligence(self, tmp_path: Path):
        collector = SignalCollector()
        base = tmp_path / "project"
        base.mkdir(parents=True)
        f_dir = base / "profiles"
        f_dir.mkdir(parents=True, exist_ok=True)
        report_data = {
            "top_findings": [
                {"id": "f1", "severity": "critical", "target": "app.com",
                 "confidence": 0.8, "tags": ["critical"]},
                {"id": "f2", "severity": "high", "target": "app.com",
                 "confidence": 0.7, "tags": ["high"]},
            ]
        }
        with open(f_dir / "finding_intelligence_report.json", "w", encoding="utf-8") as f:
            json.dump(report_data, f)
        signals = collector.collect(base)
        assert len(signals) >= 2

    def test_collect_from_nuclei_and_owasp(self, tmp_path: Path):
        collector = SignalCollector()
        base = tmp_path / "project"
        base.mkdir(parents=True)
        f_dir = base / "findings"
        f_dir.mkdir(parents=True, exist_ok=True)
        with open(f_dir / "nuclei_findings.json", "w", encoding="utf-8") as f:
            json.dump([{"id": "n1", "severity": "critical", "target": "app.com",
                        "confidence": 0.8}], f)
        with open(f_dir / "owasp_findings.json", "w", encoding="utf-8") as f:
            json.dump([{"id": "o1", "severity": "high", "target": "app.com",
                        "endpoint": "/api", "confidence": 0.7, "tags": ["api"]}], f)
        signals = collector.collect(base)
        assert len(signals) >= 2

    def test_collect_with_corrupted_files(self, tmp_path: Path):
        collector = SignalCollector()
        base = tmp_path / "project"
        base.mkdir(parents=True)
        p_dir = base / "profiles"
        p_dir.mkdir(parents=True, exist_ok=True)
        (p_dir / "web_intelligence").mkdir(parents=True, exist_ok=True)
        (p_dir / "web_intelligence" / "web_indicators.json").write_text(
            "not valid json", encoding="utf-8"
        )
        signals = collector.collect(base)
        assert len(signals) == 0

    def test_collect_exposed_api_no_endpoint(self, tmp_path: Path):
        collector = SignalCollector()
        base = tmp_path / "project"
        base.mkdir(parents=True)
        api_dir = base / "profiles" / "api_security"
        api_dir.mkdir(parents=True, exist_ok=True)
        with open(api_dir / "api_inventory.json", "w", encoding="utf-8") as f:
            json.dump({
                "endpoints": [{"id": "ep1", "exposed": True, "severity": "medium",
                                "confidence": 0.6}]
            }, f)
        signals = collector.collect(base)
        exposed = [s for s in signals if s.signal_type == SignalType.EXPOSED_API]
        assert len(exposed) == 1

    def test_collect_interesting_files_admin(self, tmp_path: Path):
        collector = SignalCollector()
        base = tmp_path / "project"
        base.mkdir(parents=True)
        bb_dir = base / "profiles" / "bug_bounty"
        bb_dir.mkdir(parents=True, exist_ok=True)
        with open(bb_dir / "interesting_files.json", "w", encoding="utf-8") as f:
            json.dump([
                {"id": "f1", "url": "/admin", "asset": "app.com", "confidence": 0.6},
                {"id": "f2", "url": "/api/docs", "asset": "app.com", "confidence": 0.5},
            ], f)
        signals = collector.collect(base)
        admin = [s for s in signals if s.signal_type == SignalType.EXPOSED_ADMIN]
        api = [s for s in signals if s.signal_type == SignalType.EXPOSED_API]
        assert len(admin) >= 1
        assert len(api) >= 1
