from __future__ import annotations

import json
from pathlib import Path

from ghostmirror.models.attack_chain_signal import AttackChainSignal, SignalType
from ghostmirror.modules.attack_chain.evidence_linker import EvidenceLinker


class TestEvidenceLinker:
    def test_link_empty(self):
        linker = EvidenceLinker()
        result = linker.link([], Path("/tmp"))
        assert len(result) == 0

    def test_link_signal(self, tmp_path: Path):
        linker = EvidenceLinker()
        signal = AttackChainSignal(
            id="test1", signal_type=SignalType.JWT_DETECTED,
            source_module="api_security",
            asset="example.com", severity="medium", confidence=0.8,
        )
        result = linker.link([signal], tmp_path)
        assert len(result) == 1
        assert result[0]["signal_id"] == "test1"
        assert result[0]["source_module"] == "api_security"

    def test_link_with_endpoint(self, tmp_path: Path):
        linker = EvidenceLinker()
        signal = AttackChainSignal(
            id="test1", signal_type=SignalType.EXPOSED_ADMIN,
            source_module="bug_bounty",
            asset="example.com", endpoint="/admin",
            severity="high", confidence=0.7,
        )
        result = linker.link([signal], tmp_path)
        assert len(result) == 1
        refs = result[0]["references"]
        endpoint_refs = [r for r in refs if r["type"] == "endpoint"]
        assert len(endpoint_refs) >= 1

    def test_link_with_source_file(self, tmp_path: Path):
        linker = EvidenceLinker()
        findings_dir = tmp_path / "findings"
        findings_dir.mkdir(parents=True)
        with open(findings_dir / "bug_bounty.json", "w", encoding="utf-8") as f:
            json.dump({"test": True}, f)
        signal = AttackChainSignal(
            id="test1", signal_type=SignalType.SECRET_EXPOSED,
            source_module="bug_bounty",
            asset="example.com", endpoint="/.env",
            severity="critical", confidence=0.9,
        )
        result = linker.link([signal], tmp_path)
        refs = result[0]["references"]
        file_refs = [r for r in refs if r["type"] == "source_file"]
        assert len(file_refs) >= 1

    def test_link_cve_signal(self, tmp_path: Path):
        linker = EvidenceLinker()
        signal = AttackChainSignal(
            id="cve1", signal_type=SignalType.CVE_KNOWN_EXPLOITED,
            source_module="vulnerability_intelligence",
            asset="server", severity="critical", confidence=0.9,
        )
        result = linker.link([signal], tmp_path)
        refs = result[0]["references"]
        vuln_refs = [r for r in refs if r["type"] == "vulnerability"]
        assert len(vuln_refs) >= 1
