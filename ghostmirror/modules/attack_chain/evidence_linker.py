from __future__ import annotations

from pathlib import Path
from typing import Any

from ghostmirror.core.logger import get_logger
from ghostmirror.models.attack_chain_signal import AttackChainSignal

logger = get_logger()


class EvidenceLinker:
    def link(
        self, signals: list[AttackChainSignal], project_path: Path,
    ) -> list[dict[str, Any]]:
        linked: list[dict[str, Any]] = []
        for signal in signals:
            refs = self._resolve_references(signal, project_path)
            entry = {
                "signal_id": signal.id,
                "signal_type": signal.signal_type.value,
                "source_module": signal.source_module,
                "references": refs,
            }
            linked.append(entry)
        return linked

    def _resolve_references(
        self, signal: AttackChainSignal, project_path: Path,
    ) -> list[dict[str, str]]:
        refs: list[dict[str, str]] = []
        findings_mapping = {
            "web_intelligence": ("findings", "web_intelligence.json"),
            "api_security": ("findings", "api_security.json"),
            "bug_bounty": ("findings", "bug_bounty.json"),
            "zero_day": ("findings", "zero_day.json"),
            "vulnerability_intelligence": ("findings", "vulnerability_intelligence_findings.json"),
            "finding_intelligence": ("profiles", "finding_intelligence_report.json"),
            "headers": ("findings", "headers.json"),
            "nuclei": ("findings", "nuclei_findings.json"),
            "owasp": ("findings", "owasp_findings.json"),
            "ssl": ("findings", "ssl.json"),
            "nmap": ("findings", "nmap.json"),
        }

        if signal.source_module in findings_mapping:
            subdir, filename = findings_mapping[signal.source_module]
            path = project_path / subdir / filename
            if path.exists():
                refs.append({
                    "type": "source_file",
                    "path": str(path),
                    "module": signal.source_module,
                })

        if signal.asset:
            refs.append({
                "type": "asset",
                "value": signal.asset,
                "module": signal.source_module,
            })
        if signal.endpoint:
            refs.append({
                "type": "endpoint",
                "value": signal.endpoint,
                "module": signal.source_module,
            })
        if signal.signal_type.value.startswith("cve_") or signal.signal_type.value.startswith("public_exploit"):
            refs.append({
                "type": "vulnerability",
                "value": signal.signal_type.value,
                "module": signal.source_module,
            })

        return refs
