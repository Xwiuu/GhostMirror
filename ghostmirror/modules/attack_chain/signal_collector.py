from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ghostmirror.core.logger import get_logger
from ghostmirror.models.attack_chain_signal import AttackChainSignal, SignalType

logger = get_logger()


class SignalCollector:
    def collect(self, project_path: Path | str) -> list[AttackChainSignal]:
        project_path = Path(project_path)
        signals: list[AttackChainSignal] = []
        signals.extend(self._from_web_intelligence(project_path))
        signals.extend(self._from_api_security(project_path))
        signals.extend(self._from_bug_bounty(project_path))
        signals.extend(self._from_zero_day(project_path))
        signals.extend(self._from_vulnerability_intelligence(project_path))
        signals.extend(self._from_finding_intelligence(project_path))
        signals.extend(self._from_headers(project_path))
        signals.extend(self._from_nuclei(project_path))
        signals.extend(self._from_owasp(project_path))
        signals.extend(self._from_ssl_nmap(project_path))
        logger.info("SIGNAL_COLLECTOR total={}", len(signals))
        return signals

    def _from_web_intelligence(self, project_path: Path) -> list[AttackChainSignal]:
        signals: list[AttackChainSignal] = []
        base = project_path / "profiles" / "web_intelligence"
        indicators = self._load_list(base / "web_indicators.json")
        for i in indicators:
            sig_type = self._map_indicator_type(i.get("indicator_type", ""))
            signals.append(AttackChainSignal(
                id=f"web_{i.get('id', '')}",
                source_module="web_intelligence",
                signal_type=sig_type,
                asset=i.get("asset", ""),
                endpoint=i.get("endpoint", ""),
                severity=i.get("severity", "info"),
                confidence=self._normalize_confidence(i.get("confidence", 0.5)),
                evidence=i,
                tags=i.get("tags", []),
            ))
        business_logic = self._load_list(base / "business_logic.json")
        for bl in business_logic:
            signals.append(AttackChainSignal(
                id=f"bl_{bl.get('id', '')}",
                source_module="web_intelligence",
                signal_type=SignalType.BUSINESS_LOGIC_SURFACE,
                asset=bl.get("asset", ""),
                endpoint=bl.get("endpoint", ""),
                severity="medium",
                confidence=self._normalize_confidence(bl.get("confidence", 0.5)),
                evidence=bl,
                tags=["business_logic"],
            ))
        auth = self._load_dict(base / "auth_profile.json") or {}
        if any(auth.get(k, False) for k in ["has_login", "has_admin", "has_register", "has_reset_password", "has_mfa"]):
            signals.append(AttackChainSignal(
                id="auth_surface_web",
                source_module="web_intelligence",
                signal_type=SignalType.AUTH_SURFACE,
                severity=auth.get("severity", "medium"),
                    confidence=self._normalize_confidence(auth.get("confidence", 0.6)),
                evidence=auth,
                tags=["auth"],
            ))
        return signals

    def _from_api_security(self, project_path: Path) -> list[AttackChainSignal]:
        signals: list[AttackChainSignal] = []
        base = project_path / "profiles" / "api_security"
        jwt = self._load_dict(base / "jwt_profile.json") or {}
        if jwt.get("detected", False):
            signals.append(AttackChainSignal(
                id="jwt_detected",
                source_module="api_security",
                signal_type=SignalType.JWT_DETECTED,
                severity="medium",
                confidence=self._normalize_confidence(jwt.get("confidence", 0.7)),
                evidence=jwt,
                tags=["jwt", "auth"],
            ))
        oauth = self._load_dict(base / "oauth_profile.json") or {}
        if oauth.get("detected", False):
            signals.append(AttackChainSignal(
                id="oauth_detected",
                source_module="api_security",
                signal_type=SignalType.OAUTH_DETECTED,
                severity="medium",
                confidence=self._normalize_confidence(oauth.get("confidence", 0.7)),
                evidence=oauth,
                tags=["oauth", "auth"],
            ))
        graphql = self._load_dict(base / "graphql_profile.json") or {}
        if graphql.get("detected", False):
            signals.append(AttackChainSignal(
                id="graphql_surface",
                source_module="api_security",
                signal_type=SignalType.GRAPHQL_SURFACE,
                severity="medium",
                confidence=self._normalize_confidence(graphql.get("confidence", 0.6)),
                evidence=graphql,
                tags=["graphql"],
            ))
        endpoints_raw = self._load_dict(base / "api_inventory.json") or {}
        endpoints = endpoints_raw.get("endpoints", []) if isinstance(endpoints_raw, dict) else (endpoints_raw if isinstance(endpoints_raw, list) else [])
        for ep in endpoints:
            if ep.get("exposed", False):
                signals.append(AttackChainSignal(
                    id=f"exposed_api_{ep.get('id', '')}",
                    source_module="api_security",
                    signal_type=SignalType.EXPOSED_API,
                    asset=ep.get("asset", ""),
                    endpoint=ep.get("path", ""),
                    severity=ep.get("severity", "medium"),
                    confidence=self._normalize_confidence(ep.get("confidence", 0.5)),
                    evidence=ep,
                    tags=["api", "exposed"],
                ))
        for bola in self._load_list(base / "bola_indicators.json"):
            signals.append(AttackChainSignal(
                id=f"bola_{bola.get('id', '')}",
                source_module="api_security",
                signal_type=SignalType.BOLA_INDICATOR,
                asset=bola.get("asset", ""),
                endpoint=bola.get("endpoint", ""),
                severity="high",
                confidence=self._normalize_confidence(bola.get("confidence", 0.6)),
                evidence=bola,
                tags=["bola", "api"],
            ))
        for bfla in self._load_list(base / "bfla_indicators.json"):
            signals.append(AttackChainSignal(
                id=f"bfla_{bfla.get('id', '')}",
                source_module="api_security",
                signal_type=SignalType.BFLA_INDICATOR,
                asset=bfla.get("asset", ""),
                endpoint=bfla.get("endpoint", ""),
                severity="high",
                confidence=self._normalize_confidence(bfla.get("confidence", 0.6)),
                evidence=bfla,
                tags=["bfla", "api"],
            ))
        for ma in self._load_list(base / "mass_assignment_indicators.json"):
            signals.append(AttackChainSignal(
                id=f"mass_asgn_{ma.get('id', '')}",
                source_module="api_security",
                signal_type=SignalType.MASS_ASSIGNMENT_INDICATOR,
                asset=ma.get("asset", ""),
                endpoint=ma.get("endpoint", ""),
                severity="medium",
                confidence=self._normalize_confidence(ma.get("confidence", 0.5)),
                evidence=ma,
                tags=["mass_assignment", "api"],
            ))
        return signals

    def _from_bug_bounty(self, project_path: Path) -> list[AttackChainSignal]:
        signals: list[AttackChainSignal] = []
        base = project_path / "profiles" / "bug_bounty"
        secrets = self._load_list(base / "secrets_discovery.json")
        for s in secrets:
            signals.append(AttackChainSignal(
                id=f"secret_{s.get('id', '')}",
                source_module="bug_bounty",
                signal_type=SignalType.SECRET_EXPOSED,
                asset=s.get("asset", ""),
                endpoint=s.get("url", ""),
                technology=s.get("technology", ""),
                severity="critical",
                confidence=self._normalize_confidence(s.get("confidence", 0.8)),
                evidence=s,
                tags=["secret", "exposure"],
            ))
        sourcemaps = self._load_list(base / "sourcemap_profile.json")
        for sm in sourcemaps:
            signals.append(AttackChainSignal(
                id=f"sourcemap_{sm.get('id', '')}",
                source_module="bug_bounty",
                signal_type=SignalType.SOURCE_MAP_EXPOSED,
                asset=sm.get("asset", ""),
                endpoint=sm.get("url", ""),
                severity="medium",
                confidence=self._normalize_confidence(sm.get("confidence", 0.7)),
                evidence=sm,
                tags=["sourcemap", "exposure"],
            ))
        admin = self._load_list(base / "interesting_files.json")
        for af in admin:
            path_str = af.get("url", af.get("path", ""))
            if "admin" in path_str.lower() or "api" in path_str.lower():
                signals.append(AttackChainSignal(
                    id=f"exposed_{af.get('id', '')}",
                    source_module="bug_bounty",
                    signal_type=SignalType.EXPOSED_ADMIN if "admin" in path_str.lower() else SignalType.EXPOSED_API,
                    asset=af.get("asset", ""),
                    endpoint=path_str,
                    severity="medium",
                    confidence=self._normalize_confidence(af.get("confidence", 0.5)),
                    evidence=af,
                    tags=["exposed", "interesting"],
                ))
        return signals

    def _from_zero_day(self, project_path: Path) -> list[AttackChainSignal]:
        signals: list[AttackChainSignal] = []
        base = project_path / "profiles" / "zero_day"
        hypotheses = self._load_list(base / "hypotheses.json")
        for h in hypotheses:
            signals.append(AttackChainSignal(
                id=f"zd_{h.get('id', '')}",
                source_module="zero_day",
                signal_type=SignalType.ZERO_DAY_HYPOTHESIS,
                asset=h.get("asset", ""),
                endpoint=h.get("endpoint", ""),
                severity="high",
                confidence=self._normalize_confidence(h.get("confidence", 0.4)),
                evidence=h,
                tags=["zero_day", "hypothesis"],
            ))
        return signals

    def _from_vulnerability_intelligence(self, project_path: Path) -> list[AttackChainSignal]:
        signals: list[AttackChainSignal] = []
        base = project_path / "profiles" / "vulnerability_intelligence"
        priorities = self._load_list(base / "vulnerability_priority.json")
        for p in priorities:
            if p.get("public_exploit_available"):
                signals.append(AttackChainSignal(
                    id=f"exploit_{p.get('cve', p.get('id', ''))}",
                    source_module="vulnerability_intelligence",
                    signal_type=SignalType.PUBLIC_EXPLOIT_AVAILABLE,
                    technology=p.get("product", ""),
                    severity="critical",
                    confidence=self._normalize_confidence(p.get("confidence", 0.8)),
                    evidence=p,
                    tags=["exploit", "public", "cve"],
                ))
            if p.get("kev"):
                signals.append(AttackChainSignal(
                    id=f"kev_{p.get('cve', p.get('id', ''))}",
                    source_module="vulnerability_intelligence",
                    signal_type=SignalType.CVE_KNOWN_EXPLOITED,
                    technology=p.get("product", ""),
                    severity="critical",
                    confidence=self._normalize_confidence(p.get("confidence", 0.9)),
                    evidence=p,
                    tags=["kev", "cve"],
                ))
        return signals

    def _from_finding_intelligence(self, project_path: Path) -> list[AttackChainSignal]:
        signals: list[AttackChainSignal] = []
        path = project_path / "profiles" / "finding_intelligence_report.json"
        report = self._load_dict(path)
        if not report:
            return signals
        findings = report.get("top_findings", report.get("enriched_findings", []))
        for f in findings:
            severity = f.get("severity", "info").lower()
            if severity in ("critical", "high"):
                tags = f.get("tags", [])
                signals.append(AttackChainSignal(
                    id=f"finding_{f.get('id', '')}",
                    source_module="finding_intelligence",
                    signal_type=SignalType.SENSITIVE_OBJECT,
                    asset=f.get("target", ""),
                    endpoint=f.get("endpoint", ""),
                    severity=severity,
                    confidence=self._normalize_confidence(f.get("confidence", 0.6)),
                    evidence=f,
                    tags=tags if isinstance(tags, list) else [],
                ))
        return signals

    def _from_headers(self, project_path: Path) -> list[AttackChainSignal]:
        signals: list[AttackChainSignal] = []
        path = project_path / "findings" / "headers.json"
        result = self._load_scan_result(path)
        if result and "findings" in result:
            for f in result["findings"]:
                title = f.get("title", "")
                if "missing" in title.lower() or "header" in title.lower():
                    signals.append(AttackChainSignal(
                        id=f"header_{f.get('id', '')}",
                        source_module="headers",
                        signal_type=SignalType.MISSING_HEADER,
                        severity=f.get("severity", "low"),
                        confidence=self._normalize_confidence(f.get("confidence", 0.9)),
                        evidence=f,
                        tags=["header", "missing"],
                    ))
        return signals

    def _from_nuclei(self, project_path: Path) -> list[AttackChainSignal]:
        signals: list[AttackChainSignal] = []
        path = project_path / "findings" / "nuclei_findings.json"
        findings = self._load_finding_list(path)
        for f in findings:
            severity = f.get("severity", "info").lower()
            if severity in ("critical", "high"):
                tags = f.get("tags", [])
                signals.append(AttackChainSignal(
                    id=f"nuclei_{f.get('id', '')}",
                    source_module="nuclei",
                    signal_type=SignalType.CVE_KNOWN_EXPLOITED if severity == "critical" else SignalType.SENSITIVE_OBJECT,
                    asset=f.get("target", ""),
                    endpoint=f.get("endpoint", ""),
                    severity=severity,
                    confidence=self._normalize_confidence(f.get("confidence", 0.7)),
                    evidence=f,
                    tags=tags if isinstance(tags, list) else [],
                ))
        return signals

    def _from_owasp(self, project_path: Path) -> list[AttackChainSignal]:
        signals: list[AttackChainSignal] = []
        path = project_path / "findings" / "owasp_findings.json"
        findings = self._load_finding_list(path)
        for f in findings:
            severity = f.get("severity", "info").lower()
            if severity in ("critical", "high", "medium"):
                signals.append(AttackChainSignal(
                    id=f"owasp_{f.get('id', '')}",
                    source_module="owasp",
                    signal_type=SignalType.SENSITIVE_OBJECT,
                    asset=f.get("target", ""),
                    endpoint=f.get("endpoint", ""),
                    severity=severity,
                    confidence=self._normalize_confidence(f.get("confidence", 0.6)),
                    evidence=f,
                    tags=f.get("tags", []),
                ))
        return signals

    def _from_ssl_nmap(self, project_path: Path) -> list[AttackChainSignal]:
        signals: list[AttackChainSignal] = []
        for name in ("ssl", "nmap"):
            path = project_path / "findings" / f"{name}.json"
            result = self._load_scan_result(path)
            if result and "findings" in result:
                for f in result["findings"]:
                    severity = f.get("severity", "info").lower()
                    if severity == "high":
                        signals.append(AttackChainSignal(
                            id=f"{name}_{f.get('id', '')}",
                            source_module=name,
                            signal_type=SignalType.SENSITIVE_OBJECT,
                            asset=f.get("target", ""),
                            severity=severity,
                            confidence=self._normalize_confidence(f.get("confidence", 0.7)),
                            evidence=f,
                            tags=[name],
                        ))
        return signals

    def _load_list(self, path: Path) -> list:
        if not path.exists():
            return []
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return data if isinstance(data, list) else []
        except Exception:
            return []

    def _load_dict(self, path: Path) -> dict | None:
        if not path.exists():
            return None
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return None

    def _load_scan_result(self, path: Path) -> dict | None:
        if not path.exists():
            return None
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return None

    def _load_finding_list(self, path: Path) -> list[dict]:
        if not path.exists():
            return []
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, list):
                return data
            if isinstance(data, dict) and "findings" in data:
                return data["findings"]
            return []
        except Exception:
            return []

    def _normalize_confidence(self, value: object) -> float:
        if isinstance(value, (int, float)):
            return float(value)
        if isinstance(value, str):
            mapping = {"very_high": 0.95, "high": 0.8, "medium": 0.5, "low": 0.2, "very_low": 0.1}
            return mapping.get(value.strip().lower(), 0.5)
        return 0.5

    def _map_indicator_type(self, indicator_type: str) -> SignalType:
        mapping = {
            "xss": SignalType.MISSING_HEADER,
            "ssti": SignalType.MISSING_HEADER,
            "ssrf": SignalType.SENSITIVE_OBJECT,
            "idor": SignalType.BOLA_INDICATOR,
            "redirect": SignalType.MISSING_HEADER,
            "traversal": SignalType.SENSITIVE_OBJECT,
            "injection": SignalType.SENSITIVE_OBJECT,
            "business_logic": SignalType.BUSINESS_LOGIC_SURFACE,
        }
        return mapping.get(indicator_type, SignalType.SENSITIVE_OBJECT)
