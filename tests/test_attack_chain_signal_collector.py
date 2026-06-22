from __future__ import annotations

import json
from pathlib import Path

import pytest

from ghostmirror.models.attack_chain_signal import AttackChainSignal, SignalType
from ghostmirror.modules.attack_chain.signal_collector import SignalCollector


class TestSignalCollector:
    @pytest.fixture
    def collector(self) -> SignalCollector:
        return SignalCollector()

    @pytest.fixture
    def project_path(self, tmp_path: Path) -> Path:
        base = tmp_path / "project"
        base.mkdir(parents=True)
        profiles = base / "profiles"
        profiles.mkdir()
        findings = base / "findings"
        findings.mkdir()
        return base

    def _write_json(self, path: Path, data):
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def test_collect_no_data(self, collector: SignalCollector, project_path: Path):
        signals = collector.collect(project_path)
        assert isinstance(signals, list)
        assert len(signals) == 0

    def test_collect_web_indicators(self, collector: SignalCollector, project_path: Path):
        self._write_json(
            project_path / "profiles" / "web_intelligence" / "web_indicators.json",
            [{"id": "xss_1", "indicator_type": "xss", "asset": "example.com",
              "severity": "high", "confidence": 0.8, "tags": ["xss"]}],
        )
        self._write_json(
            project_path / "profiles" / "web_intelligence" / "business_logic.json",
            [{"id": "bl_1", "asset": "example.com", "endpoint": "/checkout",
              "confidence": 0.6}],
        )
        signals = collector.collect(project_path)
        assert len(signals) >= 2

    def test_collect_api_security(self, collector: SignalCollector, project_path: Path):
        self._write_json(
            project_path / "profiles" / "api_security" / "jwt_profile.json",
            {"detected": True, "confidence": 0.9},
        )
        self._write_json(
            project_path / "profiles" / "api_security" / "bola_indicators.json",
            [{"id": "bola_1", "asset": "api", "endpoint": "/users/1",
              "confidence": 0.7}],
        )
        signals = collector.collect(project_path)
        jwt_signals = [s for s in signals if s.signal_type == SignalType.JWT_DETECTED]
        bola_signals = [s for s in signals if s.signal_type == SignalType.BOLA_INDICATOR]
        assert len(jwt_signals) == 1
        assert len(bola_signals) == 1

    def test_collect_bug_bounty_secrets(self, collector: SignalCollector, project_path: Path):
        self._write_json(
            project_path / "profiles" / "bug_bounty" / "secrets_discovery.json",
            [{"id": "sec_1", "asset": "example.com", "url": "/.env",
              "technology": "env", "confidence": 0.95}],
        )
        signals = collector.collect(project_path)
        secret_signals = [s for s in signals if s.signal_type == SignalType.SECRET_EXPOSED]
        assert len(secret_signals) == 1
        assert secret_signals[0].severity == "critical"

    def test_collect_zero_day(self, collector: SignalCollector, project_path: Path):
        self._write_json(
            project_path / "profiles" / "zero_day" / "hypotheses.json",
            [{"id": "hyp_1", "asset": "example.com", "endpoint": "/api",
              "confidence": 0.5}],
        )
        signals = collector.collect(project_path)
        zd_signals = [s for s in signals if s.signal_type == SignalType.ZERO_DAY_HYPOTHESIS]
        assert len(zd_signals) == 1

    def test_collect_vulnerability_intelligence(self, collector: SignalCollector, project_path: Path):
        self._write_json(
            project_path / "profiles" / "vulnerability_intelligence" / "vulnerability_priority.json",
            [{"cve": "CVE-2024-0001", "product": "product_x",
              "public_exploit_available": True, "kev": True, "confidence": 0.9}],
        )
        signals = collector.collect(project_path)
        kev = [s for s in signals if s.signal_type == SignalType.CVE_KNOWN_EXPLOITED]
        exploit = [s for s in signals if s.signal_type == SignalType.PUBLIC_EXPLOIT_AVAILABLE]
        assert len(kev) == 1
        assert len(exploit) == 1

    def test_collect_from_headers(self, collector: SignalCollector, project_path: Path):
        self._write_json(
            project_path / "findings" / "headers.json",
            {"findings": [{"id": "h1", "title": "Missing X-Frame-Options header",
                           "severity": "medium", "confidence": 0.9}]},
        )
        signals = collector.collect(project_path)
        header_signals = [s for s in signals if s.signal_type == SignalType.MISSING_HEADER]
        assert len(header_signals) == 1

    def test_collect_signal_type_values(self):
        assert SignalType.EXPOSED_ADMIN.value == "exposed_admin"
        assert SignalType.AUTH_SURFACE.value == "auth_surface"
        assert SignalType.GRAPHQL_SURFACE.value == "graphql_surface"

    def test_signal_model_validation(self):
        signal = AttackChainSignal(
            id="test_1",
            source_module="test",
            signal_type=SignalType.JWT_DETECTED,
            asset="test_asset",
            endpoint="/api/test",
            severity="high",
            confidence=0.85,
            tags=["jwt", "auth"],
        )
        assert signal.id == "test_1"
        assert signal.signal_type == SignalType.JWT_DETECTED
        assert signal.confidence == 0.85

    def test_map_indicator_type(self, collector: SignalCollector):
        assert collector._map_indicator_type("xss") == SignalType.MISSING_HEADER
        assert collector._map_indicator_type("idor") == SignalType.BOLA_INDICATOR
        assert collector._map_indicator_type("ssrf") == SignalType.SENSITIVE_OBJECT
        assert collector._map_indicator_type("unknown") == SignalType.SENSITIVE_OBJECT

    def test_load_list_nonexistent(self, collector: SignalCollector, tmp_path: Path):
        result = collector._load_list(tmp_path / "nonexistent.json")
        assert result == []

    def test_load_dict_nonexistent(self, collector: SignalCollector, tmp_path: Path):
        result = collector._load_dict(tmp_path / "nonexistent.json")
        assert result is None

    def test_load_scan_result_nonexistent(self, collector: SignalCollector, tmp_path: Path):
        result = collector._load_scan_result(tmp_path / "nonexistent.json")
        assert result is None

    def test_load_finding_list_nonexistent(self, collector: SignalCollector, tmp_path: Path):
        result = collector._load_finding_list(tmp_path / "nonexistent.json")
        assert result == []

    def test_load_list_corrupted(self, collector: SignalCollector, tmp_path: Path):
        path = tmp_path / "corrupted.json"
        path.write_text("not json", encoding="utf-8")
        result = collector._load_list(path)
        assert result == []

    def test_load_dict_corrupted(self, collector: SignalCollector, tmp_path: Path):
        path = tmp_path / "corrupted.json"
        path.write_text("not json", encoding="utf-8")
        result = collector._load_dict(path)
        assert result is None

    def test_load_finding_list_corrupted(self, collector: SignalCollector, tmp_path: Path):
        path = tmp_path / "corrupted.json"
        path.write_text("not json", encoding="utf-8")
        result = collector._load_finding_list(path)
        assert result == []

    def test_load_finding_list_dict_with_findings(self, collector: SignalCollector, tmp_path: Path):
        import json
        path = tmp_path / "findings.json"
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"findings": [{"id": "f1"}]}, f)
        result = collector._load_finding_list(path)
        assert len(result) == 1

    def test_collect_graphql_signal(self, collector: SignalCollector, project_path: Path):
        import json
        api_dir = project_path / "profiles" / "api_security"
        api_dir.mkdir(parents=True, exist_ok=True)
        with open(api_dir / "graphql_profile.json", "w", encoding="utf-8") as f:
            json.dump({"detected": True, "confidence": 0.8}, f)
        signals = collector.collect(project_path)
        gql_signals = [s for s in signals if s.signal_type == SignalType.GRAPHQL_SURFACE]
        assert len(gql_signals) == 1

    def test_collect_oauth_signal(self, collector: SignalCollector, project_path: Path):
        import json
        api_dir = project_path / "profiles" / "api_security"
        api_dir.mkdir(parents=True, exist_ok=True)
        with open(api_dir / "oauth_profile.json", "w", encoding="utf-8") as f:
            json.dump({"detected": True, "confidence": 0.7}, f)
        signals = collector.collect(project_path)
        oauth_signals = [s for s in signals if s.signal_type == SignalType.OAUTH_DETECTED]
        assert len(oauth_signals) == 1

    def test_collect_source_map_signal(self, collector: SignalCollector, project_path: Path):
        import json
        bb_dir = project_path / "profiles" / "bug_bounty"
        bb_dir.mkdir(parents=True, exist_ok=True)
        with open(bb_dir / "sourcemap_profile.json", "w", encoding="utf-8") as f:
            json.dump([{"id": "sm1", "asset": "app", "url": "/app.js.map", "confidence": 0.8}], f)
        signals = collector.collect(project_path)
        sm_signals = [s for s in signals if s.signal_type == SignalType.SOURCE_MAP_EXPOSED]
        assert len(sm_signals) == 1

    def test_collect_bfla_signal(self, collector: SignalCollector, project_path: Path):
        import json
        api_dir = project_path / "profiles" / "api_security"
        api_dir.mkdir(parents=True, exist_ok=True)
        with open(api_dir / "bfla_indicators.json", "w", encoding="utf-8") as f:
            json.dump([{"id": "bfla1", "asset": "api", "endpoint": "/admin/users", "confidence": 0.7}], f)
        signals = collector.collect(project_path)
        bfla_signals = [s for s in signals if s.signal_type == SignalType.BFLA_INDICATOR]
        assert len(bfla_signals) == 1

    def test_collect_mass_assignment_signal(self, collector: SignalCollector, project_path: Path):
        import json
        api_dir = project_path / "profiles" / "api_security"
        api_dir.mkdir(parents=True, exist_ok=True)
        with open(api_dir / "mass_assignment_indicators.json", "w", encoding="utf-8") as f:
            json.dump([{"id": "ma1", "asset": "api", "endpoint": "/users", "confidence": 0.6}], f)
        signals = collector.collect(project_path)
        ma_signals = [s for s in signals if s.signal_type == SignalType.MASS_ASSIGNMENT_INDICATOR]
        assert len(ma_signals) == 1
