from __future__ import annotations

import json
from pathlib import Path

import pytest

from ghostmirror.modules.api_security.engine import APISecurityEngine


def _write_json(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def _make_jwt(alg: str = "HS256") -> str:
    import base64, json
    header = b64({"alg": alg})
    payload = b64({"sub": "123", "name": "Test", "iat": 1516239022, "exp": 9999999999})
    return f"{header}.{payload}.sig"


def b64(data):
    import base64, json
    return base64.urlsafe_b64encode(json.dumps(data).encode()).rstrip(b"=").decode()


@pytest.fixture
def project_with_profiles(tmp_path: Path) -> Path:
    base = tmp_path / "test_project"
    tech_dir = base / "profiles"
    web_intel_dir = tech_dir / "web_intelligence"
    bug_bounty_dir = tech_dir / "bug_bounty"
    tech_dir.mkdir(parents=True, exist_ok=True)
    web_intel_dir.mkdir(parents=True, exist_ok=True)
    bug_bounty_dir.mkdir(parents=True, exist_ok=True)

    _write_json(tech_dir / "technology_profile.json", {"target": "https://api.example.com"})
    _write_json(web_intel_dir / "endpoint_inventory.json", [
            {"method": "GET", "path": "/api/users", "content_type": "application/json", "auth_required": True, "confidence": "high", "headers": {"Authorization": f"Bearer {_make_jwt()}"}},
            {"method": "POST", "path": "/api/users", "content_type": "application/json", "auth_required": True, "confidence": "high"},
            {"method": "GET", "path": "/api/users/123", "content_type": "application/json", "auth_required": False, "confidence": "medium"},
            {"method": "GET", "path": "/api/admin/dashboard", "content_type": "application/json", "auth_required": True, "confidence": "high"},
            {"method": "GET", "path": "/graphql", "content_type": "application/json", "auth_required": False, "confidence": "medium"},
            {"method": "GET", "path": "/swagger.json", "content_type": "application/json", "auth_required": False, "confidence": "medium"},
            {"method": "PUT", "path": "/api/profile", "content_type": "application/json", "auth_required": True, "confidence": "medium"},
            {"method": "PATCH", "path": "/api/users/role", "content_type": "application/json", "auth_required": True, "confidence": "medium"},
            {"method": "GET", "path": "/api/payments/456", "content_type": "application/json", "auth_required": False, "confidence": "medium"},
            {"method": "GET", "path": "/api/invoices/789", "content_type": "application/json", "auth_required": True, "confidence": "medium"},
        ])
    _write_json(web_intel_dir / "js_intelligence.json", {"internal_urls": ["/api/products", "/api/orders"]})
    _write_json(bug_bounty_dir / "api_inventory.json", [
        {"method": "GET", "path": "/api/extra", "content_type": "application/json", "auth_required": False, "confidence": "medium"},
    ])
    return base


class TestAPISecurityEngineIntegration:
    def test_full_engine_run(self, project_with_profiles: Path):
        engine = APISecurityEngine()
        report = engine.analyze_project(project_with_profiles)
        assert report.target == "https://api.example.com"
        assert report.api_inventory["total_endpoints"] >= 10
        assert report.api_inventory["auth_required_count"] > 0

    def test_engine_detects_swagger(self, project_with_profiles: Path):
        engine = APISecurityEngine()
        report = engine.analyze_project(project_with_profiles)
        assert report.swagger_profile is not None
        assert report.swagger_profile["detected"]

    def test_engine_detects_graphql(self, project_with_profiles: Path):
        engine = APISecurityEngine()
        report = engine.analyze_project(project_with_profiles)
        assert report.graphql_profile is not None
        assert report.graphql_profile["detected"]

    def test_engine_generates_bola(self, project_with_profiles: Path):
        engine = APISecurityEngine()
        report = engine.analyze_project(project_with_profiles)
        assert len(report.bola_indicators) > 0

    def test_engine_generates_bfla(self, project_with_profiles: Path):
        engine = APISecurityEngine()
        report = engine.analyze_project(project_with_profiles)
        assert len(report.bfla_indicators) > 0

    def test_engine_generates_mass_assignment(self, project_with_profiles: Path):
        engine = APISecurityEngine()
        report = engine.analyze_project(project_with_profiles)
        assert len(report.mass_assignment_indicators) > 0

    def test_engine_generates_opportunities(self, project_with_profiles: Path):
        engine = APISecurityEngine()
        report = engine.analyze_project(project_with_profiles)
        assert len(report.opportunities) > 0

    def test_engine_generates_recommendations(self, project_with_profiles: Path):
        engine = APISecurityEngine()
        report = engine.analyze_project(project_with_profiles)
        assert len(report.recommendations) > 0

    def test_engine_generates_findings(self, project_with_profiles: Path):
        engine = APISecurityEngine()
        report = engine.analyze_project(project_with_profiles)
        assert len(report.findings) > 0

    def test_engine_saves_artifacts(self, project_with_profiles: Path):
        engine = APISecurityEngine()
        engine.analyze_project(project_with_profiles)
        api_dir = project_with_profiles / "profiles" / "api_security"
        assert (api_dir / "api_security_report.json").exists()
        assert (api_dir / "api_inventory.json").exists()
        assert (api_dir / "swagger_profile.json").exists()
        assert (api_dir / "graphql_profile.json").exists()
        assert (api_dir / "jwt_profile.json").exists()
        assert (api_dir / "oauth_profile.json").exists()
        assert (api_dir / "object_inventory.json").exists()
        assert (api_dir / "rate_limit_profile.json").exists()
        assert (api_dir / "bola_indicators.json").exists()
        assert (api_dir / "bfla_indicators.json").exists()
        assert (api_dir / "api_attack_surface.json").exists()
        assert (api_dir / "api_opportunities.json").exists()
        assert (api_dir / "api_recommendations.json").exists()
        assert (api_dir / "api_findings.json").exists()
        assert (api_dir / "mass_assignment_indicators.json").exists()
        assert (api_dir / "api_correlations.json").exists()

    def test_engine_findings_saved(self, project_with_profiles: Path):
        engine = APISecurityEngine()
        engine.analyze_project(project_with_profiles)
        findings_path = project_with_profiles / "findings" / "api_security.json"
        assert findings_path.exists()
        with open(findings_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        assert isinstance(data, list)

    def test_engine_empty_without_target(self, tmp_path: Path):
        empty_project = tmp_path / "empty"
        empty_project.mkdir()
        _write_json(empty_project / "profiles" / "technology_profile.json", {})
        engine = APISecurityEngine()
        report = engine.analyze_project(empty_project)
        assert report.overall_score == 0

    def test_engine_with_explicit_target(self, project_with_profiles: Path):
        engine = APISecurityEngine()
        report = engine.analyze_project(project_with_profiles, target_url="https://custom.example.com")
        assert report.target == "https://custom.example.com"

    def test_engine_with_jwt_in_headers(self, tmp_path: Path):
        base = tmp_path / "jwt_test"
        tech_dir = base / "profiles"
        web_intel_dir = tech_dir / "web_intelligence"
        tech_dir.mkdir(parents=True, exist_ok=True)
        web_intel_dir.mkdir(parents=True, exist_ok=True)
        _write_json(tech_dir / "technology_profile.json", {"target": "https://jwt-test.example.com"})
        _write_json(web_intel_dir / "endpoint_inventory.json", [
            {"method": "GET", "path": "/api/users", "headers": {"Authorization": f"Bearer {_make_jwt('none')}"}},
        ])
        _write_json(web_intel_dir / "js_intelligence.json", {"internal_urls": []})
        engine = APISecurityEngine()
        report = engine.analyze_project(base)
        assert report.jwt_profile is not None
        assert report.jwt_profile.get("detected")
