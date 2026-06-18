"""Unit tests for the WhatWeb Integration, Fingerprint Intelligence Engine, Profiler, and CLI."""

from datetime import datetime, timezone
import json
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest
from typer.testing import CliRunner

from ghostmirror.app.cli import app
from ghostmirror.core.scope_manager import ScopeManager
from ghostmirror.integrations.base.tool_runner import (
    ToolExecutionResult,
    ToolExecutionError,
    ToolNotFoundError,
    ToolTimeoutError,
)
from ghostmirror.integrations.whatweb.scanner import WhatWebRunner
from ghostmirror.integrations.whatweb.parser import WhatWebParser
from ghostmirror.models.technology import TechnologyModel
from ghostmirror.models.fingerprint import AIProfile, FingerprintProfile
from ghostmirror.modules.base.scanner import OutOfScopeError, ScannerError
from ghostmirror.modules.models.finding import FindingModel, FindingSeverity, ScanResultModel
from ghostmirror.modules.fingerprint.intelligence import AIFingerprintEngine, FingerprintIntelligence
from ghostmirror.modules.fingerprint.profiler import TechnologyProfiler
from ghostmirror.modules.fingerprint.scanner import FingerprintScanner


# --------------------------------------------------------------------------- #
# WhatWeb Parser Tests
# --------------------------------------------------------------------------- #
def test_whatweb_parser_empty() -> None:
    assert WhatWebParser.parse_json_content("") == []
    assert WhatWebParser.parse_json_content("   ") == []


def test_whatweb_parser_invalid_json() -> None:
    with pytest.raises(ValueError, match="Invalid WhatWeb JSON output"):
        WhatWebParser.parse_json_content("{invalid")


def test_whatweb_parser_valid_json() -> None:
    mock_json = """[
        {
            "target": "http://example.com",
            "plugins": {
                "Apache": {"version": ["2.4.41"]},
                "PHP": {"version": "7.4"},
                "WordPress": {"version": ["5.7"], "os": ["Unix"]},
                "Custom": {}
            }
        }
    ]"""
    results = WhatWebParser.parse_json_content(mock_json)
    assert len(results) == 4
    
    apache = next(r for r in results if r["name"] == "Apache")
    assert apache["version"] == "2.4.41"
    
    php = next(r for r in results if r["name"] == "PHP")
    assert php["version"] == "7.4"
    
    custom = next(r for r in results if r["name"] == "Custom")
    assert custom["version"] is None


def test_whatweb_parser_file_not_found() -> None:
    with pytest.raises(FileNotFoundError):
        WhatWebParser.parse_json_file("nonexistent.json")


def test_whatweb_parser_file_valid(tmp_path: Path) -> None:
    mock_json = '[{"target": "http://test.com", "plugins": {"Nginx": {"version": ["1.18.0"]}}}]'
    json_file = tmp_path / "whatweb_out.json"
    json_file.write_text(mock_json, encoding="utf-8")
    
    results = WhatWebParser.parse_json_file(json_file)
    assert len(results) == 1
    assert results[0]["name"] == "Nginx"
    assert results[0]["version"] == "1.18.0"


# --------------------------------------------------------------------------- #
# WhatWeb Runner Tests
# --------------------------------------------------------------------------- #
@patch("ghostmirror.integrations.whatweb.scanner.ToolRunner")
def test_whatweb_runner_scan(mock_tool_runner_cls: MagicMock) -> None:
    mock_runner = MagicMock()
    mock_tool_runner_cls.return_value = mock_runner
    mock_runner.run.return_value = ToolExecutionResult(
        tool_name="whatweb",
        command="whatweb --color=never --log-json=out.json target.com",
        exit_code=0,
        stdout="WhatWeb raw output",
        stderr="",
        duration=1.2,
        success=True
    )
    
    runner = WhatWebRunner()
    result = runner.scan("target.com", "out.json")
    
    assert result.success is True
    mock_runner.run.assert_called_once_with(
        tool_name="whatweb",
        args=["--color=never", "--log-json=out.json", "target.com"],
        timeout=300.0
    )


# --------------------------------------------------------------------------- #
# AI Fingerprint Engine Tests
# --------------------------------------------------------------------------- #
def test_ai_fingerprint_engine_no_signals() -> None:
    profile = AIFingerprintEngine.analyze("<html><body>Hello World</body></html>", {})
    assert profile.ai_probability == 0.0
    assert len(profile.signals_detected) == 0
    assert profile.observations == "Nenhum sinal de construção assistida por IA detectado."


def test_ai_fingerprint_engine_lovable_signal() -> None:
    html = "<html><body>Lovable app</body></html>"
    profile = AIFingerprintEngine.analyze(html, {})
    assert profile.ai_probability == 85.0
    assert "Lovable" in profile.signals_detected
    assert "Alta probabilidade" in profile.observations


def test_ai_fingerprint_engine_multiple_signals() -> None:
    html = "<html><body>v0.dev template with replit.app and langchain</body></html>"
    profile = AIFingerprintEngine.analyze(html, {})
    # base v0 (75) + langchain (25) * 0.5 = 75 + 12.5 = 87.5
    assert profile.ai_probability == 87.5
    assert "v0" in profile.signals_detected
    assert "Replit" in profile.signals_detected
    assert "LangChain" in profile.frameworks_detected
    assert "Alta probabilidade" in profile.observations


def test_ai_fingerprint_engine_only_sdk() -> None:
    html = "<html><body>using @openai/api</body></html>"
    profile = AIFingerprintEngine.analyze(html, {})
    assert profile.ai_probability == 20.0
    assert "openai-sdk" in profile.signals_detected
    assert "OpenAI" in profile.llm_integrations
    assert "Baixa probabilidade" in profile.observations


def test_ai_fingerprint_engine_headers() -> None:
    headers = {"X-Framer-Generated": "yes", "Server": "Webflow AI"}
    profile = AIFingerprintEngine.analyze("", headers)
    assert "Framer AI" in profile.signals_detected
    assert "Webflow AI" in profile.signals_detected
    assert profile.ai_probability == 50.0


# --------------------------------------------------------------------------- #
# Fingerprint Intelligence Tests
# --------------------------------------------------------------------------- #
def test_fingerprint_intelligence_map() -> None:
    t1 = FingerprintIntelligence.map_detection("nginx", "1.18")
    assert t1 is not None
    assert t1.name == "Nginx"
    assert t1.category == "WEB SERVER"
    assert t1.version == "1.18"
    
    t2 = FingerprintIntelligence.map_detection("wordpress")
    assert t2 is not None
    assert t2.name == "WordPress"
    assert t2.category == "CMS"

    t3 = FingerprintIntelligence.map_detection("unknown-plugin")
    assert t3 is None


def test_fingerprint_intelligence_correlate() -> None:
    techs = [
        TechnologyModel(name="WordPress", category="CMS", version=None, confidence=1.0, source="WhatWeb"),
        TechnologyModel(name="Laravel", category="BACKEND FRAMEWORKS", version=None, confidence=1.0, source="WhatWeb"),
        TechnologyModel(name="NextJS", category="FRONTEND FRAMEWORKS", version=None, confidence=1.0, source="WhatWeb"),
    ]
    
    enriched = FingerprintIntelligence.correlate(techs)
    names = {t.name for t in enriched}
    
    assert "PHP" in names
    assert "NodeJS" in names
    
    # Verify WooCommerce correlation
    techs_woo = [TechnologyModel(name="WooCommerce", category="CMS", version=None, confidence=1.0, source="WhatWeb")]
    enriched_woo = FingerprintIntelligence.correlate(techs_woo)
    names_woo = {t.name for t in enriched_woo}
    assert "WordPress" in names_woo
    assert "PHP" in names_woo


# --------------------------------------------------------------------------- #
# Technology Profiler Tests
# --------------------------------------------------------------------------- #
def test_technology_profiler() -> None:
    techs = [
        TechnologyModel(name="Nginx", category="WEB SERVER", version="1.20", confidence=1.0, source="WhatWeb"),
        TechnologyModel(name="PHP", category="BACKEND LANGUAGE", version=None, confidence=1.0, source="WhatWeb"),
        TechnologyModel(name="Laravel", category="BACKEND FRAMEWORKS", version=None, confidence=0.8, source="WhatWeb"),
        TechnologyModel(name="React", category="FRONTEND FRAMEWORKS", version=None, confidence=1.0, source="WhatWeb"),
        TechnologyModel(name="WordPress", category="CMS", version=None, confidence=0.9, source="WhatWeb"),
        TechnologyModel(name="Elementor", category="BUILDERS", version=None, confidence=1.0, source="WhatWeb"),
        TechnologyModel(name="Cloudflare", category="INFRASTRUCTURE", version=None, confidence=1.0, source="WhatWeb"),
        TechnologyModel(name="Google Analytics", category="ANALYTICS", version=None, confidence=1.0, source="WhatWeb"),
        TechnologyModel(name="Stripe", category="PAYMENTS", version=None, confidence=1.0, source="WhatWeb"),
    ]
    
    profile = TechnologyProfiler.build_profile("test.com", techs)
    
    assert profile.target == "test.com"
    assert profile.webserver == "Nginx"
    assert profile.backend_language == "PHP"
    assert profile.backend_framework == "Laravel"
    assert profile.frontend_framework == "React"
    assert profile.cms == "WordPress"
    assert profile.builder == "Elementor"
    assert profile.hosting == "Cloudflare"
    assert profile.waf == "Cloudflare"
    assert profile.cdn == "Cloudflare"
    assert "Google Analytics" in profile.analytics
    assert "Stripe" in profile.payment_providers
    assert profile.confidence_score > 0.0


# --------------------------------------------------------------------------- #
# Fingerprint Scanner Tests
# --------------------------------------------------------------------------- #
@pytest.fixture()
def mock_project(tmp_path: Path) -> Path:
    # Setup standard project structure with a scope file
    project_dir = tmp_path / "projects" / "test-client-proj"
    project_dir.mkdir(parents=True)
    
    scope_data = {
        "project": {
            "client": "test-client",
            "name": "proj",
            "notes": ""
        },
        "targets": {
            "domains": ["example.com", "target.com"],
            "ips": []
        },
        "allowed_tests": {
            "headers": True,
            "ssl": True,
            "nmap": True,
            "fingerprint": True
        }
    }
    
    scope_file = project_dir / "scope.yaml"
    import yaml
    with open(scope_file, "w", encoding="utf-8") as f:
        yaml.dump(scope_data, f)
        
    return project_dir


@patch("ghostmirror.modules.fingerprint.scanner.FingerprintScanner._fetch_target_homepage")
@patch("ghostmirror.integrations.whatweb.scanner.WhatWebRunner.scan")
def test_fingerprint_scanner_success(
    mock_whatweb_scan: MagicMock,
    mock_fetch: MagicMock,
    mock_project: Path
) -> None:
    # Set up mock outputs
    mock_fetch.return_value = {
        "status_code": 200,
        "headers": {"Server": "cloudflare", "Content-Type": "text/html"},
        "html": "<html><body>Lovable app with @openai/api and nextjs-template</body></html>"
    }
    
    # WhatWeb mock JSON
    mock_whatweb_json = '[{"target": "example.com", "plugins": {"WordPress": {"version": ["5.8"]}}}]'
    
    def write_json_file(target: str, out_path: str, timeout: float | None = None) -> ToolExecutionResult:
        p = Path(out_path)
        p.write_text(mock_whatweb_json, encoding="utf-8")
        return ToolExecutionResult(
            tool_name="whatweb",
            command="whatweb --color=never example.com",
            exit_code=0,
            stdout="WordPress 5.8 detected",
            stderr="",
            duration=0.5,
            success=True
        )
        
    mock_whatweb_scan.side_effect = write_json_file
    
    scanner = FingerprintScanner(project_path=mock_project, target="example.com")
    result = scanner.run()
    
    assert result.status == "completed"
    assert len(result.findings) > 0
    
    # Assert findings generated
    titles = [f.title for f in result.findings]
    assert "WordPress Detected" in titles
    assert "PHP Detected" in titles
    assert "AI Generated Application Suspected" in titles
    
    # Assert profiles saved
    tech_prof_path = mock_project / "profiles" / "technology_profile.json"
    ai_prof_path = mock_project / "profiles" / "ai_profile.json"
    
    assert tech_prof_path.exists()
    assert ai_prof_path.exists()
    
    with open(tech_prof_path, "r", encoding="utf-8") as f:
        tech_data = json.load(f)
    assert tech_data["cms"] == "WordPress"
    assert tech_data["backend_language"] == "PHP"
    
    with open(ai_prof_path, "r", encoding="utf-8") as f:
        ai_data = json.load(f)
    assert ai_data["ai_probability"] > 50.0


@patch("ghostmirror.integrations.whatweb.scanner.WhatWebRunner.scan")
def test_fingerprint_scanner_target_not_resolved(mock_whatweb_scan: MagicMock, mock_project: Path) -> None:
    mock_whatweb_scan.return_value = ToolExecutionResult(
        tool_name="whatweb",
        command="whatweb --color=never example.com",
        exit_code=1,
        stdout="Failed to resolve example.com",
        stderr="Failed to resolve example.com",
        duration=0.2,
        success=False
    )
    
    scanner = FingerprintScanner(project_path=mock_project, target="example.com")
    with pytest.raises(ScannerError, match="Alvo inacessível: Não foi possível resolver o hostname"):
        scanner.run()


@patch("ghostmirror.integrations.whatweb.scanner.WhatWebRunner.scan")
def test_fingerprint_scanner_not_installed(mock_whatweb_scan: MagicMock, mock_project: Path) -> None:
    mock_whatweb_scan.side_effect = ToolNotFoundError("whatweb not found")
    
    scanner = FingerprintScanner(project_path=mock_project, target="example.com")
    with pytest.raises(ScannerError, match="WhatWeb não está instalado"):
        scanner.run()


@patch("ghostmirror.integrations.whatweb.scanner.WhatWebRunner.scan")
def test_fingerprint_scanner_timeout(mock_whatweb_scan: MagicMock, mock_project: Path) -> None:
    mock_whatweb_scan.side_effect = ToolTimeoutError("whatweb timed out")
    
    scanner = FingerprintScanner(project_path=mock_project, target="example.com")
    with pytest.raises(ScannerError, match="WhatWeb excedeu o tempo limite"):
        scanner.run()


@patch("ghostmirror.integrations.whatweb.scanner.WhatWebRunner.scan")
def test_fingerprint_scanner_unexpected_error(mock_whatweb_scan: MagicMock, mock_project: Path) -> None:
    mock_whatweb_scan.side_effect = RuntimeException = Exception("Unexpected")
    
    scanner = FingerprintScanner(project_path=mock_project, target="example.com")
    with pytest.raises(ScannerError, match="Erro inesperado durante o scan do WhatWeb"):
        scanner.run()


# --------------------------------------------------------------------------- #
# CLI Command Tests
# --------------------------------------------------------------------------- #
@patch("ghostmirror.app.cli.bootstrap")
@patch("ghostmirror.modules.fingerprint.scanner.FingerprintScanner.run")
def test_cli_scan_fingerprint(
    mock_run: MagicMock,
    mock_bootstrap: MagicMock,
    mock_project: Path
) -> None:
    # Setup bootstrap context
    mock_ctx = MagicMock()
    mock_bootstrap.return_value = mock_ctx
    
    # Mock project handle
    mock_handle = MagicMock()
    mock_handle.path = mock_project
    mock_ctx.projects.list_projects.return_value = [mock_handle]
    mock_ctx.projects.open_project.return_value = mock_handle
    
    # Mock scan execution results
    started = datetime.now(timezone.utc)
    mock_run.return_value = ScanResultModel(
        scanner_name="fingerprint",
        target="target.com",
        started_at=started,
        finished_at=started,
        status="completed",
        findings=[],
        statistics={"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    )
    
    # Create technology_profile.json and ai_profile.json
    profiles_dir = mock_project / "profiles"
    profiles_dir.mkdir(parents=True, exist_ok=True)
    
    tech_data = {
        "target": "target.com",
        "webserver": "Nginx",
        "backend_language": "PHP",
        "backend_framework": "Laravel",
        "frontend_framework": "Vue",
        "hosting": "Cloudflare",
        "waf": "Cloudflare",
        "technologies": [{"name": "WordPress", "category": "CMS", "version": None, "confidence": 1.0, "source": "WhatWeb"}]
    }
    
    ai_data = {
        "ai_probability": 72.0,
        "signals_detected": [],
        "frameworks_detected": [],
        "llm_integrations": [],
        "observations": ""
    }
    
    with open(profiles_dir / "technology_profile.json", "w", encoding="utf-8") as f:
        json.dump(tech_data, f)
    with open(profiles_dir / "ai_profile.json", "w", encoding="utf-8") as f:
        json.dump(ai_data, f)
        
    runner = CliRunner()
    result = runner.invoke(app, ["scan", "fingerprint", "-p", "test-client-proj", "-t", "target.com"])
    
    assert result.exit_code == 0
    assert "FINGERPRINT SCAN COMPLETE" in result.stdout
    assert "Web Server:\nNginx" in result.stdout
    assert "Backend:\nPHP" in result.stdout
    assert "Framework:\nLaravel" in result.stdout
    assert "Frontend:\nVue" in result.stdout
    assert "Hosting:\nCloudflare" in result.stdout
    assert "AI Probability:\n72.0%" in result.stdout


def test_ai_fingerprint_engine_additional_signals() -> None:
    html = "<html><body>cursor.sh replit.app Framer AI Webflow AI anthropic-sdk google-ai-sdk llama-index crew-ai</body></html>"
    profile = AIFingerprintEngine.analyze(html, {})
    assert "Cursor" in profile.signals_detected
    assert "Replit" in profile.signals_detected
    assert "Framer AI" in profile.signals_detected
    assert "Webflow AI" in profile.signals_detected
    assert "anthropic-sdk" in profile.signals_detected
    assert "google-ai-sdk" in profile.signals_detected
    assert "LlamaIndex" in profile.frameworks_detected
    assert "CrewAI" in profile.frameworks_detected


def test_fingerprint_intelligence_special_cases() -> None:
    # direct mapping check in CATEGORY_MAPPING
    t1 = FingerprintIntelligence.map_detection("Stripe")
    assert t1 is not None
    assert t1.name == "Stripe"
    
    # Title cased check
    t2 = FingerprintIntelligence.map_detection("caddy")
    assert t2 is not None
    assert t2.name == "Caddy"
    
    # Correlation cases
    t_woo = [TechnologyModel(name="WooCommerce", category="CMS", version=None, confidence=1.0, source="WhatWeb")]
    res_woo = FingerprintIntelligence.correlate(t_woo)
    assert any(x.name == "WordPress" and x.category == "CMS" for x in res_woo)
    assert any(x.name == "PHP" and x.category == "BACKEND LANGUAGE" for x in res_woo)


def test_technology_profiler_special_cases() -> None:
    techs = [
        TechnologyModel(name="Akamai", category="WAF", version=None, confidence=1.0, source="WhatWeb"),
        TechnologyModel(name="Webflow", category="BUILDERS", version=None, confidence=1.0, source="WhatWeb"),
    ]
    p1 = TechnologyProfiler.build_profile("test.com", techs)
    assert p1.waf == "Akamai"
    assert p1.hosting == "Webflow"
    assert p1.cdn == "Webflow"

    p2 = TechnologyProfiler.build_profile("test.com", [
        TechnologyModel(name="Framer", category="BUILDERS", version=None, confidence=1.0, source="WhatWeb")
    ])
    assert p2.hosting == "Framer"
    assert p2.cdn == "Framer"

    p3 = TechnologyProfiler.build_profile("test.com", [
        TechnologyModel(name="Shopify", category="CMS", version=None, confidence=1.0, source="WhatWeb")
    ])
    assert p3.hosting == "Shopify"
    assert p3.cdn == "Shopify"


@patch("ghostmirror.modules.fingerprint.scanner.httpx.Client")
def test_scanner_http_probe_paths(mock_client_cls: MagicMock, mock_project: Path) -> None:
    # 1. Test HTTPS success
    mock_client = MagicMock()
    mock_client_cls.return_value.__enter__.return_value = mock_client
    
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = {"Content-Type": "text/html"}
    mock_resp.text = "Hello HTTPS"
    mock_client.get.return_value = mock_resp
    
    scanner = FingerprintScanner(project_path=mock_project, target="target.com")
    res = scanner._fetch_target_homepage()
    assert res["status_code"] == 200
    assert res["html"] == "Hello HTTPS"
    
    # 2. Test HTTPS fails, HTTP succeeds
    mock_client.get.side_effect = [Exception("HTTPS fail"), mock_resp]
    mock_resp.text = "Hello HTTP"
    res2 = scanner._fetch_target_homepage()
    assert res2["status_code"] == 200
    assert res2["html"] == "Hello HTTP"
    
    # 3. Test both fail
    mock_client.get.side_effect = Exception("Both fail")
    res3 = scanner._fetch_target_homepage()
    assert res3["status_code"] == 0
    assert res3["html"] == ""


@patch("ghostmirror.integrations.whatweb.scanner.WhatWebRunner.scan")
def test_scanner_execution_errors(mock_whatweb_scan: MagicMock, mock_project: Path) -> None:
    scanner = FingerprintScanner(project_path=mock_project, target="example.com")
    
    # ToolExecutionError path
    mock_whatweb_scan.side_effect = ToolExecutionError("CLI failed")
    with pytest.raises(ScannerError, match="Erro durante a execução do WhatWeb"):
        scanner.run()
        
    # ValueError/JSON decoding failure in Parser
    def write_invalid_json(target: str, out_path: str, timeout: float | None = None) -> ToolExecutionResult:
        p = Path(out_path)
        p.write_text("not a json", encoding="utf-8")
        return ToolExecutionResult(
            tool_name="whatweb",
            command="whatweb example.com",
            exit_code=0,
            stdout="some output",
            stderr="",
            duration=0.5,
            success=True
        )
    mock_whatweb_scan.side_effect = write_invalid_json
    with pytest.raises(ScannerError, match="O output JSON do WhatWeb é inválido ou corrompido"):
        scanner.run()


def test_whatweb_parser_file_invalid(tmp_path: Path) -> None:
    bad_file = tmp_path / "bad.json"
    bad_file.write_text("invalid json", encoding="utf-8")
    with pytest.raises(ValueError, match="Invalid WhatWeb JSON output"):
        WhatWebParser.parse_json_file(bad_file)

