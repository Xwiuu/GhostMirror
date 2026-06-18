"""Unit tests for the Sprint 8 Nuclei integration and modules."""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import typer
from typer.testing import CliRunner

from ghostmirror.app.cli import app
from ghostmirror.integrations.base.tool_runner import ToolNotFoundError, ToolExecutionResult
from ghostmirror.integrations.nuclei.runner import NucleiRunner
from ghostmirror.integrations.nuclei.parser import NucleiParser
from ghostmirror.integrations.nuclei.updater import NucleiUpdater
from ghostmirror.models.nuclei_result import NucleiResult
from ghostmirror.models.nuclei_template import NucleiTemplate
from ghostmirror.modules.base.scanner import OutOfScopeError, ScannerError
from ghostmirror.modules.models.finding import FindingSeverity
from ghostmirror.modules.nuclei.scanner import NucleiScanner
from ghostmirror.modules.nuclei.template_selector import NucleiTemplateSelector
from ghostmirror.modules.nuclei.findings_mapper import NucleiFindingsMapper
from ghostmirror.modules.nuclei.correlation_engine import NucleiCorrelationEngine


@pytest.fixture
def temp_project(tmp_path):
    """Creates a temporary project environment simulating fingerprint and CVE intel outputs."""
    project_path = tmp_path / "test-project"
    project_path.mkdir(parents=True, exist_ok=True)
    
    # 1. Scope file
    import yaml
    scope_data = {
        "project": {"client": "Test", "name": "Project"},
        "targets": {"domains": ["example.com"], "ips": []},
        "allowed_tests": {"active_scans": True, "passive_scans": True}
    }
    with open(project_path / "scope.yaml", "w", encoding="utf-8") as f:
        yaml.dump(scope_data, f)

    # 2. Profiles directory
    profiles_dir = project_path / "profiles"
    profiles_dir.mkdir(parents=True, exist_ok=True)
    
    tech_data = {
        "target": "example.com",
        "technologies": [
            {"name": "Apache", "category": "web-server", "version": "2.4.49", "confidence": 1.0, "source": "whatweb"},
            {"name": "WordPress", "category": "cms", "version": "5.7", "confidence": 1.0, "source": "whatweb"},
            {"name": "Redis", "category": "database", "version": None, "confidence": 1.0, "source": "nmap"}
        ]
    }
    with open(profiles_dir / "technology_profile.json", "w", encoding="utf-8") as f:
        json.dump(tech_data, f)

    cve_data = {
        "target": "example.com",
        "technologies_analyzed": 3,
        "total_cves": 1,
        "findings": [
            {
                "title": "Potential Apache CVE Exposure: CVE-2021-41773",
                "severity": "HIGH",
                "target": "example.com",
            }
        ]
    }
    with open(profiles_dir / "cve_intelligence.json", "w", encoding="utf-8") as f:
        json.dump(cve_data, f)

    # 3. Recommendations directory
    recs_dir = project_path / "recommendations"
    recs_dir.mkdir(parents=True, exist_ok=True)
    rec_templates = {
        "target": "example.com",
        "templates": [
            "http/cves/2021/CVE-2021-41773.yaml",
            "http/technologies/wordpress/"
        ]
    }
    with open(recs_dir / "recommended_nuclei_templates.json", "w", encoding="utf-8") as f:
        json.dump(rec_templates, f)

    # 4. Knowledge base directory mocked inside project for easy loading
    kb_dir = project_path / "kb"
    kb_dir.mkdir(parents=True, exist_ok=True)
    nuclei_map = {
        "cves": {
            "CVE-2021-41773": "http/cves/2021/CVE-2021-41773.yaml"
        },
        "technologies": {
            "Apache": "http/technologies/apache/",
            "WordPress": "http/technologies/wordpress/",
            "Redis": "network/redis/"
        },
        "exposures": {
            "configs": "http/exposures/configs/",
            "databases": "network/databases/"
        }
    }
    with open(kb_dir / "nuclei_template_map.json", "w", encoding="utf-8") as f:
        json.dump(nuclei_map, f)

    return project_path


# --------------------------------------------------------------------------- #
# Integration Layer Tests
# --------------------------------------------------------------------------- #

def test_nuclei_result_model():
    """Validates NucleiResult Pydantic model initialization."""
    data = {
        "template-id": "cve-2021-41773",
        "template_name": "Apache Path Traversal",
        "severity": "high",
        "matched-at": "http://example.com/cgi-bin/.%2e/.%2e/.%2e/etc/passwd",
        "host": "example.com",
        "ip": "1.2.3.4",
        "curl-command": "curl http://example.com/cgi-bin/...",
        "reference": ["https://nvd.nist.gov/vuln/detail/CVE-2021-41773"],
        "description": "Apache cgi-bin path traversal",
        "tags": ["cve", "apache"],
        "cve": "CVE-2021-41773",
        "cvss": 7.5,
        "matcher-name": "body_match",
        "timestamp": "2026-06-18T00:00:00Z"
    }
    res = NucleiResult.model_validate(data)
    assert res.template_id == "cve-2021-41773"
    assert res.cvss == 7.5
    assert res.severity == "high"


def test_nuclei_template_model():
    """Validates NucleiTemplate model."""
    tpl = NucleiTemplate(
        id="apache-detect",
        name="Apache HTTP Server Detect",
        severity="info",
        description="Detects Apache",
        tags=["tech", "apache"]
    )
    assert tpl.id == "apache-detect"
    assert tpl.severity == "info"


def test_nuclei_runner_is_installed():
    """Tests runner binary detection using mock."""
    mock_runner = MagicMock()
    mock_runner.is_binary_available.return_value = True
    runner = NucleiRunner(tool_runner=mock_runner)
    assert runner.is_installed() is True
    mock_runner.is_binary_available.assert_called_once_with("nuclei")


def test_nuclei_runner_scan():
    """Tests running the nuclei tool scanner wrapper."""
    mock_runner = MagicMock()
    exec_res = ToolExecutionResult(
        tool_name="nuclei",
        command="nuclei ...",
        exit_code=0,
        stdout="raw log output",
        stderr="",
        duration=1.2,
        success=True
    )
    mock_runner.run.return_value = exec_res
    mock_runner.is_binary_available.return_value = True

    runner = NucleiRunner(tool_runner=mock_runner)
    res = runner.scan("example.com", ["my-template.yaml"], "out.jsonl")
    assert res.success is True
    mock_runner.run.assert_called_once()
    assert "-target" in mock_runner.run.call_args[1]["args"]


def test_nuclei_updater():
    """Tests nuclei updater wrapper."""
    mock_runner = MagicMock()
    mock_runner.run.return_value = ToolExecutionResult(
        tool_name="nuclei", command="nuclei -update-templates", exit_code=0, stdout="Success", stderr="", duration=2.5, success=True
    )
    updater = NucleiUpdater(tool_runner=mock_runner)
    res = updater.update_templates()
    assert res.success is True
    mock_runner.run.assert_called_once_with(tool_name="nuclei", args=["-update-templates"], timeout=300.0)


# --------------------------------------------------------------------------- #
# Parser Tests
# --------------------------------------------------------------------------- #

def test_parser_parse_line():
    """Tests parsing a single line of valid and invalid JSONL."""
    valid_line = '{"template-id":"cve-2021-41773","info":{"name":"Apache Traversal","severity":"high","classification":{"cve-id":"CVE-2021-41773","cvss-score":7.5},"reference":["ref"]},"matched-at":"http://example.com","host":"example.com","ip":"1.2.3.4","timestamp":"2026-06-18"}'
    res = NucleiParser.parse_line(valid_line)
    assert res is not None
    assert res.template_id == "cve-2021-41773"
    assert res.severity == "high"
    assert res.cve == "CVE-2021-41773"
    assert res.cvss == 7.5

    assert NucleiParser.parse_line("") is None
    assert NucleiParser.parse_line("invalid json") is None
    assert NucleiParser.parse_line('{"key": "no template id"}') is None


def test_parser_parse_file(tmp_path):
    """Tests parsing a JSONL file completely."""
    file_path = tmp_path / "results.jsonl"
    lines = [
        '{"template-id":"t1","info":{"name":"t1-name","severity":"critical"},"matched-at":"t1-match","host":"t1-host","timestamp":"t1-ts"}',
        '{"template-id":"t2","info":{"name":"t2-name","severity":"info"},"matched-at":"t2-match","host":"t2-host","timestamp":"t2-ts"}'
    ]
    file_path.write_text("\n".join(lines), encoding="utf-8")
    
    parsed = NucleiParser.parse_file(file_path)
    assert len(parsed) == 2
    assert parsed[0].template_id == "t1"
    assert parsed[0].severity == "critical"
    assert parsed[1].template_id == "t2"
    assert parsed[1].severity == "info"


# --------------------------------------------------------------------------- #
# Module Layer Tests (Selector, Mapper, Correlation, Scanner)
# --------------------------------------------------------------------------- #

def test_template_selector(temp_project):
    """Validates NucleiTemplateSelector maps files correctly."""
    kb_dir = temp_project / "kb"
    templates = NucleiTemplateSelector.select_templates(temp_project, knowledge_dir=kb_dir)
    assert len(templates) > 0
    assert "http/cves/2021/CVE-2021-41773.yaml" in templates
    # Database and Config exposures also added
    assert "network/databases/" in templates


def test_findings_mapper():
    """Validates NucleiFindingsMapper severity mapping and descriptions."""
    res = NucleiResult(
        template_id="cve-2021-41773",
        template_name="Apache Path Traversal",
        severity="critical",
        matched_at="http://example.com/cgi-bin/",
        host="example.com",
        ip="1.2.3.4",
        curl_command="curl ...",
        reference=["http://ref"],
        description="Traversal description",
        tags=["cve", "apache"],
        cve="CVE-2021-41773",
        cvss=9.8,
        matcher_name="body",
        timestamp="2026-06-18"
    )
    finding = NucleiFindingsMapper.map_to_finding(res, "example.com")
    assert finding.severity == FindingSeverity.CRITICAL
    assert "Confirmed" not in finding.title  # Correlation engine handles confirmed prefix
    assert "CVE-2021-41773" in finding.title
    assert "Traversal description" in finding.description
    assert "Comando curl" in finding.evidence


def test_correlation_engine(temp_project):
    """Validates that NucleiCorrelationEngine performs match elevation."""
    res = NucleiResult(
        template_id="cve-2021-41773",
        template_name="Apache Path Traversal",
        severity="high",
        matched_at="http://example.com/cgi-bin/",
        host="example.com",
        ip="1.2.3.4",
        tags=["cve", "apache"],
        cve="CVE-2021-41773",
        timestamp="2026"
    )
    finding = NucleiFindingsMapper.map_to_finding(res, "example.com")
    findings = [finding]

    correlated_count = NucleiCorrelationEngine.correlate(temp_project, [res], findings)
    assert correlated_count == 1
    assert "Confirmed Vulnerability" in findings[0].title
    assert "Match Confidence: CONFIRMED" in findings[0].description
    assert "Match de Tecnologia: APACHE" in findings[0].description


def test_nuclei_scanner_run(temp_project):
    """Validates full end-to-end scanner orchestration using mock runners."""
    mock_runner = MagicMock()
    mock_runner.is_installed.return_value = True

    # Simulate scan output generated inside temp project
    raw_output = temp_project / "evidence" / "nuclei" / "raw.jsonl"
    raw_output.parent.mkdir(parents=True, exist_ok=True)
    
    line = '{"template-id":"cve-2021-41773","info":{"name":"Apache Traversal","severity":"high","classification":{"cve-id":"CVE-2021-41773"}},"matched-at":"http://example.com","host":"example.com","timestamp":"2026-06-18"}'
    raw_output.write_text(line + "\n", encoding="utf-8")

    exec_res = ToolExecutionResult(
        tool_name="nuclei", command="nuclei ...", exit_code=0, stdout="", stderr="", duration=5.0, success=True
    )
    mock_runner.scan.return_value = exec_res

    scanner = NucleiScanner(
        project_path=temp_project,
        target="example.com",
        nuclei_runner=mock_runner,
        profile="standard"
    )

    with patch("ghostmirror.modules.nuclei.template_selector.NucleiTemplateSelector.select_templates") as mock_selector:
        mock_selector.return_value = ["http/cves/2021/CVE-2021-41773.yaml"]
        result = scanner.run()

    assert result.status == "completed"
    assert len(result.findings) == 1
    assert result.findings[0].severity == FindingSeverity.HIGH
    assert "Confirmed Vulnerability" in result.findings[0].title

    # Verify output profiles files exist
    assert (temp_project / "profiles" / "nuclei_profile.json").exists()
    assert (temp_project / "evidence" / "nuclei" / "parsed_results.json").exists()
    assert (temp_project / "findings" / "nuclei_findings.json").exists()


# --------------------------------------------------------------------------- #
# CLI Command Tests
# --------------------------------------------------------------------------- #

@patch("ghostmirror.core.project_manager.ProjectManager.open_project")
@patch("ghostmirror.modules.nuclei.scanner.NucleiScanner.run")
def test_cli_scan_nuclei_success(mock_run, mock_open_project, temp_project):
    """Verifies click/typer CLI invocation for scan nuclei."""
    mock_handle = MagicMock()
    mock_handle.path = temp_project
    mock_open_project.return_value = mock_handle

    from datetime import datetime, timezone
    from ghostmirror.modules.models.finding import ScanResultModel
    
    scan_res = ScanResultModel(
        scanner_name="nuclei",
        target="example.com",
        started_at=datetime.now(timezone.utc),
        finished_at=datetime.now(timezone.utc),
        status="completed",
        findings=[],
        statistics={"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    )
    mock_run.return_value = scan_res

    # Create config file to allow Typer app run safely
    runner = CliRunner()
    # Mock bootstrapper config directories
    with patch("ghostmirror.app.cli.bootstrap") as mock_boot:
        mock_app_ctx = MagicMock()
        mock_app_ctx.projects.open_project.return_value = mock_handle
        mock_boot.return_value = mock_app_ctx

        result = runner.invoke(app, ["scan", "nuclei", "--project", "test-project"])
        assert result.exit_code == 0
        assert "NUCLEI SCAN COMPLETE" in result.stdout


@patch("ghostmirror.integrations.nuclei.updater.NucleiUpdater.update_templates")
def test_cli_nuclei_update(mock_update):
    """Verifies click/typer CLI invocation for nuclei update."""
    mock_update.return_value = ToolExecutionResult(
        tool_name="nuclei", command="nuclei -update-templates", exit_code=0, stdout="All templates up-to-date", stderr="", duration=2.5, success=True
    )
    runner = CliRunner()
    with patch("ghostmirror.app.cli.bootstrap") as mock_boot:
        mock_app_ctx = MagicMock()
        mock_boot.return_value = mock_app_ctx

        result = runner.invoke(app, ["nuclei", "update"])
        assert result.exit_code == 0
        assert "Templates do Nuclei atualizados com sucesso" in result.stdout
