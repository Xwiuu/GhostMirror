"""Unit tests for the Nmap Scanner module, integration wrappers, and CLI subcommands."""

from datetime import datetime
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
from ghostmirror.integrations.nmap.scanner import NmapParser, NmapRunner
from ghostmirror.modules.base.scanner import OutOfScopeError, ScannerError
from ghostmirror.modules.nmap.scanner import NmapScanner

# Mock XML content
MOCK_NMAP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sV -oX scan.xml 127.0.0.1">
  <host>
    <status state="up"/>
    <address addr="127.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.2p1"/>
      </port>
      <port protocol="tcp" portid="23">
        <state state="open"/>
        <service name="telnet" product="Linux telnetd" version="1.0"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="Apache httpd" version="2.4.41"/>
      </port>
      <port protocol="tcp" portid="21">
        <state state="open"/>
        <service name="ftp" product="vsftpd" version="3.0.3"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="http" product="nginx" version="1.18.0" secure="true"/>
      </port>
      <port protocol="tcp" portid="445">
        <state state="open"/>
        <service name="microsoft-ds" product="Samba" version="4.11.6"/>
      </port>
      <port protocol="tcp" portid="3389">
        <state state="open"/>
        <service name="ms-wbt-server" product="Microsoft Terminal Services" version="10.0"/>
      </port>
      <port protocol="tcp" portid="3306">
        <state state="open"/>
        <service name="mysql" product="MySQL" version="8.0.25"/>
      </port>
      <port protocol="tcp" portid="5432">
        <state state="open"/>
        <service name="postgresql" product="PostgreSQL" version="12.2"/>
      </port>
      <port protocol="tcp" portid="6379">
        <state state="open"/>
        <service name="redis" product="Redis key-value store" version="6.0.5"/>
      </port>
      <port protocol="tcp" portid="27017">
        <state state="open"/>
        <service name="mongodb" product="MongoDB" version="4.2.8"/>
      </port>
      <port protocol="tcp" portid="8888">
        <state state="open"/>
        <service name="unknown" product="Unknown" version="Unknown"/>
      </port>
    </ports>
  </host>
  <host>
    <status state="down"/>
    <address addr="10.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="Apache" version="2.2"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


def test_nmap_parser_valid() -> None:
    findings = NmapParser.parse_xml_content(MOCK_NMAP_XML)
    # The down host should be skipped, so only ports of the up host are returned
    assert len(findings) == 12

    # Check first port (22/tcp)
    pf = findings[0]
    assert pf.port == 22
    assert pf.protocol == "tcp"
    assert pf.service == "ssh"
    assert pf.product == "OpenSSH"
    assert pf.version == "8.2p1"
    assert pf.state == "open"

    # Check unknown service (8888)
    pf_unknown = findings[11]
    assert pf_unknown.port == 8888
    assert pf_unknown.service == "unknown"


def test_nmap_parser_file_not_found() -> None:
    with pytest.raises(FileNotFoundError):
        NmapParser.parse_xml_file(Path("/nonexistent/file.xml"))


def test_nmap_parser_invalid_xml() -> None:
    with pytest.raises(ValueError) as exc_info:
        NmapParser.parse_xml_content("<invalid-xml>")
    assert "Invalid Nmap XML output" in str(exc_info.value)


def test_nmap_runner_calls_runner(tmp_path: Path) -> None:
    mock_runner = MagicMock()
    nmap_runner = NmapRunner(tool_runner=mock_runner)
    
    xml_out = tmp_path / "scan.xml"
    nmap_runner.scan("127.0.0.1", xml_out, ports_limit=50, timing_template=4, timeout=30.0)

    mock_runner.run.assert_called_once_with(
        tool_name="nmap",
        args=["-sV", "--top-ports", "50", "-T4", "-oX", str(xml_out), "127.0.0.1"],
        timeout=30.0,
    )


def test_nmap_scanner_success(tmp_path: Path, scope_manager: ScopeManager) -> None:
    # 1. Setup project scope
    scope = scope_manager.build_default_scope(
        client="Test Client", name="Test Engagement", domain="example.com"
    )
    scope.targets.ips.append("127.0.0.1")
    scope_manager.write_scope(tmp_path / "scope.yaml", scope)

    # Mock tool result
    mock_tool_result = ToolExecutionResult(
        tool_name="nmap",
        command="nmap -sV -oX scan.xml 127.0.0.1",
        exit_code=0,
        stdout="Nmap done: 1 IP address scanned.",
        stderr="",
        duration=12.5,
        success=True,
    )

    mock_nmap_runner = MagicMock()
    mock_nmap_runner.scan.return_value = mock_tool_result

    # We mock xml writing behavior of nmap to create mock XML on disk
    def mock_scan_side_effect(target, xml_path, *args, **kwargs):
        Path(xml_path).write_text(MOCK_NMAP_XML, encoding="utf-8")
        return mock_tool_result

    mock_nmap_runner.scan.side_effect = mock_scan_side_effect

    scanner = NmapScanner(
        project_path=tmp_path,
        target="127.0.0.1",
        scope_manager=scope_manager,
        nmap_runner=mock_nmap_runner,
    )

    result = scanner.run()

    assert result.status == "completed"
    assert result.scanner_name == "nmap"
    assert len(result.findings) == 12
    assert result.open_ports == [22, 23, 80, 21, 443, 445, 3389, 3306, 5432, 6379, 27017, 8888]
    assert "ssh" in result.services
    assert "mysql" in result.services

    # Verify severity distribution
    # INFO: 22(SSH), 80(HTTP), 443(HTTPS), 8888(Unknown) -> 4
    # MEDIUM: 21(FTP), 3389(RDP) -> 2
    # HIGH: 23(Telnet), 445(SMB), 3306(MySQL), 5432(PostgreSQL), 6379(Redis), 27017(MongoDB) -> 6
    assert result.statistics["info"] == 4
    assert result.statistics["medium"] == 2
    assert result.statistics["high"] == 6

    # Verify specific findings titles
    finding_titles = [f.title for f in result.findings]
    assert "SSH Exposed" in finding_titles
    assert "FTP Exposed" in finding_titles
    assert "Telnet Exposed" in finding_titles
    assert "SMB Exposed" in finding_titles
    assert "RDP Exposed" in finding_titles
    assert "Database Service Exposed" in finding_titles
    assert "Porta desconhecida aberta" in finding_titles

    # Verify saved evidence files
    evidence_dir = tmp_path / "evidence" / "nmap"
    assert (evidence_dir / "scan.xml").exists()
    assert (evidence_dir / "scan_raw.txt").exists()
    assert (evidence_dir / "parsed_results.json").exists()


def test_nmap_scanner_out_of_scope(tmp_path: Path, scope_manager: ScopeManager) -> None:
    scope = scope_manager.build_default_scope(
        client="Test Client", name="Test Engagement", domain="example.com"
    )
    scope_manager.write_scope(tmp_path / "scope.yaml", scope)

    scanner = NmapScanner(
        project_path=tmp_path,
        target="10.0.0.1",
        scope_manager=scope_manager,
    )

    with pytest.raises(OutOfScopeError):
        scanner.run()


def test_nmap_scanner_not_installed(tmp_path: Path, scope_manager: ScopeManager) -> None:
    scope = scope_manager.build_default_scope(
        client="Test Client", name="Test Engagement", domain="example.com"
    )
    scope_manager.write_scope(tmp_path / "scope.yaml", scope)

    mock_runner = MagicMock()
    mock_runner.scan.side_effect = ToolNotFoundError("Nmap not installed")

    scanner = NmapScanner(
        project_path=tmp_path,
        target="example.com",
        scope_manager=scope_manager,
        nmap_runner=mock_runner,
    )

    with pytest.raises(ScannerError) as exc_info:
        scanner.run()
    assert "Nmap não está instalado" in str(exc_info.value)


def test_nmap_scanner_timeout(tmp_path: Path, scope_manager: ScopeManager) -> None:
    scope = scope_manager.build_default_scope(
        client="Test Client", name="Test Engagement", domain="example.com"
    )
    scope_manager.write_scope(tmp_path / "scope.yaml", scope)

    mock_runner = MagicMock()
    mock_runner.scan.side_effect = ToolTimeoutError("Timeout exceeded")

    scanner = NmapScanner(
        project_path=tmp_path,
        target="example.com",
        scope_manager=scope_manager,
        nmap_runner=mock_runner,
    )

    with pytest.raises(ScannerError) as exc_info:
        scanner.run()
    assert "excedeu o tempo limite" in str(exc_info.value)


def test_nmap_scanner_xml_invalid(tmp_path: Path, scope_manager: ScopeManager) -> None:
    scope = scope_manager.build_default_scope(
        client="Test Client", name="Test Engagement", domain="example.com"
    )
    scope_manager.write_scope(tmp_path / "scope.yaml", scope)

    mock_tool_result = ToolExecutionResult(
        tool_name="nmap",
        command="nmap -sV -oX scan.xml example.com",
        exit_code=0,
        stdout="",
        stderr="",
        duration=2.0,
        success=True,
    )
    mock_runner = MagicMock()
    mock_runner.scan.return_value = mock_tool_result

    # Mock invalid XML output on disk
    def mock_scan_side_effect(target, xml_path, *args, **kwargs):
        Path(xml_path).write_text("<invalid-xml>", encoding="utf-8")
        return mock_tool_result

    mock_runner.scan.side_effect = mock_scan_side_effect

    scanner = NmapScanner(
        project_path=tmp_path,
        target="example.com",
        scope_manager=scope_manager,
        nmap_runner=mock_runner,
    )

    with pytest.raises(ScannerError) as exc_info:
        scanner.run()
    assert "XML do Nmap é inválido" in str(exc_info.value)


def test_nmap_scanner_failed_to_resolve(tmp_path: Path, scope_manager: ScopeManager) -> None:
    scope = scope_manager.build_default_scope(
        client="Test Client", name="Test Engagement", domain="example.com"
    )
    scope_manager.write_scope(tmp_path / "scope.yaml", scope)

    mock_tool_result = ToolExecutionResult(
        tool_name="nmap",
        command="nmap -sV -oX scan.xml example.com",
        exit_code=1,
        stdout="Failed to resolve/resolve example.com.",
        stderr="Failed to resolve example.com.",
        duration=1.0,
        success=False,
    )
    mock_runner = MagicMock()
    mock_runner.scan.return_value = mock_tool_result

    def mock_scan_side_effect(target, xml_path, *args, **kwargs):
        Path(xml_path).write_text("", encoding="utf-8")
        return mock_tool_result

    mock_runner.scan.side_effect = mock_scan_side_effect

    scanner = NmapScanner(
        project_path=tmp_path,
        target="example.com",
        scope_manager=scope_manager,
        nmap_runner=mock_runner,
    )

    with pytest.raises(ScannerError) as exc_info:
        scanner.run()
    assert "Alvo inacessível: Não foi possível resolver" in str(exc_info.value)


def test_nmap_scanner_generic_execution_error(tmp_path: Path, scope_manager: ScopeManager) -> None:
    scope = scope_manager.build_default_scope(
        client="Test Client", name="Test Engagement", domain="example.com"
    )
    scope_manager.write_scope(tmp_path / "scope.yaml", scope)

    mock_runner = MagicMock()
    mock_runner.scan.side_effect = ToolExecutionError("Process returned exit code 1")

    scanner = NmapScanner(
        project_path=tmp_path,
        target="example.com",
        scope_manager=scope_manager,
        nmap_runner=mock_runner,
    )

    with pytest.raises(ScannerError) as exc_info:
        scanner.run()
    assert "Erro durante a execução do Nmap" in str(exc_info.value)


def test_nmap_scanner_xml_missing(tmp_path: Path, scope_manager: ScopeManager) -> None:
    scope = scope_manager.build_default_scope(
        client="Test Client", name="Test Engagement", domain="example.com"
    )
    scope_manager.write_scope(tmp_path / "scope.yaml", scope)

    mock_tool_result = ToolExecutionResult(
        tool_name="nmap",
        command="nmap -sV -oX scan.xml example.com",
        exit_code=0,
        stdout="",
        stderr="",
        duration=2.0,
        success=True,
    )
    mock_runner = MagicMock()
    mock_runner.scan.return_value = mock_tool_result

    scanner = NmapScanner(
        project_path=tmp_path,
        target="example.com",
        scope_manager=scope_manager,
        nmap_runner=mock_runner,
    )

    with pytest.raises(ScannerError) as exc_info:
        scanner.run()
    assert "não foi gerado ou está vazio" in str(exc_info.value)


def test_cli_scan_nmap_out_of_scope(monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("GHOSTMIRROR_HOME", str(tmp_path))
    runner = CliRunner()

    # Create project
    runner.invoke(
        app,
        ["create", "-c", "Test Client", "-n", "Engage", "-d", "example.com"],
    )

    # Try executing nmap scan with out-of-scope target
    result = runner.invoke(
        app,
        ["scan", "nmap", "-p", "test-client-engage", "-t", "out-of-scope.com"],
    )
    
    assert result.exit_code == 1
    assert "Execução Bloqueada" in result.stdout


@patch("ghostmirror.modules.nmap.scanner.NmapScanner.run")
def test_cli_scan_nmap_success(mock_run, monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("GHOSTMIRROR_HOME", str(tmp_path))
    runner = CliRunner()

    # Create project
    runner.invoke(
        app,
        ["create", "-c", "Test Client", "-n", "Engage", "-d", "example.com"],
    )

    from ghostmirror.modules.models.finding import ScanResultModel, FindingModel, FindingSeverity

    # Mock scan result
    mock_scan_result = ScanResultModel(
        scanner_name="nmap",
        target="example.com",
        started_at=datetime.utcnow(),
        finished_at=datetime.utcnow(),
        status="completed",
        findings=[
            FindingModel(
                title="SSH Exposed",
                description="SSH Exposed",
                severity=FindingSeverity.INFO,
                target="example.com",
                recommendation="Fix it",
            ),
            FindingModel(
                title="SMB Exposed",
                description="SMB Exposed",
                severity=FindingSeverity.HIGH,
                target="example.com",
                recommendation="Fix it",
            )
        ],
        statistics={"total": 2, "high": 1, "medium": 0, "info": 1},
        open_ports=[22, 445],
        services=["ssh", "microsoft-ds"],
    )
    mock_run.return_value = mock_scan_result

    # Execute subcommand
    result = runner.invoke(
        app,
        ["scan", "nmap", "-p", "test-client-engage", "-t", "example.com"],
    )

    assert result.exit_code == 0
    assert "NMAP SCAN COMPLETE" in result.stdout
    assert "Target:" in result.stdout
    assert "example.com" in result.stdout
    assert "Open Ports:" in result.stdout
    assert "2" in result.stdout
    assert "Services:" in result.stdout
    assert "microsoft-ds" in result.stdout
    assert "ssh" in result.stdout
    assert "Findings:" in result.stdout
    assert "2" in result.stdout
    assert "High:" in result.stdout
    assert "1" in result.stdout
    assert "Medium:" in result.stdout
    assert "0" in result.stdout
    assert "Info:" in result.stdout
    assert "1" in result.stdout
