"""Concrete implementation of the Nmap Port Scanner module."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ghostmirror.core.logger import get_logger
from ghostmirror.integrations.base.tool_runner import (
    ToolError,
    ToolExecutionError,
    ToolNotFoundError,
    ToolTimeoutError,
)
from ghostmirror.integrations.models.port_finding import PortFinding
from ghostmirror.integrations.nmap.scanner import NmapParser, NmapRunner
from ghostmirror.modules.base.scanner import OutOfScopeError, ScannerBase, ScannerError
from ghostmirror.modules.models.finding import (
    FindingModel,
    FindingSeverity,
    ScanResultModel,
)
from ghostmirror.storage.filesystem import FileSystemStorage

logger = get_logger()


class NmapScanner(ScannerBase):
    """NmapScanner audits open ports, services, and software versions of a target.

    Uses ToolRunner to execute Nmap safely, parses the XML report, generates findings
    based on exposed ports, and saves raw and parsed results in the project evidence folder.
    """

    SCANNER_NAME = "nmap"
    SCANNER_VERSION = "0.1.0"

    def __init__(
        self,
        project_path: Path | str,
        target: str,
        scope_manager: Any | None = None,
        findings_manager: Any | None = None,
        nmap_runner: NmapRunner | None = None,
    ) -> None:
        super().__init__(project_path, target, scope_manager, findings_manager)
        self.nmap_runner = nmap_runner or NmapRunner()

    def get_metadata(self) -> dict[str, Any]:
        """Return NmapScanner metadata."""
        return {
            "name": self.SCANNER_NAME,
            "version": self.SCANNER_VERSION,
            "description": "Nmap Port Scanner and Service Discoverer",
        }

    def run(self) -> ScanResultModel:
        """Run the Nmap port scanner on the target.

        Validates scope first, then calls NmapRunner, parses results, maps severities,
        saves outputs, and returns the result.
        """
        from ghostmirror.modules.platform.logger import log_audit

        logger.info("SCAN_STARTED scanner={} target={}", self.SCANNER_NAME, self.target)
        log_audit(
            event="scan iniciado",
            project=self.project_path.name,
            scanner=self.SCANNER_NAME,
            result="pendente",
        )
        started_at = datetime.now(timezone.utc)

        # 1. Enforce Scope Validation
        try:
            self.validate_scope()
        except OutOfScopeError as exc:
            logger.error("SCAN_BLOCKED scanner={} target={} reason={}", self.SCANNER_NAME, self.target, exc)
            log_audit(
                event="scan finalizado",
                project=self.project_path.name,
                scanner=self.SCANNER_NAME,
                result="bloqueado",
            )
            raise

        # 2. Setup Evidence Directory
        evidence_dir = self.project_path / "evidence" / self.SCANNER_NAME
        FileSystemStorage.ensure_dir(evidence_dir)

        xml_path = evidence_dir / "scan.xml"
        raw_path = evidence_dir / "scan_raw.txt"
        json_path = evidence_dir / "parsed_results.json"

        findings: list[FindingModel] = []
        open_ports: list[int] = []
        services: list[str] = []
        status = "failed"

        try:
            # Execute scanner
            result = self.nmap_runner.scan(self.target, xml_path)

            # Save raw stdout/stderr
            raw_content = f"STDOUT:\n{result.stdout}\n\nSTDERR:\n{result.stderr}"
            FileSystemStorage.write_text(raw_path, raw_content)

            # Check execution output for target inaccessibility/resolution errors
            if "failed to resolve" in result.stdout.lower() or "failed to resolve" in result.stderr.lower():
                raise ScannerError(
                    f"Alvo inacessível: Não foi possível resolver o hostname '{self.target}'."
                )

            if not xml_path.exists() or xml_path.stat().st_size == 0:
                raise ScannerError(
                    "O output XML do Nmap não foi gerado ou está vazio."
                )

            # Parse XML
            port_findings = NmapParser.parse_xml_file(xml_path)

            # Save parsed JSON
            parsed_data = [pf.model_dump() for pf in port_findings]
            FileSystemStorage.write_json(json_path, parsed_data)

            # Filter for open ports and construct findings
            for pf in port_findings:
                if pf.state.lower() == "open":
                    open_ports.append(pf.port)
                    services.append(pf.service)
                    findings.append(self._map_port_to_finding(pf))

            status = "completed"

        except ToolNotFoundError as exc:
            logger.error("NMAP_NOT_INSTALLED error={}", exc)
            raise ScannerError(
                "Nmap não está instalado ou disponível no PATH do sistema. Por favor, instale o Nmap para prosseguir."
            ) from exc
        except ToolTimeoutError as exc:
            logger.error("NMAP_TIMEOUT error={}", exc)
            raise ScannerError(
                "O scan do Nmap excedeu o tempo limite configurado (Timeout)."
            ) from exc
        except ValueError as exc:
            logger.error("NMAP_XML_INVALID error={}", exc)
            raise ScannerError(
                "O output XML do Nmap é inválido ou corrompido."
            ) from exc
        except ScannerError:
            # Re-raise explicit scanner errors directly
            raise
        except ToolExecutionError as exc:
            logger.error("NMAP_EXECUTION_ERROR error={}", exc)
            raise ScannerError(
                f"Erro durante a execução do Nmap. Verifique as permissões ou se o host está ativo. Detalhes: {exc}"
            ) from exc
        except Exception as exc:
            logger.exception("NMAP_UNEXPECTED_ERROR error={}", exc)
            raise ScannerError(
                f"Erro inesperado durante o scan do Nmap: {exc}"
            ) from exc

        finished_at = datetime.now(timezone.utc)
        stats = self.calculate_statistics(findings)

        result_model = ScanResultModel(
            scanner_name=self.SCANNER_NAME,
            target=self.target,
            started_at=started_at,
            finished_at=finished_at,
            status=status,
            findings=findings,
            statistics=stats,
            open_ports=open_ports,
            services=services,
        )

        # 3. Persist findings (only if completed successfully)
        if status == "completed":
            self.save_findings(result_model)

        logger.info(
            "SCAN_FINISHED scanner={} target={} status={} findings={} elapsed={:.2f}s",
            self.SCANNER_NAME,
            self.target,
            status,
            len(findings),
            (finished_at - started_at).total_seconds(),
        )
        log_audit(
            event="scan finalizado",
            project=self.project_path.name,
            scanner=self.SCANNER_NAME,
            result=status,
        )

        return result_model

    def _map_port_to_finding(self, pf: PortFinding) -> FindingModel:
        """Map an open port to a detailed FindingModel based on severity rules."""
        port = pf.port
        service = pf.service
        protocol = pf.protocol
        product = pf.product
        version = pf.version

        # Rule mappings:
        # 22 SSH -> INFO
        # 80 HTTP -> INFO
        # 443 HTTPS -> INFO
        # 21 FTP -> MEDIUM
        # 23 Telnet -> HIGH
        # 445 SMB -> HIGH
        # 3389 RDP -> MEDIUM
        # 3306 MySQL -> HIGH
        # 5432 PostgreSQL -> HIGH
        # 6379 Redis -> HIGH
        # 27017 MongoDB -> HIGH
        # Default -> INFO

        port_rules = {
            22: (
                "SSH Exposed",
                FindingSeverity.INFO,
                "O serviço SSH (Secure Shell) está exposto.",
                "Restrinja o acesso à porta 22 usando regras de firewall para permitir apenas IPs confiáveis, e desative autenticação por senha em favor de chaves públicas criptográficas.",
            ),
            80: (
                "HTTP Exposed",
                FindingSeverity.INFO,
                "Um servidor web HTTP não criptografado foi detectado ativo.",
                "Redirecione todo o tráfego HTTP para HTTPS (porta 443) e configure o cabeçalho HSTS.",
            ),
            443: (
                "HTTPS Exposed",
                FindingSeverity.INFO,
                "Um servidor web HTTPS criptografado foi detectado ativo.",
                "Garanta a utilização de suites de criptografia modernas e seguras, e mantenha o certificado SSL/TLS atualizado.",
            ),
            21: (
                "FTP Exposed",
                FindingSeverity.MEDIUM,
                "O serviço FTP (File Transfer Protocol) foi detectado exposto. FTP é um protocolo antigo que trafega dados e credenciais em texto claro.",
                "Desative o serviço FTP e utilize alternativas seguras, como SFTP (SSH File Transfer Protocol) ou FTPS.",
            ),
            23: (
                "Telnet Exposed",
                FindingSeverity.HIGH,
                "O serviço Telnet foi detectado exposto. Telnet transmite todo o tráfego, incluindo comandos e credenciais de login, sem qualquer criptografia.",
                "Desative o serviço Telnet imediatamente e adote o SSH para administração remota.",
            ),
            445: (
                "SMB Exposed",
                FindingSeverity.HIGH,
                "O serviço SMB (Server Message Block) está exposto à rede. A exposição de SMB pode permitir acesso não autorizado a arquivos e expor o sistema a vulnerabilidades críticas de execução remota de código.",
                "Bloqueie o acesso à porta 445/TCP a partir da internet e restrinja seu acesso a redes internas autorizadas.",
            ),
            3389: (
                "RDP Exposed",
                FindingSeverity.MEDIUM,
                "O serviço RDP (Remote Desktop Protocol) está exposto. O RDP exposto é um alvo frequente para ataques de força bruta, sequestro de sessões e exploração de vulnerabilidades.",
                "Desative a exposição pública do RDP. Utilize conexões via VPN corporativa e adote autenticação multifator (MFA).",
            ),
            3306: (
                "Database Service Exposed",
                FindingSeverity.HIGH,
                "O serviço de banco de dados MySQL está exposto.",
                "Configure o banco de dados para escutar apenas em localhost (127.0.0.1) ou interfaces de rede privada confiáveis, e bloqueie a porta 3306/TCP no firewall.",
            ),
            5432: (
                "Database Service Exposed",
                FindingSeverity.HIGH,
                "O serviço de banco de dados PostgreSQL está exposto.",
                "Configure o banco de dados para escutar apenas em localhost (127.0.0.1) ou interfaces de rede privada confiáveis, e bloqueie a porta 5432/TCP no firewall.",
            ),
            6379: (
                "Database Service Exposed",
                FindingSeverity.HIGH,
                "O banco de dados Redis está exposto.",
                "Configure o Redis para habilitar autenticação robusta (requirepass), limite as interfaces de escuta a redes locais seguras, e bloqueie a porta 6379/TCP.",
            ),
            27017: (
                "Database Service Exposed",
                FindingSeverity.HIGH,
                "O banco de dados MongoDB está exposto.",
                "Habilite a autenticação integrada do MongoDB, restrinja o acesso a endereços IP autorizados via firewall e configure o serviço para escutar em interfaces privadas.",
            ),
        }

        if port in port_rules:
            title, severity, desc, rec = port_rules[port]
        else:
            title = "Porta desconhecida aberta"
            severity = FindingSeverity.INFO
            desc = f"Uma porta desconhecida ({port}/{protocol}) foi identificada aberta no alvo."
            rec = "Audite o serviço rodando nesta porta e bloqueie seu acesso no firewall se não for necessária para operações de negócios."

        # Include product/version info in description and evidence if available
        service_info = f"Porta: {port}/{protocol}\nServiço: {service}"
        if product != "Unknown":
            service_info += f"\nProduto: {product}"
        if version != "Unknown":
            service_info += f"\nVersão: {version}"

        full_desc = f"{desc}\n\nDetalhes do Serviço:\n{service_info}"

        return FindingModel(
            title=title,
            description=full_desc,
            severity=severity,
            target=self.target,
            evidence=service_info,
            recommendation=rec,
        )
