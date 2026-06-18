"""Concrete implementation of the Technology Fingerprint and Intelligence module."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

from ghostmirror.core.logger import get_logger
from ghostmirror.integrations.base.tool_runner import (
    ToolError,
    ToolExecutionError,
    ToolNotFoundError,
    ToolTimeoutError,
)
from ghostmirror.integrations.whatweb.scanner import WhatWebRunner
from ghostmirror.integrations.whatweb.parser import WhatWebParser
from ghostmirror.modules.base.scanner import OutOfScopeError, ScannerBase, ScannerError
from ghostmirror.modules.models.finding import (
    FindingModel,
    FindingSeverity,
    ScanResultModel,
)
from ghostmirror.modules.fingerprint.intelligence import (
    AIFingerprintEngine,
    FingerprintIntelligence,
)
from ghostmirror.modules.fingerprint.profiler import TechnologyProfiler
from ghostmirror.storage.filesystem import FileSystemStorage

logger = get_logger()


class FingerprintScanner(ScannerBase):
    """FingerprintScanner audits target technology stack, hosting, WAF, CDN, and AI footprint.

    Integrates WhatWeb for scanning, scrapes target content to identify AI indicators,
    correlates components using the Fingerprint Intelligence Engine, compiles a unified
    target profile, and registers informational findings.
    """

    SCANNER_NAME = "fingerprint"
    SCANNER_VERSION = "0.1.0"

    def __init__(
        self,
        project_path: Path | str,
        target: str,
        scope_manager: Any | None = None,
        findings_manager: Any | None = None,
        whatweb_runner: WhatWebRunner | None = None,
    ) -> None:
        super().__init__(project_path, target, scope_manager, findings_manager)
        self.whatweb_runner = whatweb_runner or WhatWebRunner()

    def get_metadata(self) -> dict[str, Any]:
        """Return FingerprintScanner metadata."""
        return {
            "name": self.SCANNER_NAME,
            "version": self.SCANNER_VERSION,
            "description": "WhatWeb Fingerprinting + Technology Profiler + AI Detection Engine",
        }

    def _fetch_target_homepage(self) -> dict[str, Any]:
        """Safely probes the target URL/domain to retrieve HTML and headers for AI checks."""
        url = self.target
        if not url.startswith(("http://", "https://")):
            url = f"https://{self.target}"

        headers = {
            "User-Agent": "GhostMirror/0.5.0 (Fingerprint Intelligence Engine)"
        }

        # First, try HTTPS
        try:
            logger.info("HTTP_PROBE_START url={} method=GET", url)
            with httpx.Client(verify=False, follow_redirects=True, timeout=8.0) as client:
                resp = client.get(url, headers=headers)
                return {
                    "status_code": resp.status_code,
                    "headers": dict(resp.headers),
                    "html": resp.text,
                }
        except Exception as exc:
            logger.warning("HTTPS_PROBE_FAILED url={} error={}", url, exc)
            # Try falling back to HTTP
            if url.startswith("https://"):
                url_http = url.replace("https://", "http://")
                try:
                    logger.info("HTTP_PROBE_FALLBACK url={} method=GET", url_http)
                    with httpx.Client(verify=False, follow_redirects=True, timeout=8.0) as client:
                        resp = client.get(url_http, headers=headers)
                        return {
                            "status_code": resp.status_code,
                            "headers": dict(resp.headers),
                            "html": resp.text,
                        }
                except Exception as exc2:
                    logger.warning("HTTP_PROBE_FAILED url={} error={}", url_http, exc2)

        return {
            "status_code": 0,
            "headers": {},
            "html": "",
        }

    def run(self) -> ScanResultModel:
        """Run the technology profiling scanner on the target.

        Validates scope first, executes WhatWeb, crawls target homepage, runs correlation and
        AI detection engine, compiles profiling models, persists findings, and returns the result.
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

        # 1. Scope Validation
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

        # 2. Setup Evidence and Profiles Directories
        evidence_dir = self.project_path / "evidence" / "whatweb"
        profiles_dir = self.project_path / "profiles"

        FileSystemStorage.ensure_dir(evidence_dir)
        FileSystemStorage.ensure_dir(profiles_dir)

        json_output_path = evidence_dir / "parsed_output.json"
        raw_output_path = evidence_dir / "raw_output.txt"

        findings: list[FindingModel] = []
        status = "failed"

        try:
            # 3. Execute WhatWeb scanner
            result = self.whatweb_runner.scan(self.target, json_output_path)

            # Save raw stdout/stderr
            raw_content = f"STDOUT:\n{result.stdout}\n\nSTDERR:\n{result.stderr}"
            FileSystemStorage.write_text(raw_output_path, raw_content)

            # Check if target resolution or connection error occurred
            if "failed to resolve" in result.stdout.lower() or "failed to resolve" in result.stderr.lower():
                raise ScannerError(
                    f"Alvo inacessível: Não foi possível resolver o hostname '{self.target}'."
                )

            if not json_output_path.exists() or json_output_path.stat().st_size == 0:
                raise ScannerError(
                    "O output JSON do WhatWeb não foi gerado ou está vazio."
                )

            # 4. Parse WhatWeb JSON file
            detections = WhatWebParser.parse_json_file(json_output_path)

            # Map raw detections to TechnologyModels
            tech_list = []
            for det in detections:
                tech_model = FingerprintIntelligence.map_detection(
                    plugin_name=det["name"],
                    version=det["version"]
                )
                if tech_model:
                    tech_list.append(tech_model)

            # 5. Scrape homepage content for AI indicators
            probe_result = self._fetch_target_homepage()

            # 6. AI footprint detection
            ai_profile = AIFingerprintEngine.analyze(
                html=probe_result["html"],
                headers=probe_result["headers"]
            )

            # 7. Correlate and enrich technologies list
            enriched_techs = FingerprintIntelligence.correlate(tech_list)

            # 8. Compile profile
            fingerprint_profile = TechnologyProfiler.build_profile(
                target=self.target,
                technologies=enriched_techs
            )

            # 9. Save JSON profiles
            FileSystemStorage.write_json(
                profiles_dir / "technology_profile.json",
                fingerprint_profile.model_dump(mode="json")
            )
            FileSystemStorage.write_json(
                profiles_dir / "ai_profile.json",
                ai_profile.model_dump(mode="json")
            )

            # 10. Construct Informational Findings
            # Generates a finding for each normalized technology detected
            for tech in fingerprint_profile.technologies:
                # Severity INFO mapping
                version_info = f" (Versão: {tech.version})" if tech.version else ""
                desc = (
                    f"A tecnologia {tech.name} ({tech.category}) foi identificada ativa no alvo{version_info}.\n\n"
                    f"Informações de Detecção:\n"
                    f"- Tecnologia: {tech.name}\n"
                    f"- Categoria: {tech.category}\n"
                    f"- Confiança: {tech.confidence * 100:.0f}%\n"
                    f"- Origem: {tech.source}"
                )
                rec = (
                    f"Mantenha a tecnologia {tech.name} atualizada na sua última versão estável "
                    f"para evitar possíveis exposições a vulnerabilidades conhecidas (CVEs)."
                )
                findings.append(
                    FindingModel(
                        title=f"{tech.name} Detected",
                        description=desc,
                        severity=FindingSeverity.INFO,
                        target=self.target,
                        evidence=f"Detection details:\n- Source: {tech.source}\n- Version: {tech.version or 'Unknown'}",
                        recommendation=rec
                    )
                )

            # Generates finding for AI suspect
            if ai_profile.ai_probability >= 30.0:
                signals_str = ", ".join(ai_profile.signals_detected)
                desc = (
                    f"Suspeita de aplicação gerada por inteligência artificial (Probabilidade: {ai_profile.ai_probability}%).\n\n"
                    f"Sinais de desenvolvimento assistido por IA ou SDKs de LLM foram detectados no código-fonte "
                    f"ou nas respostas HTTP do alvo.\n\n"
                    f"- Probabilidade Calculada: {ai_profile.ai_probability}%\n"
                    f"- Indicadores Encontrados: {signals_str}\n"
                    f"- Integrações de Modelos (LLM): {', '.join(ai_profile.llm_integrations) or 'Nenhuma'}\n"
                    f"- Frameworks Identificados: {', '.join(ai_profile.frameworks_detected) or 'Nenhum'}\n"
                    f"- Observações: {ai_profile.observations}"
                )
                rec = (
                    "Realize uma auditoria focada de segurança no código-fonte gerado e nas APIs integradas. "
                    "Gere verificações rigorosas contra falhas clássicas de injeção de prompt, vazamento de chaves "
                    "de API expostas no frontend, e verifique se as lógicas de negócio geradas por IA não contêm "
                    "brechas de controle de acesso vulneráveis."
                )
                findings.append(
                    FindingModel(
                        title="AI Generated Application Suspected",
                        description=desc,
                        severity=FindingSeverity.INFO,
                        target=self.target,
                        evidence=f"AI Signals Detected: {signals_str}\nLLM Integrations: {ai_profile.llm_integrations}",
                        recommendation=rec
                    )
                )

            status = "completed"

        except ToolNotFoundError:
            logger.warning("WHATWEB_NOT_INSTALLED — step will be skipped")
            raise
        except ToolTimeoutError as exc:
            logger.error("WHATWEB_TIMEOUT error={}", exc)
            raise ScannerError(
                "O scan do WhatWeb excedeu o tempo limite configurado (Timeout)."
            ) from exc
        except ValueError as exc:
            logger.error("WHATWEB_JSON_INVALID error={}", exc)
            raise ScannerError(
                "O output JSON do WhatWeb é inválido ou corrompido."
            ) from exc
        except ScannerError:
            raise
        except ToolExecutionError as exc:
            logger.error("WHATWEB_EXECUTION_ERROR error={}", exc)
            raise ScannerError(
                f"Erro durante a execução do WhatWeb. Verifique as permissões ou conectividade. Detalhes: {exc}"
            ) from exc
        except Exception as exc:
            logger.exception("WHATWEB_UNEXPECTED_ERROR error={}", exc)
            raise ScannerError(
                f"Erro inesperado durante o scan do WhatWeb: {exc}"
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
        )

        # 11. Save scan findings standard JSON under findings/fingerprint.json
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
