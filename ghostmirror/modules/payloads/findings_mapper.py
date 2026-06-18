"""PayloadFindingsMapper — converts PayloadResult to FindingModel."""

from __future__ import annotations

from ghostmirror.models.payload_result import PayloadResult
from ghostmirror.modules.models.finding import FindingModel, FindingSeverity

SEVERITY_MAP: dict[str, FindingSeverity] = {
    "reflected_content_detected": FindingSeverity.MEDIUM,
    "reflected_script_tag": FindingSeverity.MEDIUM,
    "reflected_img_onerror": FindingSeverity.MEDIUM,
    "reflected_svg_onload": FindingSeverity.MEDIUM,
    "reflected_javascript_url": FindingSeverity.MEDIUM,
    "reflected_template_expression": FindingSeverity.MEDIUM,
    "reflected_template_config": FindingSeverity.LOW,
    "sql_error_message": FindingSeverity.MEDIUM,
    "redirect_to_third_party": FindingSeverity.MEDIUM,
    "redirect_target_changed": FindingSeverity.LOW,
    "ssrf_surface_detected": FindingSeverity.INFO,
    "path_traversal_error": FindingSeverity.LOW,
    "header_injection_detected": FindingSeverity.MEDIUM,
    "status_class_changed": FindingSeverity.INFO,
    "status_code_changed": FindingSeverity.INFO,
    "response_time_increased": FindingSeverity.INFO,
}

SIGNAL_TITLES: dict[str, str] = {
    "reflected_content_detected": "Reflected Input Indicator",
    "reflected_script_tag": "Reflected XSS Indicator",
    "reflected_img_onerror": "Reflected XSS Indicator",
    "reflected_svg_onload": "Reflected XSS Indicator",
    "reflected_javascript_url": "Reflected XSS Indicator",
    "reflected_template_expression": "Potential Template Injection Indicator",
    "reflected_template_config": "Potential Template Injection Indicator",
    "sql_error_message": "SQL Error Indicator",
    "redirect_to_third_party": "Open Redirect Indicator",
    "redirect_target_changed": "Open Redirect Indicator",
    "ssrf_surface_detected": "SSRF Surface Indicator",
    "path_traversal_error": "Path Traversal Surface Indicator",
    "header_injection_detected": "Potential Header Injection Indicator",
    "status_class_changed": "Unexpected Status Code Change",
    "status_code_changed": "Unexpected Status Code Change",
    "response_time_increased": "Response Time Anomaly",
}

SIGNAL_RECOMMENDATIONS: dict[str, str] = (
    {
        "reflected_content_detected": (
            "Validar a codificação de saída (output encoding) para o parâmetro testado. "
            "Implementar sanitização específica para o contexto (HTML, JavaScript, URL)."
        ),
        "reflected_script_tag": (
            "Implementar Content Security Policy (CSP) e validação de entrada. "
            "Utilizar encoding contextual (OWASP Java Encoder / Microsoft AntiXSS)."
        ),
        "reflected_img_onerror": (
            "Implementar Content Security Policy (CSP) com restrição de script-src. "
            "Validar e sanitizar entradas do usuário."
        ),
        "reflected_svg_onload": (
            "Restringir elementos SVG em entradas de usuário. "
            "Implementar política de segurança de conteúdo (CSP)."
        ),
        "reflected_javascript_url": (
            "Bloquear protocolos javascript: em URLs. "
            "Validar e sanitizar URLs fornecidas pelo usuário."
        ),
        "reflected_template_expression": (
            "Validar a engine de templates utilizada. "
            "Assegurar que entradas do usuário não são interpretadas como código de template. "
            "Implementar sandboxing da template engine."
        ),
        "reflected_template_config": (
            "Revisar a exposição de configuração via template engine. "
            "Restringir acesso a variáveis internas."
        ),
        "sql_error_message": (
            "Implementar prepared statements ou ORM com parameterized queries. "
            "Garantir que mensagens de erro do banco não sejam expostas ao usuário."
        ),
        "redirect_to_third_party": (
            "Implementar whitelist de URLs de redirecionamento válidas. "
            "Nunca confiar em parâmetros de URL para determinar destinos de redirect."
        ),
        "redirect_target_changed": (
            "Revisar a lógica de redirecionamento. "
            "Validar que o destino do redirect está em uma whitelist."
        ),
        "ssrf_surface_detected": (
            "Implementar whitelist de endpoints que o servidor pode acessar. "
            "Bloquear acesso a IPs privados (127.0.0.1, 10.x.x.x, 172.16.x.x, 192.168.x.x)."
        ),
        "path_traversal_error": (
            "Normalizar e validar caminhos de arquivo. "
            "Utilizar APIs seguras que previnem path traversal. "
            "Bloquear caracteres '..' e barras em nomes de arquivo."
        ),
        "header_injection_detected": (
            "Remover caracteres de controle (CR/LF) de entradas do usuário. "
            "Utilizar APIs de header que sanitizam automaticamente."
        ),
        "status_class_changed": (
            "Revisar a manipulação de erros para o parâmetro testado. "
            "Assegurar que exceções não resultam em códigos de status inesperados."
        ),
        "status_code_changed": (
            "Revisar a lógica de tratamento para o parâmetro testado. "
            "Verificar se códigos de status alternativos são intencionais."
        ),
        "response_time_increased": (
            "Investigar aumento incomum no tempo de resposta. "
            "Pode indicar processamento excessivo ou consultas lentas."
        ),
    }
)


class PayloadFindingsMapper:
    """Converts PayloadResult objects to FindingModel instances."""

    @staticmethod
    def to_finding(result: PayloadResult) -> FindingModel | None:
        """Convert a PayloadResult to a FindingModel if a signal was matched.

        Returns None if no signal was detected (nothing to report).
        """
        if not result.matched_signal and not result.error:
            return None

        if result.dry_run or result.blocked:
            return None

        signal = result.matched_signal or "error"
        title = SIGNAL_TITLES.get(signal, "Payload Validation Finding")
        severity = SEVERITY_MAP.get(signal, FindingSeverity.INFO)
        recommendation = SIGNAL_RECOMMENDATIONS.get(
            signal, "Revisar o parâmetro testado para potenciais vulnerabilidades."
        )

        evidence_parts: list[str] = [f"URL: {result.url}"]
        evidence_parts.append(f"Payload ID: {result.payload_id}")
        evidence_parts.append(f"Parâmetro: {result.parameter}")
        evidence_parts.append(
            f"Status: baseline={result.status_code_baseline} / probe={result.status_code_probe}"
        )
        evidence_parts.append(f"Content-Length diff: {result.content_length_diff}")
        if result.signal_detail:
            evidence_parts.append(f"Detalhe: {result.signal_detail}")
        if result.response_time_probe > 0:
            evidence_parts.append(
                f"Response Time: baseline={result.response_time_baseline:.2f}s / "
                f"probe={result.response_time_probe:.2f}s"
            )
        if result.evidence_path:
            evidence_parts.append(f"Evidência: {result.evidence_path}")
        if result.error:
            evidence_parts.append(f"Erro: {result.error}")

        description = (
            f"Categoria: {result.payload_category}\n\n"
            f"Sinal: {signal}\n\n"
            + "\n".join(evidence_parts)
        )

        return FindingModel(
            title=title,
            description=description,
            severity=severity,
            target=result.target,
            evidence=result.signal_detail or result.error or "N/A",
            recommendation=recommendation,
        )

    @staticmethod
    def to_finding_list(
        results: list[PayloadResult],
    ) -> list[FindingModel]:
        """Convert multiple PayloadResult objects to FindingModel list."""
        findings: list[FindingModel] = []
        for r in results:
            finding = PayloadFindingsMapper.to_finding(r)
            if finding is not None:
                findings.append(finding)
        return findings
