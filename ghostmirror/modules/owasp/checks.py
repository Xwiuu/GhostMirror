"""Individual OWASP Top 10 Light checks (A01–A10).

All checks are **safe**: no exploitation, no brute force, no destructive payloads.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from urllib.error import URLError
from urllib.request import Request, urlopen

from ghostmirror.core.logger import get_logger
from ghostmirror.models.owasp_finding import OWASPCategory, OWASPFinding
from ghostmirror.modules.models.finding import FindingSeverity

logger = get_logger()

REQUEST_TIMEOUT = 15
USER_AGENT = "GhostMirror-OWASP/1.0 (Security Assessment)"


# --------------------------------------------------------------------------- #
# HTTP helpers (safe, read-only)
# --------------------------------------------------------------------------- #
def _request(
    target: str,
    path: str = "/",
    method: str = "GET",
    timeout: int = REQUEST_TIMEOUT,
) -> tuple[int, dict[str, str], str]:
    """Safe HTTP request returning (status_code, headers_dict, body)."""
    url = target.rstrip("/") + path
    req = Request(url, method=method.upper())
    req.add_header("User-Agent", USER_AGENT)
    try:
        with urlopen(req, timeout=timeout) as resp:
            headers = dict(resp.headers)
            body = resp.read().decode("utf-8", errors="replace")
            return resp.status, headers, body
    except URLError as exc:
        logger.debug("HTTP error for {}: {}", url, exc)
        if hasattr(exc, "code") and exc.code is not None:
            return exc.code, {}, ""
        return 0, {}, ""
    except Exception as exc:
        logger.debug("Request failed for {}: {}", url, exc)
        return 0, {}, ""


def _head_url(target: str, path: str = "/") -> int:
    """Returns HTTP status code via HEAD request (0 on failure)."""
    code, _, _ = _request(target, path, method="HEAD")
    return code


def _fetch_body(target: str, path: str = "/") -> str:
    """Returns response body as string (empty on failure)."""
    _, _, body = _request(target, path, method="GET")
    return body


# --------------------------------------------------------------------------- #
# HTML parser helpers
# --------------------------------------------------------------------------- #
@dataclass
class FormInfo:
    method: str = "GET"
    action: str = ""
    inputs: list[dict[str, str]] = field(default_factory=list)
    hidden_fields: list[dict[str, str]] = field(default_factory=list)
    has_token: bool = False


class _FormParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.forms: list[FormInfo] = []
        self._current_form: FormInfo | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attr_dict = {k: v or "" for k, v in attrs}
        if tag == "form":
            self._current_form = FormInfo(
                method=attr_dict.get("method", "GET").upper(),
                action=attr_dict.get("action", ""),
            )
        elif tag == "input" and self._current_form is not None:
            input_type = attr_dict.get("type", "text")
            input_name = attr_dict.get("name", "")
            input_info = {"type": input_type, "name": input_name}
            self._current_form.inputs.append(input_info)
            if input_type == "hidden":
                self._current_form.hidden_fields.append(input_info)
            if input_name.lower() in ("csrf_token", "_token", "authenticity_token", "nonce"):
                self._current_form.has_token = True

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._current_form is not None:
            self.forms.append(self._current_form)
            self._current_form = None


def _parse_forms(html: str) -> list[FormInfo]:
    parser = _FormParser()
    parser.feed(html)
    return parser.forms


def _find_links(html: str) -> list[str]:
    return re.findall(r'href=["\']([^"\']+)["\']', html)


def _find_scripts(html: str) -> list[str]:
    return re.findall(r'src=["\']([^"\']+)["\']', html)


def _find_inputs(html: str) -> list[str]:
    return re.findall(r'<input[^>]*name=["\']([^"\']+)["\']', html)


def _find_get_params(html: str) -> list[str]:
    params: set[str] = set()
    for match in re.findall(r'[\?&]([a-zA-Z_][a-zA-Z0-9_-]*)', html):
        params.add(match)
    return sorted(params)


# --------------------------------------------------------------------------- #
# A01 – Broken Access Control Indicators
# --------------------------------------------------------------------------- #
ADMIN_PATHS = [
    "/admin",
    "/administrator",
    "/wp-admin",
    "/manage",
    "/dashboard",
    "/controlpanel",
    "/cpanel",
    "/admin.php",
    "/admin/index.php",
    "/admin/login.php",
    "/administrator/index.php",
    "/administration",
    "/moderator",
    "/webadmin",
    "/sysadmin",
    "/panel",
    "/manager",
    "/management",
    "/backend",
    "/backoffice",
]


def check_admin_endpoints(target: str) -> list[OWASPFinding]:
    """Detect exposed administrative panels and management endpoints."""
    findings: list[OWASPFinding] = []
    accessible: list[str] = []

    for path in ADMIN_PATHS:
        status = _head_url(target, path)
        if status == 0:
            continue
        if status < 400 or status == 403:
            accessible.append(f"{path} (HTTP {status})")

    if accessible:
        findings.append(
            OWASPFinding(
                category=OWASPCategory.A01,
                title="Exposed Administrative Endpoints Detected",
                description=(
                    "Endpoints administrativos estão acessíveis via HTTP. "
                    "Painéis de gerenciamento expostos aumentam a superfície de ataque "
                    "para tentativas de acesso não autorizado."
                ),
                severity=FindingSeverity.HIGH,
                target=target,
                evidence="Endpoints acessíveis:\n" + "\n".join(accessible),
                recommendation=(
                    "Restrinja o acesso a endpoints administrativos por IP/firewall, "
                    "implemente autenticação forte e considere o uso de VPN para "
                    "acesso administrativo. Remova endpoints não utilizados."
                ),
                owasp_score=15,
            )
        )

    return findings


# --------------------------------------------------------------------------- #
# A02 – Cryptographic Failures
# --------------------------------------------------------------------------- #
def check_cryptographic_failures(project_path: Path) -> list[OWASPFinding]:
    """Correlate SSL findings with OWASP cryptographic failures."""
    findings: list[OWASPFinding] = []
    ssl_path = project_path / "findings" / "ssl.json"

    if not ssl_path.exists():
        return findings

    try:
        with open(ssl_path, "r", encoding="utf-8") as f:
            ssl_data = json.load(f)
    except Exception as exc:
        logger.warning("Could not load ssl.json for OWASP A02: {}", exc)
        return findings

    cert_summary = ssl_data.get("certificate_summary") or {}
    target = ssl_data.get("target", "")

    # Check expired certificate
    if cert_summary.get("is_expired"):
        findings.append(
            OWASPFinding(
                category=OWASPCategory.A02,
                title="Expired SSL/TLS Certificate",
                description=(
                    "O certificado SSL/TLS do alvo está expirado. "
                    "Certificados expirados causam falhas de criptografia "
                    "e indicam má gestão de segurança."
                ),
                severity=FindingSeverity.CRITICAL,
                target=target,
                evidence=f"Issuer: {cert_summary.get('issuer', 'Unknown')}\n"
                f"Expires: {cert_summary.get('expires_at', 'Unknown')}",
                recommendation="Renove imediatamente o certificado SSL/TLS junto à autoridade certificadora emissora.",
                owasp_score=25,
            )
        )

    # Check weak TLS versions
    tls_versions = cert_summary.get("tls_versions") or []
    weak_tls = [v for v in tls_versions if v in ("TLS 1.0", "TLS 1.1", "SSLv3", "SSLv2")]
    if weak_tls:
        findings.append(
            OWASPFinding(
                category=OWASPCategory.A02,
                title="Obsolete TLS Protocol Detected",
                description=(
                    f"Protocolos TLS obsoletos detectados: {', '.join(weak_tls)}. "
                    "Versões antigas do TLS possuem vulnerabilidades conhecidas "
                    "(POODLE, BEAST, LUCKY13) e devem ser desabilitadas."
                ),
                severity=FindingSeverity.HIGH,
                target=target,
                evidence=f"Protocolos suportados: {', '.join(tls_versions)}",
                recommendation="Desabilite TLS 1.0, TLS 1.1 e SSL. Force o uso de TLS 1.2 e TLS 1.3.",
                owasp_score=15,
            )
        )

    # Check weak signature algorithm (SHA1)
    sig_alg = cert_summary.get("signature_algorithm", "")
    if "sha1" in sig_alg.lower() or "md5" in sig_alg.lower():
        findings.append(
            OWASPFinding(
                category=OWASPCategory.A02,
                title="Weak Certificate Signature Algorithm",
                description=(
                    f"O certificado utiliza algoritmo de assinatura fraco: {sig_alg}. "
                    "Algoritmos como SHA-1 e MD5 são considerados inseguros."
                ),
                severity=FindingSeverity.MEDIUM,
                target=target,
                evidence=f"Signature Algorithm: {sig_alg}",
                recommendation="Reemita o certificado com algoritmo de assinatura SHA-256 ou superior.",
                owasp_score=8,
            )
        )

    # Check weak key
    key_size = cert_summary.get("key_size", 0)
    if key_size and key_size < 2048:
        findings.append(
            OWASPFinding(
                category=OWASPCategory.A02,
                title="Weak SSL/TLS Key Size",
                description=(
                    f"O tamanho da chave RSA é {key_size} bits, abaixo do "
                    "mínimo recomendado de 2048 bits. Chaves fracas podem ser "
                    "quebradas computacionalmente."
                ),
                severity=FindingSeverity.HIGH,
                target=target,
                evidence=f"Key Size: {key_size} bits",
                recommendation="Gere um novo par de chaves RSA com no mínimo 2048 bits (4096 preferível).",
                owasp_score=12,
            )
        )

    # Self-signed certificate
    if cert_summary.get("is_self_signed"):
        findings.append(
            OWASPFinding(
                category=OWASPCategory.A02,
                title="Self-Signed Certificate In Use",
                description=(
                    "O alvo utiliza um certificado autoassinado. Conexões "
                    "criptografadas com certificados autoassinados não podem "
                    "ter a identidade do servidor validada."
                ),
                severity=FindingSeverity.HIGH,
                target=target,
                evidence=f"Issuer: {cert_summary.get('issuer', 'Unknown')}",
                recommendation="Substitua o certificado autoassinado por um certificado emitido por AC confiável.",
                owasp_score=12,
            )
        )

    return findings


# --------------------------------------------------------------------------- #
# A03 – Injection Indicators
# --------------------------------------------------------------------------- #
INJECTION_SURFACE_PARAMS = ["q", "search", "id", "page", "query", "s", "term", "keyword"]


def check_injection_surface(target: str) -> list[OWASPFinding]:
    """Identify potential injection surfaces (parameters, forms, search)."""
    findings: list[OWASPFinding] = []
    body = _fetch_body(target)

    if not body:
        return findings

    params_in_links = _find_get_params(body)
    forms = _parse_forms(body)

    # Find form-based parameters
    form_params: list[str] = []
    for form in forms:
        for inp in form.inputs:
            if inp["name"]:
                form_params.append(inp["name"])

    # Cross-reference with known injection surface params
    injection_params = [p for p in params_in_links if p.lower() in INJECTION_SURFACE_PARAMS]
    injection_form_params = [p for p in form_params if p.lower() in INJECTION_SURFACE_PARAMS]

    all_params = injection_params + injection_form_params

    if all_params:
        findings.append(
            OWASPFinding(
                category=OWASPCategory.A03,
                title="Potential Injection Surface Identified",
                description=(
                    "Parâmetros comuns de injeção foram identificados na aplicação. "
                    "Parâmetros como 'id', 'search', 'q', 'page' são frequentemente "
                    "alvos de SQL Injection, Command Injection e XSS."
                ),
                severity=FindingSeverity.MEDIUM,
                target=target,
                evidence="Parâmetros de injeção potenciais:\n" + "\n".join(f"?{p}=<value>" for p in sorted(set(all_params))),
                recommendation=(
                    "Valide e sanitize rigorosamente todas as entradas do usuário. "
                    "Utilize prepared statements para consultas SQL, encoding de saída "
                    "para XSS e liste branca para parâmetros permitidos."
                ),
                owasp_score=8,
            )
        )

    # Count all forms as injection surface if present
    if forms:
        findings.append(
            OWASPFinding(
                category=OWASPCategory.A03,
                title=f"Forms Detected ({len(forms)} forms) — Potential Injection Vectors",
                description=(
                    f"Foram detectados {len(forms)} formulários HTML na página principal. "
                    "Formulários representam superfície potencial para ataques de injeção "
                    "se os dados não forem devidamente validados."
                ),
                severity=FindingSeverity.LOW,
                target=target,
                evidence=f"Total de forms: {len(forms)}\n" + "\n".join(
                    f"- {f.method} {f.action or '/'} ({len(f.inputs)} inputs)"
                    for f in forms[:10]
                ),
                recommendation=(
                    "Implemente validação de entrada no servidor, utilize prepared statements "
                    "e aplique encoding de saída específico para o contexto."
                ),
                owasp_score=3,
            )
        )

    # Search functionality
    search_indicators = re.findall(
        r'(search|busca|pesquisa|find|suche)', body, re.IGNORECASE
    )
    if search_indicators:
        findings.append(
            OWASPFinding(
                category=OWASPCategory.A03,
                title="Search Functionality Detected — Potential Injection Surface",
                description=(
                    "Funcionalidade de busca/pesquisa detectada. Campos de busca "
                    "são vetores conhecidos para SQL Injection, NoSQL Injection "
                    "e XSS refletido."
                ),
                severity=FindingSeverity.MEDIUM,
                target=target,
                evidence=f"Indicadores de busca encontrados: {', '.join(set(search_indicators))}",
                recommendation=(
                    "Implemente sanitização de entrada em campos de busca, "
                    "limite o tamanho de queries e utilize prepared statements "
                    "para consultas ao banco de dados."
                ),
                owasp_score=8,
            )
        )

    return findings


# --------------------------------------------------------------------------- #
# A04 – Insecure Design Indicators
# --------------------------------------------------------------------------- #
def check_insecure_design(
    target: str,
    has_admin_endpoints: bool = False,
) -> list[OWASPFinding]:
    """Identify indicators of insecure design patterns."""
    findings: list[OWASPFinding] = []

    if has_admin_endpoints:
        findings.append(
            OWASPFinding(
                category=OWASPCategory.A04,
                title="Insecure Design — Administrative Interface Without Apparent Access Control",
                description=(
                    "Endpoints administrativos estão publicamente acessíveis sem "
                    "barreiras aparentes. Isso pode indicar falha de design onde "
                    "áreas sensíveis não possuem controle de acesso adequado."
                ),
                severity=FindingSeverity.HIGH,
                target=target,
                evidence="Endpoints administrativos expostos publicamente.",
                recommendation=(
                    "Implemente controle de acesso baseado em função (RBAC) para "
                    "todas as áreas administrativas. Utilize autenticação multi-fator "
                    "e restrinja acesso por IP."
                ),
                owasp_score=15,
            )
        )

    return findings


# --------------------------------------------------------------------------- #
# A05 – Security Misconfiguration
# --------------------------------------------------------------------------- #
MISCONFIG_PATHS = [
    "/.git/config",
    "/.svn/entries",
    "/.env",
    "/backup.zip",
    "/config.php.bak",
    "/database.sql",
    "/phpinfo.php",
    "/test.php",
    "/info.php",
    "/wp-config.php.bak",
    "/dump.sql",
    "/backup.sql",
    "/app.tar.gz",
    "/.htaccess",
    "/.DS_Store",
]

DIRECTORY_LISTING_INDICATORS = [
    "Index of /",
    "<title>Index of",
    "Parent Directory</a>",
    "Directory listing for",
]


def check_misconfigurations(target: str) -> list[OWASPFinding]:
    """Detect security misconfigurations like exposed files and directory listing."""
    findings: list[OWASPFinding] = []

    # Check exposed sensitive files
    exposed_files: list[str] = []
    for path in MISCONFIG_PATHS:
        body = _fetch_body(target, path)
        if not body:
            continue
        if len(body) > 20:
            exposed_files.append(path)

    if exposed_files:
        findings.append(
            OWASPFinding(
                category=OWASPCategory.A05,
                title="Sensitive Files Exposed",
                description=(
                    "Arquivos sensíveis estão publicamente acessíveis no servidor web. "
                    "Isso pode expor credenciais, configurações de ambiente, "
                    "backups de banco de dados e informações internas."
                ),
                severity=FindingSeverity.CRITICAL,
                target=target,
                evidence="Arquivos expostos:\n" + "\n".join(exposed_files),
                recommendation=(
                    "Remova ou proteja com autenticação os seguintes arquivos. "
                    "Configure o servidor web para bloquear acesso a diretórios "
                    "e arquivos ocultos. Nunca armazene backups no diretório raiz web."
                ),
                owasp_score=25,
            )
        )

    # Check directory listing
    for path in ["/", "/admin/", "/assets/", "/uploads/", "/backup/"]:
        body = _fetch_body(target, path)
        if body and any(indicator in body for indicator in DIRECTORY_LISTING_INDICATORS):
            findings.append(
                OWASPFinding(
                    category=OWASPCategory.A05,
                    title="Directory Listing Enabled",
                    description=(
                        f"Directory listing está ativo em {path}. "
                        "Isso expõe a estrutura de diretórios e arquivos do servidor, "
                        "permitindo que atacantes descubram recursos não intencionados."
                    ),
                    severity=FindingSeverity.MEDIUM,
                    target=target,
                    evidence=f"Directory listing detectado em: {path}",
                    recommendation=(
                        "Desabilite directory listing no servidor web. "
                        "Para Apache: 'Options -Indexes'. Para Nginx: 'autoindex off;'."
                    ),
                    owasp_score=8,
                )
            )
            break

    return findings


# --------------------------------------------------------------------------- #
# A06 – Vulnerable (Outdated) Components
# --------------------------------------------------------------------------- #
def check_vulnerable_components(project_path: Path) -> list[OWASPFinding]:
    """Correlate technology, CVE, and Nuclei findings into OWASP component risk."""
    findings: list[OWASPFinding] = []

    # Load vulnerability profile
    vuln_path = project_path / "profiles" / "vulnerability_profile.json"
    if vuln_path.exists():
        try:
            with open(vuln_path, "r", encoding="utf-8") as f:
                vuln_data = json.load(f)
            target = vuln_data.get("target", "")
            total_cves = vuln_data.get("total_cves", 0)
            critical = vuln_data.get("critical_count", 0)
            high = vuln_data.get("high_count", 0)
            matches = vuln_data.get("matches") or []

            if total_cves > 0:
                top_cves = []
                for match in matches[:10]:
                    cve = match.get("matched_cve", {})
                    cve_id = cve.get("cve_id", "N/A")
                    tech = match.get("technology", "Unknown")
                    sev = match.get("risk_level", "INFO")
                    top_cves.append(f"- {cve_id} ({tech}, {sev})")

                severity = FindingSeverity.CRITICAL if critical > 0 else FindingSeverity.HIGH
                findings.append(
                    OWASPFinding(
                        category=OWASPCategory.A06,
                        title=f"Outdated/Vulnerable Components Detected ({total_cves} CVEs)",
                        description=(
                            f"Foram correlacionadas {total_cves} vulnerabilidades conhecidas "
                            f"com as tecnologias identificadas no alvo. Destas, {critical} são "
                            f"críticas e {high} são de alta severidade."
                        ),
                        severity=severity,
                        target=target,
                        evidence="Top CVEs correlacionados:\n" + "\n".join(top_cves),
                        recommendation=(
                            "Atualize todas as tecnologias identificadas para as versões "
                            "mais recentes e corrigidas. Priorize vulnerabilidades com "
                            "exploit público disponível."
                        ),
                        owasp_score=15 if critical > 0 else 10,
                    )
                )
        except Exception as exc:
            logger.warning("Could not load vulnerability profile for A06: {}", exc)

    # Load technology profile for additional context
    tech_path = project_path / "profiles" / "technology_profile.json"
    if tech_path.exists():
        try:
            with open(tech_path, "r", encoding="utf-8") as f:
                tech_data = json.load(f)
            target = target or tech_data.get("target", "")

            outdated_techs: list[str] = []
            for tech in tech_data.get("technologies", []):
                name = tech.get("name", "")
                version = tech.get("version", "")
                if version and version not in ("", "unknown", "Unknown", "—"):
                    outdated_techs.append(f"{name} {version}")

            if outdated_techs:
                findings.append(
                    OWASPFinding(
                        category=OWASPCategory.A06,
                        title=f"Component Inventory ({len(tech_data.get('technologies', []))} technologies)",
                        description=(
                            "Foi identificado um inventário de componentes de software. "
                            "Todos os componentes devem ser mantidos atualizados para "
                            "evitar vulnerabilidades conhecidas."
                        ),
                        severity=FindingSeverity.LOW,
                        target=target,
                        evidence="Componentes mapeados:\n" + "\n".join(
                            f"- {t.get('name', '')}" for t in tech_data.get("technologies", [])
                        ),
                        recommendation=(
                            "Implemente um processo de gestão de dependências e "
                            "monitore continuamente novas vulnerabilidades que afetem "
                            "as tecnologias em uso."
                        ),
                        owasp_score=3,
                    )
                )
        except Exception as exc:
            logger.warning("Could not load technology profile for A06: {}", exc)

    return findings


# --------------------------------------------------------------------------- #
# A07 – Identification and Authentication Indicators
# --------------------------------------------------------------------------- #
LOGIN_INDICATORS = re.compile(
    r'(login|sign.?in|log.?in|entrar|acessar|autenticar|log on)', re.IGNORECASE
)
PASSWORD_FIELD_INDICATOR = re.compile(r'type=["\']password["\']', re.IGNORECASE)


def check_auth_indicators(target: str) -> list[OWASPFinding]:
    """Identify authentication-related interfaces."""
    findings: list[OWASPFinding] = []
    body = _fetch_body(target)

    if not body:
        return findings

    has_login_form = False
    has_password_field = False
    auth_endpoints: list[str] = []

    # Check for common auth paths
    for path in ["/login", "/signin", "/auth", "/wp-login.php", "/admin/login", "/reset", "/forgot"]:
        status = _head_url(target, path)
        if 200 <= status < 400:
            auth_endpoints.append(f"{path} (HTTP {status})")
            has_login_form = True

    # Check HTML for login-related keywords
    if LOGIN_INDICATORS.search(body):
        has_login_form = True

    # Check for password fields
    if PASSWORD_FIELD_INDICATOR.search(body):
        has_password_field = True
        if not any("login" in e.lower() for e in auth_endpoints):
            auth_endpoints.append("/ (login form on homepage)")

    # Check for MFA/SSO indicators
    mfa_indicators = re.findall(
        r'(mfa|2fa|two.?factor|otp|authenticator|sso|single.?sign.?on|okta|auth0|duo)',
        body,
        re.IGNORECASE,
    )
    sso_detected = bool(re.search(r'(sso|okta|auth0|azuread|openid|oauth)', body, re.IGNORECASE))

    if has_login_form or has_password_field:
        finding = OWASPFinding(
            category=OWASPCategory.A07,
            title="Authentication Interface Detected",
            description=(
                "Interface de autenticação identificada no alvo. "
                "Superfícies de login devem ser protegidas contra ataques "
                "de força bruta, credential stuffing e enumeração de usuários."
            ),
            severity=FindingSeverity.INFO,
            target=target,
            evidence=(
                f"Password field: {'Yes' if has_password_field else 'No'}\n"
                f"MFA indicators: {', '.join(mfa_indicators) or 'None'}\n"
                f"SSO detected: {'Yes' if sso_detected else 'No'}\n"
                f"Auth endpoints:\n" + ("\n".join(auth_endpoints) if auth_endpoints else "None")
            ),
            recommendation=(
                "Implemente proteção contra força bruta (account lockout, "
                "rate limiting, CAPTCHA), utilize autenticação multi-fator "
                "e evite mensagens de erro que enumerem usuários válidos."
            ),
            owasp_score=1,
        )
        findings.append(finding)

    if mfa_indicators:
        findings.append(
            OWASPFinding(
                category=OWASPCategory.A07,
                title="Multi-Factor Authentication Indicators Detected",
                description=(
                    "Indicadores de autenticação multi-fator (MFA) foram detectados. "
                    "A presença de MFA é uma boa prática de segurança."
                ),
                severity=FindingSeverity.INFO,
                target=target,
                evidence=f"Indicadores MFA: {', '.join(mfa_indicators)}",
                recommendation=(
                    "Certifique-se de que MFA é obrigatório para todos os usuários, "
                    "especialmente administradores e usuários com acesso a dados sensíveis."
                ),
                owasp_score=1,
            )
        )

    if sso_detected:
        findings.append(
            OWASPFinding(
                category=OWASPCategory.A07,
                title="Single Sign-On (SSO) Integration Detected",
                description=(
                    "Integração SSO identificada. SSO centraliza a autenticação "
                    "e simplifica o gerenciamento de identidades."
                ),
                severity=FindingSeverity.INFO,
                target=target,
                evidence="Provider SSO detectado na aplicação.",
                recommendation=(
                    "Revise a configuração SSO para garantir que esteja utilizando "
                    "protocolos seguros (OAuth 2.0, SAML 2.0) com validação adequada "
                    "de tokens e redirect URIs."
                ),
                owasp_score=1,
            )
        )

    return findings


# --------------------------------------------------------------------------- #
# A08 – Software and Data Integrity Indicators
# --------------------------------------------------------------------------- #
CDN_PATTERNS = [
    r'cdn\.',
    r'cloudfront\.net',
    r'jsdelivr\.net',
    r'unpkg\.com',
    r'cdnjs\.cloudflare\.com',
]


def check_integrity(target: str) -> list[OWASPFinding]:
    """Identify external resources loaded without integrity validation."""
    findings: list[OWASPFinding] = []
    body = _fetch_body(target)

    if not body:
        return findings

    scripts = _find_scripts(body)
    links = _find_links(body)
    all_external = scripts + links

    external_resources: list[str] = []
    remote_without_integrity: list[str] = []

    for src in all_external:
        if src.startswith("http://") or src.startswith("https://"):
            external_resources.append(src)
            # Check for integrity attribute
            has_integrity = any(
                f'src="{src}"' in body and 'integrity="' in body
                for _ in [1]
            )
            # Since we parsed raw body, check proximity
            src_idx = body.find(f'src="{src}"')
            if src_idx >= 0:
                snippet = body[src_idx : src_idx + len(src) + 200]
                if 'integrity="' not in snippet:
                    remote_without_integrity.append(src)

    if external_resources:
        cdn_resources = [
            r
            for r in external_resources
            if any(re.search(p, r) for p in CDN_PATTERNS)
        ]
        if cdn_resources:
            findings.append(
                OWASPFinding(
                    category=OWASPCategory.A08,
                    title="External CDN Resources Loaded — Integrity Not Verified",
                    description=(
                        "O alvo carrega recursos de CDNs externos sem validação "
                        "de integridade (SRI - Subresource Integrity). Isso permite "
                        "que um comprometimento do CDN resulte em execução de código "
                        "malicioso no contexto da aplicação."
                    ),
                    severity=FindingSeverity.MEDIUM,
                    target=target,
                    evidence="CDN Resources sem SRI:\n" + "\n".join(cdn_resources[:10]),
                    recommendation=(
                        "Adicione atributos 'integrity' e 'crossorigin' aos elementos "
                        "<script> e <link> que carregam recursos de CDNs. Utilize "
                        "Content-Security-Policy com 'strict-dynamic' para limitar "
                        "execução de scripts externos."
                    ),
                    owasp_score=8,
                )
            )

    if remote_without_integrity:
        findings.append(
            OWASPFinding(
                category=OWASPCategory.A08,
                title=f"External Resources Without Integrity Check ({len(remote_without_integrity)})",
                description=(
                    f"{len(remote_without_integrity)} recursos externos são carregados "
                    "sem validação de integridade via SRI (Subresource Integrity)."
                ),
                severity=FindingSeverity.MEDIUM,
                target=target,
                evidence="Recursos sem SRI:\n" + "\n".join(remote_without_integrity[:15]),
                recommendation=(
                    "Implemente SRI (Subresource Integrity) para todos os recursos "
                    "carregados de terceiros. Utilize 'integrity' hash e "
                    "'crossorigin=\"anonymous\"' nos elementos."
                ),
                owasp_score=5,
            )
        )

    # Custom elements / third-party widgets
    third_party_patterns = [
        (r'google-analytics\.com', "Google Analytics"),
        (r'googletagmanager\.com', "Google Tag Manager"),
        (r'facebook\.com/tr', "Facebook Pixel"),
        (r'hotjar\.com', "Hotjar"),
        (r'intercom\.io', "Intercom"),
        (r'stripe\.com', "Stripe"),
        (r'paypal\.com', "PayPal"),
    ]
    detected_third_party = []
    for pattern, name in third_party_patterns:
        if re.search(pattern, body, re.IGNORECASE):
            detected_third_party.append(name)

    if detected_third_party:
        findings.append(
            OWASPFinding(
                category=OWASPCategory.A08,
                title="Third-Party Dependencies Detected",
                description=(
                    f"Integrações de terceiros detectadas: {', '.join(detected_third_party)}. "
                    "Dependências externas expandem a superfície de ataque e "
                    "devem ser monitoradas quanto à segurança."
                ),
                severity=FindingSeverity.LOW,
                target=target,
                evidence=f"Terceiros detectados: {', '.join(detected_third_party)}",
                recommendation=(
                    "Revise as permissões concedidas a integrações de terceiros. "
                    "Remova integrações não utilizadas e mantenha as bibliotecas "
                    "de terceiros atualizadas."
                ),
                owasp_score=3,
            )
        )

    return findings


# --------------------------------------------------------------------------- #
# A09 – Security Logging Indicators
# --------------------------------------------------------------------------- #
SECURITY_HEADERS = {
    "X-Content-Type-Options": "Prevents MIME-type sniffing",
    "X-Frame-Options": "Prevents clickjacking attacks",
    "Content-Security-Policy": "Controls resources the browser can load",
    "Strict-Transport-Security": "Enforces HTTPS connections",
    "X-XSS-Protection": "Enables browser XSS filter",
    "Referrer-Policy": "Controls referrer information sent with requests",
    "Permissions-Policy": "Controls browser features permissions",
    "X-Powered-By": "Technology disclosure (should be removed)",
    "Server": "Server version disclosure (should be minimized)",
}

REPORTING_HEADERS = {
    "Report-To": "Browser reporting endpoint for CSP violations and other reports",
    "NEL": "Network Error Logging",
}

MONITORING_HEADERS = {
    "X-Request-Id": "Request tracking identifier",
    "Traceparent": "Distributed tracing header",
}


def check_logging_indicators(target: str) -> list[OWASPFinding]:
    """Evaluate security, monitoring, and reporting HTTP headers."""
    findings: list[OWASPFinding] = []
    _, headers, _ = _request(target, "/", method="GET")

    if not headers:
        return findings

    present_headers: dict[str, str] = {}
    missing_security: list[str] = []

    for header, purpose in SECURITY_HEADERS.items():
        header_lower = header.lower()
        # Also check underscores for real-world header names
        normalized = {k.lower(): v for k, v in headers.items()}
        value = normalized.get(header_lower)
        if value:
            present_headers[header] = value
        else:
            missing_security.append(header)

    missing_reporting = [
        h for h in REPORTING_HEADERS if h.lower() not in {k.lower() for k in headers}
    ]
    missing_monitoring = [
        h for h in MONITORING_HEADERS if h.lower() not in {k.lower() for k in headers}
    ]

    if missing_security:
        findings.append(
            OWASPFinding(
                category=OWASPCategory.A09,
                title=f"Missing Security Headers ({len(missing_security)} ausentes)",
                description=(
                    "Headers de segurança HTTP estão ausentes na resposta do servidor. "
                    "Headers como CSP, HSTS e X-Frame-Options são fundamentais para "
                    "proteger contra ataques comuns como XSS, clickjacking e MITM."
                ),
                severity=FindingSeverity.MEDIUM,
                target=target,
                evidence="Headers ausentes:\n" + "\n".join(
                    f"- {h}: {SECURITY_HEADERS.get(h, '')}" for h in missing_security
                ),
                recommendation=(
                    "Implemente os headers de segurança ausentes. Use "
                    "Content-Security-Policy, Strict-Transport-Security, "
                    "X-Content-Type-Options, X-Frame-Options e "
                    "Referrer-Policy com valores seguros."
                ),
                owasp_score=8,
            )
        )

    if present_headers:
        findings.append(
            OWASPFinding(
                category=OWASPCategory.A09,
                title=f"Security Headers Present ({len(present_headers)} configurados)",
                description=(
                    f"{len(present_headers)} headers de segurança estão configurados. "
                    "A presença destes headers indica boas práticas de segurança "
                    "no servidor web."
                ),
                severity=FindingSeverity.INFO,
                target=target,
                evidence="Headers configurados:\n" + "\n".join(
                    f"- {k}: {v}" for k, v in present_headers.items()
                ),
                recommendation=(
                    "Revise periodicamente a configuração de headers de segurança "
                    "e mantenha CSP atualizado conforme as necessidades da aplicação."
                ),
                owasp_score=1,
            )
        )

    if missing_reporting:
        findings.append(
            OWASPFinding(
                category=OWASPCategory.A09,
                title="Reporting/Monitoring Headers Not Configured",
                description=(
                    "Headers de monitoramento e reporte (Report-To, NEL) não "
                    "estão configurados. Estes headers permitem receber relatórios "
                    "de violações de segurança do navegador."
                ),
                severity=FindingSeverity.LOW,
                target=target,
                evidence=f"Missing reporting headers: {', '.join(missing_reporting)}",
                recommendation=(
                    "Configure headers Report-To e NEL para receber relatórios "
                    "de violações CSP, falhas de rede e outros eventos de segurança."
                ),
                owasp_score=3,
            )
        )

    return findings


# --------------------------------------------------------------------------- #
# A10 – SSRF Indicators
# --------------------------------------------------------------------------- #
SSRF_PARAMS = [
    "url", "redirect", "callback", "feed", "webhook",
    "import", "fetch", "load", "image", "file", "page",
    "path", "view", "include", "document", "source",
]


def check_ssrf_surface(target: str) -> list[OWASPFinding]:
    """Identify potential Server-Side Request Forgery surfaces."""
    findings: list[OWASPFinding] = []
    body = _fetch_body(target)

    if not body:
        return findings

    # Check URL parameters in links
    params_in_links = _find_get_params(body)
    ssrf_params_in_links = [
        p for p in params_in_links if p.lower() in SSRF_PARAMS
    ]

    # Check forms for URL-like fields
    forms = _parse_forms(body)
    ssrf_form_params: list[str] = []
    for form in forms:
        for inp in form.inputs:
            name = inp.get("name", "").lower()
            if name in SSRF_PARAMS:
                ssrf_form_params.append(inp["name"])

    # Check for webhook/URL patterns in JS or hidden elements
    webhook_patterns = re.findall(
        r'(https?://[^\s"\']*(?:webhook|callbacks|api)[^\s"\']*)',
        body,
        re.IGNORECASE,
    )

    if ssrf_params_in_links or ssrf_form_params:
        all_ssrf = list(set(ssrf_params_in_links + ssrf_form_params))
        findings.append(
            OWASPFinding(
                category=OWASPCategory.A10,
                title="Potential SSRF Surface Identified",
                description=(
                    "Parâmetros que podem ser usados para Server-Side Request Forgery "
                    "(SSRF) foram identificados na aplicação. SSRF permite que um "
                    "atacante force o servidor a fazer requisições a destinos "
                    "internos ou externos não intencionados."
                ),
                severity=FindingSeverity.MEDIUM,
                target=target,
                evidence="Parâmetros SSRF potenciais:\n" + "\n".join(
                    f"?{p}=<url>" for p in sorted(all_ssrf)
                ),
                recommendation=(
                    "Implemente validação rigorosa de URLs fornecidas pelo usuário. "
                    "Utilize lista branca de domínios permitidos, bloqueie endereços "
                    "de rede interna (127.0.0.1, 10.x.x.x, 172.16-31.x.x, 192.168.x.x) "
                    "e valide o schema (apenas https)."
                ),
                owasp_score=8,
            )
        )

    if webhook_patterns:
        findings.append(
            OWASPFinding(
                category=OWASPCategory.A10,
                title="Webhook/Callback URL Patterns Detected",
                description=(
                    "URLs de webhook ou callback foram identificadas na aplicação. "
                    "Webhooks que aceitam URLs externas configuráveis pelo usuário "
                    "são vetores conhecidos de SSRF."
                ),
                severity=FindingSeverity.LOW,
                target=target,
                evidence="URLs de webhook detectadas:\n" + "\n".join(webhook_patterns[:5]),
                recommendation=(
                    "Valide e restrinja URLs de webhook a uma lista de destinos "
                    "permitidos. Implemente verificação de resolução DNS reversa "
                    "para prevenir ataques SSRF."
                ),
                owasp_score=3,
            )
        )

    return findings
