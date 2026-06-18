"""Generates OWASP-specific security recommendations based on categories and findings."""

from __future__ import annotations

from ghostmirror.models.owasp_finding import OWASPCategory, OWASPFinding

CATEGORY_RECOMMENDATIONS: dict[OWASPCategory, list[str]] = {
    OWASPCategory.A01: [
        "Implemente controle de acesso baseado em função (RBAC) para todos os recursos administrativos.",
        "Utilize autenticação multi-fator (MFA) para acesso a painéis administrativos.",
        "Restrinja o acesso a endpoints administrativos por IP ou VPN corporativa.",
        "Monitore e registre todas as tentativas de acesso a áreas administrativas.",
    ],
    OWASPCategory.A02: [
        "Substitua todos os certificados que utilizam algoritmos de assinatura SHA-1.",
        "Desabilite protocolos TLS 1.0, TLS 1.1 e SSL em todos os servidores.",
        "Configure cipher suites fortes priorizando Perfect Forward Secrecy (PFS).",
        "Implemente certificados com chaves RSA de no mínimo 2048 bits ou ECDSA.",
    ],
    OWASPCategory.A03: [
        "Implemente prepared statements parametrizados para todas as consultas SQL.",
        "Valide e sanitize rigorosamente todas as entradas do usuário (server-side).",
        "Utilize encoding de saída específico para o contexto (HTML, JS, SQL, etc.).",
        "Implemente Content Security Policy (CSP) para mitigar XSS.",
        "Realize testes de injeção periódicos com ferramentas automatizadas.",
    ],
    OWASPCategory.A04: [
        "Adote um ciclo de desenvolvimento seguro (SDLC) com revisões de design.",
        "Implemente controles de acesso em nível de design, não apenas na interface.",
        "Realize threat modeling durante a fase de design de novas funcionalidades.",
        "Utilize o princípio do menor privilégio em todo o design da aplicação.",
    ],
    OWASPCategory.A05: [
        "Desabilite directory listing em todos os servidores web.",
        "Remova arquivos de backup, configuração e dump de banco de dados do diretório web.",
        "Configure headers de segurança (CSP, HSTS, X-Frame-Options, etc.).",
        "Remova exposição de versões de servidor e tecnologia (Server, X-Powered-By).",
        "Implemente varreduras automatizadas de segurança de configuração.",
    ],
    OWASPCategory.A06: [
        "Mantenha todas as tecnologias, bibliotecas e frameworks atualizados.",
        "Implemente um processo de gestão de dependências e SBOM (Software Bill of Materials).",
        "Monitore continuamente fontes de CVE para vulnerabilidades que afetem seu stack.",
        "Remova ou substitua componentes que não recebem mais atualizações de segurança.",
    ],
    OWASPCategory.A07: [
        "Implemente proteção contra força bruta (account lockout, rate limiting, CAPTCHA).",
        "Utilize autenticação multi-fator (MFA) para todos os usuários.",
        "Evite mensagens de erro que enumerem usuários válidos ou senhas incorretas.",
        "Implemente políticas de senha forte e gerenciamento seguro de sessão.",
    ],
    OWASPCategory.A08: [
        "Implemente Subresource Integrity (SRI) para todos os recursos carregados de CDNs.",
        "Utilize Content Security Policy com 'strict-dynamic' para limitar scripts.",
        "Valide a integridade de todas as dependências de terceiros.",
        "Implemente assinatura digital para atualizações de software e dados.",
    ],
    OWASPCategory.A09: [
        "Implemente logging centralizado de eventos de segurança.",
        "Configure headers de segurança HTTP (CSP, HSTS, X-Frame-Options, etc.).",
        "Configure headers de monitoramento (Report-To, NEL) para receber relatórios.",
        "Implemente mecanismos de detecção e alerta para eventos de segurança.",
        "Garanta que logs incluam timestamp, usuário, IP, ação e resultado.",
    ],
    OWASPCategory.A10: [
        "Implemente validação rigorosa de URLs fornecidas pelo usuário.",
        "Utilize lista branca de domínios e protocolos permitidos para requisições.",
        "Bloqueie requisições a endereços de rede interna (127.0.0.1, 10.x.x.x, 192.168.x.x).",
        "Implemente timeout e limite de redirecionamentos para requisições externas.",
        "Utilize isolamento de rede para serviços que fazem requisições externas.",
    ],
}

GENERAL_RECOMMENDATIONS = [
    "Estabeleça um programa contínuo de segurança com varreduras periódicas.",
    "Implemente um processo formal de gestão de vulnerabilidades.",
    "Realize testes de penetração autorizados regularmente.",
    "Mantenha uma política de segurança da informação atualizada.",
    "Treine a equipe de desenvolvimento em práticas de codificação segura.",
]


class OWASPRecommendationEngine:
    """Generates consolidated OWASP recommendations based on detected categories."""

    @staticmethod
    def generate(
        categories: list[OWASPCategory],
        findings: list[OWASPFinding] | None = None,
    ) -> list[str]:
        """Generate recommendations from detected categories and critical findings."""
        recs: list[str] = []
        seen: set[str] = set()

        for cat in categories:
            if cat in CATEGORY_RECOMMENDATIONS:
                for rec in CATEGORY_RECOMMENDATIONS[cat]:
                    if rec not in seen:
                        seen.add(rec)
                        recs.append(rec)

        # Add general recommendations
        for rec in GENERAL_RECOMMENDATIONS:
            if rec not in seen:
                seen.add(rec)
                recs.append(rec)

        return recs
