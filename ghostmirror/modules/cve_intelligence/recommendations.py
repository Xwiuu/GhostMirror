"""Recommendation Engine and Nuclei Template Mapper for CVE Intelligence."""

from __future__ import annotations

from ghostmirror.models.cve_match import CVEMatchModel
from ghostmirror.models.technology import TechnologyModel


class CVERecommendationEngine:
    """Generates remediation actions and identifies relevant Nuclei templates."""

    @staticmethod
    def get_technology_recommendations(tech_name: str) -> list[str]:
        """Provides custom remediation lists for specific technologies."""
        recs = {
            "Apache": [
                "Atualizar o Apache HTTP Server para a versão corrigida mais recente.",
                "Validar a configuração de diretórios para evitar exposição e directory listing indesejado.",
                "Executar templates Nuclei específicos de Apache para verificar path traversal e vazamento de informações."
            ],
            "WordPress": [
                "Atualizar o core do WordPress, plugins e temas ativos imediatamente.",
                "Executar enumeração detalhada de plugins para identificar vulnerabilidades conhecidas adicionais.",
                "Executar templates Nuclei para WordPress core e conhecidos plugins inseguros."
            ],
            "Redis": [
                "Remover exposição pública do serviço Redis restringindo acesso nas portas do firewall/VPN.",
                "Habilitar autenticação forte configurando a diretiva 'requirepass' no arquivo redis.conf.",
                "Validar que a escuta (bind) esteja restrita a interfaces de localhost ou redes internas seguras."
            ],
            "PHP": [
                "Atualizar a versão do runtime PHP para uma versão estável e sob suporte ativo.",
                "Ocultar a exposição de versão desativando a diretiva 'expose_php' no arquivo php.ini.",
                "Revisar e remover qualquer arquivo exposto publicamente que execute a função 'phpinfo()'."
            ],
            "Nginx": [
                "Atualizar o servidor Nginx para a versão estável mais recente corrigida.",
                "Desativar módulos obsoletos ou não utilizados de forma a reduzir a superfície de ataque.",
                "Revisar cabeçalhos HTTP de segurança para mitigar ataques comuns de web."
            ],
            "OpenSSH": [
                "Atualizar o OpenSSH para a versão estável mitigada (ex: 9.8p1 ou superior).",
                "Restringir portas de SSH por IP de origem no firewall ou gateway corporativo.",
                "Desabilitar autenticação por senha e aplicar login apenas por chaves de criptografia assimétrica."
            ],
            "WooCommerce": [
                "Atualizar o plugin WooCommerce para a versão estável livre de bypass de autenticação.",
                "Validar permissões e grupos de usuários administradores da loja virtual."
            ],
            "Laravel": [
                "Garantir que o arquivo de variáveis de ambiente (.env) não seja legível publicamente.",
                "Certificar-se de que a opção 'APP_DEBUG=false' está configurada no ambiente de produção.",
                "Atualizar os pacotes de depuração como Ignition e a versão core do framework."
            ]
        }
        return recs.get(tech_name, [
            f"Atualizar a tecnologia '{tech_name}' para sua última versão estável.",
            f"Executar auditoria de configuração local na tecnologia '{tech_name}'."
        ])

    @staticmethod
    def generate_recommendations(
        matches: list[CVEMatchModel],
        technologies: list[TechnologyModel]
    ) -> list[str]:
        """Consolidates unique recommendations for all matched CVEs/technologies.

        Parameters
        ----------
        matches : list[CVEMatchModel]
            List of matches.
        technologies : list[TechnologyModel]
            Detected technologies.

        Returns
        -------
        list[str]
            Flat list of unique recommendation strings.
        """
        recs = set()

        # Add general matched technology recommendations
        matched_techs = {m.technology for m in matches}
        for tech in matched_techs:
            for rec in CVERecommendationEngine.get_technology_recommendations(tech):
                recs.add(rec)

        # Fallback technology recommendations if no matches but tech is present
        for t in technologies:
            if t.name in ["Redis", "WordPress", "OpenSSH", "Apache"] and t.name not in matched_techs:
                # Add default security warnings
                recs.add(f"Monitorar a tecnologia '{t.name}' e garantir atualizações de segurança frequentes.")

        # Ensure we always return a basic checklist
        if not recs:
            recs.add("Manter todas as tecnologias identificadas atualizadas para as versões mais recentes.")
            recs.add("Implementar políticas estritas de controle de acesso de rede (firewall/VPN).")

        return sorted(list(recs))

    @staticmethod
    def map_nuclei_templates(
        matches: list[CVEMatchModel],
        technologies: list[TechnologyModel],
        nuclei_map: dict
    ) -> list[str]:
        """Maps target vulnerabilities and tech profiles to Nuclei templates.

        Parameters
        ----------
        matches : list[CVEMatchModel]
            List of CVE matches.
        technologies : list[TechnologyModel]
            Detected technologies.
        nuclei_map : dict
            The template map dictionary loaded from knowledge base.

        Returns
        -------
        list[str]
            List of recommended templates to run.
        """
        templates = set()

        # 1. Map CVEs directly
        cve_templates = nuclei_map.get("cves", {})
        for match in matches:
            cve_id = match.matched_cve.cve_id
            if cve_id in cve_templates:
                templates.add(cve_templates[cve_id])

        # 2. Map Technologies directly
        tech_templates = nuclei_map.get("technologies", {})
        for tech in technologies:
            tech_name = tech.name
            if tech_name in tech_templates:
                templates.add(tech_templates[tech_name])

        # 3. Map Exposures based on profile characteristics
        exposures = nuclei_map.get("exposures", {})

        # Database exposed if category is DATABASE or service name matches DB services
        has_db = any(
            t.category.upper() == "DATABASE" or t.name.lower() in ["redis", "mongodb", "mysql", "postgresql", "postgres"]
            for t in technologies
        )
        if has_db and "databases" in exposures:
            templates.add(exposures["databases"])

        # Config exposure if WAF is missing
        has_waf = any(
            t.category.upper() == "WAF" or t.name.lower() == "cloudflare"
            for t in technologies
        )
        if not has_waf and "configs" in exposures:
            templates.add(exposures["configs"])

        return sorted(list(templates))
