"""Orchestration engine for technology intelligence and risk profiling."""

from __future__ import annotations

import json
from pathlib import Path
from datetime import datetime, timezone

from ghostmirror.core.logger import get_logger
from ghostmirror.models.fingerprint import FingerprintProfile
from ghostmirror.models.technology import TechnologyModel
from ghostmirror.modules.models.finding import FindingModel, FindingSeverity, ScanResultModel
from ghostmirror.modules.technology_intelligence.knowledge_base import KnowledgeBase
from ghostmirror.modules.technology_intelligence.profiler import TechnologyProfilerEngine
from ghostmirror.modules.technology_intelligence.recommendations import RecommendationEngine

logger = get_logger()


class TechnologyIntelligenceEngine:
    """Orchestrates threat definition loading, profiling, recommendation generation, and findings."""

    def __init__(self, knowledge_dir: Path | str | None = None) -> None:
        self.kb = KnowledgeBase(knowledge_dir=knowledge_dir)

    def analyze_project(self, project_path: Path) -> dict:
        """Loads target profiles, executes scoring and recommendations, and writes output files.

        Parameters
        ----------
        project_path : Path
            The absolute path to the project directory.

        Returns
        -------
        dict
            The unified technology intelligence report dictionary.
        """
        profiles_dir = project_path / "profiles"
        findings_dir = project_path / "findings"
        tech_profile_path = profiles_dir / "technology_profile.json"
        ssl_findings_path = findings_dir / "ssl.json"

        if not tech_profile_path.exists():
            raise FileNotFoundError(
                f"Perfil de tecnologia não encontrado em {tech_profile_path}. "
                "Por favor, execute 'ghostmirror scan fingerprint' no alvo primeiro."
            )

        # 1. Load technology fingerprint profile
        with open(tech_profile_path, "r", encoding="utf-8") as f:
            raw_profile = json.load(f)
        profile = FingerprintProfile.model_validate(raw_profile)

        # 2. Try loading TLS versions from SSL scan findings if available
        tls_versions = []
        if ssl_findings_path.exists():
            try:
                with open(ssl_findings_path, "r", encoding="utf-8") as f:
                    ssl_data = json.load(f)
                cert_summary = ssl_data.get("certificate_summary")
                if cert_summary:
                    tls_versions = cert_summary.get("tls_versions", [])
            except Exception as exc:
                logger.warning("Could not read TLS versions from ssl.json: {}", exc)

        # 3. Execute Profiling & Attack Surface Engines
        risk_profile = TechnologyProfilerEngine.calculate_risk(profile.target, profile.technologies, tls_versions)
        attack_surface = TechnologyProfilerEngine.analyze_attack_surface(
            target=profile.target,
            technologies=profile.technologies,
            risk_score=risk_profile.risk_score
        )

        # 4. Generate recommendations and Nuclei templates
        recommended_scans, recommended_nuclei = RecommendationEngine.generate_recommendations(
            technologies=profile.technologies,
            kb=self.kb
        )

        # 5. Generate automated findings
        findings = self._generate_findings(profile, attack_surface, tls_versions)

        # 6. Save profiles to disk
        profiles_dir.mkdir(parents=True, exist_ok=True)
        findings_dir.mkdir(parents=True, exist_ok=True)

        with open(profiles_dir / "attack_surface_profile.json", "w", encoding="utf-8") as f:
            json.dump(attack_surface.model_dump(mode="json"), f, indent=2, ensure_ascii=False)

        with open(profiles_dir / "risk_profile.json", "w", encoding="utf-8") as f:
            json.dump(risk_profile.model_dump(mode="json"), f, indent=2, ensure_ascii=False)

        # Build final report
        report = {
            "target": profile.target,
            "risk_score": risk_profile.risk_score,
            "risk_level": risk_profile.risk_level,
            "technologies": attack_surface.technologies,
            "recommended_scans": recommended_scans,
            "recommended_nuclei_templates": recommended_nuclei,
            "high_value_assets": attack_surface.high_value_assets,
            "potential_entry_points": attack_surface.potential_entry_points,
            "observations": risk_profile.observations,
            "findings": [f.model_dump(mode="json") for f in findings],
        }

        # Save technology_intelligence.json report to findings
        with open(findings_dir / "technology_intelligence.json", "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        logger.info(
            "INTEL_ENGINE_COMPLETE target={} risk_score={} findings={}",
            profile.target,
            risk_profile.risk_score,
            len(findings),
        )

        return report

    def _generate_findings(
        self,
        profile: FingerprintProfile,
        attack_surface: AttackSurfaceProfile,
        tls_versions: list[str]
    ) -> list[FindingModel]:
        """Evaluates profiles against risk rules to generate Findings."""
        findings = []
        target = profile.target

        # 1. WordPress CMS exposure
        if "WordPress" in attack_surface.cms:
            findings.append(
                FindingModel(
                    title="WordPress Attack Surface Identified",
                    description=(
                        "O Content Management System (CMS) WordPress foi detectado no alvo. "
                        "WordPress expõe superfícies de ataque comuns relacionadas a plugins, "
                        "temas vulneráveis e interfaces administrativas."
                    ),
                    severity=FindingSeverity.MEDIUM,
                    target=target,
                    evidence="CMS: WordPress",
                    recommendation=(
                        "Restrinja o acesso ao painel '/wp-admin/' por IP ou VPN. "
                        "Mantenha todos os plugins e temas atualizados e desabilite o XML-RPC "
                        "caso não seja utilizado."
                    )
                )
            )

        # 2. Laravel framework exposure
        if "Laravel" in attack_surface.frameworks:
            findings.append(
                FindingModel(
                    title="Laravel Attack Surface Identified",
                    description=(
                        "O framework de desenvolvimento Laravel foi identificado ativo. "
                        "Configurações inadequadas, como o modo debug ativado ou arquivos '.env' "
                        "expostos, podem comprometer a aplicação."
                    ),
                    severity=FindingSeverity.MEDIUM,
                    target=target,
                    evidence="Framework: Laravel",
                    recommendation=(
                        "Verifique se o arquivo '.env' não é legível publicamente e certifique-se "
                        "de que a opção 'APP_DEBUG=false' está configurada no ambiente de produção."
                    )
                )
            )

        # 3. Redis Exposure Risk
        if "Redis" in attack_surface.databases:
            findings.append(
                FindingModel(
                    title="Redis Exposure Risk",
                    description=(
                        "O banco de dados em memória Redis foi identificado no inventário do alvo. "
                        "Por padrão, o Redis pode estar configurado sem autenticação ou exposto "
                        "diretamente em portas públicas."
                    ),
                    severity=FindingSeverity.HIGH,
                    target=target,
                    evidence="Database: Redis",
                    recommendation=(
                        "Certifique-se de que o Redis está configurado para aceitar conexões apenas de "
                        "localhost/VPN e habilite a diretiva 'requirepass' no arquivo 'redis.conf'."
                    )
                )
            )

        # 4. Multiple High Value Assets
        if len(attack_surface.high_value_assets) >= 3:
            findings.append(
                FindingModel(
                    title="Multiple High Value Assets Identified",
                    description=(
                        f"Foram identificados {len(attack_surface.high_value_assets)} ativos de alto valor "
                        "no perfil tecnológico do alvo, como gerenciadores de banco de dados, CMS "
                        "ou gateways de pagamento."
                    ),
                    severity=FindingSeverity.HIGH,
                    target=target,
                    evidence=f"High value assets count: {len(attack_surface.high_value_assets)}",
                    recommendation=(
                        "Implemente defesa em camadas (defense-in-depth), restrinja acessos externos, "
                        "segregue redes de banco de dados e monitore logs de acesso detalhadamente."
                    )
                )
            )

        # 5. Outdated TLS version
        if tls_versions and any(v in tls_versions for v in ["TLS 1.0", "TLS 1.1", "SSLv3", "SSLv2"]):
            findings.append(
                FindingModel(
                    title="Outdated TLS Version Allowed",
                    description=(
                        f"O servidor SSL/TLS aceita protocolos obsoletos e inseguros. "
                        f"Versões suportadas detectadas: {', '.join(tls_versions)}."
                    ),
                    severity=FindingSeverity.HIGH,
                    target=target,
                    evidence=f"Supported protocols: {tls_versions}",
                    recommendation=(
                        "Desabilite suporte a protocolos TLS 1.0, TLS 1.1, SSLv3 e SSLv2 na configuração do "
                        "servidor web ou balanceador de carga. Force o uso de TLS 1.2 e TLS 1.3 com ciphers seguros."
                    )
                )
            )

        # 6. WAF / CDN Protection check
        waf_present = any(t.category == "WAF" or t.name == "Cloudflare" for t in profile.technologies)
        cdn_present = any(t.category == "CDN" or t.name == "Cloudflare" for t in profile.technologies)
        if not waf_present and not cdn_present:
            findings.append(
                FindingModel(
                    title="No WAF or CDN Protected",
                    description=(
                        "O alvo parece não utilizar um Web Application Firewall (WAF) ou uma Content "
                        "Delivery Network (CDN) para proteção e otimização de borda."
                    ),
                    severity=FindingSeverity.LOW,
                    target=target,
                    evidence="No Cloudflare or equivalent WAF/CDN signature identified.",
                    recommendation=(
                        "Considere implementar uma solução de WAF/CDN (como Cloudflare, AWS CloudFront + WAF) "
                        "para proteger o servidor de ataques automatizados, DDoS e tentativas de exploit."
                    )
                )
            )

        return findings
