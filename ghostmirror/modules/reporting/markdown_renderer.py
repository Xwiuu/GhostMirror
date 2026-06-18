"""Markdown Renderer to compile reports into a clean document-ready markdown file."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from ghostmirror.modules.models.finding import FindingModel


class MarkdownReportRenderer:
    """Renders standardized markdown reports."""

    @staticmethod
    def render(
        project_name: str,
        target: str,
        profile: str,
        score: int,
        risk_level: str,
        collected_data: dict[str, Any],
        is_lab: bool = False,
    ) -> str:
        """Compiles report data into a clean markdown string."""
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        # Gather findings by severity
        all_findings: list[FindingModel] = collected_data.get("all_findings", [])
        findings_by_sev: dict[str, list[FindingModel]] = {
            "CRITICAL": [],
            "HIGH": [],
            "MEDIUM": [],
            "LOW": [],
            "INFO": [],
        }
        for f in all_findings:
            sev = f.severity.value.upper()
            if sev in findings_by_sev:
                findings_by_sev[sev].append(f)

        severity_counts = {sev: len(lst) for sev, lst in findings_by_sev.items()}

        # 1. Header and Cover info
        lab_badge = "\n> **🧪 LAB TARGET** — Ambiente Controlado (GhostMirror Lab Mode)\n" if is_lab else ""

        # Build module execution summary
        timeline = collected_data.get("timeline", {})
        steps = timeline.get("steps", [])
        executed = [s for s in steps if s.get("status") == "completed"]
        skipped = [s for s in steps if s.get("status") == "skipped"]
        failed = [s for s in steps if s.get("status") == "failed"]
        has_modules = bool(steps)

        modules_md = ""
        if has_modules:
            modules_md += f"""
### Resumo de Execução
- **Executados:** {len(executed)} | **Pulados:** {len(skipped)} | **Falhas:** {len(failed)}

| Módulo | Status | Duração | Findings | Erros |
| :--- | :--- | :--- | :--- | :--- |
"""
            for s in steps:
                st = s.get("status", "?")
                dur = s.get("duration", 0)
                fc = s.get("findings_count", s.get("findings", 0))
                errs = "; ".join(s.get("errors", []))[:120] if s.get("errors") else "—"
                modules_md += f"| {s.get('name', '?')} | {st} | {dur}s | {fc} | {errs} |\n"
            modules_md += "\n---\n"
        else:
            modules_md = "\n*Nenhum módulo foi executado nesta varredura.*\n\n---\n"

        md = f"""# GHOSTMIRROR SECURITY ASSESSMENT{lab_badge}

- **Projeto:** {project_name}
- **Perfil de Execução:** {profile.upper()}
- **Alvo Principal:** `{target}`
- **Data de Geração:** {now}

---

## 1. RESUMO EXECUTIVO

Este relatório consolida os resultados da auditoria de segurança interna autorizada realizada no alvo principal `{target}` para o projeto `{project_name}`.

O score global de risco foi calculado em **{score}/100**, resultando em uma classificação de risco **{risk_level}**.

### Estatísticas de Vulnerabilidades
- **Crítica:** {severity_counts["CRITICAL"]}
- **Alta:** {severity_counts["HIGH"]}
- **Média:** {severity_counts["MEDIUM"]}
- **Baixa:** {severity_counts["LOW"]}
- **Informacional:** {severity_counts["INFO"]}

---

## 2. MÓDULOS EXECUTADOS

{modules_md}
## 3. TECNOLOGIAS MAPEADAS

Abaixo estão listadas as tecnologias identificadas durante a fase de fingerprint:

| Tecnologia | Versão Mapeada | Categorias |
| :--- | :--- | :--- |
"""
        tech_profile = collected_data["profiles"].get("technology_profile") or {}
        technologies = tech_profile.get("technologies", [])
        if technologies:
            for tech in technologies:
                name = tech.get("name", "Unknown")
                version = tech.get("version", "—")
                categories = ", ".join(tech.get("categories", []))
                md += f"| {name} | {version} | {categories} |\n"
        else:
            md += "| — | Nenhum mapeado | — |\n"

        # 3. CVE Matches
        md += """
---

## 4. CVES EM POTENCIAL CORRELACIONADAS

Abaixo estão listadas as vulnerabilidades conhecidas (CVEs) correlacionadas com as tecnologias identificadas:

| Identificador CVE | Tecnologia | Severidade | Exploit Público |
| :--- | :--- | :--- | :--- |
"""
        cve_profile = collected_data["profiles"].get("vulnerability_profile") or {}
        cve_matches = cve_profile.get("matches", [])
        if cve_matches:
            for match in cve_matches[:25]:
                cve_id = match.get("matched_cve", {}).get("cve_id", "CVE-Unknown")
                tech_name = match.get("technology", "—")
                sev = match.get("risk_level", "INFO")
                exploit = "Sim" if match.get("matched_cve", {}).get("exploit_available") else "Não"
                md += f"| {cve_id} | {tech_name} | {sev} | {exploit} |\n"
            if len(cve_matches) > 25:
                md += f"| ... | Exibidos 25 de {len(cve_matches)} CVEs | ... | ... |\n"
        else:
            md += "| — | Nenhuma CVE em potencial correlacionada | — | — |\n"

        # 4. Detailed findings
        md += """
---

## 5. DETALHAMENTO DE VULNERABILIDADES E EVIDÊNCIAS

"""
        if all_findings:
            for idx, f in enumerate(all_findings, start=1):
                sev = f.severity.value.upper()
                md += f"### 4.{idx} [{sev}] {f.title}\n\n"
                md += f"- **Alvo:** `{f.target}`\n"
                md += f"- **Descrição:** {f.description}\n\n"

                if f.evidence:
                    md += "#### Evidência Técnica\n"
                    md += "```\n"
                    md += f"{f.evidence.strip()}\n"
                    md += "```\n\n"

                md += "#### Recomendação\n"
                md += f"{f.recommendation}\n\n"
                md += "---\n\n"
        else:
            md += "Nenhuma vulnerabilidade foi detectada neste assessment.\n\n"

        # 5. OWASP Top 10 Assessment
        md += """
---

## 6. OWASP TOP 10 ASSESSMENT

"""
        owasp_profile = collected_data["profiles"].get("owasp_profile") or {}
        all_findings_data = collected_data.get("findings") or {}
        owasp_findings = all_findings_data.get("owasp_findings") or []

        if owasp_profile:
            owasp_score = owasp_profile.get("risk_score", 0)
            owasp_level = owasp_profile.get("risk_level", "N/A")
            owasp_categories = owasp_profile.get("categories", [])
            owasp_total = len(owasp_findings)

            md += f"""
A avaliação OWASP Top 10 Light identificou **{owasp_total}** achados em **{len(owasp_categories)}** categorias.

**OWASP Risk Score:** {owasp_score}/100 — **{owasp_level}**

### Categorias Avaliadas

| Categoria | Achados |
| :--- | :--- |
"""
            for cat in owasp_categories:
                cat_count = len([f for f in owasp_findings if isinstance(f, dict) and f.get("category") == cat])
                md += f"| {cat} | {cat_count} |\n"

            recs = owasp_profile.get("recommendations", [])
            if recs:
                md += """
### Recomendações OWASP

"""
                for i, rec in enumerate(recs[:8], 1):
                    md += f"{i}. {rec}\n"

            md += "\n---\n"
        else:
            md += """
*Dados do OWASP Top 10 Light não disponíveis. Execute `ghostmirror scan owasp` para gerar.*

---\n
"""

        # 6. Safe Payload Validation
        payload_profile = collected_data["profiles"].get("payload_profile") or {}
        payload_findings = all_findings_data.get("payload_findings") or []

        if payload_profile:
            pp_total = payload_profile.get("total_payloads_registered", 0)
            pp_executed = payload_profile.get("payloads_executed", 0)
            pp_blocked = payload_profile.get("payloads_blocked", 0)
            pp_findings = payload_profile.get("findings_generated", 0)
            pp_risk_score = payload_profile.get("risk_score", 0)
            pp_risk_level = payload_profile.get("risk_level", "N/A")
            pp_dry_run = payload_profile.get("dry_run", False)

            md += f"""
## 7. SAFE PAYLOAD VALIDATION

A validação de payloads seguros registrou **{pp_total}** payloads, dos quais **{pp_executed}** foram executados e **{pp_blocked}** bloqueados.

**Payload Risk Score:** {pp_risk_score}/100 — **{pp_risk_level}**
**Dry Run:** {'Sim' if pp_dry_run else 'Não'}
**Findings Gerados:** {pp_findings}

"""

            if payload_findings:
                md += """
### Payload Findings

| Título | Severidade | Alvo | Evidência |
| :--- | :--- | :--- | :--- |
"""
                for finding in payload_findings:
                    md += f"| {finding.get('title', 'N/A')} | {finding.get('severity', 'INFO')} | {finding.get('target', 'N/A')} | {str(finding.get('evidence', 'N/A'))[:80]} |\n"

            md += "\n---\n"
        else:
            md += """
## 7. SAFE PAYLOAD VALIDATION

*Dados do Safe Payload Validation não disponíveis. Execute `ghostmirror scan payloads` para gerar.*

---\n
"""

        # 7. Next steps
        md += """
## 8. RECOMENDAÇÕES GERAIS E PRÓXIMOS PASSOS

1. **Fase de Mitigação:** Priorize a aplicação de patches e atualizações nas tecnologias que apresentarem CVEs de criticidade Crítica ou Alta.
2. **Hardening de Rede:** Restrinja o acesso a portas administrativas expostas utilizando regras de firewall estritas.
3. **Varredura Recorrente:** Execute varreduras programadas para garantir o monitoramento contínuo da superfície de ataque do projeto.
"""
        return md
