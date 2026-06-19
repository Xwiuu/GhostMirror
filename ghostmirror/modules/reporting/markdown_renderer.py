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

        # 5b. Finding Intelligence

        fi_report = collected_data["profiles"].get("finding_intelligence_report") or {}
        enriched_findings = collected_data["profiles"].get("enriched_findings") or []

        if fi_report:
            priority_counts = fi_report.get("priority_counts", {})
            kev_count = fi_report.get("kev_count", 0)
            exploit_count = fi_report.get("exploit_count", 0)
            total = fi_report.get("total_findings", 0)

            md += f"""
A Finding Intelligence Engine enriqueceu **{total}** findings com metadados profissionais.

### Priority Distribution

| Priority | Count | Status |
| :--- | :--- | :--- |
"""
            for p in ["P1", "P2", "P3", "P4", "P5"]:
                count = priority_counts.get(p, 0)
                status = "Critical" if p == "P1" else "High" if p == "P2" else "Medium" if p == "P3" else "Low" if p == "P4" else "Info"
                md += f"| **{p}** | {count} | {status} |\n"

            md += f"""
**KEV Listed:** {kev_count}
**Exploits Available:** {exploit_count}

#### Executive Summary

{fi_report.get('executive_summary', '')}

"""

        else:
            md += """
*Finding Intelligence data not available. Run `ghostmirror analyze findings` or `ghostmirror findings intelligence` to generate.*

"""

        # 5c. Priority Matrix
        md += """
---

## 5c. Priority Matrix

"""

        if fi_report:
            matrix = fi_report.get("priority_matrix", {})
            md += """
| Priority | Findings | Severity Range | Action Required |
| :--- | :--- | :--- | :--- |
"""
            priority_info = {
                "P1": ("CRITICAL", "Critical - Immediate remediation required"),
                "P2": ("HIGH", "High - Remediate within 30 days"),
                "P3": ("MEDIUM", "Medium - Remediate within 90 days"),
                "P4": ("LOW", "Low - Remediate within 180 days"),
                "P5": ("INFO", "Informational - Monitor"),
            }
            for p in ["P1", "P2", "P3", "P4", "P5"]:
                count = matrix.get(p, 0)
                if count == 0:
                    continue
                info = priority_info.get(p, ("INFO", "General"))
                md += f"| **{p}** | {count} | {info[0]} | {info[1]} |\n"
        else:
            md += "*Priority Matrix not available.*\n\n"

        # 5d. Top 10 Findings
        md += """
---

## 5d. Top 10 Findings

"""

        top_findings = collected_data["profiles"].get("top_findings") or []
        if top_findings:
            md += """
| # | Title | Severity | Priority | Confidence | Asset |
| :--- | :--- | :--- | :--- | :--- | :--- |
"""
            for i, tf in enumerate(top_findings, 1):
                sev = (tf.get("severity") or "INFO").upper()
                prio = tf.get("priority", "P5")
                conf = tf.get("confidence", "LOW")
                asset = tf.get("affected_asset") or "—"
                title = tf.get("title", "?")
                md += f"| {i} | **{title}** | {sev} | {prio} | {conf} | {asset} |\n"
        else:
            md += "*Top 10 Findings not available.*\n\n"

        # 5e. Quick Wins
        md += """
---

## 5e. Quick Wins

"""

        quick_wins = collected_data["profiles"].get("quick_wins") or []
        if quick_wins:
            for i, qw in enumerate(quick_wins, 1):
                qw_title = qw.get("title", "?")
                qw_sev = (qw.get("severity") or "INFO").upper()
                qw_rec = qw.get("recommendation", "")
                md += f"""### {i}. [{qw_sev}] {qw_title}
- **Quick Fix:** {qw_rec}

"""
        else:
            md += "*No quick wins identified.*\n\n"

        # 6. OWASP Top 10 Assessment
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

            **OWASP Risk Score:** {owasp_score}/100 - **{owasp_level}**

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

        # 7. Vulnerability Intelligence
        vi_report = collected_data["profiles"].get("vulnerability_intelligence_report") or {}
        vi_priorities = collected_data["profiles"].get("vulnerability_priority") or []
        vi_epss = collected_data["profiles"].get("epss_profile") or []
        vi_kev = collected_data["profiles"].get("kev_profile") or []
        vi_exploit = collected_data["profiles"].get("exploit_profile") or []
        vi_opportunities = collected_data["profiles"].get("attack_opportunities") or []

        if vi_report:
            md += """
---

## 7. VULNERABILITY INTELLIGENCE

A plataforma de inteligência avançada de vulnerabilidades correlacionou CVEs, EPSS, KEV, Exploit Intelligence e superfície de ataque para priorização de riscos.

### Score Overview

| Métrica | Valor |
| :--- | :--- |
"""
            md += f"| **Overall Score** | {vi_report.get('overall_score', 0)}/100 |\n"
            md += f"| **Risk Level** | {vi_report.get('risk_level', 'NONE')} |\n"
            md += f"| **Total CVEs** | {vi_report.get('total_cves', 0)} |\n"
            md += f"| **Critical Priorities** | {vi_report.get('critical_priorities', 0)} |\n"
            md += f"| **KEV Count** | {vi_report.get('kev_count', 0)} |\n"
            md += f"| **Public Exploits** | {vi_report.get('public_exploits', 0)} |\n\n"

            if vi_epss:
                md += "### EPSS Distribution\n\n| Classification | Count |\n| :--- | :--- |\n"
                epss_dist = vi_report.get('epss_distribution', {})
                for cls in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "VERY_LOW"]:
                    count = epss_dist.get(cls, 0)
                    md += f"| {cls} | {count} |\n"
                md += "\n"

            if vi_kev:
                md += "### KEV Analysis\n\n| CVE | Vendor | Product | Ransomware |\n| :--- | :--- | :--- | :--- |\n"
                kev_list = [k for k in vi_kev if k.get("kev")]
                for k in kev_list:
                    md += f"| {k.get('cve', '')} | {k.get('vendor_project', '')} | {k.get('product', '')} | {'Yes' if k.get('ransomware_usage') else 'No'} |\n"
                md += "\n"

            if vi_exploit:
                md += "### Exploit Intelligence\n\n| CVE | Public Exploit | Metasploit | Nuclei | Weaponization |\n| :--- | :--- | :--- | :--- | :--- |\n"
                for e in vi_exploit:
                    md += f"| {e.get('cve', '')} | {'Yes' if e.get('public_exploit') else 'No'} | {'Yes' if e.get('metasploit') else 'No'} | {'Yes' if e.get('nuclei_template') else 'No'} | {e.get('weaponization_level', 'NONE')} |\n"
                md += "\n"

            if vi_priorities:
                md += "### Priority Matrix\n\n| Priority | CVE | Product | Risk Score | Reason |\n| :--- | :--- | :--- | :--- | :--- |\n"
                for p in vi_priorities[:10]:
                    md += f"| #{p.get('priority', '')} | {p.get('cve', '')} | {p.get('enriched', {}).get('product', '')} | {p.get('risk_score', 0)}/100 | {p.get('reason', '')} |\n"
                md += "\n"

            if vi_opportunities:
                md += "### Attack Opportunities\n\n| Technology | CVE | Score | Vector |\n| :--- | :--- | :--- | :--- |\n"
                for o in vi_opportunities[:5]:
                    md += f"| {o.get('technology', '')} | {o.get('cve', '')} | {o.get('attack_opportunity_score', 0)}/100 | {o.get('attack_vector', '')} |\n"
                md += "\n"

            # Quick Wins
            quick_wins_data = [p for p in vi_priorities if p.get('risk_score', 0) >= 70][:5]
            if quick_wins_data:
                md += "### Quick Wins\n\n| CVE | Product | Risk Score | Remediation |\n| :--- | :--- | :--- | :--- |\n"
                for qw in quick_wins_data:
                    enriched = qw.get('enriched', {})
                    md += f"| {qw.get('cve', '')} | {enriched.get('product', '')} | {qw.get('risk_score', 0)}/100 | Update {enriched.get('product', '')} to patched version |\n"
                md += "\n"

            md += "---\n"
        else:
            md += """
---

## 7. VULNERABILITY INTELLIGENCE

*Dados de Vulnerability Intelligence não disponíveis. Execute `ghostmirror analyze vulnerabilities` ou `ghostmirror intelligence vulnerabilities` para gerar.*

---\n
"""

        # 8. Web Intelligence
        wi_report = collected_data["profiles"].get("web_intelligence_report") or {}
        wi_endpoints = collected_data["profiles"].get("web_endpoint_inventory") or []
        wi_params = collected_data["profiles"].get("web_parameter_inventory") or []
        wi_js = collected_data["profiles"].get("web_js_intelligence") or {}
        wi_auth = collected_data["profiles"].get("web_auth_profile") or {}
        wi_indicators = collected_data["profiles"].get("web_indicators") or []
        wi_opportunities = collected_data["profiles"].get("web_opportunities") or []
        wi_correlations = collected_data["profiles"].get("web_correlations") or []
        wi_business = collected_data["profiles"].get("web_business_logic") or []

        if wi_report:
            md += """
---

## 8. WEB INTELLIGENCE

A Web Intelligence Engine realizou uma análise passiva de vulnerabilidades web no alvo, identificando endpoints, parâmetros, indicadores e oportunidades de ataque.

### Web Attack Surface Overview

| Métrica | Valor |
| :--- | :--- |
"""
            md += f"| **Total Endpoints** | {wi_report.get('total_endpoints', 0)} |\n"
            md += f"| **Total Parameters** | {wi_report.get('total_parameters', 0)} |\n"
            md += f"| **Total Indicators** | {wi_report.get('total_indicators', 0)} |\n"
            md += f"| **Auth Endpoints** | {wi_report.get('auth_profile', {}).get('total_auth_endpoints', 0)} |\n"
            md += f"| **API Endpoints** | {wi_report.get('attack_surface', {}).get('api_endpoints', 0)} |\n"
            md += f"| **Forms** | {wi_report.get('attack_surface', {}).get('forms_count', 0)} |\n"
            md += f"| **JS Scripts Analyzed** | {wi_report.get('js_findings', {}).get('scripts_analyzed', 0)} |\n"
            md += f"| **Exposure** | {wi_report.get('overall_score', 0)} — {wi_report.get('risk_level', 'INFO')} |\n\n"

            if wi_auth and wi_auth.get('total_auth_endpoints', 0) > 0:
                md += "### Auth Intelligence\n\n| Feature | Status |\n| :--- | :--- |\n"
                md += f"| Login | {'✓' if wi_auth.get('has_login') else '✗'} ({len(wi_auth.get('login_endpoints', []))}) |\n"
                md += f"| Register | {'✓' if wi_auth.get('has_register') else '✗'} ({len(wi_auth.get('register_endpoints', []))}) |\n"
                md += f"| Reset Password | {'✓' if wi_auth.get('has_reset_password') else '✗'} |\n"
                md += f"| Admin | {'✓' if wi_auth.get('has_admin') else '✗'} ({len(wi_auth.get('admin_endpoints', []))}) |\n"
                md += f"| MFA | {'✓' if wi_auth.get('has_mfa') else '✗'} |\n\n"

            if wi_indicators:
                md += "### Vulnerability Indicators\n\n| Type | Count |\n| :--- | :--- |\n"
                ind_count: dict[str, int] = {}
                for ind in wi_indicators:
                    itype = ind.get('indicator_type', 'unknown')
                    ind_count[itype] = ind_count.get(itype, 0) + 1
                for itype, count in sorted(ind_count.items(), key=lambda x: -x[1]):
                    md += f"| {itype.replace('_', ' ').title()} | {count} |\n"
                md += "\n"

            if wi_opportunities:
                md += "### Opportunity Matrix\n\n| Score | Classification | Title |\n| :--- | :--- | :--- |\n"
                for opp in wi_opportunities[:10]:
                    score = opp.get('score', 0)
                    cls = opp.get('classification', 'LOW')
                    md += f"| {score}/100 | **{cls}** | {opp.get('title', '')} |\n"
                md += "\n"

            if wi_business:
                md += "### Business Logic Areas\n\n| Area | Risk | Endpoints |\n| :--- | :--- | :--- |\n"
                for area in wi_business:
                    md += f"| **{area.get('area', '').title()}** | {area.get('risk', 'info')} | {len(area.get('endpoints', []))} |\n"
                md += "\n"

            if wi_js and wi_js.get('secrets_found'):
                md += "### JS Intelligence — ⚠ Secrets Found!\n\n"
                for secret in wi_js['secrets_found'][:5]:
                    md += f"- `{secret[:80]}`\n"
                md += "\n"

            md += "---\n"
        else:
            md += """
---

## 8. WEB INTELLIGENCE

*Dados de Web Intelligence não disponíveis. Execute `ghostmirror web` ou `ghostmirror analyze web` para gerar.*

---\n
"""

        # 9. Safe Payload Validation
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
## 9. SAFE PAYLOAD VALIDATION

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
## 9. SAFE PAYLOAD VALIDATION

*Dados do Safe Payload Validation não disponíveis. Execute `ghostmirror scan payloads` para gerar.*

---\n
"""

        # 10. Attack Surface Intelligence
        as_profile = collected_data["profiles"].get("attack_surface_profile") or {}
        intel_report = collected_data["profiles"].get("intelligence_report") or {}
        risk_matrix_data = collected_data["profiles"].get("risk_matrix") or {}
        attack_paths_data = collected_data["profiles"].get("attack_paths") or []

        waf = as_profile.get("waf", {})
        cdn = as_profile.get("cdn", {})
        hosting = as_profile.get("hosting", {})
        dns = as_profile.get("dns", {})

        waf_status = f"{waf.get('vendor', 'N/A')} (Confidence: {waf.get('confidence', 0)}%)" if waf.get("detected") else "Not Detected"
        cdn_status = f"{cdn.get('vendor', 'N/A')} (Confidence: {cdn.get('confidence', 0)}%)" if cdn.get("detected") else "Not Detected"
        hosting_status = f"{hosting.get('provider', 'N/A')} (Confidence: {hosting.get('confidence', 0)}%)" if hosting.get("detected") else "Not Identified"

        dns_record_count = sum(len(v) for v in dns.get("records", {}).values()) if isinstance(dns.get("records"), dict) else 0
        dns_spf = "MISSING" if dns.get("spf_missing", True) else "OK"
        dns_dmarc = "MISSING" if dns.get("dmarc_missing", True) else "OK"
        dns_dkim = "MISSING" if dns.get("dkim_missing", True) else "OK"

        md += f"""
## 10. ATTACK SURFACE INTELLIGENCE

### WAF, CDN & Hosting Detection

| Category | Status | Detail |
| :--- | :--- | :--- |
| WAF | {'✓ Detected' if waf.get('detected') else '✗ Not Detected'} | {waf_status} |
| CDN | {'✓ Detected' if cdn.get('detected') else '✗ Not Detected'} | {cdn_status} |
| Hosting | {'✓ Identified' if hosting.get('detected') else '✗ Not Identified'} | {hosting_status} |
| DNS Records | {dns_record_count} records | SPF: {dns_spf}, DMARC: {dns_dmarc}, DKIM: {dns_dkim} |

### Open Ports & Services
- **Ports:** {', '.join(str(p) for p in as_profile.get('open_ports', [])) or 'None'}
- **Services:** {', '.join(as_profile.get('services_exposed', [])) or 'None identified'}

---

## 11. RISK MATRIX

"""

        if risk_matrix_data:
            md += """
| Dimension | Score | Level | Description |
| :--- | :--- | :--- | :--- |
"""
            for entry_key in ["likelihood", "impact", "exploitability", "exposure", "business_risk"]:
                entry = risk_matrix_data.get(entry_key, {})
                cat = entry.get("category", entry_key.capitalize())
                score_val = entry.get("score", 0)
                level_val = entry.get("level", "Unknown")
                desc = entry.get("description", "")
                md += f"| **{cat}** | {score_val}/100 | {level_val} | {desc} |\n"

            overall_level = risk_matrix_data.get("overall_level", "Unknown")
            md += f"""
**Overall Risk Level:** {overall_level}

"""
        else:
            md += "*Risk Matrix not available. Run `ghostmirror analyze attack-surface` to generate.*\n\n"

        as_score = intel_report.get("overall_attack_surface_score", as_profile.get("attack_surface_score", 0))
        risk_score = intel_report.get("overall_risk_score", 0)
        security_score = intel_report.get("overall_security_score", 0)

        md += f"""
### Score Overview
- **Attack Surface Score:** {as_score}/100
- **Risk Score:** {risk_score}/100
- **Overall Security Score:** {security_score}/100

---

## 12. ATTACK PATHS

"""

        if attack_paths_data:
            for ap in attack_paths_data[:5]:
                ap_title = ap.get("title", "Unknown Path")
                ap_desc = ap.get("description", "")
                ap_risk_score = ap.get("risk_score", 0)
                ap_risk_level = ap.get("risk_level", "INFO")
                ap_likelihood = ap.get("likelihood", "Unknown")
                ap_impact = ap.get("impact", "Unknown")
                ap_steps = ap.get("steps", [])
                ap_mitigations = ap.get("mitigations", [])

                md += f"""
### {ap_title}

**Description:** {ap_desc}
**Risk Score:** {ap_risk_score}/100 | **Risk Level:** {ap_risk_level} | **Likelihood:** {ap_likelihood} | **Impact:** {ap_impact}

#### Attack Chain
"""
                for step in ap_steps:
                    s_order = step.get("order", 0)
                    s_label = step.get("label", "")
                    s_detail = step.get("detail", "")
                    md += f"  {s_order}. **{s_label}** — {s_detail}\n"

                if ap_mitigations:
                    md += """
#### Mitigations
"""
                    for m in ap_mitigations:
                        md += f"- {m}\n"
                md += "\n---\n"
        else:
            md += "*No attack paths modeled. Run `ghostmirror analyze attack-paths` to generate.*\n\n"

        # 13. Executive Summary
        exec_summary_data = collected_data["profiles"].get("executive_summary") or {}
        summary_text = exec_summary_data.get("summary", intel_report.get("executive_summary", ""))

        md += """
## 13. INTELLIGENCE EXECUTIVE SUMMARY

"""
        if summary_text:
            md += summary_text + "\n\n"
        else:
            md += "*Executive Summary not available. Run `ghostmirror intelligence` to generate.*\n\n"

        md += "---\n\n"

        # 14. Pentest Recommendations
        intel_recommendations = intel_report.get("recommendations", [])
        md += """
## 14. PENTEST RECOMMENDATIONS

"""

        if intel_recommendations:
            for rec in intel_recommendations:
                rec_type = rec.get("assessment_type", rec.get("type", "Assessment"))
                rec_priority = rec.get("priority", "Medium")
                rec_justification = rec.get("justification", "")
                rec_refs = rec.get("findings_reference", [])
                ref_str = ", ".join(rec_refs[:3]) if rec_refs else ""
                md += f"- **[Priority: {rec_priority}] {rec_type}**\n"
                md += f"  - {rec_justification}\n"
                if ref_str:
                    md += f"  - References: {ref_str}\n"
                md += "\n"
        else:
            md += "*Pentest recommendations not available. Run `ghostmirror intelligence` to generate.*\n\n"

        # 15. Next steps
        md += """
## 15. RECOMENDAÇÕES GERAIS E PRÓXIMOS PASSOS

1. **Fase de Mitigação:** Priorize a aplicação de patches e atualizações nas tecnologias que apresentarem CVEs de criticidade Crítica ou Alta.
2. **Hardening de Rede:** Restrinja o acesso a portas administrativas expostas utilizando regras de firewall estritas.
3. **Varredura Recorrente:** Execute varreduras programadas para garantir o monitoramento contínuo da superfície de ataque do projeto.
4. **Vulnerability Intelligence:** Utilize `ghostmirror analyze vulnerabilities` para priorizar riscos com EPSS, KEV e Exploit Intelligence.
"""
        return md
