"""HTML Renderer to compile reports into a visual dark-themed format."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from ghostmirror.modules.models.finding import FindingModel


class HTMLReportRenderer:
    """Renders visual dark premium reports with responsive components and graphs."""

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
        """Compiles report data into a standalone visual HTML page string."""
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        # 1. Gather findings by severity
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

        # 2. Build module execution summary table
        timeline = collected_data.get("timeline", {})
        steps = timeline.get("steps", [])
        executed = [s for s in steps if s.get("status") == "completed"]
        skipped = [s for s in steps if s.get("status") == "skipped"]
        failed = [s for s in steps if s.get("status") == "failed"]
        has_modules = bool(steps)
        modules_html = ""
        if has_modules:
            for s in steps:
                st = s.get("status", "?")
                icon = "✓" if st == "completed" else ("⏭" if st == "skipped" else "✗")
                color = "success" if st == "completed" else ("warning" if st == "skipped" else "danger")
                dur = s.get("duration", 0)
                fc = s.get("findings_count", s.get("findings", 0))
                errs = "; ".join(s.get("errors", []))[:120] if s.get("errors") else "—"
                modules_html += f"""
                <tr>
                    <td>{s.get("name", "?")}</td>
                    <td><span class="mod-status mod-{color}">{icon} {st}</span></td>
                    <td>{dur}s</td>
                    <td>{fc}</td>
                    <td style="font-size:0.8rem;color:var(--text-muted);">{errs}</td>
                </tr>"""

        # 3. Get technologies list
        tech_profile = collected_data["profiles"].get("technology_profile") or {}
        technologies = tech_profile.get("technologies", [])
        tech_list_html = ""
        if technologies:
            for tech in technologies:
                name = tech.get("name", "Unknown")
                version = tech.get("version", "—")
                categories = ", ".join(tech.get("categories", []))
                tech_list_html += f"""
                <tr class="tech-row">
                    <td><strong>{name}</strong></td>
                    <td><span class="badge badge-info">{version}</span></td>
                    <td><span class="text-muted">{categories}</span></td>
                </tr>
                """
        else:
            tech_list_html = "<tr><td colspan='3' class='text-center'>Nenhuma tecnologia mapeada no escopo.</td></tr>"

        # 3. Mapped CVEs List
        cve_profile = collected_data["profiles"].get("vulnerability_profile") or {}
        cve_matches = cve_profile.get("matches", [])
        cve_list_html = ""
        if cve_matches:
            for match in cve_matches[:25]:  # limit to top 25 CVEs for size
                cve_id = match.get("matched_cve", {}).get("cve_id", "CVE-Unknown")
                tech_name = match.get("technology", "—")
                sev = match.get("risk_level", "INFO")
                exploit = "Sim" if match.get("matched_cve", {}).get("exploit_available") else "Não"
                cve_list_html += f"""
                <tr>
                    <td><strong>{cve_id}</strong></td>
                    <td>{tech_name}</td>
                    <td><span class="severity-badge sev-{sev.lower()}">{sev}</span></td>
                    <td><span class="badge {'badge-crit' if exploit == 'Sim' else 'badge-info'}">{exploit}</span></td>
                </tr>
                """
            if len(cve_matches) > 25:
                cve_list_html += f"""
                <tr>
                    <td colspan="4" class="text-center text-muted">Exibindo 25 de {len(cve_matches)} CVEs correlacionadas. Verifique a base de dados para o restante.</td>
                </tr>
                """
        else:
            cve_list_html = "<tr><td colspan='4' class='text-center'>Nenhum CVE em potencial identificado.</td></tr>"

        # 4. Detailed findings list rendering
        findings_details_html = ""
        if all_findings:
            for index, f in enumerate(all_findings, start=1):
                sev = f.severity.value.upper()
                evidence_html = ""
                if f.evidence:
                    evidence_html = f"""
                    <div class="evidence-box">
                        <div class="evidence-header">Evidência Técnica</div>
                        <pre><code>{f.evidence}</code></pre>
                    </div>
                    """
                findings_details_html += f"""
                <div class="finding-card border-{sev.lower()}" id="finding-{index}">
                    <div class="finding-header">
                        <span class="severity-badge sev-{sev.lower()}">{sev}</span>
                        <span class="finding-title">{f.title}</span>
                    </div>
                    <div class="finding-body">
                        <p><strong>Alvo:</strong> <code>{f.target}</code></p>
                        <p><strong>Descrição:</strong></p>
                        <p>{f.description}</p>
                        {evidence_html}
                        <div class="remediation-box">
                            <strong>Recomendação:</strong>
                            <p>{f.recommendation}</p>
                        </div>
                    </div>
                </div>
                """
        else:
            findings_details_html = "<div class='no-findings-box'>Nenhuma vulnerabilidade foi detectada neste assessment.</div>"

        # 5. Build final HTML template
        html_template = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <title>GhostMirror Security Assessment - {project_name}</title>
    <style>
        :root {{
            --bg-color: #0b0f17;
            --card-bg: #141b27;
            --border-color: #232d3f;
            --text-color: #e2e8f0;
            --text-muted: #94a3b8;
            --accent-color: #00f0ff;
            --crit-color: #ff4d4f;
            --high-color: #ff7a45;
            --med-color: #ffc53d;
            --low-color: #1890ff;
            --info-color: #8c8c8c;
        }}
        * {{
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }}
        body {{
            font-family: 'Outfit', 'Inter', -apple-system, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-color);
            line-height: 1.6;
            padding: 40px;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        /* COVER PAGE */
        .cover {{
            text-align: center;
            padding: 100px 20px;
            border-bottom: 2px solid var(--border-color);
            margin-bottom: 50px;
            background: radial-gradient(circle at center, #1b263b 0%, var(--bg-color) 70%);
        }}
        .cover h1 {{
            font-size: 3.5rem;
            color: var(--accent-color);
            margin-bottom: 10px;
            text-transform: uppercase;
            letter-spacing: 2px;
            text-shadow: 0 0 10px rgba(0, 240, 255, 0.3);
        }}
        .cover h2 {{
            font-size: 1.8rem;
            font-weight: 300;
            color: var(--text-color);
            margin-bottom: 40px;
        }}
        .cover-meta {{
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 20px;
            max-width: 600px;
            margin: 0 auto;
            text-align: left;
            background: rgba(20, 27, 39, 0.7);
            padding: 30px;
            border-radius: 8px;
            border: 1px solid var(--border-color);
        }}
        .cover-meta div {{
            font-size: 0.95rem;
        }}
        .cover-meta strong {{
            color: var(--accent-color);
        }}

        /* DASHBOARD GRID */
        .dashboard-grid {{
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            gap: 30px;
            margin-bottom: 50px;
        }}
        .card {{
            background-color: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            padding: 30px;
            text-align: center;
            position: relative;
            box-shadow: 0 4px 20px rgba(0,0,0,0.2);
        }}
        .score-circle {{
            width: 140px;
            height: 140px;
            border-radius: 50%;
            margin: 0 auto 15px auto;
            display: flex;
            align-items: center;
            justify-content: center;
            flex-direction: column;
            border: 8px solid var(--border-color);
            background: radial-gradient(circle at center, #172237 0%, #0d1527 100%);
        }}
        .score-val {{
            font-size: 3rem;
            font-weight: bold;
            color: var(--accent-color);
        }}
        .risk-level-badge {{
            display: inline-block;
            padding: 6px 16px;
            border-radius: 20px;
            font-weight: bold;
            font-size: 1.1rem;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-top: 10px;
        }}
        .risk-crit {{ background-color: rgba(255,77,79,0.2); color: var(--crit-color); border: 1px solid var(--crit-color); }}
        .risk-high {{ background-color: rgba(255,122,69,0.2); color: var(--high-color); border: 1px solid var(--high-color); }}
        .risk-med {{ background-color: rgba(255,197,61,0.2); color: var(--med-color); border: 1px solid var(--med-color); }}
        .risk-low {{ background-color: rgba(24,144,255,0.2); color: var(--low-color); border: 1px solid var(--low-color); }}

        /* SEVERITY COUNTS */
        .severity-counts {{
            display: flex;
            justify-content: space-around;
            align-items: center;
            height: 100%;
        }}
        .severity-item {{
            text-align: center;
        }}
        .severity-val {{
            font-size: 2rem;
            font-weight: bold;
        }}
        .severity-label {{
            font-size: 0.8rem;
            color: var(--text-muted);
            text-transform: uppercase;
        }}

        /* HEADINGS */
        h3.section-title {{
            font-size: 1.8rem;
            color: var(--accent-color);
            border-left: 4px solid var(--accent-color);
            padding-left: 15px;
            margin-bottom: 25px;
            margin-top: 50px;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}

        /* TABLES */
        .table-responsive {{
            margin-bottom: 30px;
            border: 1px solid var(--border-color);
            border-radius: 8px;
            overflow: hidden;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            text-align: left;
            background-color: var(--card-bg);
        }}
        th, td {{
            padding: 15px 20px;
            border-bottom: 1px solid var(--border-color);
        }}
        th {{
            background-color: rgba(35, 45, 63, 0.4);
            color: var(--accent-color);
            font-weight: bold;
        }}
        tr:last-child td {{
            border-bottom: none;
        }}

        /* BADGES */
        .badge {{
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.8rem;
            font-weight: bold;
        }}
        .badge-info {{ background-color: #23354f; color: #58a6ff; }}
        .badge-crit {{ background-color: #4b1717; color: #ff6b6b; }}
        .severity-badge {{
            display: inline-block;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: bold;
            text-align: center;
        }}
        .sev-critical {{ background-color: var(--crit-color); color: #fff; }}
        .sev-high {{ background-color: var(--high-color); color: #fff; }}
        .sev-medium {{ background-color: var(--med-color); color: #000; }}
        .sev-low {{ background-color: var(--low-color); color: #fff; }}
        .sev-info {{ background-color: var(--info-color); color: #fff; }}

        /* FINDING CARDS */
        .finding-card {{
            background-color: var(--card-bg);
            border-radius: 8px;
            border-left: 5px solid var(--border-color);
            margin-bottom: 25px;
            padding: 25px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.15);
        }}
        .border-critical {{ border-left-color: var(--crit-color); }}
        .border-high {{ border-left-color: var(--high-color); }}
        .border-medium {{ border-left-color: var(--med-color); }}
        .border-low {{ border-left-color: var(--low-color); }}
        .border-info {{ border-left-color: var(--info-color); }}

        .finding-header {{
            display: flex;
            align-items: center;
            gap: 15px;
            margin-bottom: 15px;
        }}
        .finding-title {{
            font-size: 1.3rem;
            font-weight: bold;
            color: #ffffff;
        }}
        .finding-body p {{
            margin-bottom: 15px;
        }}
        .evidence-box {{
            background-color: #080c12;
            border: 1px solid var(--border-color);
            border-radius: 6px;
            margin: 15px 0;
            overflow: hidden;
        }}
        .evidence-header {{
            background-color: #111823;
            padding: 8px 15px;
            font-size: 0.8rem;
            color: var(--text-muted);
            border-bottom: 1px solid var(--border-color);
            font-weight: bold;
        }}
        pre {{
            padding: 15px;
            overflow-x: auto;
            font-family: 'Consolas', 'Courier New', monospace;
            font-size: 0.85rem;
            color: #58a6ff;
        }}
        .remediation-box {{
            background-color: rgba(0, 240, 255, 0.03);
            border: 1px dashed rgba(0, 240, 255, 0.2);
            border-radius: 6px;
            padding: 15px;
            margin-top: 15px;
        }}
        .remediation-box strong {{
            color: var(--accent-color);
            display: block;
            margin-bottom: 5px;
        }}

        .no-findings-box {{
            background-color: var(--card-bg);
            border: 1px dashed var(--border-color);
            border-radius: 8px;
            padding: 40px;
            text-align: center;
            color: var(--text-muted);
            font-size: 1.1rem;
        }}

        /* FOOTER */
        .footer {{
            text-align: center;
            padding: 40px 0;
            margin-top: 60px;
            border-top: 1px solid var(--border-color);
            color: var(--text-muted);
            font-size: 0.85rem;
        }}
        
        /* PRINT / PDF STYLING */
        @media print {{
            body {{
                background-color: #ffffff;
                color: #000000;
                padding: 20px;
            }}
            .card, .finding-card, table, .cover-meta {{
                background-color: #ffffff !important;
                border: 1px solid #cccccc !important;
                color: #000000 !important;
                box-shadow: none !important;
            }}
            .cover {{
                background: none !important;
            }}
            pre {{
                background-color: #f6f8fa !important;
                color: #000000 !important;
                border: 1px solid #cccccc !important;
            }}
            .remediation-box {{
                background: none !important;
                border-color: #666666 !important;
            }}
            .finding-title, h3.section-title, .cover h1 {{
                color: #000000 !important;
            }}
            .severity-badge, .badge {{
                border: 1px solid #000000 !important;
                color: #000000 !important;
                background-color: transparent !important;
            }}
        }}
        .mod-status {{
            display: inline-block;
            padding: 2px 10px;
            border-radius: 12px;
            font-size: 0.75rem;
            font-weight: bold;
            text-transform: uppercase;
        }}
        .mod-success {{ background-color: rgba(0,200,83,0.15); color: #00c853; }}
        .mod-warning {{ background-color: rgba(255,193,7,0.15); color: #ffc107; }}
        .mod-danger {{ background-color: rgba(255,77,79,0.15); color: #ff4d4f; }}
        .mod-summary-card {{
            display: flex; gap: 20px; margin-bottom: 20px;
        }}
        .mod-summary-item {{
            background: var(--card-bg); border: 1px solid var(--border-color);
            border-radius: 8px; padding: 15px 20px; text-align: center; flex: 1;
        }}
        .mod-summary-val {{
            font-size: 1.8rem; font-weight: bold;
        }}
        .lab-badge {{
            display: inline-block;
            padding: 4px 14px;
            background: linear-gradient(135deg, #ff9800, #f57c00);
            color: #fff;
            font-weight: 700;
            font-size: 0.85rem;
            border-radius: 12px;
            letter-spacing: 1px;
            text-transform: uppercase;
            box-shadow: 0 2px 8px rgba(255, 152, 0, 0.4);
        }}
    </style>
</head>
<body>
    <div class="container">
        
        <!-- COVER PAGE -->
        <div class="cover">
            <h1>GhostMirror</h1>
            <h2>Relatório de Pentest Interno Autorizado</h2>
            <div class="cover-meta">
                <div><strong>Projeto:</strong> {project_name}</div>
                <div><strong>Perfil de Scan:</strong> {profile.upper()}</div>
                <div><strong>Alvo Principal:</strong> <code>{target}</code></div>
                <div><strong>Data de Geração:</strong> {now}</div>
                {"        <div style=\"margin-top: 10px;\"><span class=\"lab-badge\">LAB TARGET</span></div>" if is_lab else ""}
            </div>
        </div>

        <!-- DASHBOARD -->
        <div class="dashboard-grid">
            <div class="card">
                <div class="score-circle">
                    <span class="score-val">{score}</span>
                    <span style="font-size: 0.75rem; color: var(--text-muted); text-transform: uppercase;">Risco Global</span>
                </div>
                <span class="risk-level-badge risk-{risk_level.lower()}">{risk_level}</span>
            </div>
            
            <div class="card" style="grid-column: span 2;">
                <h4 style="color: var(--accent-color); margin-bottom: 20px; text-transform: uppercase; letter-spacing: 1px;">Estatísticas de Vulnerabilidade</h4>
                <div class="severity-counts">
                    <div class="severity-item">
                        <div class="severity-val" style="color: var(--crit-color);">{severity_counts["CRITICAL"]}</div>
                        <div class="severity-label">Critica</div>
                    </div>
                    <div class="severity-item">
                        <div class="severity-val" style="color: var(--high-color);">{severity_counts["HIGH"]}</div>
                        <div class="severity-label">Alta</div>
                    </div>
                    <div class="severity-item">
                        <div class="severity-val" style="color: var(--med-color);">{severity_counts["MEDIUM"]}</div>
                        <div class="severity-label">Média</div>
                    </div>
                    <div class="severity-item">
                        <div class="severity-val" style="color: var(--low-color);">{severity_counts["LOW"]}</div>
                        <div class="severity-label">Baixa</div>
                    </div>
                    <div class="severity-item">
                        <div class="severity-val" style="color: var(--info-color);">{severity_counts["INFO"]}</div>
                        <div class="severity-label">Info</div>
                    </div>
                </div>
            </div>
        </div>

        <!-- RESUMO EXECUTIVO -->
        <h3 class="section-title">1. Resumo Executivo</h3>
        <div class="card" style="text-align: left; margin-bottom: 40px;">
            <p style="margin-bottom: 15px;">
                Este documento apresenta os resultados da auditoria de segurança e teste de intrusão interna autorizada realizada no alvo principal <strong>{target}</strong>, no escopo do projeto <strong>{project_name}</strong>.
            </p>
            <p style="margin-bottom: 15px;">
                A avaliação foi estruturada utilizando a metodologia do GhostMirror Platform, envolvendo varredura de portas, análise de criptografia SSL/TLS, identificação de impressões digitais de tecnologia e correlação com vulnerabilidades públicas divulgadas (CVEs).
            </p>
            <p>
                O score global de risco foi calculado em <strong>{score}/100</strong>, classificando a superfície de ataque atual como de nível <strong>{risk_level}</strong>. Recomenda-se a mitigação imediata das vulnerabilidades críticas e altas apresentadas no relatório técnico.
            </p>
        </div>

        <!-- MÓDULOS EXECUTADOS -->
        <h3 class="section-title">2. Módulos Executados</h3>
        <div class="card" style="text-align: left; margin-bottom: 40px;">
""" + (f"""
            <div class="mod-summary-card">
                <div class="mod-summary-item">
                    <div class="mod-summary-val" style="color: #00c853;">{len(executed)}</div>
                    <div style="color: var(--text-muted); font-size:0.85rem;">Executados</div>
                </div>
                <div class="mod-summary-item">
                    <div class="mod-summary-val" style="color: #ffc107;">{len(skipped)}</div>
                    <div style="color: var(--text-muted); font-size:0.85rem;">Pulados</div>
                </div>
                <div class="mod-summary-item">
                    <div class="mod-summary-val" style="color: #ff4d4f;">{len(failed)}</div>
                    <div style="color: var(--text-muted); font-size:0.85rem;">Falhas</div>
                </div>
            </div>""" if has_modules else "") + f"""
            <div class="table-responsive">
                <table>
                    <thead>
                        <tr>
                            <th>Módulo</th>
                            <th>Status</th>
                            <th>Duração</th>
                            <th>Findings</th>
                            <th>Erros</th>
                        </tr>
                    </thead>
                    <tbody>
                        {modules_html if modules_html else '<tr><td colspan="5" class="text-center text-muted">Nenhum módulo foi executado nesta varredura.</td></tr>'}
                    </tbody>
                </table>
            </div>
        </div>

        <!-- TECNOLOGIAS DETECTADAS -->
        <h3 class="section-title">3. Tecnologias Mapeadas</h3>
        <div class="table-responsive">
            <table>
                <thead>
                    <tr>
                        <th>Tecnologia</th>
                        <th>Versão Identificada</th>
                        <th>Categorias</th>
                    </tr>
                </thead>
                <tbody>
                    {tech_list_html}
                </tbody>
            </table>
        </div>

        <!-- POTENCIAIS CVES -->
        <h3 class="section-title">4. CVEs Correlacionadas</h3>
        <div class="table-responsive">
            <table>
                <thead>
                    <tr>
                        <th>Identificador CVE</th>
                        <th>Tecnologia Afetada</th>
                        <th>Severidade</th>
                        <th>Exploit Público</th>
                    </tr>
                </thead>
                <tbody>
                    {cve_list_html}
                </tbody>
            </table>
        </div>

        <!-- VULNERABILIDADES DETALHADAS -->
        <h3 class="section-title">5. Vulnerabilidades Confirmadas e Evidências</h3>
        <div class="findings-list">
            {findings_details_html}
        </div>

        <!-- OWASP TOP 10 ASSESSMENT -->
        <h3 class="section-title">6. OWASP Top 10 Assessment</h3>
        <div class="card" style="text-align: left; margin-bottom: 40px;">
"""

        owasp_profile = collected_data["profiles"].get("owasp_profile") or {}
        all_findings_data = collected_data.get("findings") or {}
        owasp_findings = all_findings_data.get("owasp_findings") or []

        if owasp_profile:
            owasp_score = owasp_profile.get("risk_score", 0)
            owasp_level = owasp_profile.get("risk_level", "N/A")
            owasp_categories = owasp_profile.get("categories", [])
            owasp_total = len(owasp_findings)

            html_template += f"""
            <div class="dashboard-grid" style="margin-bottom: 20px;">
                <div class="card">
                    <div class="score-circle" style="width: 120px; height: 120px;">
                        <span class="score-val" style="font-size: 2.5rem;">{owasp_score}</span>
                        <span style="font-size: 0.7rem; color: var(--text-muted); text-transform: uppercase;">OWASP Risk</span>
                    </div>
                    <span class="risk-level-badge risk-{owasp_level.lower()}">{owasp_level}</span>
                </div>
                <div class="card" style="grid-column: span 2;">
                    <h4 style="color: var(--accent-color); margin-bottom: 15px; text-transform: uppercase;">OWASP Top 10 Summary</h4>
                    <div class="severity-counts">
                        <div class="severity-item">
                            <div class="severity-val" style="color: var(--accent-color); font-size: 1.5rem;">{owasp_total}</div>
                            <div class="severity-label">Findings</div>
                        </div>
                        <div class="severity-item">
                            <div class="severity-val" style="color: var(--accent-color); font-size: 1.5rem;">{len(owasp_categories)}</div>
                            <div class="severity-label">Categories</div>
                        </div>
                    </div>
                </div>
            </div>
            """

            # Category breakdown
            if owasp_categories:
                html_template += """
            <div class="table-responsive">
                <table>
                    <thead>
                        <tr>
                            <th>Category</th>
                            <th>Status</th>
                        </tr>
                    </thead>
                    <tbody>
                """
                for cat in owasp_categories:
                    cat_findings = [f for f in owasp_findings if isinstance(f, dict) and f.get("category") == cat]
                    cat_count = len(cat_findings)
                    max_sev = "INFO"
                    for f in cat_findings:
                        sev = f.get("severity", "INFO").upper()
                        if sev == "CRITICAL":
                            max_sev = "CRITICAL"
                        elif sev == "HIGH" and max_sev != "CRITICAL":
                            max_sev = "HIGH"
                        elif sev == "MEDIUM" and max_sev not in ("CRITICAL", "HIGH"):
                            max_sev = "MEDIUM"
                    sev_badge = f"sev-{max_sev.lower()}"
                    html_template += f"""
                        <tr>
                            <td><strong>{cat}</strong></td>
                            <td><span class="severity-badge {sev_badge}">{cat_count} findings ({max_sev})</span></td>
                        </tr>
                    """
                html_template += """
                    </tbody>
                </table>
            </div>
            """

            # OWASP Recommendation
            recs = owasp_profile.get("recommendations", [])
            if recs:
                html_template += """
            <div class="card" style="text-align: left; margin-top: 20px;">
                <h4 style="color: var(--accent-color); margin-bottom: 15px;">OWASP Recommendations</h4>
                <ul style="padding-left: 20px;">
                """
                for rec in recs[:8]:
                    html_template += f"<li style='margin-bottom: 8px;'>{rec}</li>"
                html_template += """
                </ul>
            </div>
            """
        else:
            html_template += """
            <p>OWASP Top 10 Light assessment data not available. Execute <code>ghostmirror scan owasp</code> to generate.</p>
            """

        html_template += """
        </div>

        <!-- SAFE PAYLOAD VALIDATION -->
        <h3 class="section-title">7. Safe Payload Validation</h3>
        <div class="card">
        """

        payload_profile = collected_data["profiles"].get("payload_profile") or {}
        payload_all_findings = all_findings_data.get("payload_findings") or []

        if payload_profile:
            pp_total = payload_profile.get("total_payloads_registered", 0)
            pp_executed = payload_profile.get("payloads_executed", 0)
            pp_blocked = payload_profile.get("payloads_blocked", 0)
            pp_findings = payload_profile.get("findings_generated", 0)
            pp_risk_score = payload_profile.get("risk_score", 0)
            pp_risk_level = payload_profile.get("risk_level", "N/A")
            pp_dry_run = payload_profile.get("dry_run", False)

            html_template += f"""
            <div class="dashboard-row">
                <div class="score-circle" style="border-color: var(--accent-color);">
                    <span class="score-val" style="font-size: 2.5rem;">{pp_risk_score}</span>
                    <span style="font-size: 0.7rem; color: var(--text-muted); text-transform: uppercase;">Payload Risk</span>
                </div>
                <div class="severity-container">
                    <span class="risk-level-badge risk-{pp_risk_level.lower()}">{pp_risk_level}</span>
                </div>
            </div>
            <div class="stats-row">
                <div class="stats-card">
                    <h4 style="color: var(--accent-color); margin-bottom: 15px; text-transform: uppercase;">Payload Summary</h4>
                    <div class="severity-row">
                        <span class="severity-label">Registered</span>
                        <span class="severity-val" style="color: var(--accent-color); font-size: 1.5rem;">{pp_total}</span>
                    </div>
                    <div class="severity-row">
                        <span class="severity-label">Executed</span>
                        <span class="severity-val" style="color: var(--accent-color); font-size: 1.5rem;">{pp_executed}</span>
                    </div>
                    <div class="severity-row">
                        <span class="severity-label">Blocked</span>
                        <span class="severity-val" style="color: var(--accent-color); font-size: 1.5rem;">{pp_blocked}</span>
                    </div>
                    <div class="severity-row">
                        <span class="severity-label">Findings</span>
                        <span class="severity-val" style="color: var(--accent-color); font-size: 1.5rem;">{pp_findings}</span>
                    </div>
                    <div class="severity-row">
                        <span class="severity-label">Dry Run</span>
                        <span class="severity-val" style="color: var(--accent-color); font-size: 1.5rem;">{'Yes' if pp_dry_run else 'No'}</span>
                    </div>
                </div>
            </div>
            """

            if payload_all_findings:
                html_template += """
                <h4 style="color: var(--accent-color); margin-bottom: 15px;">Payload Findings</h4>
                <table class="findings-table">
                    <thead>
                        <tr>
                            <th>Title</th>
                            <th>Severity</th>
                            <th>Target</th>
                            <th>Evidence</th>
                        </tr>
                    </thead>
                    <tbody>
                """
                for finding in payload_all_findings:
                    sev = finding.get("severity", "INFO").lower()
                    title = finding.get("title", "N/A")
                    target = finding.get("target", "N/A")
                    evidence = finding.get("evidence", "N/A")[:120]
                    html_template += f"""
                        <tr>
                            <td>{title}</td>
                            <td><span class="severity-badge severity-{sev}">{sev.upper()}</span></td>
                            <td>{target}</td>
                            <td style="font-size: 0.75rem;">{evidence}</td>
                        </tr>
                    """
                html_template += """
                    </tbody>
                </table>
                """
        else:
            html_template += """
            <p>Safe Payload Validation data not available. Execute <code>ghostmirror scan payloads</code> to generate.</p>
            """

        html_template += """
        </div>

        <!-- RECOMENDAÇÕES E PRÓXIMOS PASSOS -->
        <h3 class="section-title">8. Recomendações e Próximos Passos</h3>
        <div class="card" style="text-align: left;">
            <ul style="padding-left: 20px;">
                <li style="margin-bottom: 12px;"><strong>Fase de Mitigação:</strong> Revise as configurações de servidores web e aplique patches de segurança para as tecnologias identificadas com CVEs ativas.</li>
                <li style="margin-bottom: 12px;"><strong>Segmentação de Rede:</strong> Isole as portas administrativas expostas e limite acessos a sistemas confidenciais via VPN/Firewall.</li>
                <li style="margin-bottom: 12px;"><strong>Ciclo de Varredura:</strong> Estabeleça auditorias recorrentes do GhostMirror para assegurar que nenhuma nova porta seja aberta ou que atualizações incorretas introduzam novos riscos.</li>
            </ul>
        </div>

        <!-- FOOTER -->
        <div class="footer">
            <p>Gerado automaticamente pelo <strong>GhostMirror Platform</strong> &copy; {datetime.now(timezone.utc).year}</p>
            <p style="margin-top: 5px; font-size: 0.75rem;">Confidencial - Destinado apenas para uso interno autorizado.</p>
        </div>

    </div>
</body>
</html>
"""
        return html_template
