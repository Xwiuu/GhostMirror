"""Export bounty reports to HTML."""
from __future__ import annotations
from pathlib import Path
from ghostmirror.models.bounty_report import BountyReport

class HTMLExporter:
    @staticmethod
    def export_report(report: BountyReport, path: str | Path) -> str:
        submissions_html = ""
        for i, sub in enumerate(report.submissions, 1):
            sev_color = {"Critical": "#e74c3c", "High": "#e67e22", "Medium": "#f1c40f", "Low": "#3498db", "Informational": "#95a5a6"}
            color = sev_color.get(sub.severity.value, "#95a5a6")
            steps_html = ""
            for s in sub.steps_to_reproduce:
                steps_html += f"<li><strong>Step {s.step_number}:</strong> {s.description}<br><em>Expected: {s.expected_observation}</em></li>"
            evidence_html = ""
            for e in sub.evidence:
                evidence_html += f"<div class=\"evidence-block\"><strong>{e.label}</strong><pre>{e.content}</pre></div>"
            refs_html = ""
            for r in sub.references:
                refs_html += f"<li>{r}</li>"
            biz = sub.impact.get("business", "")
            tech = sub.impact.get("technical", "")
            sub_html = f"""
            <div class="submission">
                <div class="severity-badge" style="background:{color}">{sub.severity.value}</div>
                <h2>{sub.title}</h2>
                <p><strong>Priority:</strong> {sub.priority.value} | <strong>Confidence:</strong> {sub.confidence} | <strong>Asset:</strong> {sub.affected_asset}</p>
                <p><strong>Category:</strong> {sub.category} | <strong>CWE:</strong> {sub.cwe} | <strong>CVSS:</strong> {str(sub.cvss) if sub.cvss is not None else "N/A"}</p>
                <h3>Summary</h3><p>{sub.summary}</p>
                <h3>Impact</h3>
                <p><strong>Business:</strong> {biz}</p>
                <p><strong>Technical:</strong> {tech}</p>
                <h3>Steps to Reproduce</h3><ol>{steps_html}</ol>
                <h3>Evidence</h3>{evidence_html}
                <h3>Remediation</h3><p>{sub.remediation}</p>
                <h3>References</h3><ul>{refs_html}</ul>
            </div>"""
            submissions_html += sub_html
        stats_rows = ""
        for k, v in report.summary_stats.items():
            stats_rows += f"<tr><td>{k.title()}</td><td>{v}</td></tr>"
        html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>Bug Bounty Report - {report.target}</title>
<style>body{{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;max-width:1200px;margin:0 auto;padding:20px;background:#1a1a2e;color:#e0e0e0}}h1{{color:#e94560}}h2{{color:#0f3460;background:#e94560;padding:10px;border-radius:5px;margin-top:30px}}h3{{color:#e94560;border-bottom:1px solid #333;padding-bottom:5px}}.submission{{background:#16213e;padding:20px;border-radius:10px;margin:20px 0;border-left:4px solid #e94560}}.severity-badge{{display:inline-block;padding:4px 12px;border-radius:4px;color:#fff;font-weight:bold;font-size:0.9em;margin-bottom:10px}}.evidence-block{{background:#0f3460;padding:15px;border-radius:5px;margin:10px 0}}.evidence-block pre{{background:#1a1a2e;padding:10px;border-radius:3px;overflow-x:auto;font-size:0.85em}}table{{width:100%;border-collapse:collapse;margin:15px 0}}th,td{{border:1px solid #333;padding:8px;text-align:left}}th{{background:#0f3460;color:#e94560}}a{{color:#e94560;text-decoration:none}}pre{{white-space:pre-wrap;word-break:break-word}}</style></head><body>
<h1>Bug Bounty Report</h1>
<p><strong>Target:</strong> {report.target}<br><strong>Generated:</strong> {report.generated_at}</p>
<h2>Summary Statistics</h2>
<table><tr><th>Severity</th><th>Count</th></tr>{stats_rows}</table>
<h2>Submissions ({len(report.submissions)})</h2>
{submissions_html}
</body></html>"""
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(html, encoding="utf-8")
        return html
