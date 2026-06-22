# HackerOne Style Reporting — GhostMirror

## Overview

The HackerOne Style Reporting module transforms GhostMirror findings, hypotheses, and
intelligence into professional bug bounty and pentest submission reports compatible
with HackerOne, Bugcrowd, and internal consulting formats.

## Architecture

```
ghostmirror/modules/hackerone_reporting/
├── __init__.py
├── engine.py                  # Main orchestrator
├── submission_builder.py      # Builds submissions from all sources
├── severity_mapper.py         # Maps internal severities to bounty format
├── reproduction_steps.py      # Safe, non-destructive reproduction steps
├── impact_writer.py           # Business and technical impact descriptions
├── evidence_formatter.py      # Evidence formatting and redaction
├── remediation_writer.py      # Specific remediation recommendations
├── references_mapper.py       # OWASP, CWE, PortSwigger, MITRE references
├── template_renderer.py       # HackerOne, Bugcrowd, Internal templates
├── markdown_exporter.py       # Markdown export
├── json_exporter.py           # JSON export
├── html_exporter.py           # HTML export
└── report_index.py            # Report index with statistics
```

## Models

- **BountySubmission** — Single vulnerability submission with all fields (severity, priority, steps, evidence, remediation, references)
- **BountyReport** — Aggregated report with multiple submissions and summary statistics
- **ReproductionStep** — Safe, observational reproduction step
- **EvidenceBlock** — Evidence block with type and redaction flag
- **BountySeverity / BountyPriority** — Enums for bounty-format severity and priority

## CLI Commands

```bash
# Generate complete bounty report
ghostmirror bounty report --project <slug>

# List submissions
ghostmirror bounty submissions --project <slug>

# Export individual submission to HackerOne format
ghostmirror bounty export-hackerone --project <slug> --index 1

# Export individual submission to Bugcrowd format
ghostmirror bounty export-bugcrowd --project <slug> --index 1
```

## Output Structure

```
reports/bounty/
├── bounty_report.json       # Complete report in JSON format
├── bounty_report.md         # Report in Markdown format
├── bounty_report.html       # Report in HTML format (dark theme)
├── submissions/
│   ├── H1-001-*.md          # Individual HackerOne-style submissions
│   └── ...
└── index.json               # Index with statistics and priorities
```

## Data Sources

The engine consumes:

1. **Enriched Findings** — From finding intelligence engine
2. **Web Intelligence Indicators** — From web intelligence engine
3. **API Security Indicators** — From API security intelligence
4. **Vulnerability Intelligence** — From vulnerability intelligence engine
5. **Zero-Day Hypotheses** — From zero-day hypothesis engine

## Safety Guarantees

- All reproduction steps are observational and non-destructive
- No exploit code, payloads, or bypass techniques are generated
- No active exploitation steps are produced
- Evidence is automatically redacted (tokens, secrets, cookies, API keys)
- Hypotheses are clearly marked as requiring manual validation

## Report Templates

Three templates are available:
- **HackerOne** — Standard HackerOne submission format
- **Bugcrowd** — Bugcrowd VRT-based submission format
- **Internal Pentest** — Format for internal consulting reports

## Severity Mapping

| Internal    | Bounty        | Priority |
|-------------|---------------|----------|
| CRITICAL    | Critical      | P1       |
| HIGH        | High          | P2       |
| MEDIUM      | Medium        | P3       |
| LOW         | Low           | P4       |
| INFO        | Informational | P5       |

## Confidence Mapping

| Internal    | Bounty    |
|-------------|-----------|
| LOW         | Low       |
| MEDIUM      | Medium    |
| HIGH        | High      |
| CONFIRMED   | Confirmed |

## Warning

> Use only on targets you own or are explicitly authorized to test.
> Reports are generated from evidence collected by GhostMirror and may
> require manual validation before submission to bug bounty programs.
