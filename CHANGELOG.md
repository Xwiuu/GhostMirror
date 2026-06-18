# Changelog

All notable changes to GhostMirror are documented here.

## v1.0-alpha — 2026-06-18

### Foundation
- Project scaffolding: package structure, CLI entrypoint, console runner
- Pydantic-validated project lifecycle (create, list, open)
- Scope system with `scope.yaml` build, load, and validation
- Global configuration (`config/default.yaml` + `config/settings.yaml`)
- Centralized logging with Loguru (5 sinks: execution, scanner, audit, errors, console)
- Docker support with volume mounts for persistence

### Scanner Framework
- Abstract `ScannerBase` with `run()` contract, `ScanResultModel` output
- `ScopeGuard` runtime enforcement — blocks out-of-scope targets
- `FindingsManager` for persisting scan results to JSON

### SSL/TLS Scanner
- Certificate chain validation, expiry, and issuer extraction
- Protocol version detection (TLS 1.0 → 1.3)
- Cipher suite enumeration against Mozilla recommendation profiles
- Weak algorithm detection (SHA-1 signatures, RSA < 2048)
- OCSP Must-Staple and certificate transparency checks
- Port-scan integration for discovering TLS-enabled services

### Nmap Integration
- `NmapIntegration` (core wrapper) and `NmapScanner` (scanner module)
- Controlled argument construction — no arbitrary flags
- Result parsing into Pydantic models
- Scope enforcement, timeout, and output directory management
- CLI commands: `scan nmap` with `--project`, `--target`, `--profile` flags

### Fingerprint Intelligence
- WhatWeb integration for technology fingerprinting
- Result parsing into structured models
- Risk scoring based on detected technologies
- `scan fingerprint` CLI command

### Technology Intelligence
- `TechnologyIntelligenceEngine` for analyzing technology profiles
- Risk categorization (end-of-life, deprecated, vulnerable)
- `technology-intel` CLI command

### CVE Intelligence
- `CVEIntelligenceEngine` for matching technologies against known CVEs
- Local knowledge database (`knowledge/cve/`)
- Prioritized CVE lists per technology
- `cve-intel` CLI command

### Nuclei Smart Integration
- Template management (update, list, select by category/severity)
- Smart template selection based on technology profile
- Safe execution without exploitation flags (`-no-auto-exploit`)
- Result parsing into `NucleiResult` model with severity
- Validation mode (triage + optional confirmation before execution)
- `scan nuclei` CLI command

### Reporting Engine
- Report collection: gathers findings from all scanner modules
- Scoring: blended score (findings + risk profile + vulnerability profile)
- HTML renderer with severity badges, score gauge, visual sections
- Markdown renderer with structured sections
- PDF generation via WeasyPrint (HTML → PDF)
- `report generate` CLI command

### Platform Diagnostics (Sprint 10)
- `doctor` — comprehensive environment diagnostic (Python, dependencies, tools, config, Docker)
- `health-check` — quick pass/fail validation
- `status` — per-project status overview
- Enhanced error handling with structured error hierarchy
- Interactive CLI menu (9 options + rich console)

### Full Scan Orchestration
- Pipeline engine: sequential multi-scanner runs
- Three profiles: `lite` (headers + SSL), `standard` (+ Nmap + fingerprint + tech/CVE + Nuclei + OWASP), `deep` (+ Nuclei + OWASP)
- `full-scan` CLI command with progress reporting

### OWASP Top 10 Light Engine (Sprint 11)
- Safe, non-exploitative OWASP Top 10 assessment (A01–A10)
- HTTP enumeration engine: robots.txt, sitemap.xml, security.txt, links, scripts, forms
- Form analyzer: method, action, inputs, hidden fields, CSRF token detection
- Per-category scoring (0–100) and risk classification (LOW/MEDIUM/HIGH/CRITICAL)
- Evidence output: `findings/owasp_findings.json`, `profiles/owasp_profile.json`, `evidence/owasp/*.json`
- CLI command: `scan owasp` (interactive + non-interactive)
- Full integration with reporting engine (HTML/MD sections + blended scoring)
- Full integration with standard/deep scan pipeline
