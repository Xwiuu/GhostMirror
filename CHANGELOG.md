# Changelog

All notable changes to GhostMirror are documented here.

## v1.0-alpha — 2026-06-18

### Rust Engine Foundation (Sprint 12)
- Native Rust workspace (`ghostmirror-rs/`) with CLI (clap) and 3 modules
- **Port Scanner**: TCP Connect Scan, supports single port, list, range, 3s timeout, concurrent batches
- **Banner Grabber**: TCP banner + HTTP HEAD/GET banner extraction (Server, X-Powered-By, Via)
- **HTTP Fingerprint**: HEAD/GET + HTML analysis, detects 15 technologies (WordPress, Drupal, Joomla, Laravel, Django, Flask, Express, Next.js, React, Vue.js, Angular, Nginx, Apache, IIS, Cloudflare) — no external dependencies
- Python bridge (`ghostmirror/integrations/rust/`) with `ToolRunner`-based execution and Pydantic models
- CLI commands: `scan rust-portscan`, `scan rust-banner`, `scan rust-fingerprint`
- Benchmark script: Nmap vs Rust, WhatWeb vs Rust, saved to `projects/evidence/rust/benchmark.json`
- CI: Rust job with `cargo fmt`, `cargo clippy`, `cargo test`, release build
- Docker: Multi-stage build with Rust builder stage
- 90%+ test coverage target for Rust modules

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

### Safe Payload Engine (Sprint 13)
- `PayloadRegistry`: register, organize, and query 20+ safe non-destructive payloads across 7 categories
- `SafetyPolicy`: blocks destructive payloads, BLOCKED safety level, requires confirmation for sensitive ones
- `PayloadEngine`: orchestrates safe payload scan lifecycle with dry-run, rate limiting, evidence capture
- `PayloadExecutor`: executes payloads with baseline vs probe comparison, HTTP requests, and signal detection
- Comparators: ReflectionComparator, ErrorSignatureComparator, RedirectComparator, StatusComparator, TimingComparator
- Evidence capture with body sanitization (no full bodies, no secrets exposed)
- Rate limiter: 2 req/s, max 25 payloads per target
- OWASP integration: consumes `evidence/owasp/forms.json` and `evidence/owasp/enumeration.json`
- CLI command: `scan payloads` with `--project`, `--target`, `--category`, `--dry-run`, `--confirm-sensitive`
- Report integration: "Safe Payload Validation" section in HTML and Markdown reports
- Pipeline integration: payloads step in DEEP profile
- Doctor/HealthCheck: validates registry integrity and safety policy
- Safety levels: PASSIVE, SAFE_REFLECTION, SAFE_ERROR_TRIGGER, MANUAL_CONFIRMATION_REQUIRED, BLOCKED
- Outputs: `findings/payload_findings.json`, `profiles/payload_profile.json`, `evidence/payloads/*.json`
- 95%+ test coverage on payloads module
- Documentation: `docs/PAYLOAD_ENGINE_SAFETY.md`

### Lab Mode (Sprint 14)
- Lab catalog with 4 environments: OWASP Juice Shop, DVWA, WebGoat, GhostMirror Vuln Demo
- Docker Compose lifecycle management (`up`, `down`, `ps`) via `DockerRunner`
- `LabManager`: start, stop, status, health check for lab environments
- `LabCatalog`: registry and validation of supported vulnerable environments
- 5-point health check: Docker, compose file, container, port, URL
- `LabProjectFactory`: auto-creates projects with `lab: true`, localhost targets, restrictive `allowed_tests`
- `LabSafetyGuard`: blocks any scan against public domains/IPs in lab projects
- `LabBenchmark`: full-scan deep profile with per-step duration/findings metrics
- CLI group: `ghostmirror lab list|start|stop|status|health|create-project|benchmark`
- Scope model extended: `urls` field in `ScopeTargets`, `lab` flag in `ScopeProjectInfo`
- Report badge: `LAB TARGET` in HTML and Markdown reports for lab projects
- Vuln Demo: custom FastAPI app with 10 safe indicator endpoints
- Doctor extended: validates lab catalog integrity and compose file presence
- 48 unit tests (100% mocked Docker, no real containers)
- Documentation: `docs/LAB_MODE.md`
