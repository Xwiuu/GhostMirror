# Sprint History

## Sprint 1 — Foundation
- Project scaffolding and package structure
- Pydantic models for project, scope, configuration
- Project lifecycle CLI (create, list, open)
- Scope system with `scope.yaml` build, load, Pydantic validation
- Global configuration (`config/default.yaml` + `config/settings.yaml`)
- Centralized logging with Loguru (5 sinks)
- Docker support (`Dockerfile`, `docker-compose.yml`)
- `ghostmirror version` command

## Sprint 2 — Recon Module
- Passive surface mapping scanner
- HTTP header analysis
- Subdomain enumeration structure

## Sprint 3 — SSL/TLS Assessment
- Certificate chain validation and expiry checks
- Protocol version detection (TLS 1.0 → 1.3)
- Cipher suite analysis against Mozilla profiles
- Weak algorithm detection (SHA-1, RSA < 2048)
- OCSP Must-Staple and CT checks
- CLI command: `scan ssl`

## Sprint 4 — Nmap Integration
- `NmapIntegration` core wrapper with controlled args
- `NmapScanner` module extending `ScannerBase`
- Result parsing into Pydantic models
- Scan profiles (quick, standard, full)
- Scope enforcement for target IPs
- CLI command: `scan nmap`

## Sprint 5 — Fingerprint Intelligence
- WhatWeb integration for technology detection
- Result parsing to structured models
- Risk scoring based on detected tech
- CLI command: `scan fingerprint`

## Sprint 6 — Technology Intelligence
- `TechnologyIntelligenceEngine` analysis pipeline
- Risk categorization (EOL, deprecated, vulnerable)
- Knowledge database for technology profiles
- CLI command: `technology-intel`

## Sprint 7 — CVE Intelligence
- `CVEIntelligenceEngine` for CVE matching
- Local CVE knowledge database
- Prioritized CVE lists by technology
- CLI command: `cve-intel`

## Sprint 8 — Nuclei Smart Integration
- Template management (update, list, select)
- Smart template selection from tech profile
- Safe execution (no exploitation flags)
- Result parsing with severity classification
- Validation mode (triage + confirmation)
- CLI command: `scan nuclei`

## Sprint 9 — Interactive Menu & Reporting
- Rich interactive CLI menu (10 options)
- Full scan orchestration pipeline
- Three profiles: lite, standard, deep
- Reporting engine: HTML, Markdown, PDF
- Blended scoring system
- CLI commands: `full-scan`, `report generate`

## Sprint 10 — Platform Consolidation
- `doctor` — environment diagnostics
- `health-check` — quick validation
- `status` — project status overview
- Enhanced error handling (structured hierarchy)
- CLI help refinements and exit codes
- 226 tests, 0 failures

## Sprint 11 — OWASP Top 10 Light Engine
- Safe, non-exploitative OWASP Top 10 assessment (A01–A10)
- HTTP enumeration engine (robots.txt, sitemap.xml, security.txt, links, scripts, forms)
- Form analyzer with CSRF token detection
- Per-category findings and scoring (0–100)
- Evidence output to `evidence/owasp/`
- CLI command: `scan owasp`
- Full integration with reporting engine (HTML/MD sections + blended scoring)
- Full integration with standard/deep scan pipeline
- 10 category checks (Broken Access Control, Cryptographic Failures, Injection, Insecure Design, Misconfiguration, Vulnerable Components, Authentication, Integrity, Logging, SSRF)

## Sprint 12 — Rust Engine Foundation
- Native Rust workspace (`ghostmirror-rs/`) with Cargo.toml, CLI (clap), 3 scan modules
- `Port Scanner`: TCP Connect Scan, single/list/range ports, configurable timeout, concurrent batches
- `Banner Grabber`: TCP service banner + HTTP HEAD/GET banner extraction (Server, X-Powered-By, Via)
- `HTTP Fingerprint`: HEAD + GET requests, header analysis, HTML analysis — detects 15 technologies (WordPress, Drupal, Joomla, Laravel, Django, Flask, Express, Next.js, React, Vue.js, Angular, Nginx, Apache, IIS, Cloudflare) without WhatWeb/BuiltWith/Wappalyzer
- JSON serialization via serde with standardized `PortResult`, `BannerResult`, `FingerprintResult` models
- Python bridge (`ghostmirror/integrations/rust/`): subprocess execution via `ToolRunner`, JSON parsed into Pydantic models
- CLI commands: `scan rust-portscan`, `scan rust-banner`, `scan rust-fingerprint`
- Benchmark: Nmap vs Rust, WhatWeb vs Rust — saved to `projects/evidence/rust/benchmark.json`
- CI job: `cargo fmt`, `cargo clippy`, `cargo test`, release build
- Docker: multi-stage build with Rust builder stage
- Rust unit + integration tests, Python bridge tests

## Sprint 13 — Safe Payload Engine
- `PayloadRegistry`: register, organize, and query safe non-destructive payloads
- `SafetyPolicy`: blocks destructive payloads, BLOCKED safety level, unconfirmed sensitive payloads
- `PayloadEngine`: orchestrates safe payload scan lifecycle with dry-run, rate limiting, evidence capture
- `PayloadExecutor`: executes payloads with baseline vs probe comparison, HTTP requests, signal detection
- 7 safe payload categories: XSS_REFLECTION, SQL_ERROR_INDICATOR, OPEN_REDIRECT_INDICATOR, SSRF_SURFACE_INDICATOR, PATH_TRAVERSAL_INDICATOR, HEADER_INJECTION_INDICATOR, TEMPLATE_INJECTION_INDICATOR
- 5 comparators: ReflectionComparator, ErrorSignatureComparator, RedirectComparator, StatusComparator, TimingComparator
- Evidence capture with body sanitization (no full bodies, no secrets)
- Rate limiter: 2 req/s, max 25 payloads per target
- Dry-run mode: list payloads without executing
- OWASP integration: consumes `evidence/owasp/forms.json` and `evidence/owasp/enumeration.json`
- CLI command: `scan payloads` with `--project`, `--target`, `--category`, `--dry-run`, `--confirm-sensitive`
- Report integration: "Safe Payload Validation" section in HTML and Markdown reports
- Pipeline integration: payloads step in DEEP profile
- Doctor/HealthCheck: validates registry integrity and safety policy
- Safety levels: PASSIVE, SAFE_REFLECTION, SAFE_ERROR_TRIGGER, MANUAL_CONFIRMATION_REQUIRED, BLOCKED
- Automatic blocking of destructive, BLOCKED, and unconfirmed payloads
- Outputs: `findings/payload_findings.json`, `profiles/payload_profile.json`, `evidence/payloads/payload_results.json`, `evidence/payloads/sanitized_evidence.json`
- 95%+ test coverage on payloads module
