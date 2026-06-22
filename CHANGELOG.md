# Changelog

All notable changes to GhostMirror are documented here.

## v1.0-alpha — 2026-06-22

### Zero-Day Hypothesis Engine (Sprint 16)
- New `ZeroDayEngine` orchestrating 14-module hypothesis generation pipeline
- **Anomaly Engine**: detect unexpected status codes, rare headers, size inconsistencies, exposed objects, rare endpoints (admin, debug, swagger, .git, .env)
- **Differential Engine**: compare safe endpoint variants for divergent status/size/content-type behavior
- **Hidden Functionality Engine**: scan JS, source maps, and bundles for feature flags (isAdmin, debugMode), debug routes (/actuator, /heapdump), internal functions (_private, _admin)
- **Business Logic Engine**: map checkout, coupon, wallet, transfer, subscription, invoice, and auth flows; detect financial parameters and multi-step flows
- **Attack Chain Engine**: correlate JWT + Admin + Objects, GraphQL + Introspection, Source Maps + Internal Routes into attack chains
- **Confidence Engine**: 4-level confidence (LOW/MEDIUM/HIGH/VERY_HIGH) based on signal quantity, quality, source diversity, and correlation
- **Hypothesis Builder**: generate structured hypotheses with title, confidence, signals, reasoning, attack scenario, and recommendations
- **Research Queue**: prioritize all hypotheses/opportunities/chains by priority, confidence, and score
- **Scoring**: composite 0-100 score (25% anomaly + 25% attack chain + 20% hypothesis + 15% business logic + 10% exposure + 5% API/web)
- 7 Pydantic models: AnomalySignal, Anomaly, AnomalyProfile, AttackChain, ResearchOpportunity, ZeroDayHypothesis, HypothesisReport
- CLI group: `ghostmirror zero-day run|anomalies|attack-chains|hypotheses|research` + `ghostmirror analyze zero-day`
- Pipeline integration: zero_day step in standard, deep, and bounty profiles
- Report integration: Zero-Day Hypothesis Intelligence collected in report collector
- Documentation: `docs/ZERO_DAY_HYPOTHESIS_ENGINE.md`
- Updated README, CHANGELOG, USAGE, SPRINTS, ROADMAP

### API Security Intelligence (Sprint 15)
- New `APISecurityEngine` orchestrating 21-module API intelligence pipeline
- **API Inventory**: multi-source consolidation (web intel, bug bounty, JS, network, endpoint mapper)
- **Swagger/OpenAPI Discovery**: detect /swagger, /openapi.json, /api-docs, /docs
- **OpenAPI Parser**: extract paths, methods, schemas, auth definitions
- **GraphQL Discovery**: detect /graphql endpoints and frameworks (Apollo, Hasura, Graphene, Yoga)
- **GraphQL Intelligence**: analyze introspection, playground, graphiql indicators
- **JWT Intelligence**: detect JWT tokens (redacted), analyze alg/kid/typ/iss/aud/exp, detect weak algs
- **OAuth/OIDC Intelligence**: detect providers (Keycloak, Auth0, Azure AD, Cognito, Okta, Google, GitHub)
- **Auth Intelligence**: combine JWT + OAuth into unified auth surface
- **Endpoint Classifier**: classify as API, admin, auth, payment, GraphQL
- **Object Mapper**: identify resources (User, Financial, Admin, Business, Content, Security, Config)
- **Parameter Analyzer**: classify object references and sensitive parameters
- **Rate Limit Intelligence**: detect RateLimit headers and classify strength
- **BOLA Indicators**: generate BOLA hypotheses from endpoints + objects + auth (LOW/MEDIUM/HIGH)
- **BFLA Indicators**: detect BFLA opportunities in admin/privileged APIs
- **Mass Assignment Indicators**: detect PUT/PATCH/POST on complex objects with sensitive fields
- **Correlation Engine**: cross-reference JWT + Admin + Swagger + GraphQL + BOLA + BFLA
- **Opportunity Scoring**: 0-100, classifications LOW/MEDIUM/HIGH/CRITICAL
- **Report Builder**: APISecurityReport with all findings and recommendations
- CLI group: `ghostmirror api inventory|graphql|jwt|oauth|opportunities` + `ghostmirror analyze api`
- Pipeline integration: api_security step in standard, deep, and bounty profiles
- Report integration: API Security Intelligence section in HTML and Markdown reports
- Documentation: `docs/API_SECURITY_INTELLIGENCE.md`
- Updated README, CHANGELOG, USAGE, SPRINTS, ROADMAP

## v1.0-alpha — 2026-06-22

### Bug Bounty Mode (Sprint 14.2)
- New `BugBountyEngine` orchestrating 9-module recon pipeline
- **Headless Crawler**: Playwright-based crawling with XHR/fetch interception and form extraction
- **Network Capture**: request ingestion, scope filtering, API candidate detection
- **JS Bundle Analyzer**: download JS bundles, detect sourcemaps, endpoints, secrets
- **Sourcemap Analyzer**: discover `.map` files, extract original sources and endpoints
- **API Discovery**: multi-source consolidation (network, JS, sourcemap, web intelligence)
- **Parameter Mining**: extract params from forms, routes, and JS bundles
- **Secrets Discovery**: 10+ regex patterns (Google Maps, AWS, JWT, Slack, GitHub, etc.) with auto-redaction
- **Interesting Files**: check robots.txt, .env, backup, admin, sitemap.xml, .git, etc.
- **Subdomain Discovery**: CT logs (crt.sh), HTML links, JS URLs + DNS resolution
- **Scoring & Recommendations**: opportunity scoring, risk classification, actionable recommendations
- **Report Builder**: `BugBountyReport` model with consolidated findings
- **Findings Mapper**: maps bounty findings to standard `FindingModel` entries
- CLI group: `ghostmirror bounty scan|crawl|js|apis|secrets|report`
- `BountyScopeGuard`: rate-limited, depth-controlled scope enforcement
- 153 unit tests (100% mocked, no real network/Playwright)
- Documentation: `docs/BUG_BOUNTY_MODE.md`
- Updated README, CHANGELOG, USAGE, SPRINTS, ROADMAP

## v1.0-alpha — 2026-06-18

### UX Hardening & Operator Experience (Sprint 14.1)
- Reorganized interactive menu: Novo Projeto, Scan Rápido, Scan Completo (profile picker), Laboratórios, Relatórios, Sistema
- **Quick Scan**: one-shot scan from URL input, temp project auto-deleted if zero findings
- **Pipeline resilience**: `ToolNotFoundError` → SKIPPED step (pipeline continues); general failures → FAILED step (logged, pipeline continues)
- **Profile rename**: `lite` → `quick` with alias support
- **Profile descriptions**: time estimates and module lists displayed during profile selection
- **ExecutionStatus enum**: `PENDING`, `SUCCESS`, `FAILED`, `SKIPPED`, `WARNING` with getter methods (`get_executed_modules`, `get_skipped_modules`, `get_failed_modules`)
- **run_id**: 12-char hex UUID on every scan execution
- **`url_normalizer.py`**: URL/host normalization utility (accepts bare domains, www, http/https)
- **`error_handler.py`**: user-friendly Rich Panel messages for ToolNotFoundError, OutOfScopeError, ToolTimeoutError, ProjectError, ReportGenerationError, FileNotFoundError, KeyboardInterrupt — no Python tracebacks exposed
- **`banner.py`**: `render_banner()` (full Rich Panel) and `render_compact_banner()` (one-line)
- **`progress.py`**: `ProgressDashboard` class with live-updating Rich Layout (header, module table, elapsed time footer); `scan_progress()` context manager
- **`doctor_fix.py`**: interactive repair mode — detects missing tools, suggests install commands, executes with user confirmation
- **Doctor output**: cleaner icons (✓/✗/!), install suggestions table for missing tools
- **Logging enrichment**: execution.log and scanner.log now include `run_id`, `module`, `status`, `duration`, `findings` fields from log extra context
- **Report renderers**: new "Módulos Executados" section in HTML and MD reports with module summary cards (Executed/Skipped/Failed counts) and per-module table (module, status, duration, findings, errors)
- **Lab health**: migrated from plain console.print to Rich Table with check name + status columns
- **Lab status**: added URL column to status table
- 45 new tests (url_normalizer, error_handler, progress, menu, doctor_fix, skipped_modules)
- Documentation updated (README, CHANGELOG)

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
