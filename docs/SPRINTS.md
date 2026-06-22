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

## Sprint 14 — Lab Mode
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

## Sprint 14.2 — Bug Bounty Mode
- Full bug bounty recon pipeline with 9 modules orchestrated by `BugBountyEngine`
- **Headless Crawler**: Playwright-based navigation with request interception and form extraction
- **Network Capture**: ingest captured requests, filter by scope, detect API candidates
- **JS Bundle Analyzer**: download and analyze JS bundles for sourcemaps, endpoints, secrets
- **Sourcemap Analyzer**: discover and parse `.map` files for source code exposure
- **API Discovery**: combine network, JS, sourcemap, and web intelligence sources
- **Parameter Mining**: extract parameters from forms, routes, and JS
- **Secrets Discovery**: regex-based scanning for 10+ secret types with auto-redaction
- **Interesting Files**: check for robots.txt, .env, backup, admin, sitemap, etc.
- **Subdomain Discovery**: CT logs (crt.sh), HTML links, JS URLs + DNS resolution
- **Scoring & Recommendations**: prioritize opportunities and generate actionable recommendations
- **Report Builder**: consolidate findings into `BugBountyReport` model
- **Findings Mapper**: map bounty findings into standard `FindingModel` for reporting
- CLI group: `ghostmirror bounty scan|crawl|js|apis|secrets|report`
- BountyScopeGuard: rate-limited, depth-controlled scope enforcement
- 153 unit tests (100% mocked, no real network/Playwright)
- Documentation: `docs/BUG_BOUNTY_MODE.md`

## Sprint 15 — API Security Intelligence
- Full API security analysis pipeline with 21 modules orchestrated by `APISecurityEngine`
- **API Inventory**: consolidate endpoints from web intelligence, bug bounty, JS bundles, network capture, and endpoint mapper with dedup
- **Swagger/OpenAPI Discovery**: detect /swagger, /swagger-ui, /openapi.json, /api-docs, /docs
- **OpenAPI Parser**: extract paths, methods, schemas, auth definitions, version
- **GraphQL Discovery**: detect /graphql endpoints and frameworks (Apollo, Hasura, Graphene, Yoga)
- **GraphQL Intelligence**: analyze introspection, playground, and graphiql exposure levels
- **JWT Intelligence**: detect JWT tokens (redacted), parse header claims (alg, kid, typ), payload claims (iss, aud, exp), detect none algorithm and missing expiration
- **OAuth/OIDC Intelligence**: detect providers (Keycloak, Auth0, Azure AD, Cognito, Okta, Google, GitHub), map endpoints (authorize, token, userinfo, jwks)
- **Auth Intelligence**: combine JWT + OAuth into unified auth surface analysis
- **Endpoint Classifier**: classify as API, admin, auth, payment, or GraphQL
- **Object Mapper**: identify resources across 7 categories (User, Financial, Admin, Business, Content, Security, Config)
- **Parameter Analyzer**: classify object reference parameters and sensitive parameters
- **Rate Limit Intelligence**: detect RateLimit headers and classify as Unknown/Present/Strong/Weak
- **BOLA Indicators**: generate hypotheses from endpoint + object + auth, confidence LOW/MEDIUM/HIGH
- **BFLA Indicators**: detect admin/privileged API endpoints with action verbs
- **Mass Assignment Indicators**: detect PUT/PATCH/POST on complex objects with sensitive fields
- **Correlation Engine**: cross-reference JWT + Admin + Swagger + GraphQL + BOLA/BFLA for high-value surfaces
- **Opportunity Scoring**: 0-100 scale with LOW/MEDIUM/HIGH/CRITICAL classifications
- **Exposure Analysis**: calculate API Exposure Score (0-100) from 10 weighted factors
- **Recommendations**: generate specific, actionable API security recommendations
- **Findings Mapper**: map indicators to standard `FindingModel` for report integration
- **Report Builder**: consolidate into `APISecurityReport` model
- **CLI commands**: `ghostmirror api inventory|graphql|jwt|oauth|opportunities` + `ghostmirror analyze api`
- **Pipeline integration**: api_security step in standard, deep, and bounty profiles
- **Report integration**: API Security Intelligence section in HTML and Markdown reports
- Documentation: `docs/API_SECURITY_INTELLIGENCE.md`
- Updated README, CHANGELOG, USAGE, SPRINTS, ROADMAP

## Sprint 16 — Zero-Day Hypothesis Engine
- Full hypothesis generation pipeline with 14 modules orchestrated by `ZeroDayEngine`
- **Anomaly Engine**: detect unexpected status codes, rare headers, size inconsistencies (statistical outlier detection), 30+ rare endpoint patterns (admin, debug, swagger, .git, .env, actuator), sensitive header exposure
- **Differential Engine**: group endpoints by base path, compare status/size/content-type across safe variants (/resource vs /resource/ vs /resource?id=1), detect divergent behavior without fuzzing or brute force
- **Hidden Functionality Engine**: scan JS intelligence, source maps, bundles for 30+ feature flag patterns (isAdmin, debugMode, featureFlag), 25+ debug route patterns (/actuator, /heapdump, /__webpack_hmr), internal functions (_private, _internal), exposed source maps with route extraction
- **Business Logic Engine**: map 8 business flow categories (checkout, coupon/discount, wallet/balance, transfer, subscription, invoice, auth/security, admin), detect financial parameters in requests, identify multi-step complex flows
- **Attack Chain Engine**: 6 correlation chains — JWT+Admin+Objects, GraphQL+Introspection, SourceMaps+Routes, JWT+GraphQL, Admin+SensitiveObjects, API Object Relationships
- **Confidence Engine**: 4-level confidence (LOW/MEDIUM/HIGH/VERY_HIGH), signal quality scoring (10-45 per type), source diversity analysis, cross-module correlation evaluation
- **Hypothesis Builder**: generate structured hypotheses from attack chains, anomalies, opportunities; build cross-cutting hypotheses from signal concentration; detect hypothesis type from components
- **Research Queue**: merge hypotheses + opportunities + attack chains, sort by priority/confidence/score, generate prioritized research queue
- **Scoring**: composite 0-100 (25% anomaly + 25% attack chain + 20% hypothesis + 15% business logic + 10% exposure + 5% API/web), classify LOW/MEDIUM/HIGH/CRITICAL
- 7 Pydantic models: AnomalySignal, Anomaly, AnomalyProfile, AttackChain, ResearchOpportunity, ZeroDayHypothesis, HypothesisReport
- CLI group: `ghostmirror zero-day run|anomalies|attack-chains|hypotheses|research` + `ghostmirror analyze zero-day`
- Pipeline integration: zero_day step in standard, deep, and bounty profiles, dependency on web_intelligence + api_security
- Report integration: Zero-Day Hypothesis Intelligence section in collector
- Documentation: `docs/ZERO_DAY_HYPOTHESIS_ENGINE.md`

## Sprint 17 — HackerOne Style Reporting
- New `HackerOneReportingEngine` orchestrating 14-module bounty submission pipeline
- 5 Pydantic models: BountySubmission, BountyReport, ReproductionStep, EvidenceBlock, BountySeverity/BountyPriority
- Submission Builder consuming 5 intelligence sources
- Safe, non-destructive reproduction steps for 15+ finding categories
- Automatic evidence redaction (tokens, secrets, API keys, JWTs, cookies)
- Professional impact descriptions (business + technical)
- Specific remediation recommendations per vulnerability category
- References mapping (OWASP, CWE, PortSwigger, MITRE, NIST)
- Template Renderer: HackerOne, Bugcrowd, Internal Pentest
- Exporters: Markdown, JSON, HTML (dark theme)
- Report Index with statistics, top 10, quick wins, research opportunities
- CLI group: `ghostmirror bounty report|submissions|export-hackerone|export-bugcrowd`
- Report integration: Bug Bounty Submissions section in main reports
- Documentation: `docs/HACKERONE_STYLE_REPORTING.md`
- 96 unit tests covering all modules
