# Roadmap

## Completed Sprints

| Sprint | Focus | Status |
|--------|-------|--------|
| 1 | Foundation: structure, projects, scope, CLI, logging, config, Docker | ✅ |
| 2 | Recon module (passive surface mapping) | ✅ |
| 3 | SSL/TLS assessment module | ✅ |
| 4 | Nmap port scanning integration | ✅ |
| 5 | Fingerprint intelligence engine | ✅ |
| 6 | Technology intelligence engine | ✅ |
| 7 | CVE intelligence engine | ✅ |
| 8 | Nuclei smart integration | ✅ |
| 9 | Interactive menu + full scan + reporting | ✅ |
| 10 | Platform consolidation: doctor, health-check, status, logging, error handling | ✅ |
| 11 | OWASP Top 10 Light Engine (safe, read-only assessment) | ✅ |

## Upcoming Sprints

### Sprint 12 — Rust Engine ✅
- Native Rust workspace with port scanner, banner grabber, HTTP fingerprint
- Python bridge via subprocess JSON output
- Benchmark: Nmap vs Rust, WhatWeb vs Rust

### Sprint 13 — Safe Payload Engine ✅
- Safe, non-destructive payload validation framework
- 7 categories of safe payloads with safety policy enforcement
- Dry-run, rate limiting, evidence capture, OWASP integration
- CLI command: `scan payloads`

### Sprint 14 — Lab Mode ✅
- Isolated test environment with disposable containers
- Safe experimentation without affecting production
- Automated lab provisioning and teardown

### Sprint 14.2 — Bug Bounty Mode ✅
- Headless crawling, JS/sourcemap analysis, API discovery
- Parameter mining, secrets detection, interesting files
- Subdomain discovery, automated scoring & reporting
- CLI: `ghostmirror bounty scan|crawl|js|apis|secrets|report`

### Sprint 15 — API Security Intelligence ✅
- Non-destructive API analysis pipeline (21 modules)
- API Inventory consolidation from 5 sources
- Swagger/OpenAPI discovery and parsing
- GraphQL detection and intelligence (introspection, playground)
- JWT intelligence with token redaction and weak-algorithm detection
- OAuth/OIDC provider and endpoint mapping
- Object mapping (User, Financial, Admin, Business, Content, Security, Config)
- BOLA, BFLA, Mass Assignment indicator generation
- Rate limiting intelligence
- Correlation engine scoring and recommendations
- CLI: `ghostmirror api inventory|graphql|jwt|oauth|opportunities`
- Report integration (HTML/Markdown)
- Pipeline integration (standard, deep, bounty profiles)

### Sprint 16 — Zero-Day Hypothesis Engine ✅
- 14-module hypothesis generation pipeline
- Anomaly detection, differential analysis, hidden functionality discovery
- Business logic mapping, attack chain correlation
- Confidence engine, hypothesis builder, research queue, composite scoring
- CLI: `ghostmirror zero-day run|anomalies|attack-chains|hypotheses|research`
- Pipeline integration (standard, deep, bounty profiles)
- Documentation: `docs/ZERO_DAY_HYPOTHESIS_ENGINE.md`

### Sprint 17 — Dashboard *(planned)*
- Web-based dashboard for real-time scan monitoring
- Historical trend analysis and visual reports
- Team collaboration features
