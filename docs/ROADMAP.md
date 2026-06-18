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

### Sprint 14 — Lab Mode
- Isolated test environment with disposable containers
- Safe experimentation without affecting production
- Automated lab provisioning and teardown

### Sprint 15 — Dashboard
- Web-based dashboard for real-time scan monitoring
- Historical trend analysis and visual reports
- Team collaboration features
