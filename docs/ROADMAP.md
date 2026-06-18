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

## Upcoming Sprints

### Sprint 11 — OWASP Top 10 Light Engine
- Safe, non-exploitative OWASP Top 10 assessment (A01–A10)
- Read-only HTTP checks (HEAD/GET only, no payloads)
- Per-category scoring and recommendations
- Integrated into pipeline and reporting

### Sprint 12 — Rust Engine
- High-performance scanning via Rust native modules
- Parallel HTTP checks and DNS resolution
- Python/Rust FFI bridge

### Sprint 13 — Payload Engine Seguro
- Controlled, sandboxed payload delivery for authenticated tests
- No brute-force, no DoS, no SQLMap-style injection
- Audit trail for every payload sent

### Sprint 14 — Lab Mode
- Isolated test environment with disposable containers
- Safe experimentation without affecting production
- Automated lab provisioning and teardown

### Sprint 15 — Dashboard
- Web-based dashboard for real-time scan monitoring
- Historical trend analysis and visual reports
- Team collaboration features
