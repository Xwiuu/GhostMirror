# GhostMirror v1.0-alpha

## Highlights

- **Internal Pentest Platform** — project lifecycle, scope enforcement, modular scanner framework
- **Interactive CLI** — Typer + Rich interactive menu and non-interactive commands
- **Scope Guard** — runtime scope enforcement with Pydantic-validated `scope.yaml`
- **Headers Scanner** — HTTP security headers assessment (CSP, HSTS, XFO, etc.)
- **SSL/TLS Scanner** — certificate chain, protocol versions, cipher suites, weak algorithms
- **Nmap Integration** — controlled port scanning with profile support (quick, standard, full)
- **WhatWeb / Fingerprint Intelligence** — technology detection and risk scoring
- **Technology Intelligence** — tech profiling, EOL/deprecated risk categorization
- **CVE Intelligence** — CVE matching against detected technologies
- **Nuclei Smart Validation** — safe template execution with smart selection and triage
- **Reporting Engine** — HTML, Markdown, and PDF report generation with blended scoring
- **Full Scan Orchestration** — lite, standard, and deep pipeline profiles
- **Platform Diagnostics** — `doctor`, `health-check`, and `status` commands
- **OWASP Top 10 Light Engine** (Sprint 11) — safe read-only A01–A10 assessment

## Safety Notice

GhostMirror must only be used on systems with explicit written authorization.
Every scan is bounded by a `scope.yaml` file that defines permitted targets.
Intrusive and destructive categories are disabled by default.

## Validation

| Check | Status |
|-------|--------|
| Tests | 229 passed, 0 failures |
| Build | 2026.06.18 |
| Python | 3.12+ |
| Docker build | Not validated on this host (Docker engine unavailable) |

## Known Warnings

- Pydantic Config deprecation — `NucleiResult` uses class-based `config`, should migrate to `ConfigDict` (Pydantic V2)
- `cryptography` `not_valid_after` deprecation — test mocks use naive datetime, should use UTC-aware
- `datetime.utcnow()` deprecation — two test files use deprecated `utcnow()`
