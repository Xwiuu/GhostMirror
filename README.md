# GhostMirror

**Internal Pentest Automation Platform** — v1.0-alpha (Sprint 18)

GhostMirror is an **internal** platform used exclusively by our software house for
**authorized** security audits, attack-surface mapping, security assessments and
report generation.

> ⚠️ **Important**
> - GhostMirror is **not** a public tool.
> - GhostMirror is **not** a tool for attacks.
> - GhostMirror is operated **only** against assets covered by a formally
>   approved engagement scope.

Every project is bounded by a `scope.yaml` file that explicitly enumerates the
in-scope targets and the allowed test categories. Intrusive and destructive
categories are disabled by default and must be opted into deliberately.

---

## Features

- Interactive & non-interactive CLI (Typer + Rich) with reorganized menu
- Quick Scan — one-shot scan from URL input (auto-deletes empty projects)
- Project lifecycle management (create, list, open, validate)
- Pydantic-validated scope system (`scope.yaml`)
- Modular scanner framework (headers, SSL/TLS, Nmap, fingerprint, Nuclei)
- **OWASP Top 10 Light Engine** — safe, read-only OWASP assessment (A01–A10)
- Technology & CVE intelligence engines
- Full scan orchestration (Quick, Standard, Deep profiles)
- Pipeline resilience — missing tools skip steps, errors never crash the pipeline
- Multi-format report generation (HTML, Markdown, PDF) with module execution summary
- **Lab Mode** — controlled vulnerable environments (Juice Shop, DVWA, WebGoat, Vuln Demo) for training and testing
- **Bug Bounty Mode** — headless recon, JS analysis, API discovery, parameter mining, secrets detection, subdomain discovery, automated reporting
- **API Security Intelligence** — non-destructive API analysis: inventory, Swagger/OpenAPI discovery, GraphQL detection, JWT intelligence, OAuth mapping, object mapping, BOLA/BFLA/Mass Assignment indicators, correlation engine, opportunity scoring, attack surface calculation
- **Zero-Day Hypothesis Engine** — anomaly detection, differential analysis, hidden functionality discovery, business logic mapping, attack chain correlation, structured hypothesis generation with confidence scoring, prioritized research queue
- **Attack Chain Intelligence** — transforms isolated signals into prioritized, comprehensible attack chains: signal collection from 10+ modules, attack graph construction, 10 chain templates, scoring (0-100), prioritization, business/technical impact analysis, evidence linking, defensive recommendations, CLI and pipeline integration
- **Pentester Assistant Engine** — guidance copilot for authorized manual review: context loading from 14+ intelligence sources, triage with composite scoring, safe next steps, investigation planning, validation checklists, evidence reasoning, investigative questions, executive risk narrative, HackerOne submission guidance, zero-day safe handling, safety deny-list enforcement
- **Platform diagnostics**: `doctor`, `health-check`, `status`, `doctor --fix`
- Rich progress dashboard with live-updating module table
- User-friendly error handling (no Python tracebacks exposed)
- Centralized logging with enriched context (run_id, module, status, duration, findings)
- Global configuration system (`config/default.yaml` + `config/settings.yaml`)
- Dockerized environment

---

## 🗂 Project structure

```
GHOSTMIRROR/
├── ghostmirror-rs/                 # Rust native engine (port scanner, banner, fingerprint)
│   ├── Cargo.toml
│   ├── src/
│   │   ├── main.rs                 # CLI (clap) — portscan, banner, fingerprint
│   │   ├── lib.rs
│   │   ├── models.rs               # PortResult, BannerResult, FingerprintResult
│   │   ├── output.rs               # JSON serialization
│   │   ├── port_scanner.rs         # TCP Connect Scan
│   │   ├── banner_grabber.rs       # TCP + HTTP banner grab
│   │   └── http_fingerprint.rs     # HEAD/GET + HTML analysis
│   └── tests/                      # Rust integration tests
├── ghostmirror/                    # Python package
│   ├── app/                        # Application layer (CLI / entrypoints)
│   │   ├── baner.py                # Rich visual banner (full + compact)
│   │   ├── cli.py                  # Typer + Rich interactive CLI (menu + non-interactive)
│   │   ├── error_handler.py        # User-friendly error display with Rich Panels
│   │   ├── main.py                 # Console entrypoint (`ghostmirror`)
│   │   ├── progress.py             # Live-updating scan progress dashboard
│   │   └── url_normalizer.py       # URL normalization utilities
│   ├── core/                       # Use-case orchestration
│   │   ├── config_manager.py       # Global settings
│   │   ├── exceptions.py           # Exception hierarchy
│   │   ├── logger.py               # Loguru configuration (5 sinks)
│   │   ├── project_manager.py      # Project lifecycle
│   │   └── scope_manager.py        # Scope build / load / validate
│   ├── models/                     # Pydantic domain models
│   ├── storage/                    # Filesystem persistence
│   ├── integrations/               # External tool integrations
│   │   ├── nmap/                   # Nmap integration
│   │   ├── nuclei/                 # Nuclei integration
│   │   ├── whatweb/                # WhatWeb integration
│   │   └── rust/                   # Rust native engine bridge
│   │       ├── runner.py           # RustBridge — subprocess + JSON parse
│   │       ├── models.py           # Pydantic models for Rust output
│   │       └── benchmark.py        # Benchmark: Nmap vs Rust, WhatWeb vs Rust
│   ├── modules/                    # Scanner framework + concrete modules
│   │   ├── base/                   # ScannerBase (abstract)
│   │   ├── findings/               # FindingsManager
│   │   ├── reporting/              # ReportGenerator (HTML/MD/PDF)
│   │   ├── orchestrator/           # Full scan orchestration
│   │   ├── headers/                # HTTP Security Headers scanner
│   │   ├── ssl/                    # SSL/TLS scanner
│   │   ├── nmap/                   # Port scanner
│   │   ├── fingerprint/            # Technology fingerprint scanner
│   │   ├── nuclei/                 # Nuclei vulnerability scanner
│   │   ├── cve_intelligence/       # CVE matching engine
│   │   ├── technology_intelligence/ # Technology risk engine
│   │   ├── zero_day/               # Zero-Day Hypothesis Engine
│   │   └── platform/               # Doctor, health-check, diagnostics, logging
│   └── knowledge/                  # Knowledge databases (CVE, CMS, frameworks, etc.)
├── config/                         # Global configuration
│   ├── default.yaml                # Default settings
│   └── settings.yaml               # User overrides
├── projects/                       # Generated engagement projects
│   └── evidence/rust/              # Rust benchmark results
├── reports/                        # Generated reports
├── logs/                           # Centralized logs
│   ├── execution.log               # All events
│   ├── scanner.log                 # Scanner-only events
│   ├── audit.log                   # Audit trail (scan start/finish)
│   └── errors.log                  # Error backtraces
├── tests/                          # pytest suite
├── Dockerfile                      # Multi-stage build (Rust + Python)
├── docker-compose.yml
├── pyproject.toml
└── README.md
```

Each project created by GhostMirror gets its own isolated tree:

```
projects/<client>-<project>/
├── scope.yaml
├── metadata.json
├── findings/
├── profiles/
├── evidence/
├── execution/
├── reports/
└── recommendations/
```

---

## 🚀 Installation (local)

Requires **Python 3.12+** and **Rust 1.85+** (for native engine).

```bash
# Build native Rust engine
cd ghostmirror-rs
cargo build --release
cd ..

# Then proceed with Python installation
```

```bash
# 1. Create and activate a virtual environment
python -m venv .venv
# Windows (PowerShell)
.venv\Scripts\Activate.ps1
# Linux / macOS
source .venv/bin/activate

# 2. Install GhostMirror (editable) + dependencies
pip install -e .
# or: pip install -r requirements.txt
```

This installs the `ghostmirror` console command.

---


## 🔍 HackerOne / Bug Bounty Reporting

GhostMirror gera relatórios profissionais no estilo HackerOne e Bugcrowd para programas de bug bounty e testes de penetração.

```bash
# Gerar relatório completo de bug bounty submissions
ghostmirror bounty report --project <slug>

# Listar submissions geradas
ghostmirror bounty submissions --project <slug>

# Exportar submission individual no formato HackerOne
ghostmirror bounty export-hackerone --project <slug> --index 1

# Exportar submission individual no formato Bugcrowd
ghostmirror bounty export-bugcrowd --project <slug> --index 1
```

Os relatórios são salvos em `reports/bounty/` com submissions individuais, estatísticas e índices.

> ⚠️ Use only on targets you own or are explicitly authorized to test.
> Reports may require manual validation before submission.

## 🐳 Docker

```bash
# Build (tag: ghostmirror:1.0-alpha)
docker compose build

# Print version (default command, exits cleanly)
docker compose run --rm ghostmirror version

# Run environment diagnostics
docker compose run --rm ghostmirror doctor

# Run quick health check
docker compose run --rm ghostmirror health-check

# Show project status
docker compose run --rm ghostmirror status --project <slug>

# Run the interactive CLI inside the container
docker compose run --rm ghostmirror interactive

# Any sub-command works the same way
docker compose run --rm ghostmirror list
docker compose run --rm ghostmirror create --client "Empresa X" --name "Auditoria"
docker compose run --rm ghostmirror full-scan --project <slug> --profile standard
```

`projects/`, `reports/`, `logs/` and `config/` are mounted as volumes, so data
created inside the container persists on the host.

---

## 🖥 Usage

### Interactive menu

```bash
ghostmirror
```

Main menu options:
1. Novo Projeto — create a project interactively
2. Scan Rápido — quick scan from URL (temp project, auto-delete if empty)
3. Scan Completo — run full scan pipeline with profile picker (Quick/Standard/Deep)
4. Laboratórios — submenu: list, start, stop, status, health
5. Relatórios — generate HTML/MD/PDF reports
6. Sistema — submenu: Doctor, Health Check, Status, Config, Update Templates, Version
0. Sair — exit

### Platform commands (Sprint 10)

```bash
# Version info
ghostmirror version

# Full environment diagnostic
ghostmirror doctor

# Quick health check
ghostmirror health-check

# Project status
ghostmirror status --project <slug>
```

### Rust native engine commands (Sprint 12)

```bash
ghostmirror scan rust-portscan --host example.com --ports 22,80,443
ghostmirror scan rust-banner --host example.com --port 80
ghostmirror scan rust-fingerprint --url https://example.com
```

### Benchmark (Rust vs Nmap / WhatWeb)

```bash
python -m ghostmirror.integrations.rust.benchmark
```

### Bug Bounty commands

```bash
ghostmirror bounty scan --project <slug> --target https://example.com
ghostmirror bounty crawl --project <slug> --target https://example.com
ghostmirror bounty js --project <slug> --target https://example.com
ghostmirror bounty apis --project <slug>
ghostmirror bounty secrets --project <slug>
ghostmirror bounty report --project <slug>
```

### API Security Intelligence commands

```bash
ghostmirror api --project <slug> --target https://example.com
ghostmirror api inventory --project <slug>
ghostmirror api graphql --project <slug>
ghostmirror api jwt --project <slug>
ghostmirror api oauth --project <slug>
ghostmirror api opportunities --project <slug>
ghostmirror analyze api --project <slug> --target https://example.com
```

### Non-interactive commands

```bash
ghostmirror version
ghostmirror config
ghostmirror create --client "Empresa X" --name "Auditoria Externa" \
    --domain empresa.com.br --notes "Janela noturna"
ghostmirror list
ghostmirror open empresa-x-auditoria-externa
ghostmirror full-scan --project <slug> --profile standard
ghostmirror status --project <slug>
```

### Exit codes

| Command | Condition | Exit code |
|---------|-----------|-----------|
| `version` | — | 0 |
| `doctor` | System READY | 0 |
| `doctor` | System WARNING/UNREADY | 1 |
| `health-check` | HEALTHY | 0 |
| `health-check` | UNHEALTHY | 1 |
| `status` | Project found | 0 |
| `status` | Project not found | 1 |
| `--help` | — | 0 |

---

## 🧪 Testing

```bash
pip install -e ".[dev]"   # or: pip install pytest
pytest                    # pytest suite (Python)
pytest --cov=ghostmirror  # With coverage report

# Rust tests
cd ghostmirror-rs
cargo test                # Rust unit + integration tests
cargo fmt --all --check   # Formatting check
cargo clippy -- -D warnings  # Lint check
```

The suite covers all modules including platform diagnostics, error handling,
and CLI commands.

---

## 📜 Logging

All events are written to `logs/` with enriched context when available:

```
[2026-06-18 10:42:01] [INFO] PROJECT_CREATED slug=empresa-x-auditoria uuid=...
[2026-06-18 10:42:02] [INFO] [run_id=a1b2c3d4e5f6 module=orchestrator] FULL_SCAN_START ...
[2026-06-18 10:42:03] [INFO] [run_id=a1b2c3d4e5f6 module=headers status=completed duration=3.2s findings=5] ...
[2026-06-18 10:42:04] [AUDIT] event='scan iniciado' user='root' project='...' scanner='orchestrator'
```

### Log sinks

| File | Level | Content |
|------|-------|---------|
| `execution.log` | INFO | All non-audit events |
| `scanner.log` | INFO | Scanner & integration events |
| `audit.log` | INFO | Audit trail (scan lifecycle) |
| `errors.log` | ERROR | Full backtrace for errors |
| Console (stderr) | WARNING | Warnings and errors only |

---

## 🏗 Architecture Layers

```
┌─────────────────────────────────────────────┐
│                 CLI Layer                    │
│  (Typer + Rich: interactive & non-int.)     │
├─────────────────────────────────────────────┤
│             Application Layer               │
│  (project lifecycle, scan orchestration)     │
├─────────────────────────────────────────────┤
│              Domain Models                  │
│  (Pydantic: Project, Scope, Finding, etc.)   │
├─────────────────────────────────────────────┤
│            Scanner Framework                │
│  (ScannerBase → ssl, nmap, nuclei, etc.)     │
├─────────────────────────────────────────────┤
│          Intelligence Engines               │
│  (Technology, CVE, Fingerprint)              │
├─────────────────────────────────────────────┤
│      Rust Native Engine (ghostmirror-rs)    │
│  (portscan, banner, fingerprint CLI)         │
├─────────────────────────────────────────────┤
│            Storage & Persistence            │
│  (Filesystem: findings, profiles, evidence)  │
├─────────────────────────────────────────────┤
│         Reporting & Diagnostics             │
│  (HTML/MD/PDF, doctor, health-check, status) │
└─────────────────────────────────────────────┘
```

## 🦀 Rust Native Engine

GhostMirror agora possui motor nativo em Rust para operações de alta performance:

| Comando | Descrição |
|---------|-----------|
| `ghostmirror scan rust-portscan` | TCP Connect Scan (única/lista/range) |
| `ghostmirror scan rust-banner` | Banner grabbing TCP + HTTP |
| `ghostmirror scan rust-fingerprint` | Detecção de 15 tecnologias web |

### Detecções próprias (sem WhatWeb/BuiltWith/Wappalyzer)

- **CMS**: WordPress, Drupal, Joomla
- **Frameworks**: Laravel, Django, Flask, Express, Next.js
- **Frontend**: React, Vue.js, Angular
- **Servidores**: Nginx, Apache, IIS
- **CDN/WAF**: Cloudflare

### Benchmark

```bash
python -m ghostmirror.integrations.rust.benchmark
```

Resultados salvos em `projects/evidence/rust/benchmark.json`.

## 🩺 Platform Commands

### ghostmirror doctor
Comprehensive environment diagnostic:
- Python version and virtual environment check
- Dependency validation (all required packages)
- External tool availability (Nmap, WhatWeb, Nuclei)
- Configuration file integrity
- Docker status
- Reports READY, WARNING, or UNREADY with actionable details.

```bash
ghostmirror doctor
```

### ghostmirror doctor --fix
Interactive repair mode — detects missing tools, suggests install commands, and
executes them one-by-one with user confirmation:

```bash
ghostmirror doctor --fix
```

### ghostmirror health-check
Quick pass/fail validation:
- Verifies core dependencies are importable
- Checks configuration is loadable
- Returns HEALTHY or UNHEALTHY with a single message.

```bash
ghostmirror health-check
```

### ghostmirror status
Per-project status overview:
- Project metadata and scope summary
- Scan history per module
- Findings count by severity
- Report generation status

```bash
ghostmirror status --project <slug>
```

### ghostmirror full-scan
Orchestrated multi-scanner pipeline (resilient — missing tools are skipped, errors never crash):
- `quick` — headers + SSL + Nmap + fingerprint + report
- `standard` — headers + SSL + Nmap + fingerprint + tech/CVE intelligence + Nuclei + OWASP + report
- `deep` — headers + SSL + Nmap + fingerprint + tech/CVE intelligence + Nuclei + OWASP + payloads + report

```bash
ghostmirror full-scan --project <slug> --profile standard
```

### ghostmirror report generate
Multi-format report generation from collected findings:

```bash
ghostmirror report generate --project <slug> --format html
ghostmirror report generate --project <slug> --format markdown
ghostmirror report generate --project <slug> --format pdf
```

## 🗺 Roadmap

| Sprint | Focus | Status |
| ------ | ----- | ------ |
| 1 | Foundation: structure, projects, scope, CLI, logging, config, Docker | ✅ |
| 2 | Recon module (passive surface mapping) | ✅ |
| 3 | SSL/TLS assessment module | ✅ |
| 4 | Nmap port scanning integration | ✅ |
| 5 | Fingerprint intelligence engine | ✅ |
| 6 | Technology intelligence engine | ✅ |
| 7 | CVE intelligence engine | ✅ |
| 8 | Nuclei smart integration | ✅ |
| 9 | Interactive menu + full scan + reporting | ✅ |
| **10** | **Platform consolidation: doctor, health-check, status, logging, error handling** | ✅ |
| **11** | **OWASP Top 10 Light Engine (safe, read-only checks)** | ✅ |
| **12** | **Rust Engine Foundation (port scanner, banner, fingerprint, Python bridge)** | ✅ |
| **13** | **Safe Payload Engine (non-destructive payloads, dry-run, safety policy)** | ✅ |
| **14.1** | **UX Hardening: new interactive menu, pipeline resilience, progress dashboard, error handler, doctor --fix, logging enrichment, report module summary, lab Rich tables** | ✅ |
| **14.2** | **Bug Bounty Mode: headless crawling, JS/sourcemap analysis, API discovery, parameter mining, secrets detection, interesting files, subdomain discovery, scoring & reporting** | ✅ |
