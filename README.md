# GhostMirror

**Internal Pentest Automation Platform** — v1.0-alpha (Sprint 12)

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

- Interactive & non-interactive CLI (Typer + Rich)
- Project lifecycle management (create, list, open, validate)
- Pydantic-validated scope system (`scope.yaml`)
- Modular scanner framework (headers, SSL/TLS, Nmap, fingerprint, Nuclei)
- **OWASP Top 10 Light Engine** — safe, read-only OWASP assessment (A01–A10)
- Technology & CVE intelligence engines
- Full scan orchestration (Lite, Standard, Deep profiles)
- Multi-format report generation (HTML, Markdown, PDF)
- **Lab Mode** — controlled vulnerable environments (Juice Shop, DVWA, WebGoat, Vuln Demo) for training and testing
- **Platform diagnostics**: `doctor`, `health-check`, `status`
- Centralized logging (execution, scanner, audit, errors)
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
│   │   ├── cli.py                  # Typer + Rich interactive CLI (menu + non-interactive)
│   │   └── main.py                 # Console entrypoint (`ghostmirror`)
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
1. Projetos — manage projects
2. Scans Individuais — run individual scanners
3. Scan Completo Autorizado — run full scan pipeline
4. Intelligence — technology & CVE analysis
5. Relatórios — generate reports
6. Atualizações — update Nuclei templates
7. Doctor — environment diagnostics
8. Health Check — quick validation
9. Status — project status
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

All events are written to `logs/` in the format:

```
[2026-06-18 10:42:01] [INFO] PROJECT_CREATED slug=empresa-x-auditoria uuid=...
[2026-06-18 10:42:02] [INFO] FULL_SCAN_START project=... target=... profile=standard
[2026-06-18 10:42:03] [AUDIT] event='scan iniciado' user='root' project='...' scanner='orchestrator'
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
Orchestrated multi-scanner pipeline:
- `lite` — headers + SSL
- `standard` — headers + SSL + Nmap + fingerprint + tech/CVE intelligence + Nuclei + OWASP
- `deep` — headers + SSL + Nmap + fingerprint + tech/CVE intelligence + Nuclei + OWASP

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
