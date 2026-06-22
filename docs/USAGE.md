# Usage Guide

## Installation

```bash
python -m venv .venv
source .venv/bin/activate   # Linux/macOS
.venv\Scripts\Activate.ps1  # Windows
pip install -e .
```

## Docker

```bash
docker compose build
docker compose run --rm ghostmirror version
docker compose run --rm ghostmirror doctor
docker compose run --rm ghostmirror health-check
```

## Basic Workflow

### 1. Create a project

```bash
ghostmirror create --client "Client Name" --name "Project Name" --domain target.com
```

### 2. Verify scope

```bash
ghostmirror open <project-slug>
```

The scope.yaml file defines permitted targets. Scans against non-scoped targets
are blocked at runtime.

### 3. Run a scan

Individual scanners:

```bash
ghostmirror scan headers -p <slug> -t target.com
ghostmirror scan ssl -p <slug> -t target.com
ghostmirror scan nmap -p <slug> -t target.com
ghostmirror scan fingerprint -p <slug> -t target.com
ghostmirror scan nuclei -p <slug> -t target.com
```

Or run the full pipeline:

```bash
ghostmirror full-scan --project <slug> --profile lite
ghostmirror full-scan --project <slug> --profile standard
ghostmirror full-scan --project <slug> --profile deep
```

### 4. Generate a report

```bash
ghostmirror report generate --project <slug> --format html
ghostmirror report generate --project <slug> --format markdown
ghostmirror report generate --project <slug> --format pdf
```


## Bug Bounty / HackerOne Reporting

GhostMirror gera relatórios de bug bounty no formato HackerOne e Bugcrowd.

### Generate bounty report

```bash
ghostmirror bounty report --project <slug>
```

### List submissions

```bash
ghostmirror bounty submissions --project <slug>
```

### Export individual submission

```bash
# HackerOne format
ghostmirror bounty export-hackerone --project <slug> --index 1

# Bugcrowd format
ghostmirror bounty export-bugcrowd --project <slug> --index 1
```

### Output

Reports are saved to `reports/bounty/`:

```
reports/bounty/
├── bounty_report.json       # Complete report (JSON)
├── bounty_report.md         # Report (Markdown)
├── bounty_report.html       # Report (HTML, dark theme)
├── submissions/
│   ├── H1-001-*.md          # Individual HackerOne submissions
│   └── ...
└── index.json               # Statistics and priorities
```

See [HACKERONE_STYLE_REPORTING.md](HACKERONE_STYLE_REPORTING.md) for full documentation.

> ⚠️ **Warning**: Use only on authorized targets. Manual validation required before submission.

## Interactive Mode

```bash
ghostmirror
```

Opens a Rich-based menu with options for projects, scans, intelligence,
reporting, diagnostics, and more.

## Platform Diagnostics

```bash
ghostmirror doctor        # comprehensive environment check
ghostmirror health-check  # quick pass/fail
ghostmirror status --project <slug>  # project overview
```

## Safe Payload Validation

```bash
# Dry-run: list payloads without executing
ghostmirror scan payloads -p <slug> -t target.com --dry-run

# Execute by category
ghostmirror scan payloads -p <slug> -t target.com --category XSS_REFLECTION

# Execute with sensitive confirmation
ghostmirror scan payloads -p <slug> -t target.com --confirm-sensitive

# Custom parameter
ghostmirror scan payloads -p <slug> -t target.com --parameter search
```

See [PAYLOAD_ENGINE_SAFETY.md](PAYLOAD_ENGINE_SAFETY.md) for full safety documentation.

## Lab Mode

Start, scan, and benchmark controlled vulnerable environments locally:

```bash
# List available labs
ghostmirror lab list

# Start a lab environment
ghostmirror lab start juice-shop

# Check lab health
ghostmirror lab health juice-shop

# Create a lab-scoped project
ghostmirror lab create-project juice-shop

# Run a full scan against the lab
ghostmirror full-scan --project lab-juice-shop --profile deep

# Run a benchmark (full-scan deep + metrics)
ghostmirror lab benchmark juice-shop

# Stop the lab
ghostmirror lab stop juice-shop
```

See [LAB_MODE.md](LAB_MODE.md) for full documentation.

## Bug Bounty Mode

Automated reconnaissance for authorized bug bounty targets:

```bash
# Full bounty scan (headless crawl + JS analysis + API discovery + secrets)
ghostmirror bounty scan --project <slug> --target https://example.com

# Headless crawl only
ghostmirror bounty crawl --project <slug> --target https://example.com

# JS bundle analysis
ghostmirror bounty js --project <slug> --target https://example.com

# Show discovered APIs
ghostmirror bounty apis --project <slug>

# Show discovered secrets
ghostmirror bounty secrets --project <slug>

# Show bounty report
ghostmirror bounty report --project <slug>
```

See [BUG_BOUNTY_MODE.md](BUG_BOUNTY_MODE.md) for full documentation.

## API Security Intelligence

Non-destructive API analysis, classification, correlation, and scoring:

```bash
# Full API Security Intelligence analysis
ghostmirror api --project <slug> --target https://example.com

# Consolidated API inventory
ghostmirror api inventory --project <slug>

# GraphQL discovery and intelligence
ghostmirror api graphql --project <slug>

# JWT token analysis (redacted tokens, algorithms, claims)
ghostmirror api jwt --project <slug>

# OAuth/OIDC provider detection
ghostmirror api oauth --project <slug>

# API opportunity matrix
ghostmirror api opportunities --project <slug>

# Full analysis via analyze sub-app
ghostmirror analyze api --project <slug> --target https://example.com
```

The API Security Intelligence engine operates on previously collected data (web intelligence, bug bounty, technology profile). Run `ghostmirror web` or a full pipeline scan first to populate the required profiles.

See [API_SECURITY_INTELLIGENCE.md](API_SECURITY_INTELLIGENCE.md) for full documentation.

## Zero-Day Hypothesis Engine

Non-destructive hypothesis generation for unknown vulnerabilities, anomalies, and research opportunities:

```bash
# Full Zero-Day Hypothesis Engine analysis
ghostmirror zero-day run --project <slug>

# View detected anomalies
ghostmirror zero-day anomalies --project <slug>

# View attack chains
ghostmirror zero-day attack-chains --project <slug>

# View generated hypotheses
ghostmirror zero-day hypotheses --project <slug>

# View prioritized research queue
ghostmirror zero-day research --project <slug>

# Via analyze sub-app
ghostmirror analyze zero-day --project <slug>
```

The Zero-Day Hypothesis Engine operates on previously collected data (web intelligence, API security, bug bounty). Run a full pipeline scan first to populate the required profiles.

> **Important**: This engine does NOT find zero-days automatically. It generates hypotheses, anomalies, and research opportunities that require manual validation by a security researcher.

See [ZERO_DAY_HYPOTHESIS_ENGINE.md](ZERO_DAY_HYPOTHESIS_ENGINE.md) for full documentation.
