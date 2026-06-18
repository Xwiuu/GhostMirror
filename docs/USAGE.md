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
