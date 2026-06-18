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
