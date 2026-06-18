"""Benchmark script to compare Rust native engine vs external tools (Nmap, WhatWeb)."""

from __future__ import annotations

import json
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from ghostmirror.core.logger import get_logger
from ghostmirror.integrations.rust.runner import RustBridge

logger = get_logger()

EVIDENCE_DIR = Path("projects/evidence/rust")


def _run_nmap_portscan(host: str, ports: str) -> dict[str, Any]:
    """Run nmap port scan and return timing and result summary."""
    start = time.perf_counter()
    result = subprocess.run(
        ["nmap", "-p", ports, "-T4", "--open", host],
        capture_output=True,
        text=True,
        timeout=120,
    )
    duration = time.perf_counter() - start
    return {
        "tool": "nmap",
        "exit_code": result.returncode,
        "duration_s": round(duration, 3),
        "stdout_size": len(result.stdout),
    }


def _run_rust_portscan(host: str, ports: str) -> dict[str, Any]:
    """Run Rust port scanner and return timing and result summary."""
    bridge = RustBridge()
    start = time.perf_counter()
    result = bridge.portscan(host=host, ports=ports)
    duration = time.perf_counter() - start
    return {
        "tool": "rust",
        "open_ports": len(result.open_ports),
        "duration_s": round(duration, 3),
        "duration_ms": result.duration_ms,
    }


def _run_whatweb_fingerprint(url: str) -> dict[str, Any]:
    """Run WhatWeb fingerprint and return timing."""
    start = time.perf_counter()
    result = subprocess.run(
        ["whatweb", url],
        capture_output=True,
        text=True,
        timeout=60,
    )
    duration = time.perf_counter() - start
    return {
        "tool": "whatweb",
        "exit_code": result.returncode,
        "duration_s": round(duration, 3),
        "stdout_size": len(result.stdout),
    }


def _run_rust_fingerprint(url: str) -> dict[str, Any]:
    """Run Rust fingerprint and return timing."""
    bridge = RustBridge()
    start = time.perf_counter()
    result = bridge.fingerprint(url=url)
    duration = time.perf_counter() - start
    return {
        "tool": "rust",
        "technologies": len(result.technologies),
        "duration_s": round(duration, 3),
    }


def run_benchmark(
    target_host: str,
    ports: str = "22,80,443",
    target_url: str | None = None,
) -> dict[str, Any]:
    """Run all benchmarks and save results to evidence directory."""
    url = target_url or f"https://{target_host}"

    benchmark = {
        "benchmark_id": datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S"),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "target_host": target_host,
        "target_url": url,
        "ports": ports,
        "results": {},
        "comparisons": [],
    }

    # Port scan comparison
    logger.info("BENCHMARK_START type=portscan target={}", target_host)
    nmap_result = _run_nmap_portscan(target_host, ports)
    rust_result = _run_rust_portscan(target_host, ports)
    benchmark["results"]["portscan"] = {"nmap": nmap_result, "rust": rust_result}

    speedup = 0
    if rust_result["duration_s"] > 0 and nmap_result["duration_s"] > 0:
        speedup = round(nmap_result["duration_s"] / rust_result["duration_s"], 2)
    benchmark["comparisons"].append({
        "test": "portscan",
        "nmap_duration_s": nmap_result["duration_s"],
        "rust_duration_s": rust_result["duration_s"],
        "speedup_x": speedup,
    })
    logger.info("BENCHMARK_COMPLETE type=portscan speedup={}x", speedup)

    # Fingerprint comparison
    logger.info("BENCHMARK_START type=fingerprint target={}", url)
    ww_result = _run_whatweb_fingerprint(url)
    rf_result = _run_rust_fingerprint(url)
    benchmark["results"]["fingerprint"] = {"whatweb": ww_result, "rust": rf_result}

    speedup_fp = 0
    if rf_result["duration_s"] > 0 and ww_result["duration_s"] > 0:
        speedup_fp = round(ww_result["duration_s"] / rf_result["duration_s"], 2)
    benchmark["comparisons"].append({
        "test": "fingerprint",
        "whatweb_duration_s": ww_result["duration_s"],
        "rust_duration_s": rf_result["duration_s"],
        "speedup_x": speedup_fp,
    })
    logger.info("BENCHMARK_COMPLETE type=fingerprint speedup={}x", speedup_fp)

    # Save
    EVIDENCE_DIR.mkdir(parents=True, exist_ok=True)
    filepath = EVIDENCE_DIR / "benchmark.json"
    filepath.write_text(json.dumps(benchmark, indent=2, ensure_ascii=False), encoding="utf-8")
    logger.info("BENCHMARK_SAVED path={}", filepath)

    return benchmark


def print_summary(benchmark: dict[str, Any]) -> None:
    """Print human-readable benchmark summary."""
    print("\n=== GHOSTMIRROR RUST BENCHMARK ===")
    print(f"Target: {benchmark['target_host']}")
    print(f"Date: {benchmark['timestamp']}")
    print()
    for comp in benchmark["comparisons"]:
        print(f"[{comp['test'].upper()}]")
        if comp["test"] == "portscan":
            print(f"  Nmap:  {comp['nmap_duration_s']}s")
            print(f"  Rust:  {comp['rust_duration_s']}s")
        else:
            print(f"  WhatWeb: {comp['whatweb_duration_s']}s")
            print(f"  Rust:    {comp['rust_duration_s']}s")
        print(f"  Speedup: {comp['speedup_x']}x")
        print()
